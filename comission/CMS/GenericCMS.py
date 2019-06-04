#!/usr/bin/env python3

import io
import os
import re
import zipfile
from abc import abstractmethod
from filecmp import dircmp
from typing import List, Pattern

import requests
from checksumdir import dirhash
from pathlib import Path

import comission.utilsCMS as uCMS
from comission.utils.logging import LOGGER
from .models.Core import Core
from .models.Addon import Addon
from .models.Alteration import Alteration
from .models.Vulnerability import Vulnerability


class GenericCMS:
    """ Generic CMS object """

    site_url = ""
    release_site = ""
    download_core_url = ""
    base_download_addon_url = ""
    cve_ref_url = ""

    def __init__(self):
        self.dir_path = ""
        self.plugins = []
        self.themes = []
        self.core = Core()
        self.regex_version_core = re.compile("version = '(.*)';")

        self.core.ignored_files = []
        self.ignored_files_addon = []

        self.version_files_selector = {"./": self.regex_version_core}

    def get_core_version(self) -> str:
        suspects = []

        for suspect_file_path, version_core_regexp in self.version_files_selector.items():
            try:
                with open(os.path.join(self.dir_path, suspect_file_path)) as version_file:
                    for line in version_file:
                        version_core_match = version_core_regexp.search(line)
                        if version_core_match:
                            suspects.append(version_core_match.group(1).strip())
                            break
            except FileNotFoundError as e:
                LOGGER.debug(str(e))
                pass

        suspects_length = len(suspects)

        if suspects_length == 0:
            LOGGER.print_cms("alert", "[-] Version not found. Search manually !", "", 0)
            return ""

        elif suspects_length == 1:
            LOGGER.print_cms("info", "[+] Version used : " + suspects[0], "", 0)
            self.core.version = suspects[0]
            self.core.version_major = suspects[0].split(".")[0]
            return suspects[0]

        else:
            for suspect in suspects:
                LOGGER.print_cms(
                    "alert",
                    "[-] Multiple versions found." + suspect + " You "
                    "should probably check by yourself manually.",
                    "",
                    0,
                )
            return ""

    def get_addon_version(
        self, addon: Addon, addon_path: str, version_file_regexp: Pattern, to_strip: str
    ) -> str:
        version = ""
        try:
            path = os.path.join(addon_path, addon.filename)
            with open(path, encoding="utf8") as addon_info:
                for line in addon_info:
                    version = version_file_regexp.search(line)
                    if version:
                        addon.version = version.group(1).strip(to_strip)
                        LOGGER.print_cms("default", "Version : " + addon.version, "", 1)
                        break

        except FileNotFoundError as e:
            msg = "No standard extension file. Search manually !"
            LOGGER.print_cms("alert", "[-] " + msg, "", 1)
            addon.notes = msg
            return ""
        return addon.version

    @abstractmethod
    def get_url_release(self):
        """
        Get the url to fetch last release data
        """
        pass

    @abstractmethod
    def extract_core_last_version(self, response):
        """
        Extract core last version from HTTP response content
        """
        return ""

    def get_core_last_version(self) -> str:
        """
        Fetch information on last release
        """
        url_release = self.get_url_release()

        try:
            response = requests.get(url_release)
            response.raise_for_status()

            if response.status_code == 200:
                self.last_version = self.extract_core_last_version(response)

        except requests.exceptions.HTTPError as e:
            LOGGER.print_cms("alert", "[-] Unable to retrieve last version. Search manually !", "", 1)
            LOGGER.debug(str(e))
            pass
        return self.last_version

    @abstractmethod
    def get_addon_last_version(self, addon) -> str:
        """
        Get the last released of the plugin and the date
        """
        pass

    @abstractmethod
    def get_archive_name(self) -> str:
        """
        Get the last released of the plugin and the date
        """
        return ""

    def check_core_alteration(self, core_url: str) -> List[Alteration]:
        self.get_archive_name()
        alterations = []
        temp_directory = uCMS.TempDir.create()

        LOGGER.print_cms("info", "[+] Checking core alteration", "", 0)

        try:
            response = requests.get(core_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), "r")
                zip_file.extractall(temp_directory)
                zip_file.close()

        except requests.exceptions.HTTPError as e:
            LOGGER.print_cms(
                "alert", "[-] Unable to find the original archive. Search manually !", "", 0
            )
            self.core.alterations = alterations
            LOGGER.debug(str(e))
            return self.core.alterations

        clean_core_path = os.path.join(temp_directory, Path(self.get_archive_name()))

        dcmp = dircmp(clean_core_path, self.dir_path, self.core.ignored_files)
        uCMS.diff_files(dcmp, alterations, self.dir_path)

        self.core.alterations = alterations
        if alterations is not None:
            msg = "[+] For further analysis, archive downloaded here : " + clean_core_path
            LOGGER.print_cms("info", msg, "", 0)

        return self.core.alterations

    @abstractmethod
    def get_addon_url(self, addon) -> str:
        """
        Generate the addon's url
        """
        pass

    def check_addon_alteration(
        self, addon: Addon, addon_path: str, temp_directory: str
    ) -> str:

        addon_url = self.get_addon_url(addon)

        LOGGER.print_cms("default", f"To download the addon: {addon_url}", "", 1)
        altered = ""

        try:
            response = requests.get(addon_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), "r")
                zip_file.extractall(temp_directory)
                zip_file.close()

                project_dir_hash = dirhash(addon_path, "sha1")
                ref_dir = os.path.join(temp_directory, addon.name)
                ref_dir_hash = dirhash(ref_dir, "sha1")

                if project_dir_hash == ref_dir_hash:
                    altered = "NO"
                    LOGGER.print_cms("good", f"Different from sources : {altered}", "", 1)

                else:
                    altered = "YES"
                    LOGGER.print_cms("alert", f"Different from sources : {altered}", "", 1)

                    dcmp = dircmp(addon_path, ref_dir, self.ignored_files_addon)
                    uCMS.diff_files(dcmp, addon.alterations, addon_path)

                addon.altered = altered

                if addon.alterations is not None:
                    LOGGER.print_cms(
                        "info",
                        f"[+] For further analysis, archive downloaded here : {ref_dir}",
                        "",
                        1,
                    )

        except requests.exceptions.HTTPError as e:
            addon.notes = "The download link is not standard. Search manually !"
            LOGGER.print_cms("alert", addon.notes, "", 1)
            LOGGER.debug(str(e))
            return addon.notes

        return altered

    @abstractmethod
    def check_vulns_core(self):
        """
        Check if there are any vulns on the CMS core used
        """
        pass

    @abstractmethod
    def check_vulns_addon(self, addon) -> List[Vulnerability]:
        """
        Check if there are any vulns on the plugin
        """
        pass

    def core_analysis(self) -> Core:
        LOGGER.print_cms(
            "info",
            "#######################################################"
            + "\n\t\tCore analysis"
            + "\n#######################################################",
            "",
            0,
        )
        # Check current CMS version
        if self.core.version == "":
            self.get_core_version()

        # Get the last released version
        self.get_core_last_version()

        # Check for vuln on the CMS version
        self.check_vulns_core()

        # Check if the core have been altered
        self.check_core_alteration(self.download_core_url + self.core.version + ".zip")

        return self.core

    @abstractmethod
    def addon_analysis(self, addon_type) -> List[Addon]:
        """
        CMS plugin analysis, return a list of dict
        """
        pass

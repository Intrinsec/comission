#!/usr/bin/env python3

import io
import os
import re
import zipfile
from filecmp import dircmp
from typing import List, Tuple, Union, Dict, Pattern

import requests
from checksumdir import dirhash

import comission.utilsCMS as uCMS

from comission.utilsCMS import Log as log


class GenericCMS:
    """ Generic CMS object """

    site_url = ""
    release_site = ""
    download_core_url = ""
    download_addon_url = ""
    cve_ref_url = ""

    def __init__(self):
        self.dir_path = ""
        self.plugins = []
        self.themes = []
        self.core_details = {
            "infos": {"version": "", "last_version": "", "version_major": ""},
            "alterations": [],
            "vulns": [],
        }
        self.regex_version_core = re.compile("version = '(.*)';")

        self.ignored_files_core = []
        self.ignored_files_addon = []

        self.version_files_selector = {"./": self.regex_version_core}

    def get_core_version(self) -> Tuple[str, Union[None, FileNotFoundError]]:
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
                uCMS.log_debug(str(e))
                pass

        suspects_length = len(suspects)

        if suspects_length == 0:
            log.print_cms("alert", "[-] Version not found. Search manually !", "", 0)
            return "", None

        elif suspects_length == 1:
            log.print_cms("info", "[+] Version used : " + suspects[0], "", 0)
            self.core_details["infos"]["version"] = suspects[0]
            self.core_details["infos"]["version_major"] = suspects[0].split(".")[0]
            return suspects[0], None

        else:
            for suspect in suspects:
                log.print_cms(
                    "alert",
                    "[-] Multiple versions found." + suspect + " You "
                    "should probably check by yourself manually.",
                    "",
                    0,
                )
            return "", None

    def get_addon_version(
        self, addon: Dict, addon_path: str, version_file_regexp: Pattern, to_strip: str
    ) -> Tuple[str, Union[None, FileNotFoundError]]:
        version = ""
        try:
            path = os.path.join(addon_path, addon["filename"])
            with open(path, encoding="utf8") as addon_info:
                for line in addon_info:
                    version = version_file_regexp.search(line)
                    if version:
                        addon["version"] = version.group(1).strip(to_strip)
                        log.print_cms("default", "Version : " + addon["version"], "", 1)
                        break

        except FileNotFoundError as e:
            msg = "No standard extension file. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            addon["notes"] = msg
            return "", e
        return version, None

    def get_url_release(self):
        """
        Get the url to fetch last release data
        """
        raise NotImplemented

    def extract_core_last_version(self, response):
        """
        Extract core last version from HTTP response content
        """
        raise NotImplemented

    def get_core_last_version(self) -> Tuple[str, Union[None, requests.exceptions.HTTPError]]:
        """
        Fetch information on last release
        """
        last_version_core = ""
        url_release = self.get_url_release()

        try:
            response = requests.get(url_release)
            response.raise_for_status()

            if response.status_code == 200:
                last_version_core = self.extract_core_last_version(response)

        except requests.exceptions.HTTPError as e:
            msg = "Unable to retrieve last version. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            return "", e
        return last_version_core, None

    def get_addon_last_version(self, addon):
        """
        Get the last released of the plugin and the date
        """
        raise NotImplemented

    def get_archive_name(self):
        """
        Get the last released of the plugin and the date
        """
        raise NotImplemented

    def check_core_alteration(
        self, core_url: str
    ) -> Tuple[Union[str, List], Union[None, requests.exceptions.HTTPError]]:
        self.get_archive_name()
        alterations = []
        temp_directory = uCMS.TempDir.create()

        log.print_cms("info", "[+] Checking core alteration", "", 0)

        try:
            response = requests.get(core_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), "r")
                zip_file.extractall(temp_directory)
                zip_file.close()

        except requests.exceptions.HTTPError as e:
            msg = "[-] Unable to find the original archive. Search manually ! "
            log.print_cms("alert", msg, "", 0)
            return msg, e

        clean_core_path = os.path.join(temp_directory, self.get_archive_name())

        dcmp = dircmp(clean_core_path, self.dir_path, self.ignored_files_core)
        uCMS.diff_files(dcmp, alterations, self.dir_path)

        if alterations is not None:
            msg = "[+] For further analysis, archive downloaded here : " + clean_core_path
            log.print_cms("info", msg, "", 0)

        return alterations, None

    def get_addon_url(self, addon):
        """
        Generate the addon's url
        """
        raise NotImplemented

    def check_addon_alteration(
        self, addon: Dict, addon_path: str, temp_directory: str
    ) -> Tuple[str, Union[None, requests.exceptions.HTTPError]]:

        addon_url = self.get_addon_url(addon)

        log.print_cms("default", "To download the addon: " + addon_url, "", 1)
        altered = ""

        try:
            response = requests.get(addon_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), "r")
                zip_file.extractall(temp_directory)
                zip_file.close()

                project_dir_hash = dirhash(addon_path, "sha1")
                ref_dir = os.path.join(temp_directory, addon["name"])
                ref_dir_hash = dirhash(ref_dir, "sha1")

                if project_dir_hash == ref_dir_hash:
                    altered = "NO"
                    log.print_cms("good", "Different from sources : " + altered, "", 1)

                else:
                    altered = "YES"
                    log.print_cms("alert", "Different from sources : " + altered, "", 1)

                    dcmp = dircmp(addon_path, ref_dir, self.ignored_files_addon)
                    uCMS.diff_files(dcmp, addon["alterations"], addon_path)

                addon["altered"] = altered

                if addon["alterations"] is not None:
                    msg = "[+] For further analysis, archive downloaded here : " + ref_dir
                    log.print_cms("info", msg, "", 1)

        except requests.exceptions.HTTPError as e:
            msg = "The download link is not standard. Search manually !"
            log.print_cms("alert", msg, "", 1)
            addon["notes"] = msg
            return msg, e

        return altered, None

    def check_vulns_core(self, version_core):
        """
        Check if there are any vulns on the CMS core used
        """
        raise NotImplemented

    def check_vulns_addon(self, addon):
        """
        Check if there are any vulns on the plugin
        """
        raise NotImplemented

    def core_analysis(self) -> Dict:
        log.print_cms(
            "info",
            "#######################################################"
            + "\n\t\tCore analysis"
            + "\n#######################################################",
            "",
            0,
        )
        # Check current CMS version
        _, err = self.get_core_version()

        # Get the last released version
        _, err = self.get_core_last_version()

        # Check for vuln on the CMS version
        self.core_details["vulns"], err = self.check_vulns_core(
            self.core_details["infos"]["version"]
        )

        # Check if the core have been altered
        download_url = self.download_core_url + self.core_details["infos"]["version"] + ".zip"

        self.core_details["alterations"], err = self.check_core_alteration(download_url)

        return self.core_details

    def addon_analysis(self, addon_type):
        """
        CMS plugin analysis, return a list of dict
        """
        raise NotImplemented

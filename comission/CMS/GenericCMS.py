#!/usr/bin/env python3
import io
import os
import re
import zipfile
from filecmp import dircmp
from typing import List, Tuple, Union, Dict, Pattern

import requests

import comission.utilsCMS as uCMS

from comission.utilsCMS import Log as log


class GenericCMS:
    """ Generic CMS object """

    site_url = ""
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

    def get_core_last_version(self, url):
        """
        Get the last released of the CMS
        """
        raise NotImplemented

    def get_addon_last_version(self, addon):
        """
        Get the last released of the plugin and the date
        """
        raise NotImplemented

    def check_core_alteration(
        self, core_url: str, ignored_files: List, archive_name: str
    ) -> Tuple[Union[str, List], Union[None, requests.exceptions.HTTPError]]:
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

        clean_core_path = os.path.join(temp_directory, archive_name)

        dcmp = dircmp(clean_core_path, self.dir_path, ignored_files)
        uCMS.diff_files(dcmp, alterations, self.dir_path)

        if alterations is not None:
            msg = "[+] For further analysis, archive downloaded here : " + clean_core_path
            log.print_cms("info", msg, "", 0)

        return alterations, None

    def check_addon_alteration(self, addon, addon_path, temp_directory):
        """
        Check if the plugin have been altered
        """
        raise NotImplemented

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

    def core_analysis(self):
        """
        CMS Core analysis, return a dict {"infos": [], "alterations": [], "vulns":[]}
        """
        raise NotImplemented

    def addon_analysis(self, addon_type):
        """
        CMS plugin analysis, return a list of dict
        """
        raise NotImplemented

#!/usr/bin/env python3

import io
import os
import re
import zipfile
from filecmp import dircmp
from typing import List, Tuple, Union, Dict, Pattern

import requests
from checksumdir import dirhash
from lxml import etree

import comission.utilsCMS as uCMS
from comission.utilsCMS import Log as log
from .GenericCMS import GenericCMS


class DPL(GenericCMS):
    """ DRUPAL object """

    site_url = "https://www.drupal.org"
    download_core_url = "https://ftp.drupal.org/files/projects/drupal-"
    download_addon_url = "https://ftp.drupal.org/files/projects/"
    cve_ref_url = ""

    def __init__(self, dir_path, plugins_dir, themes_dir):
        super().__init__()
        self.dir_path = dir_path
        self.addons_path = "sites/all/"
        self.plugins_dir = plugins_dir
        self.themes_dir = themes_dir
        self.plugin_path = ""
        self.core_details = {
            "infos": {"version": "", "last_version": "", "version_major": ""},
            "alterations": [],
            "vulns": [],
        }
        self.plugins = []
        self.themes = []

        self.regex_version_core_dpl7 = re.compile("define\('VERSION', '(.*)'\);")
        self.regex_version_core_dpl8 = re.compile("const VERSION = '(.*)';")
        self.regex_version_addon = re.compile("version = (.*)")
        self.regex_version_addon_web = re.compile('<h2><a href="(.*?)">(.+?) (.+?)</a></h2>')
        self.regex_date_last_release = re.compile('<time pubdate datetime="(.*?)">(.+?)</time>')

        # If no custom plugins directory, then it's in default location
        if self.plugins_dir == "":
            self.plugins_dir = os.path.join(self.addons_path + "modules")

        # If no custom themes directory, then it's in default location
        if self.themes_dir == "":
            self.themes_dir = os.path.join(self.addons_path + "themes")

    def get_core_version(self, dir_path: str) -> Tuple[str, Union[None, FileNotFoundError]]:

        selector = {
            "includes/bootstrap.inc": self.regex_version_core_dpl7,
            "core/lib/Drupal.php": self.regex_version_core_dpl8,
        }
        suspects = []

        for cms_path, version_core_regexp in selector.items():
            try:
                with open(os.path.join(dir_path, cms_path)) as version_file:
                    for line in version_file:
                        version_core_match = version_core_regexp.search(line)
                        if version_core_match:
                            suspects.append(version_core_match.group(1).strip())
                            break
            except FileNotFoundError as e:
                uCMS.log_debug(e)
                pass

        suspects_length = len(suspects)

        if suspects_length == 0:
            log.print_cms("alert", "[-] DRUPAL version not found. Search manually !", "", 0)
            return "", None

        elif suspects_length == 1:
            log.print_cms("info", "[+] DRUPAL version used : " + suspects[0], "", 0)
            self.core_details["infos"]["version"] = suspects[0]
            self.core_details["infos"]["version_major"] = suspects[0].split(".")[0]
            return "", None

        else:
            for suspect in suspects:
                log.print_cms(
                    "alert",
                    "[-] Multiple DRUPAL version found." + suspect + " You "
                    "should probably check by yourself manually !",
                    "",
                    0,
                )
            return "", None

    def get_addon_version(
        self, addon: Dict, addon_path: str, version_file_regexp: Pattern
    ) -> Tuple[str, Union[None, FileNotFoundError]]:
        version = ""
        try:
            path = os.path.join(addon_path, addon["filename"])
            with open(path) as addon_info:
                for line in addon_info:
                    version = version_file_regexp.search(line)
                    if version:
                        addon["version"] = version.group(1).strip('"')
                        log.print_cms("default", "Version : " + addon["version"], "", 1)
                        break

        except FileNotFoundError as e:
            msg = "No standard extension file. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            addon["notes"] = msg
            return "", e
        return version, None

    def get_core_last_version(
        self, url: str
    ) -> Tuple[str, Union[None, requests.exceptions.HTTPError]]:
        last_version_core = ""
        major = self.core_details["infos"]["version_major"]
        url_release = url + major + ".x"

        try:
            response = requests.get(url_release)
            response.raise_for_status()

            if response.status_code == 200:
                tree = etree.fromstring(response.content)
                last_version_core = tree.xpath("/project/releases/release/tag")[0].text
                log.print_cms("info", "[+] Last CMS version: " + last_version_core, "", 0)
                self.core_details["infos"]["last_version"] = last_version_core

        except requests.exceptions.HTTPError as e:
            msg = "Unable to retrieve last drupal version. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            return "", e
        return last_version_core, None

    def get_addon_last_version(
        self, addon: Dict
    ) -> Tuple[str, Union[None, requests.exceptions.HTTPError]]:
        version_web_regexp = self.regex_version_addon_web
        date_last_release_regexp = self.regex_date_last_release

        releases_url = "{}/project/{}/releases".format(self.site_url, addon["name"])
        addon["last_version"] = "Not found"

        if addon["version"] == "VERSION":
            msg = "This is a default addon. Analysis is not yet implemented !"
            log.print_cms("alert", msg, "", 1)
            addon["notes"] = msg
            return "", None

        try:
            response = requests.get(releases_url, allow_redirects=False)
            response.raise_for_status()

            if response.status_code == 200:
                page = response.text

                last_version_result = version_web_regexp.search(page)
                date_last_release_result = date_last_release_regexp.search(page)

                if last_version_result and date_last_release_result:
                    addon["last_version"] = last_version_result.group(3)
                    addon["last_release_date"] = date_last_release_result.group(2)
                    addon["link"] = releases_url

                    if addon["last_version"] == addon["version"]:
                        log.print_cms("good", "Up to date !", "", 1)
                    else:
                        log.print_cms(
                            "alert",
                            "Outdated, last version: ",
                            addon["last_version"]
                            + " ( "
                            + addon["last_release_date"]
                            + " )\n\tCheck : "
                            + releases_url,
                            1,
                        )

        except requests.exceptions.HTTPError as e:
            msg = "Addon not in drupal official site. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            addon["notes"] = msg
            return "", e
        return addon["last_version"], None

    def check_core_alteration(
        self, core_url: str
    ) -> Tuple[Union[str, List], Union[None, requests.exceptions.HTTPError]]:
        alterations = []
        ignored = [
            "modules",
            "CHANGELOG.txt",
            "COPYRIGHT.txt",
            "LICENSE.txt",
            "MAINTAINERS.txt",
            "INSTALL.txt",
            "README.txt",
            "INSTALL.mysql.txt",
            "INSTALL.pgsql.txt",
            "INSTALL.sqlite.txt",
            "UPGRADE.txt",
        ]

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
            msg = "[-] The original drupal archive has not been found. Search " "manually ! "
            log.print_cms("alert", msg, "", 0)
            return msg, e

        clean_core_path = os.path.join(
            temp_directory, "drupal-" + self.core_details["infos"]["version"]
        )

        dcmp = dircmp(clean_core_path, self.dir_path, ignored)
        uCMS.diff_files(dcmp, alterations, self.dir_path)

        return alterations, None

    def check_addon_alteration(
        self, addon: Dict, addon_path: str, temp_directory: str
    ) -> Tuple[Union[str, List, None], Union[None, requests.exceptions.HTTPError]]:
        addon_url = "{}{}-{}.zip".format(self.download_addon_url, addon["name"], addon["version"])

        if addon["version"] == "VERSION":
            # TODO
            return None, None

        log.print_cms("default", "To download the addon : " + addon_url, "", 1)

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

                    ignored = ["tests"]

                    dcmp = dircmp(addon_path, ref_dir, ignored)
                    uCMS.diff_files(dcmp, addon["alterations"], addon_path)

                addon["altered"] = altered

        except requests.exceptions.HTTPError as e:
            msg = "The download link is not standard. Search manually !"
            log.print_cms("alert", msg, "", 1)
            addon["notes"] = msg
            return msg, e
        return altered, None

    def check_vulns_core(self, version_core: str) -> Tuple[List, None]:
        # TODO
        log.print_cms("alert", "CVE check not yet implemented !", "", 1)
        return [], None

    def check_vulns_addon(self, addon: Dict) -> Tuple[List, None]:
        # TODO
        log.print_cms("alert", "CVE check not yet implemented !", "", 1)
        return [], None

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
        _, err = self.get_core_version(self.dir_path)

        # Get the last released version
        _, err = self.get_core_last_version("https://updates.drupal.org/release-history/drupal/")

        # Check for vuln on the CMS version
        self.core_details["vulns"], err = self.check_vulns_core(
            self.core_details["infos"]["version"]
        )

        # Check if the core have been altered
        download_url = self.download_core_url + self.core_details["infos"]["version"] + ".zip"
        self.core_details["alterations"], err = self.check_core_alteration(download_url)

        return self.core_details

    def addon_analysis(self, addon_type: str) -> List:
        temp_directory = uCMS.TempDir.create()
        addons = []
        addons_path = ""

        log.print_cms(
            "info",
            "#######################################################"
            + "\n\t\t"
            + addon_type
            + " analysis"
            + "\n#######################################################",
            "",
            0,
        )

        if self.core_details["infos"]["version_major"] == "7":
            self.addons_path = "sites/all/"

        elif self.core_details["infos"]["version_major"] == "8":
            self.addons_path = "/"

        # Get the list of addon to work with
        if addon_type == "plugins":
            addons_path = self.plugins_dir

        elif addon_type == "themes":
            addons_path = self.themes_dir

        addons_name = uCMS.fetch_addons(os.path.join(self.dir_path, addons_path), "standard")

        for addon_name in addons_name:
            addon = {
                "status": "todo",
                "name": "",
                "version": "",
                "last_version": "",
                "last_release_date": "",
                "link": "",
                "altered": "",
                "cve": "",
                "vulns_details": "",
                "notes": "",
                "alterations": [],
            }
            log.print_cms("info", "[+] " + addon_name, "", 0)

            addon["name"] = addon_name
            addon["type"] = addon_type
            addon["filename"] = addon["name"] + ".info"

            addon_path = os.path.join(self.dir_path, addons_path, addon_name)

            # Get addon version
            _, err = self.get_addon_version(addon, addon_path, self.regex_version_addon)
            if err is not None:
                addons.append(addon)
                continue

            # Check addon last version
            _, err = self.get_addon_last_version(addon)
            if err is not None:
                addons.append(addon)
                continue

            # Check if there are known CVE
            _, err = self.check_vulns_addon(addon)
            if err is not None:
                addons.append(addon)
                continue

            # Check if the addon have been altered
            _, err = self.check_addon_alteration(addon, addon_path, temp_directory)
            if err is not None:
                addons.append(addon)
                continue

            addons.append(addon)

        if addon_type == "plugins":
            self.plugins = addons
        elif addon_type == "themes":
            self.themes = addons

        return addons

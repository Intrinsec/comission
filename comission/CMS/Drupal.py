#!/usr/bin/env python3

import os
import re
from typing import List, Tuple, Union, Dict

import requests
from lxml import etree

import comission.utilsCMS as uCMS
from comission.utilsCMS import Log as log
from .GenericCMS import GenericCMS


class DPL(GenericCMS):
    """ DRUPAL object """

    site_url = "https://www.drupal.org"
    release_site = "https://updates.drupal.org/release-history/drupal/"
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

        self.regex_version_core_dpl7 = re.compile("define\('VERSION', '(.*)'\);")
        self.regex_version_core_dpl8 = re.compile("const VERSION = '(.*)';")
        self.regex_version_addon = re.compile("version = (.*)")
        self.regex_version_addon_web = re.compile('<h2><a href="(.*?)">(.+?) (.+?)</a></h2>')
        self.regex_date_last_release = re.compile('<time pubdate datetime="(.*?)">(.+?)</time>')

        self.core.ignored_files = [
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

        self.ignored_files_addon = ["tests"]

        self.version_files_selector = {
            "includes/bootstrap.inc": self.regex_version_core_dpl7,
            "core/lib/Drupal.php": self.regex_version_core_dpl8,
        }

        # If no custom plugins directory, then it's in default location
        if self.plugins_dir == "":
            self.plugins_dir = os.path.join(self.addons_path + "modules")

        # If no custom themes directory, then it's in default location
        if self.themes_dir == "":
            self.themes_dir = os.path.join(self.addons_path + "themes")

    def get_url_release(self) -> str:
        return f"{self.release_site}{self.core.version_major}.x"

    def extract_core_last_version(self, response) -> str:
        tree = etree.fromstring(response.content)
        last_version_core = tree.xpath("/project/releases/release/tag")[0].text
        log.print_cms("info", f"[+] Last CMS version: {last_version_core}", "", 0)
        self.core.last_version = last_version_core

        return last_version_core

    def get_addon_last_version(
        self, addon: Dict
    ) -> Tuple[str, Union[None, requests.exceptions.HTTPError]]:
        releases_url = f"{self.site_url}/project/{addon['name']}/releases"

        if addon["version"] == "VERSION":
            addon["notes"] = "This is a default addon. Analysis is not yet implemented !"
            log.print_cms("alert", addon["notes"], "", 1)
            return "", None

        try:
            response = requests.get(releases_url, allow_redirects=False)
            response.raise_for_status()

            if response.status_code == 200:
                page = response.text

                last_version_result = self.regex_version_addon_web.search(page)
                date_last_release_result = self.regex_date_last_release.search(page)

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
                            f"{addon['last_version']} ({addon['last_release_date']} ) \n\tCheck : {releases_url}",
                            1,
                        )

        except requests.exceptions.HTTPError as e:
            addon["notes"] = "Addon not on official site. Search manually !"
            log.print_cms("alert", f"[-] {addon['notes']}", "", 1)
            return addon["notes"], e
        return addon["last_version"], None

    def get_addon_url(self, addon) -> str:
        return f"{self.download_addon_url}{addon['name']}-{addon['version']}.zip"

    def check_vulns_core(self) -> Tuple[List, None]:
        # TODO
        log.print_cms("alert", "CVE check not yet implemented !", "", 1)
        return [], None

    def check_vulns_addon(self, addon: Dict) -> Tuple[List, None]:
        # TODO
        log.print_cms("alert", "CVE check not yet implemented !", "", 1)
        return [], None

    def get_archive_name(self):
        return f"drupal-{self.core.version}"

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

        if self.core.version_major == "7":
            self.addons_path = "sites/all/"

        elif self.core.version_major == "8":
            self.addons_path = "/"

        # Get the list of addon to work with
        if addon_type == "plugins":
            addons_path = self.plugins_dir

        elif addon_type == "themes":
            addons_path = self.themes_dir

        addons_name = uCMS.fetch_addons(os.path.join(self.dir_path, addons_path), "standard")

        for addon_name in addons_name:
            addon = {
                "type": addon_type,
                "status": "todo",
                "name": addon_name,
                "version": "",
                "last_version": "Not found",
                "last_release_date": "",
                "link": "",
                "altered": "",
                "cve": "",
                "vulns_details": "",
                "notes": "",
                "alterations": [],
                "filename": addon_name + ".info",
            }
            log.print_cms("info", "[+] " + addon_name, "", 0)

            addon_path = os.path.join(self.dir_path, addons_path, addon_name)

            # Get addon version
            _, err = self.get_addon_version(addon, addon_path, self.regex_version_addon, '"')
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

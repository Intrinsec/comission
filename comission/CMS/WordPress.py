#!/usr/bin/env python3

import os
import re
from distutils.version import LooseVersion # pylint: disable=import-error
from typing import List, Tuple, Union, Dict

import requests
from bs4 import BeautifulSoup

import comission.utilsCMS as uCMS
from comission.utilsCMS import Log as log
from .GenericCMS import GenericCMS
from .models.Vulnerability import Vulnerability
from .models.Addon import Addon


class WP(GenericCMS):
    """ WordPress object """

    site_url = "https://wordpress.org/"
    release_site = "https://api.wordpress.org/core/version-check/1.7/"
    download_core_url = "https://wordpress.org/wordpress-"
    download_addon_url = "https://downloads.wordpress.org/plugin/"
    cve_ref_url = "https://wpvulndb.com/api/v3/"

    def __init__(self, dir_path, wp_content, plugins_dir, themes_dir, wpvulndb_token):
        super().__init__()
        self.dir_path = dir_path
        self.wp_content = wp_content
        self.plugins_dir = plugins_dir
        self.themes_dir = themes_dir
        self.wpvulndb_token = wpvulndb_token

        self.regex_version_core = re.compile("\$wp_version = '(.*)';")
        self.regex_version_addon = re.compile("(?i)Version: (.*)")
        self.regex_version_addon_web_plugin = re.compile('"softwareVersion": "(.*)"')
        self.regex_version_addon_web_theme = re.compile("Version: <strong>(.*)</strong>")
        self.regex_date_last_release_plugin = re.compile('"dateModified": "(.*)"')
        self.regex_date_last_release_theme = re.compile("Last updated: <strong>(.*)</strong>")

        self.core.ignored_files = [
            ".git",
            "cache",
            "plugins",
            "themes",
            "images",
            "license.txt",
            "readme.html",
            "version.php",
        ]

        self.ignored_files_addon = ["css", "img", "js", "fonts", "images"]

        self.version_files_selector = {"wp-includes/version.php": self.regex_version_core}

        if self.wp_content == "":
            # Take the first directory. Force it with --wp-content if you want another one.
            self.wp_content = self.get_wp_content(dir_path)[0]

        # If no custom plugins directory, then it's in wp-content
        if self.plugins_dir == "":
            self.plugins_dir = os.path.join(self.dir_path, self.wp_content, "plugins")

        # If no custom themes directory, then it's in wp-content
        if self.themes_dir == "":
            self.themes_dir = os.path.join(self.dir_path, self.wp_content, "themes")

    def get_wp_content(self, dir_path: str) -> List[str]:
        tocheck = {"plugins", "themes"}
        suspects = []
        for dirname in next(os.walk(dir_path))[1]:
            if tocheck.issubset(next(os.walk(os.path.join(dir_path, dirname)))[1]):
                suspects.append(dirname)
        if len(suspects) > 1:
            log.print_cms(
                "warning",
                "[+] Several directories are suspected to be wp-contents. "
                "Please check and if needed force one with --wp-content.",
                "",
                0,
            )
            for path in suspects:
                log.print_cms("info", f"[+] {path}", "", 1)
            # If none where found, fallback to default one
        if len(suspects) == 0:
            suspects.append("wp-content")
        return suspects

    def get_addon_main_file(self, addon: Addon, addon_path: str) -> str:
        if addon.type == "themes":
            addon.filename = "style.css"

        elif addon.type == "plugins":
            main_file = []

            filename_list = [addon.name + ".php", "plugin.php"]

            if addon.subtype != "mu":
                filename_list.append("plugin.php")

            for filename in filename_list:
                if os.path.isfile(os.path.join(addon_path, filename)):
                    main_file.append(filename)
            if main_file:
                # If the two files exist, the one named as the plugin is more
                # likely to be the main one
                addon.filename = main_file[0]
            else:
                # If no file found, put a random name to trigger an error later
                addon.filename = "nofile"

        return addon.filename

    def get_url_release(self) -> str:
        return self.release_site

    def extract_core_last_version(self, response) -> str:
        page_json = response.json()
        last_version_core = page_json["offers"][0]["version"]
        log.print_cms("info", f"[+] Last CMS version: {last_version_core}", "", 0)
        self.core.last_version = last_version_core

        return last_version_core

    def get_addon_last_version(self, addon: Addon) -> str:
        releases_url = f"{self.site_url}{addon.type}/{addon.name}/"

        # Default on addon of type plugin
        version_web_regexp = self.regex_version_addon_web_plugin
        date_last_release_regexp = self.regex_date_last_release_plugin

        if addon.type == "themes":
            version_web_regexp = self.regex_version_addon_web_theme
            date_last_release_regexp = self.regex_date_last_release_theme

        try:
            response = requests.get(releases_url, allow_redirects=False)
            response.raise_for_status()

            if response.status_code == 200:
                page = response.text

                last_version_result = version_web_regexp.search(page)
                date_last_release_result = date_last_release_regexp.search(page)

                if last_version_result and date_last_release_result:
                    addon.last_version = last_version_result.group(1)
                    addon.last_release_date = date_last_release_result.group(1).split("T")[0]
                    addon.link = releases_url

                    if addon.last_version == addon.version:
                        log.print_cms("good", "Up to date !", "", 1)
                    else:
                        log.print_cms(
                            "alert",
                            "Outdated, last version: ",
                            f"{addon.last_version} ({addon.last_release_date} ) \n\tCheck : {releases_url}",
                            1,
                        )

        except requests.exceptions.HTTPError as e:
            addon.notes = "Addon not on official site. Search manually !"
            log.print_cms("alert", f"[-] {addon.notes}", "", 1)
            raise e
        return addon.last_version

    def get_addon_url(self, addon: Addon) -> str:
        if addon.version == "trunk":
            url = f"{self.download_addon_url}{addon.name}.zip"
        else:
            url = f"{self.download_addon_url}{addon.name}.{addon.version}.zip"
        return url

    def check_vulns_core(self) -> List[Vulnerability]:
        version = self.core.version.replace(".", "")

        url = f"{self.cve_ref_url}wordpresses/{version}"
        url_details = "https://wpvulndb.com/vulnerabilities/"

        headers = {"Authorization": f"Token token={self.wpvulndb_token}"}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            if response.status_code == 200:
                page_json = response.json()

                vulns = page_json[self.core.version]["vulnerabilities"]
                log.print_cms("info", "[+] CVE list", "", 1)

                if len(vulns) > 0:
                    for vuln in vulns:
                        vuln_url = url_details + str(vuln["id"])
                        vuln_details = Vulnerability()

                        vuln_details.name = vuln["title"]
                        vuln_details.link = vuln_url
                        vuln_details.type = vuln["vuln_type"]
                        vuln_details.poc = "CHECK"
                        vuln_details.fixed_in = vuln["fixed_in"]

                        if self.get_poc(vuln_url):
                            vuln_details.poc = "YES"

                        log.print_cms("alert", vuln["title"], "", 1)
                        log.print_cms(
                            "info", f"[+] Fixed in version {str(vuln['fixed_in'])}", "", 1
                        )

                        self.core.vulns.append(vuln_details)
                else:
                    log.print_cms("good", "No CVE were found", "", 1)

        except requests.exceptions.HTTPError as e:
            log.print_cms("info", "No entry on wpvulndb.", "", 1)
            uCMS.log_debug(str(e))
            pass

        return self.core.vulns

    def get_poc(self, url: str) -> List[str]:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "lxml")

        return [el.get_text() for el in soup.findAll("pre", {"class": "poc"})]

    def check_vulns_addon(self, addon: Addon) -> List[Vulnerability]:
        url = f"{self.cve_ref_url}plugins/{addon.name}"
        url_details = "https://wpvulndb.com/vulnerabilities/"

        headers = {"Authorization": f"Token token={self.wpvulndb_token}"}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            if response.status_code == 200:
                page_json = response.json()

                vulns = page_json[addon.name]["vulnerabilities"]
                log.print_cms("info", "[+] CVE list", "", 1)

                if len(vulns) > 0:
                    addon.cve = "YES"

                    for vuln in vulns:
                        vuln_url = url_details + str(vuln["id"])
                        vuln_details = Vulnerability()

                        vuln_details.link = vuln_url
                        vuln_details.type = vuln["vuln_type"]
                        vuln_details.fixed_in = vuln["fixed_in"]
                        vuln_details.poc = "TO CHECK"

                        if self.get_poc(vuln_url):
                            vuln_details.poc = "YES"

                        try:
                            if LooseVersion(addon.version) < LooseVersion(vuln["fixed_in"]):
                                log.print_cms("alert", vuln["title"], "", 1)
                                vuln_details.name = vuln["title"]
                                addon.vulns.append(vuln_details)

                        except (TypeError, AttributeError):
                            log.print_cms(
                                "alert",
                                "Unable to compare version. Please check this "
                                f"vulnerability : {vuln['title']}",
                                "",
                                1,
                            )

                            vuln_details.name = f" To check : {vuln['title']}"
                            addon.vulns.append(vuln_details)

                else:
                    log.print_cms("good", "No CVE were found", "", 1)
                    addon.cve = "NO"

        except requests.exceptions.HTTPError as e:
            log.print_cms("info", "No entry on wpvulndb.", "", 1)
            addon.cve = "NO"
            pass
        return addon.vulns

    def get_archive_name(self) -> str:
        return "wordpress"

    def addon_analysis(self, addon_type: str) -> List[Addon]:
        temp_directory = uCMS.TempDir.create()
        addons = []

        log.print_cms(
            "info",
            "\n#######################################################"
            + "\n\t\t"
            + addon_type
            + " analysis"
            + "\n#######################################################",
            "",
            0,
        )

        addons_paths = {}

        if addon_type == "plugins":
            addons_paths = {
                "standard": self.plugins_dir,
                "mu": os.path.join(self.dir_path, self.wp_content, "mu-plugins"),
            }
        elif addon_type == "themes":
            addons_paths = {"standard": self.themes_dir}

        for key, addons_path in addons_paths.items():
            # Get the list of addon to work with
            addons_name = uCMS.fetch_addons(addons_path, key)

            for addon_name in addons_name:
                addon = Addon()
                addon.type = addon_type
                addon.name = addon_name

                log.print_cms("info", "[+] " + addon.name, "", 0)

                addon.path = os.path.join(addons_path, addon.name)

                if addon_type == "plugins":
                    if key == "mu":
                        addon.subtype = "mu"
                        addon.path = os.path.join(addons_path)
                    else:
                        addon.subtype = ""

                try:
                    # Check addon main file
                    self.get_addon_main_file(addon, addon.path)

                    # Get addon version
                    self.get_addon_version(addon, addon.path, self.regex_version_addon, " ")

                    # Check addon last version
                    self.get_addon_last_version(addon)

                    # Check known CVE in wpvulndb
                    self.check_vulns_addon(addon)

                    # Check if the addon have been altered
                    self.check_addon_alteration(addon, addon.path, temp_directory)

                    addons.append(addon)
                except Exception as e:
                    uCMS.log_debug(str(e))
                    addons.append(addon)
                    pass

        if addon_type == "plugins":
            self.plugins = addons
        elif addon_type == "themes":
            self.themes = addons

        return addons

#!/usr/bin/env python3

import re
import os
import io
import zipfile
import requests

import comission.utilsCMS as uCMS

from comission.utilsCMS import Log as log

from lxml import etree
from filecmp import dircmp
from checksumdir import dirhash
from distutils.version import LooseVersion


class CMS:
    """ CMS object """
    def __init__(self):
        self.site_url = ""
        self.download_core_url = ""
        self.download_plugin_url = ""
        self.cve_ref_url = ""
        self.core_details = {"infos": [], "alterations": [], "vulns":[]}
        self.plugins = []

    def get_core_version(self):
        """
        Get the CMS core version
        """
        raise NotImplemented

    def get_addon_version(self):
        """
        Get a plugin version
        """
        raise NotImplemented

    def get_core_last_version(self):
        """
        Get the last released of the CMS
        """
        raise NotImplemented

    def get_addon_last_version(self):
        """
        Get the last released of the plugin and the date
        """
        raise NotImplemented

    def check_core_alteration(self):
        """
        Check if the core have been altered
        """
        raise NotImplemented

    def check_addon_alteration(self):
        """
        Check if the plugin have been altered
        """
        raise NotImplemented

    def check_vulns_core(self):
        """
        Check if there are any vulns on the CMS core used
        """
        raise NotImplemented

    def check_vulns_addon(self):
        """
        Check if there are any vulns on the plugin
        """
        raise NotImplemented

    def core_analysis(self):
        """
        CMS Core analysis, return a dict {"infos": [], "alterations": [], "vulns":[]}
        """
        raise NotImplemented

    def addon_analysis(self):
        """
        CMS plugin analysis, return a list of dict
        """
        raise NotImplemented


class WP (CMS):
    """ WordPress object """

    def __init__(self, wp_content):
        super().__init__()
        self.site_url = "https://wordpress.org/"
        self.site_api = "https://api.wordpress.org/core/version-check/1.7/"
        self.download_core_url = "https://wordpress.org/wordpress-"
        self.download_addon_url = "https://downloads.wordpress.org/plugin/"
        self.cve_ref_url = "https://wpvulndb.com/api/v2/"
        self.wp_content = wp_content
        self.core_details = {
                                "infos": {
                                            "version":"", "last_version":"", "version_major":""
                                         },
                                "alterations":[],
                                "vulns":[]
                            }
        self.plugins = []
        self.themes = []

    def get_wp_content(self, dir_path):
        tocheck = ["plugins", "themes"]
        suspects = []
        for dirname in next(os.walk(dir_path))[1]:
            if set(tocheck).issubset(next(os.walk(os.path.join(dir_path, dirname)))[1]):
                suspects.append(dirname)
        return suspects

    def get_addon_main_file(self, addon, addon_path):
        if addon["type"] == "themes":
            addon["filename"] = "style.css"

        elif addon["type"] == "plugins":
            main_file = []

            filename_list = [addon["name"] + ".php", "plugin.php"]

            if addon.get("mu") == "YES":
                filename_list = [addon["name"] + ".php"]

            for filename in filename_list:
                if os.path.isfile(os.path.join(addon_path, filename)):
                    main_file.append(filename)
            if main_file:
                # If the two files exist, the one named as the plugin is more
                # likely to be the main one
                addon["filename"] = main_file[0]
            else:
                # If no file found, put a random name to trigger an error later
                addon["filename"] = "nofile"

        return addon["filename"], None

    def get_core_version(self, dir_path, version_core_regexp, cms_path):
        try:
            with open(os.path.join(dir_path, cms_path)) as version_file:
                version_core = ''
                for line in version_file:
                    version_core_match = version_core_regexp.search(line)
                    if version_core_match:
                        version_core = version_core_match.group(1).strip()
                        log.print_cms("info", "[+] WordPress version used : " + version_core, "", 0)
                        self.core_details["infos"]["version"] = version_core
                        self.core_details["infos"]["version_major"] = version_core.split(".")[0]
                        break

        except FileNotFoundError as e:
            log.print_cms("alert", "[-] WordPress version not found. Search manually !", 0)
            return "", e
        return version_core, None

    def get_addon_version(self, addon, addon_path, version_file_regexp):
        try:
            path = os.path.join(addon_path, addon["filename"])
            with open(path) as addon_info:
                version = ''
                for line in addon_info:
                    version = version_file_regexp.search(line)
                    if version:
                        addon["version"] = version.group(1).strip()
                        log.print_cms("default", "Version : " + addon["version"], "", 1)
                        break

        except FileNotFoundError as e:
            msg = "No standard addon file found. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            addon["notes"] = msg
            return "", e
        return version, None

    def get_core_last_version(self, url):
        last_version_core = ""
        try:
            response = requests.get(url)
            response.raise_for_status()

            if response.status_code == 200:
                page_json = response.json()

                last_version_core = page_json["offers"][0]["version"]
                log.print_cms("info", "[+] Last WordPress version: " + last_version_core, "", 0)
                self.core_details["infos"]["last_version"] = last_version_core

        except requests.exceptions.HTTPError as e:
            msg = "Unable to retrieve last WordPress version. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            return "", e
        return last_version_core, None

    def get_addon_last_version(self, addon):
        if addon["type"] == "plugins":
            releases_url = "https://wordpress.org/plugins/{}/".format(addon["name"])
            version_web_regexp = re.compile("\"softwareVersion\": \"(.*)\"")
            date_last_release_regexp = re.compile("\"dateModified\": \"(.*)\"")
        elif addon["type"] == "themes":
            releases_url = "https://wordpress.org/themes/{}/".format(addon["name"])
            version_web_regexp = re.compile("Version: <strong>(.*)</strong>")
            date_last_release_regexp = re.compile("Last updated: <strong>(.*)</strong>")

        addon["last_version"] = "Not found"
        try:
            response = requests.get(releases_url, allow_redirects=False)
            response.raise_for_status()

            if response.status_code == 200:
                page = response.text

                last_version_result = version_web_regexp.search(page)
                date_last_release_result = date_last_release_regexp.search(page)

                if last_version_result and date_last_release_result:
                    addon["last_version"] = last_version_result.group(1)
                    addon["last_release_date"] = date_last_release_result.group(1).split("T")[0]
                    addon["link"] = releases_url

                    if addon["last_version"] == addon["version"]:
                        log.print_cms("good", "Up to date !", "", 1)
                    else:
                        log.print_cms("alert", "Outdated, last version: ", addon["last_version"] +
                                      " ( " + addon["last_release_date"] + " )\n\tCheck : " +
                                      releases_url, 1)

        except requests.exceptions.HTTPError as e:
            msg = "Addon not in WordPress official site. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            addon["notes"] = msg
            return "", e
        return addon["last_version"], None

    def check_core_alteration(self, dir_path, core_url):
        alterations = []
        ignored = [".git", "cache", "plugins", "themes", "images", "license.txt", "readme.html",
                   "version.php"]

        temp_directory = uCMS.TempDir.create()

        log.print_cms("info", "[+] Checking core alteration", "", 0)

        try:
            response = requests.get(core_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), 'r')
                zip_file.extractall(temp_directory)
                zip_file.close()

        except requests.exceptions.HTTPError as e:
            msg = "[-] The original WordPress archive has not been found. Search manually ! "
            log.print_cms("alert", msg, "", 0)
            return msg, e

        clean_core_path = os.path.join(temp_directory, "wordpress")

        dcmp = dircmp(clean_core_path, dir_path, ignored)
        uCMS.diff_files(dcmp, alterations, dir_path)

        if alterations is not None:
            msg = "[+] For further analysis, archive downloaded here : " + clean_core_path
            log.print_cms("info", msg, "", 1)

        return alterations, None

    def check_addon_alteration(self, addon, dir_path, temp_directory):
        addon_url = "{}{}.{}.zip".format(self.download_addon_url, addon["name"], addon["version"])

        if addon["version"] == "trunk":
            addon_url = "{}{}.zip".format(self.download_addon_url, addon["name"])

        log.print_cms("default", "To download the addon: " + addon_url, "", 1)

        try:
            response = requests.get(addon_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), 'r')
                zip_file.extractall(temp_directory)
                zip_file.close()

                project_dir = os.path.join(dir_path, self.wp_content, "plugins", addon["name"])
                project_dir_hash = dirhash(project_dir, 'sha1')
                ref_dir = os.path.join(temp_directory, addon["name"])
                ref_dir_hash = dirhash(ref_dir, 'sha1')

                if project_dir_hash == ref_dir_hash:
                    altered = "NO"
                    log.print_cms("good", "Different from sources : " + altered, "", 1)
                else:
                    altered = "YES"
                    log.print_cms("alert", "Different from sources : " + altered, "", 1)

                    ignored = ["css", "img", "js", "fonts", "images"]

                    dcmp = dircmp(project_dir, ref_dir, ignored)
                    uCMS.diff_files(dcmp, addon["alterations"], project_dir)

                addon["edited"] = altered

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
        vulns_details = []
        version = version_core.replace('.', '')
        url = "{}wordpresses/{}".format(self.cve_ref_url, version)
        url_details = "https://wpvulndb.com/vulnerabilities/"

        try:
            response = requests.get(url)
            response.raise_for_status()

            if response.status_code == 200:
                page_json = response.json()

                vulns = page_json[version_core]["vulnerabilities"]
                log.print_cms("info", "[+] CVE list" , "", 1)

                for vuln in vulns:

                    vuln_details = {
                                    "name": "", "link": "", "type": "", "poc": "",  "fixed_in": ""
                                    }

                    vuln_url = url_details + str(vuln["id"])

                    vuln_details["name"] = vuln["title"]
                    vuln_details["link"] = vuln_url
                    vuln_details["type"] = vuln["vuln_type"]
                    vuln_details["poc"] = "CHECK"
                    vuln_details["fixed_in"] = vuln["fixed_in"]

                    if uCMS.get_poc(vuln_url):
                        vuln_details["poc"] = "YES"

                    log.print_cms("alert", vuln["title"], "", 1)
                    log.print_cms("info", "[+] Fixed in version " + str(vuln["fixed_in"]), "", 1)

                    vulns_details.append(vuln_details)

        except requests.exceptions.HTTPError as e:
            msg = "No entry on wpvulndb."
            log.print_cms("info", "[+] " + msg, "", 1)
            return "", e
        return vulns_details, None

    def check_vulns_addon(self, addon):
        cve = ""
        url_details = "https://wpvulndb.com/vulnerabilities/"
        try:
            url = "{}plugins/{}".format(self.cve_ref_url, addon["name"])

            response = requests.get(url)
            response.raise_for_status()

            if response.status_code == 200:
                page_json = response.json()

                vulns = page_json[addon["name"]]["vulnerabilities"]
                log.print_cms("info", "[+] CVE list", "", 1)

                for vuln in vulns:

                    vuln_url = url_details + str(vuln["id"])
                    vuln_details = {
                                    "name": "", "link": "", "type": "", "poc": "",  "fixed_in": ""
                                    }

                    try:
                        if LooseVersion(addon["version"]) < LooseVersion(vuln["fixed_in"]):
                            log.print_cms("alert", vuln["title"], "", 1)

                            vuln_details["name"] = vuln["title"]
                            vuln_details["link"] = vuln_url
                            vuln_details["type"] = vuln["vuln_type"]
                            vuln_details["fixed_in"] = vuln["fixed_in"]
                            vuln_details["poc"] = "CHECK"

                            if uCMS.get_poc(vuln_url):
                                vuln_details["poc"] = "YES"

                            addon["vulns"].append(vuln_details)

                    except (TypeError, AttributeError)  as e:
                        log.print_cms("alert", "Unable to compare version. Please check this " \
                                      "vulnerability :" + vuln["title"], "", 1)

                        vuln_details["name"] = " To check : " + vuln["title"]
                        vuln_details["link"] = vuln_url
                        vuln_details["type"] = vuln["vuln_type"]
                        vuln_details["fixed_in"] = vuln["fixed_in"]
                        vuln_details["poc"] = "CHECK"

                        if uCMS.get_poc(vuln_url):
                            vuln_details["poc"] = "YES"

                        addon["vulns"].append(vuln_details)

                if addon["vulns"]:
                    addon["cve"] = "YES"
                else:
                    addon["cve"] = "NO"

        except requests.exceptions.HTTPError as e:
            msg = "No entry on wpvulndb."
            log.print_cms("info", "[+] " + msg , "", 1)
            addon["cve"] = "NO"
            return "", e
        return cve, None

    def core_analysis(self, dir_path):
        log.print_cms("info",
        "#######################################################" \
        + "\n\t\tCore analysis" \
        + "\n#######################################################" \
        , "", 0)
        # Check current CMS version
        _, err = self.get_core_version(dir_path, re.compile("\$wp_version = '(.*)';"),
                                       "wp-includes/version.php")
        # Get the last released version
        _, err = self.get_core_last_version(self.site_api)

        # Check for vuln on the CMS version
        self.core_details["vulns"], err = self.check_vulns_core(self.core_details["infos"]["version"])

        # Check if the core have been altered
        download_url = self.download_core_url + self.core_details["infos"]["version"] + ".zip"

        self.core_details["alterations"], err = self.check_core_alteration(dir_path, download_url)

        return self.core_details

    def addon_analysis(self, dir_path, addon_type):
        temp_directory = uCMS.TempDir.create()
        addons = []

        log.print_cms("info",
        "#######################################################" \
        + "\n\t\t" + addon_type + " analysis" \
        + "\n#######################################################" \
        , "", 0)

        # Get the list of addon to work with
        if self.wp_content == "":
            self.wp_content = self.get_wp_content(dir_path)[0]

        addons_paths = {
                       "standard": os.path.join(self.wp_content, addon_type)
                      }

        if addon_type == "plugins":
            addons_paths["mu"] = os.path.join(self.wp_content, "mu-plugins")

        for key, addons_path in addons_paths.items():
            addons_name = uCMS.fetch_addons(os.path.join(dir_path, addons_path), key)

            for addon_name in addons_name:
                addon = {
                        "type":addon_type, "status":"todo", "name":addon_name, "version":"",
                        "last_version":"", "last_release_date":"", "link":"", "edited":"", "cve":"",
                        "vulns":[], "notes":"", "alterations":[], "filename":"", "path":""
                        }

                addon_path = os.path.join(dir_path, addons_path, addon_name)

                if addon_type == "plugins":
                    if key == "mu":
                        addon["mu"] = "YES"
                        addon_path = os.path.join(dir_path, addons_path)
                    else:
                        addon["mu"] = "NO"

                log.print_cms("info", "[+] " + addon_name, "", 0)

                # Check addon main file
                _, err = self.get_addon_main_file(addon, addon_path)
                if err is not None:
                    addons.append(addon)
                    continue

                # Get addon version
                _, err = self.get_addon_version(addon, addon_path, re.compile("(?i)Version: (.*)"))
                if err is not None:
                    addons.append(addon)
                    continue

                # Check addon last version
                _, err = self.get_addon_last_version(addon)
                if err is not None:
                    addons.append(addon)
                    continue

                # Check known CVE in wpvulndb
                _, err = self.check_vulns_addon(addon)
                if err is not None:
                    addons.append(addon)
                    continue

                # Check if the addon have been altered
                _, err = self.check_addon_alteration(addon, dir_path, temp_directory)
                if err is not None:
                    addons.append(addon)
                    continue

                addons.append(addon)

        if addon_type == "plugins":
            self.plugins = addons
        elif addon_type == "themes":
            self.themes = addons

        return addons


class DPL (CMS):
    """ DRUPAL object """

    def __init__(self):
        super().__init__()
        self.site_url = "https://www.drupal.org"
        self.download_core_url = "https://ftp.drupal.org/files/projects/drupal-"
        self.download_addon_url = "https://ftp.drupal.org/files/projects/"
        self.cve_ref_url = ""
        self.addons_path = "sites/all/"
        self.plugins_path = os.path.join(self.addons_path + "modules")
        self.themes_path = os.path.join(self.addons_path + "themes")
        self.plugin_path = ""
        self.core_details = {
                                "infos": {
                                            "version":"", "last_version":"","version_major":""
                                         },
                                "alterations": [], "vulns":[]
                            }
        self.plugins = []
        self.themes = []

    def get_core_version(self, dir_path):

        selector = {
                    "includes/bootstrap.inc": re.compile("define\('VERSION', '(.*)'\);"),
                    "core/lib/Drupal.php": re.compile("const VERSION = '(.*)';")
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
                log.print_cms("alert", "[-] Multiple DRUPAL version found." + suspect + " You "
                              "should probably check by yourself manually !", "", 0)
            return "", None

    def get_addon_version(self, addon, addon_path, version_file_regexp):
        version = ""
        try:
            path = os.path.join(addon_path, addon["filename"])
            with open(path) as addon_info:
                for line in addon_info:
                    version = version_file_regexp.search(line)
                    if version:
                        addon["version"] = version.group(1).strip("\"")
                        log.print_cms("default", "Version : " + addon["version"],
                                      "", 1)
                        break

        except FileNotFoundError as e:
            msg = "No standard extension file. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            addon["notes"] = msg
            return "", e
        return version, None

    def get_core_last_version(self, url, version_core):
        last_version_core = ""
        major = self.core_details["infos"]["version_major"]
        url_release = url + major + ".x"

        try:
            response = requests.get(url_release)
            response.raise_for_status()

            if response.status_code == 200:
                tree = etree.fromstring(response.content)
                last_version_core = tree.xpath("/project/releases/release/tag")[0].text
                log.print_cms("info", "[+] Last CMS version: " + last_version_core,
                              "", 0)
                self.core_details["infos"]["last_version"] = last_version_core

        except requests.exceptions.HTTPError as e:
            msg = "Unable to retrieve last drupal version. Search manually !"
            log.print_cms("alert", "[-] " + msg, "", 1)
            return "", e
        return last_version_core, None

    def get_addon_last_version(self, addon):
        version_web_regexp = re.compile("<h2><a href=\"(.*?)\">(.+?) (.+?)</a></h2>")
        date_last_release_regexp = re.compile("<time pubdate datetime=\"(.*?)\">(.+?)</time>")

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
                        log.print_cms("alert", "Outdated, last version: ", addon["last_version"]
                                      + " ( " + addon["last_release_date"]
                                      + " )\n\tCheck : " + releases_url, 1)

        except requests.exceptions.HTTPError as e:
            msg = "Addon not in drupal official site. Search manually !"
            log.print_cms("alert", "[-] "+ msg, "", 1)
            addon["notes"] = msg
            return "", e
        return addon["last_version"], None

    def check_core_alteration(self, dir_path, version_core, core_url):
        alterations = []
        ignored = ["modules", "CHANGELOG.txt", "COPYRIGHT.txt", "LICENSE.txt", "MAINTAINERS.txt",
                   "INSTALL.txt", "README.txt"]

        temp_directory = uCMS.TempDir.create()

        log.print_cms("info", "[+] Checking core alteration", "", 0)

        try:
            response = requests.get(core_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), 'r')
                zip_file.extractall(temp_directory)
                zip_file.close()

        except requests.exceptions.HTTPError as e:
            msg = "[-] The original drupal archive has not been found. Search " \
                  "manually ! "
            log.print_cms("alert", msg, "", 0)
            return msg, e

        clean_core_path = os.path.join(temp_directory, "drupal-" + version_core)

        dcmp = dircmp(clean_core_path, dir_path, ignored)
        uCMS.diff_files(dcmp, alterations, dir_path)

        return alterations, None

    def check_addon_alteration(self, addon, addon_path, temp_directory):
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
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), 'r')
                zip_file.extractall(temp_directory)
                zip_file.close()

                project_dir_hash = dirhash(addon_path, 'sha1')
                ref_dir = os.path.join(temp_directory, addon["name"])
                ref_dir_hash = dirhash(ref_dir, 'sha1')

                if project_dir_hash == ref_dir_hash:
                    altered = "NO"
                    log.print_cms("good", "Different from sources : " + altered, "", 1)

                else:
                    altered = "YES"
                    log.print_cms("alert", "Different from sources : " + altered, "", 1)

                    ignored = ["tests"]

                    dcmp = dircmp(addon_path, ref_dir, ignored)
                    uCMS.diff_files(dcmp, addon["alterations"], addon_path)

                addon["edited"] = altered

        except requests.exceptions.HTTPError as e:
            msg = "The download link is not standard. Search manually !"
            log.print_cms("alert", msg, "", 1)
            addon["notes"] = msg
            return msg, e
        return altered, None

    def check_vulns_core(self, version_core):
        # TODO
        log.print_cms("alert", "CVE check not yet implemented !", "", 1)
        return [], None

    def check_vulns_addon(self, addon):
        # TODO
        log.print_cms("alert", "CVE check not yet implemented !", "", 1)
        return [], None

    def core_analysis(self, dir_path):
        log.print_cms("info",
                      "#######################################################"
                      + "\n\t\tCore analysis"
                      + "\n#######################################################"
                      , "", 0)

        # Check current CMS version
        _, err = self.get_core_version(dir_path)

        # Get the last released version
        _, err = self.get_core_last_version("https://updates.drupal.org/release-history/drupal/",
                                            self.core_details["infos"]["version"])

        # Check for vuln on the CMS version
        self.core_details["vulns"], err = self.check_vulns_core(self.core_details["infos"]["version"])

        # Check if the core have been altered
        download_url = self.download_core_url + self.core_details["infos"]["version"] + ".zip"
        self.core_details["alterations"], err = self.check_core_alteration(dir_path, self.core_details["infos"]["version"],
                                                                           download_url)

        return self.core_details

    def addon_analysis(self, dir_path, addon_type):
        temp_directory = uCMS.TempDir.create()
        addons = []

        log.print_cms("info",
                      "#######################################################"
                      + "\n\t\t" + addon_type + " analysis"
                      + "\n#######################################################"
                      , "", 0)

        if self.core_details["infos"]["version_major"] == "7":
            self.addons_path = "sites/all/"

        elif self.core_details["infos"]["version_major"] == "8":
            self.addons_path = "/"

        # Get the list of addon to work with
        if addon_type == "plugins":
            addons_path = self.plugins_path

        elif addon_type == "themes":
            addons_path = self.themes_path

        addons_name = uCMS.fetch_addons(os.path.join(dir_path, addons_path), "standard")

        for addon_name in addons_name:
            addon = {
                        "status":"todo","name":"", "version":"","last_version":"",
                        "last_release_date":"", "link":"", "edited":"", "cve":"",
                        "vulns_details":"", "notes":"", "alterations":[]
                    }
            log.print_cms("info", "[+] " + addon_name, "", 0)

            addon["name"] = addon_name
            addon["type"] = addon_type
            addon["filename"] = addon["name"] + ".info"

            addon_path = os.path.join(dir_path, addons_path, addon_name)

            # Get addon version
            _, err = self.get_addon_version(addon, addon_path, re.compile("version = (.*)"))
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

#!/usr/bin/env python3

import re
import os
import io
import sys
import json
import shutil
import zipfile
import requests

from utilsCMS import *
from reportCMS import *

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
        self.plugin_path = ""
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

    def __init__(self):
        super()
        self.site_url = "https://wordpress.org/"
        self.site_api = "https://api.wordpress.org/core/version-check/1.7/"
        self.download_core_url = "https://wordpress.org/wordpress-"
        self.download_addon_url = "https://downloads.wordpress.org/plugin/"
        self.cve_ref_url = "https://wpvulndb.com/api/v2/"
        self.wp_content = ""
        self.plugin_path = ""
        self.theme_path = ""
        self.core_details = {"infos": {"version":"", "last_version":""},
                            "alterations": [], "vulns":[]}
        self.plugins = []
        self.themes = []

    def get_wp_content(self, dir_path):
        tocheck = ["plugins", "themes"]
        suspects = []
        for dirname in next(os.walk(dir_path))[1]:
            if set(tocheck).issubset(next(os.walk(os.path.join(dir_path,dirname)))[1]):
                suspects.append(dirname)
        return suspects

    def get_addon_main_file(self, addon, addon_path):
        if addon["type"] == "themes":
            addon["filename"] = "style.css"

        elif addon["type"] == "plugins":
            main_file = []

            for filename in [addon["name"] + ".php", "plugin.php"]:
                if os.path.isfile(os.path.join(addon_path, filename)):
                    main_file.append(filename)
            if main_file:
                # If the two files exist, the one named as the plugin is more likely to
                # be the main one
                addon["filename"] = main_file[0]
            else:
                # If no file found, put a random name to trigger an error
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
                        print_cms("info", "[+] WordPress version used : "+ version_core, "", 0)
                        self.core_details["infos"]["version"] = version_core
                        break

        except FileNotFoundError as e:
            print_cms("alert", "[-] WordPress version not found. Search manually !", 0)
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
                        print_cms("default", "Version : "+ addon["version"],
                                    "", 1)
                        break

        except FileNotFoundError as e:
            msg = "No standard addon file found. Search manually !"
            print_cms("alert", "[-] " + msg, "", 1)
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
                print_cms("info", "[+] Last WordPress version: "+ last_version_core, "", 0)
                self.core_details["infos"]["last_version"] = last_version_core

        except requests.exceptions.HTTPError as e:
            msg = "Unable to retrieve last WordPress version. Search manually !"
            print_cms("alert", "[-] "+ msg, "", 1)
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

        last_version = "Not found"
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
                        print_cms("good", "Up to date !", "", 1)
                    else:
                        print_cms("alert", "Outdated, last version: ", addon["last_version"] +
                        " ( " + addon["last_release_date"] +" )\n\tCheck : " + releases_url, 1)

        except requests.exceptions.HTTPError as e:
            msg = "Addon not in WordPress official site. Search manually !"
            print_cms("alert", "[-] "+ msg, "", 1)
            addon["notes"] = msg
            return "", e
        return addon["last_version"], None

    def check_core_alteration(self, dir_path, version_core, core_url):
        alterations = []
        ignored = [".git", "cache", "plugins", "themes", "images", "license.txt",
                    "readme.html", "version.php"]

        temp_directory = create_temp_directory()

        print_cms("info", "[+] Checking core alteration", "", 0)

        try:
            response = requests.get(core_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), 'r')
                zip_file.extractall(temp_directory)
                zip_file.close()

        except requests.exceptions.HTTPError as e:
            msg = "[-] The original WordPress archive has not been found. Search manually !"
            print_cms("alert", msg, "", 0)
            return msg, e

        clean_core_path = os.path.join(temp_directory, "wordpress")

        dcmp = dircmp(clean_core_path, dir_path, ignored)
        diff_files(dcmp, alterations, dir_path)

        return alterations, None

    def check_addon_alteration(self, plugin, dir_path, temp_directory):
        plugin_url = "{}{}.{}.zip".format(self.download_addon_url,
                                                plugin["name"],
                                                plugin["version"])

        if plugin["version"] == "trunk":
            plugin_url = "{}{}.zip".format(self.download_addon_url,
                                            plugin["name"])

        print_cms("default", "To download the plugin: " + plugin_url, "", 1)

        try:
            response = requests.get(plugin_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), 'r')
                zip_file.extractall(temp_directory)
                zip_file.close()

                project_dir = os.path.join(dir_path, self.wp_content, "plugins",
                                            plugin["name"])
                project_dir_hash = dirhash(project_dir, 'sha1')
                ref_dir = os.path.join(temp_directory, plugin["name"])
                ref_dir_hash = dirhash(ref_dir, 'sha1')

                if project_dir_hash == ref_dir_hash:
                    altered = "NO"
                    print_cms("good", "Different from sources : " + altered, "", 1)
                else:
                    altered = "YES"
                    print_cms("alert", "Different from sources : " + altered, "", 1)

                    ignored = ["css", "img", "js", "fonts", "images"]

                    root_path = os.path.join(dir_path, self.wp_content, "plugins")

                    dcmp = dircmp(project_dir, ref_dir, ignored)
                    diff_files(dcmp, plugin["alterations"], project_dir)

                plugin["edited"] = altered

        except requests.exceptions.HTTPError as e:
            msg = "The download link is not standard. Search manually !"
            print_cms("alert", msg, "", 1)
            plugin["notes"] = msg
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
                print_cms("info", "[+] CVE list" , "", 1)

                for vuln in vulns:

                    vuln_details = {"name": "", "link": "", "type": "",
                                    "poc": "",  "fixed_in": ""
                                    }

                    vuln_url = url_details + str(vuln["id"])

                    vuln_details["name"] = vuln["title"]
                    vuln_details["link"] = vuln_url
                    vuln_details["type"] = vuln["vuln_type"]
                    vuln_details["poc"] = "CHECK"
                    vuln_details["fixed_in"] = vuln["fixed_in"]

                    if get_poc(vuln_url):
                        vuln_details["poc"] = "YES"

                    print_cms("alert", vuln["title"] , "", 1)
                    print_cms("info", "[+] Fixed in version "+ str(vuln["fixed_in"]) , "", 1)

                    vulns_details.append(vuln_details)

        except requests.exceptions.HTTPError as e:
            msg = "No entry on wpvulndb."
            print_cms("info", "[+] " + msg , "", 1)
            return "", e
        return vulns_details, None

    def check_vulns_addon(self, plugin):
        cve = ""
        url_details = "https://wpvulndb.com/vulnerabilities/"
        try:
            url = "{}plugins/{}".format(self.cve_ref_url,plugin["name"])

            response = requests.get(url)
            response.raise_for_status()

            if response.status_code == 200:
                page_json = response.json()

                vulns = page_json[plugin["name"]]["vulnerabilities"]
                print_cms("info", "[+] CVE list", "", 1)

                for vuln in vulns:

                    vuln_url = url_details + str(vuln["id"])
                    vuln_details = {"name": "", "link": "", "type": "",
                                    "poc": "",  "fixed_in": ""
                                    }

                    try:
                        if LooseVersion(plugin["version"]) < LooseVersion(vuln["fixed_in"]):
                            print_cms("alert", vuln["title"] , "", 1)

                            vuln_details["name"] = vuln["title"]
                            vuln_details["link"] = vuln_url
                            vuln_details["type"] = vuln["vuln_type"]
                            vuln_details["fixed_in"] = vuln["fixed_in"]
                            vuln_details["poc"] = "CHECK"

                            if get_poc(vuln_url):
                                vuln_details["poc"] = "YES"

                            plugin["vulns"].append(vuln_details)

                    except TypeError as e:
                        print_cms("alert", "Unable to compare version. Please check this \
                                            vulnerability :" + vuln["title"] , "", 1)

                        vuln_details["name"] = " To check : " + vuln["title"]
                        vuln_details["link"] = vuln_url
                        vuln_details["type"] = vuln["vuln_type"]
                        vuln_details["fixed_in"] = vuln["fixed_in"]
                        vuln_details["poc"] = "CHECK"

                        if get_poc(vuln_url):
                            vuln_details["poc"] = "YES"

                        plugin["vulns"].append(vuln_details)

                if plugin["vulns"]:
                    plugin["cve"] = "YES"
                else:
                    plugin["cve"] = "NO"

        except requests.exceptions.HTTPError as e:
            msg = "No entry on wpvulndb."
            print_cms("info", "[+] " + msg , "", 1)
            plugin["cve"] = "NO"
            return "", e
        return cve, None

    def core_analysis(self, dir_path):
        print_cms("info",
        "#######################################################" \
        + "\n\t\tCore analysis" \
        + "\n#######################################################" \
        , "", 0)
        # Check current CMS version
        _ , err = self.get_core_version(dir_path,
                                        re.compile("\$wp_version = '(.*)';"),
                                        "wp-includes/version.php")
        # Get the last released version
        _ , err = self.get_core_last_version(self.site_api)

        # Check for vuln on the CMS version
        self.core_details["vulns"] , err = self.check_vulns_core(version_core)

        # Check if the core have been altered
        self.core_details["alterations"], err = self.check_core_alteration(dir_path, version_core,
                                                                        self.download_core_url +
                                                                        version_core + ".zip")

        return self.core_details

    def addon_analysis(self, dir_path, addon_type):
        temp_directory = create_temp_directory()
        addons = []

        print_cms("info",
        "#######################################################" \
        + "\n\t\t" + addon_type + " analysis" \
        + "\n#######################################################" \
        , "", 0)

        # Get the list of addon to work with
        self.wp_content = self.get_wp_content(dir_path)[0]
        addons_path = os.path.join(self.wp_content, addon_type)

        addons_name = fetch_addons(os.path.join(dir_path, addons_path))

        for addon_name in addons_name:
            addon = {"type":"", "status":"todo", "name":"", "version":"",
                    "last_version":"", "last_release_date":"", "link":"",
                    "edited":"", "cve":"", "vulns":[], "notes":"",
                    "alterations" : [], "filename":""
                    }
            print_cms("info", "[+] " + addon_name , "", 0)
            addon["name"] = addon_name
            addon["type"] = addon_type

            addon_path = os.path.join(dir_path, addons_path, addon_name)

            # Check addon main file
            _ , err = self.get_addon_main_file(addon, addon_path)
            if err is not None:
                addons.append(addon)
                continue

            # Get addon version
            _ , err = self.get_addon_version(addon, addon_path,
                                                re.compile("(?i)Version: (.*)"))
            if err is not None:
                addons.append(addon)
                continue

            # Check addon last version
            _ , err = self.get_addon_last_version(addon)
            if err is not None:
                addons.append(addon)
                continue

            # Check known CVE in wpvulndb
            _ , err = self.check_vulns_addon(addon)
            if err is not None:
                addons.append(addon)
                continue

            # Check if the addon have been altered
            _ , err = self.check_addon_alteration(addon, dir_path,
                                                    temp_directory)
            if err is not None:
                addons.append(addon)
                continue

            addons.append(addon)
        shutil.rmtree(temp_directory, ignore_errors=True)

        if addon_type == "plugins":
            self.plugins = addons
        elif addon_type == "themes":
            self.themes = addons

        return addons


class DPL (CMS):
    """ DRUPAL object """

    def __init__(self):
        super()
        self.site_url = "https://www.drupal.org"
        self.download_core_url = "https://ftp.drupal.org/files/projects/drupal-"
        self.download_plugin_url = "https://ftp.drupal.org/files/projects/"
        self.cve_ref_url = ""
        self.plugin_path = ""
        self.core_details = {"infos": {"version":"", "last_version":""},
                            "alterations": [], "vulns":[]}
        self.plugins = []

    def get_core_version(self, dir_path, version_core_regexp, cms_path):
        try:
            with open(os.path.join(dir_path, cms_path)) as version_file:
                version_core = ''
                for line in version_file:
                    version_core_match = version_core_regexp.search(line)
                    if version_core_match:
                        version_core = version_core_match.group(1).strip()
                        print_cms("info", "[+] DRUPAL version used : "+ version_core, "", 0)
                        self.core_details["infos"]["version"] = version_core
                        break

        except FileNotFoundError as e:
            print_cms("alert", "[-] DRUPAL version not found. Search manually !", "", 0)
            return "", e
        return version_core, None

    def get_addon_version(self, plugin, dir_path, plugin_main_file, version_file_regexp, plugin_path):
        try:
            with open(os.path.join(dir_path, plugin_path, plugin_main_file)) as plugin_info:
                for line in plugin_info:
                    version = version_file_regexp.search(line)
                    if version:
                        plugin["version"] = version.group(1).strip("\"")
                        print_cms("default", "Version : "+ plugin["version"], "", 1)
                        break

        except FileNotFoundError as e:
            msg = "No standard extension file. Search manually !"
            print_cms("alert", "[-] " + msg, "", 1)
            plugin["notes"] = msg
            return "", e
        return version, None

    def get_core_last_version(self, url, version_core):
        last_version_core = ""
        major = version_core.split(".")[0]
        url_release = url + major + ".x"

        try:
            response = requests.get(url_release)
            response.raise_for_status()

            if response.status_code == 200:
                tree = etree.fromstring(response.content)
                last_version_core = tree.xpath("/project/releases/release/tag")[0].text
                print_cms("info", "[+] Last CMS version: "+ last_version_core, "", 0)
                self.core_details["infos"]["last_version"] = last_version_core

        except requests.exceptions.HTTPError as e:
            msg = "Unable to retrieve last wordpress version. Search manually !"
            print_cms("alert", "[-] "+ msg, "", 1)
            return "", e
        return last_version_core, None

    def get_addon_last_version(self, plugin):
        version_web_regexp = re.compile("<h2><a href=\"(.*?)\">(.+?) (.+?)</a></h2>")
        date_last_release_regexp = re.compile("<time pubdate datetime=\"(.*?)\">(.+?)</time>")

        releases_url = "{}/project/{}/releases".format(self.site_url, plugin["name"])
        last_version = "Not found"

        if plugin["version"] == "VERSION":
            msg = "This is a default plugin. Analysis is not yet implemented !"
            print_cms("alert", msg, "", 1)
            plugin["notes"] = msg
            return "", None

        try:
            response = requests.get(releases_url, allow_redirects=False)
            response.raise_for_status()

            if response.status_code == 200:
                page = response.text

                last_version_result = version_web_regexp.search(page)
                date_last_release_result = date_last_release_regexp.search(page)

                if last_version_result and date_last_release_result:
                    plugin["last_version"] = last_version_result.group(3)
                    plugin["last_release_date"] = date_last_release_result.group(2)
                    plugin["link"] = releases_url

                    if plugin["last_version"] == plugin["version"]:
                        print_cms("good", "Up to date !", "", 1)
                    else:
                        print_cms("alert", "Outdated, last version: ", plugin["last_version"]
                                    + " ( " + plugin["last_release_date"]
                                    + " )\n\tCheck : " + releases_url, 1)

        except requests.exceptions.HTTPError as e:
            msg = "Plugin not in drupal official site. Search manually !"
            print_cms("alert", "[-] "+ msg, "", 1)
            plugin["notes"] = msg
            return "", e
        return plugin["last_version"], None

    def check_core_alteration(self, dir_path, version_core, core_url):
        alterations = []
        ignored = ["modules", "CHANGELOG.txt", "COPYRIGHT.txt", "LICENSE.txt", \
                    "MAINTAINERS.txt", "INSTALL.txt", "README.txt"]

        temp_directory = create_temp_directory()

        print_cms("info", "[+] Checking core alteration", "", 0)

        try:
            response = requests.get(core_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), 'r')
                zip_file.extractall(temp_directory)
                zip_file.close()

        except requests.exceptions.HTTPError as e:
            msg = "[-] The original drupal archive has not been found. Search manually !"
            print_cms("alert", msg, "", 0)
            return msg, e

        clean_core_path = os.path.join(temp_directory, "drupal-" + version_core)

        dcmp = dircmp(clean_core_path, dir_path, ignored)
        diff_files(dcmp, alterations, dir_path)

        return alterations, None

    def check_addon_alteration(self, plugin, dir_path, temp_directory):
        plugin_url = "{}{}-{}.zip".format(self.download_plugin_url,
                                                plugin["name"],
                                                plugin["version"])

        if plugin["version"] == "VERSION":
            # TODO
            return None, None

        print_cms("default", "To download the plugin : " + plugin_url, "", 1)

        try:
            response = requests.get(plugin_url)
            response.raise_for_status()

            if response.status_code == 200:
                zip_file = zipfile.ZipFile(io.BytesIO(response.content), 'r')
                zip_file.extractall(temp_directory)
                zip_file.close()

                project_dir = os.path.join(dir_path, "modules", plugin["name"])
                project_dir_hash = dirhash(project_dir, 'sha1')
                ref_dir = os.path.join(temp_directory, plugin["name"])
                ref_dir_hash = dirhash(ref_dir, 'sha1')

                if project_dir_hash == ref_dir_hash:
                    altered = "NO"
                    print_cms("good", "Different from sources : " + altered, "", 1)
                else:
                    altered = "YES"
                    print_cms("alert", "Different from sources : " + altered, "", 1)

                    ignored = ["tests"]

                    root_path = os.path.join(dir_path, "modules")

                    dcmp = dircmp(project_dir, ref_dir, ignored)
                    diff_files(dcmp, plugin["alterations"], project_dir)

                plugin["edited"] = altered

        except requests.exceptions.HTTPError as e:
            msg = "The download link is not standard. Search manually !"
            print_cms("alert", msg, "", 1)
            plugin["notes"] = msg
            return msg, e
        return altered, None

    def check_vulns_core(self, version_core):
        # TODO
        print_cms("alert","CVE check not yet implemented !" , "", 1)
        return [], None

    def check_vulns_addon(self, plugin):
        # TODO
        print_cms("alert","CVE check not yet implemented !" , "", 1)
        return [], None

    def core_analysis(self, dir_path):
        print_cms("info",
        "#######################################################" \
        + "\n\t\tCore analysis" \
        + "\n#######################################################" \
        , "", 0)
        # Check current CMS version
        _ , err = self.get_core_version(dir_path,
                                                    re.compile("define\('VERSION', '(.*)'\);"),
                                                    "includes/bootstrap.inc")
        # Get the last released version
        _ , err = self.get_core_last_version("https://updates.drupal.org/release-history/drupal/", version_core)

        # Check for vuln on the CMS version
        self.core_details["vulns"] , err = self.check_vulns_core(version_core)

        # Check if the core have been altered
        self.core_details["alterations"], err = self.check_core_alteration(dir_path, version_core,
                                                                        self.download_core_url +
                                                                        version_core + ".zip")

        return self.core_details

    def addon_analysis(self, dir_path):
        temp_directory = create_temp_directory()

        print_cms("info",
        "#######################################################" \
        + "\n\t\tPlugins analysis" \
        + "\n#######################################################" \
        , "", 0)

        # Get the list of plugin to work with
        addons_name = fetch_addons(os.path.join(dir_path,"modules"))

        for addon_name in addons_name:
            plugin = {"status":"todo","name":"", "version":"","last_version":"",
                            "last_release_date":"", "link":"", "edited":"", "cve":"",
                            "vulns_details":"", "notes":"", "alterations" : []
                            }
            print_cms("info", "[+] " + addon_name, "", 0)
            plugin["name"] = addon_name

            # Get plugin version
            _ , err = self.get_addon_version(plugin, dir_path,
                                                addon_name + ".info",
                                                re.compile("version = (.*)"),
                                                "modules/" + addon_name)
            if err is not None:
                self.plugins.append(plugin)
                continue

            # Check plugin last version
            _ , err = self.get_addon_last_version(plugin)
            if err is not None:
                self.plugins.append(plugin)
                continue

            # Check if there are known CVE
            _ , err = self.check_vulns_addon(plugin)
            if err is not None:
                self.plugins.append(plugin)
                continue

            # Check if the plugin have been altered
            _ , err = self.check_addon_alteration(plugin, dir_path,
                                                    temp_directory)
            if err is not None:
                self.plugins.append(plugin)
                continue

            self.plugins.append(plugin)
        shutil.rmtree(temp_directory, ignore_errors=True)

        return self.plugins


if __name__ == "__main__":
    args = parse_args()

    if not args.DIR:
        print_cms("alert", "No path received !", "", 0)
        sys.exit()

    dir_path = args.DIR

    if args.CMS == "wordpress":
        to_check = ["wp-includes", "wp-admin"]
        verify_path(dir_path, to_check)
        cms = WP()

    elif args.CMS == "drupal":
        to_check = ["includes", "modules", "scripts", "themes"]
        verify_path(dir_path, to_check)
        cms = DPL()

    else:
        print_cms("alert", "CMS unknown or unsupported !", "", 0)
        sys.exit()

    # Analyse the CMS
    core_details = cms.core_analysis(dir_path)

    for addon_type in ["plugins", "themes"]:
        cms.addon_analysis(dir_path, addon_type)

    # Save results to a file
    if args.type == "CSV" and args.output:
        # Initialize the output file
        result_csv = ComissionCSV(args.output)
        # Add data and generate result file
        result_csv.add_data(core_details, cms.plugins, cms.themes)

    elif args.type == "XLSX" and args.output:
        # Initialize the output file
        result_xlsx = ComissionXLSX(args.output)
        # Add data
        result_xlsx.add_data(core_details, cms.plugins, cms.themes)
        # Generate result file
        result_xlsx.generate_xlsx()

    else:
        print_cms("alert", "Output type unknown or missing filename !", "", 0)
        sys.exit()

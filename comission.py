#!/usr/bin/env python3

import re
import os
import io
import sys
import json
import shutil
import zipfile
import requests
import xlsxwriter

from utilsCMS import *
from filecmp import dircmp
from checksumdir import dirhash
from distutils.version import LooseVersion


def get_core_version(dir_path,version_core_regexp, cms_path ):
    try:
        with open(os.path.join(dir_path, cms_path)) as version_file:
            version_core = ''
            for line in version_file:
                version_core_match = version_core_regexp.search(line)
                if version_core_match:
                    version_core = version_core_match.group(1).strip()
                    print_cms("info", "[+] CMS version used : "+ version_core, "", 0)
                    break

    except FileNotFoundError as e:
        print_cms("alert", "[-] CMS version not found. Search manually !", 0)
        return "", e
    return version_core, None

def get_plugin_version(plugin_details, dir_path, plugin_main_file, version_file_regexp, plugins_path):
    try:
        with open(os.path.join(dir_path, plugins_path, plugin_main_file)) as plugin_info:
            version = ''
            for line in plugin_info:
                version = version_file_regexp.search(line)
                if version:
                    plugin_details["version"] = version.group(1).strip()
                    print_cms("default", "Version : "+ plugin_details["version"], "", 1)
                    break

    except FileNotFoundError as e:
        msg = "No standard extension file. Search manually !"
        print_cms("alert", "[-] " + msg, "", 1)
        plugin_details["notes"] = msg
        return "", e
    return version, None

def get_core_last_version(url):
    last_version_core = ""
    try:
        response = requests.get(url)
        response.raise_for_status()

        if response.status_code == 200:
            page_json = response.json()

            last_version_core = page_json["offers"][0]["version"]
            print_cms("info", "[+] Last CMS version: "+ last_version_core, "", 0)

    except requests.exceptions.HTTPError as e:
        msg = "Unable to retrieve last wordpress version. Search manually !"
        print_cms("alert", "[-] "+ msg, "", 1)
        return "", e
    return last_version_core, None

def get_plugin_last_version_info(plugin_details):
    version_web_regexp = re.compile("\"softwareVersion\": \"(.*)\"")
    date_last_release_regexp = re.compile("\"dateModified\": \"(.*)\"")
    releases_url = "https://wordpress.org/plugins/{}/".format(plugin_details["name"])
    last_version = "Not found"
    try:
        response = requests.get(releases_url, allow_redirects=False)
        response.raise_for_status()

        if response.status_code == 200:
            page = response.text

            last_version_result = version_web_regexp.search(page)
            date_last_release_result = date_last_release_regexp.search(page)

            if last_version_result and date_last_release_result:
                plugin_details["last_version"] = last_version_result.group(1)
                plugin_details["last_release_date"] = date_last_release_result.group(1).split("T")[0]
                plugin_details["link"] = releases_url

                if plugin_details["last_version"] == plugin_details["version"]:
                    print_cms("good", "Up to date !", "", 1)
                else:
                    print_cms("alert", "Outdated, last version: ", plugin_details["last_version"] + \
                    "( " + plugin_details["last_release_date"] +" )\n\tCheck : " + releases_url, 1)

    except requests.exceptions.HTTPError as e:
        msg = "Plugin not in wordpress official site. Search manually !"
        print_cms("alert", "[-] "+ msg, "", 1)
        plugin_details["notes"] = msg
        return "", e
    return plugin_details["last_version"], None

def check_core_alteration(dir_path, version_core, core_url):

    alterations = []
    ignored = [".git", "cache", "plugins", "themes", "images", \
                "license.txt", "readme.html", "version.php"]

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
        msg = "[-] The original wordpress archive has not been found. Search manually !"
        print_cms("alert", msg, "", 0)
        return msg, e

    dcmp = dircmp(temp_directory + "/wordpress", dir_path, ignored)
    diff_files(dcmp, alterations, "core")

    return alterations, None

def check_plugin_alteration(plugin_details, dir_path, temp_directory):
    plugin_url = "https://downloads.wordpress.org/plugin/{}.{}.zip".format(plugin_details["name"], plugin_details["version"])

    if plugin_details["version"] == "trunk":
        plugin_url = "https://downloads.wordpress.org/plugin/{}.zip".format(plugin_details["name"])

    print_cms("default", "To download the plugin : " + plugin_url, "", 1)

    try:
        response = requests.get(plugin_url)
        response.raise_for_status()

        if response.status_code == 200:
            zip_file = zipfile.ZipFile(io.BytesIO(response.content), 'r')
            zip_file.extractall(temp_directory)
            zip_file.close()

            project_dir = os.path.join(dir_path, "wp-content", "plugins", plugin_details["name"])
            project_dir_hash = dirhash(project_dir, 'sha1')
            ref_dir = os.path.join(temp_directory, plugin_details["name"])
            ref_dir_hash = dirhash(ref_dir, 'sha1')

            if project_dir_hash == ref_dir_hash:
                altered = "NO"
                print_cms("good", "Different from sources : " + altered, "", 1)
            else:
                altered = "YES"
                print_cms("alert", "Different from sources : " + altered, "", 1)

                ignored = ["css", "img", "js", "fonts", "images"]

                dcmp = dircmp(project_dir, ref_dir, ignored)
                diff_files(dcmp, plugin_details["alterations"], plugin_details["name"])

            plugin_details["edited"] = altered

    except requests.exceptions.HTTPError as e:
        msg = "The download link is not standard. Search manually !"
        print_cms("alert", msg, "", 1)
        plugin_details["notes"] = msg
        return msg, e
    return altered, None

def check_wpvulndb_core(version_core):
    vulns_details = []

    version = version_core.replace('.', '')
    url = "https://wpvulndb.com/api/v2/wordpresses/" + version
    url_details = "https://wpvulndb.com/vulnerabilities/"

    try:
        response = requests.get(url)
        response.raise_for_status()

        if response.status_code == 200:
            page_json = response.json()

            vulns = page_json[version_core]["vulnerabilities"]
            print_cms("info", "[+] CVE list" , "", 1)
            for vuln in vulns:
                vuln_details = {"name": vuln["title"], "link": url_details + str(vuln["id"]), \
                                "type": vuln["vuln_type"], "fixed_in": vuln["fixed_in"]
                                }
                print_cms("alert", vuln["title"] , "", 1)
                print_cms("info", "[+] Fixed in version "+ str(vuln["fixed_in"]) , "", 1)
                vulns_details.append(vuln_details)

    except requests.exceptions.HTTPError as e:
        msg = "No entry on wpvulndb."
        print_cms("info", "[+] " + msg , "", 1)
        return "", e
    return vulns_details, None

def check_wpvulndb_plugin(plugin_details):
    cve = ""
    try:
        url = "https://wpvulndb.com/api/v2/plugins/" + plugin_details["name"]

        response = requests.get(url)
        response.raise_for_status()

        if response.status_code == 200:
            page_json = response.json()

            vulns = page_json[plugin_details["name"]]["vulnerabilities"]
            print_cms("info", "[+] CVE list", "", 1)
            for vuln in vulns:
                fixed_version = vuln["fixed_in"]
                try:
                    if LooseVersion(plugin_details["version"]) < LooseVersion(fixed_version):
                        print_cms("alert", vuln["title"] , "", 1)
                        plugin_details["cve_details"] = "\n".join([plugin_details["cve_details"], vuln["title"]])

                except TypeError as e:
                    print_cms("alert", "Unable to compare version. Please check this \
                                        vulnerability :" + vuln["title"] , "", 1)
                    plugin_details["cve_details"] = "\n".join([plugin_details["cve_details"], " To check : ", vuln["title"]])

            if plugin_details["cve_details"]:
                plugin_details["cve"] = "YES"
            else:
                plugin_details["cve"] = "NO"

    except requests.exceptions.HTTPError as e:
        msg = "No entry on wpvulndb."
        print_cms("info", "[+] " + msg , "", 1)
        plugin_details["cve"] = "NO"
        return "", e
    return cve, None

def get_core_details(dir_path):
    core_details = {"infos": [], "alterations": [], "vulns":[]}

    print_cms("info",
    "#######################################################" \
    + "\n\t\tCore analysis" \
    + "\n#######################################################" \
    , "", 0)
    # Check current CMS version
    version_core , err = get_core_version(dir_path, re.compile("\$wp_version = '(.*)';"), \
                                            "wp-includes/version.php")
    last_version_core , err = get_core_last_version("https://api.wordpress.org/core/version-check/1.7/")

    core_details["infos"] = [version_core, last_version_core]

    # Check for vuln on the CMS version
    core_details["vulns"] , err = check_wpvulndb_core(version_core)

    # Check if the core have been altered
    core_details["alterations"], err = check_core_alteration(dir_path, version_core, "https://wordpress.org/wordpress-" + version_core + ".zip")

    return core_details

def get_plugins_details(dir_path):
    plugins_details = []
    temp_directory = create_temp_directory()

    print_cms("info",
    "#######################################################" \
    + "\n\t\tPlugins analysis" \
    + "\n#######################################################" \
    , "", 0)

    # Get the list of plugin to work with
    plugins_name = fetch_plugins(dir_path)

    for plugin_name in plugins_name:
        plugin_details = {"status":"todo","name":"", "version":"","last_version":"", \
                        "last_release_date":"", "link":"", "edited":"", "cve":"", \
                        "cve_details":"", "notes":"", "alterations" : [] \
                        }
        print_cms("info", "[+] " + plugin_name , "", 0)
        plugin_details["name"] = plugin_name

        # Get plugin version
        _ , err = get_plugin_version(plugin_details, dir_path, plugin_name + "/" + plugin_name +".php"
                                    , re.compile("(?i)Version: (.*)"),
                                    "wp-content/plugins")
        if err is not None:
            plugins_details.append(plugin_details)
            continue

        # Check plugin last version
        _ , err = get_plugin_last_version_info(plugin_details)
        if err is not None:
            plugins_details.append(plugin_details)
            continue

        # Check if there are known CVE in wpvulndb
        _ , err = check_wpvulndb_plugin(plugin_details)
        if err is not None:
            plugins_details.append(plugin_details)
            continue

        # Check if the plugin have been altered
        _ , err = check_plugin_alteration(plugin_details, dir_path, temp_directory)
        if err is not None:
            plugins_details.append(plugin_details)
            continue

        plugins_details.append(plugin_details)
    shutil.rmtree(temp_directory, ignore_errors=True)

    return plugins_details


class ComissionXLSX:
    """ CoMisSion XLS Generator """

    def __init__(self, output_filename="output.xlsx"):
        """ Generate XLSX """
        self.workbook = xlsxwriter.Workbook(output_filename)
        self.core_worksheet = self.workbook.add_worksheet("Core")
        self.core_alteration_worksheet = self.workbook.add_worksheet("Core Alteration")
        self.plugins_worksheet = self.workbook.add_worksheet("Plugins")
        self.plugins_alteration_worksheet = self.workbook.add_worksheet("Plugins Alteration")
        self.generate_heading(self.workbook)
        self.generate_formating(self.workbook)

    def add_data(self,core_details,plugins_details):
        # Add core data
        self.add_core_data('A2', core_details["infos"])

        # Add core vulns
        x = 2
        for core_vuln_details in core_details["vulns"]:
            core_vuln_details_list = [core_vuln_details["name"],core_vuln_details["link"], \
                                    core_vuln_details["type"],core_vuln_details["fixed_in"] \
                                    ]
            self.add_core_data('D'+ str(x), core_vuln_details_list)
            x += 1

        # Add core alteration details
        x = 2
        for core_alteration in core_details["alterations"]:
            core_alterations_list = [core_alteration["file"], core_alteration["status"]]
            self.add_core_alteration_data('A'+ str(x), core_alterations_list)
            x += 1

        # Add plugin details
        x = 2
        for plugin_details in plugins_details:
            plugin_details_list = [plugin_details["status"], plugin_details["name"], \
                                plugin_details["version"], plugin_details["last_version"], \
                                plugin_details["last_release_date"], plugin_details["link"], \
                                plugin_details["edited"], plugin_details["cve"], \
                                plugin_details["cve_details"], plugin_details["notes"] \
                                ]
            self.add_plugin_data('A'+ str(x), plugin_details_list)
            x += 1

        # Add plugins alteration details
        x = 2
        for plugin_details in plugins_details:
            for plugin_alteration in plugin_details["alterations"]:
                plugin_alteration_list = [plugin_details["name"], plugin_alteration["file"], \
                                            plugin_alteration["status"]]
                self.add_plugin_alteration_data('A'+ str(x), plugin_alteration_list)
                x += 1

    def add_plugin_data(self, position, plugin = []):
        self.plugins_worksheet.write_row(position, plugin)

    def add_core_data(self, position, data):
        self.core_worksheet.write_row(position, data)

    def add_core_alteration_data(self, position, data):
        self.core_alteration_worksheet.write_row(position, data)

    def add_plugin_alteration_data(self, position, data):
        self.plugins_alteration_worksheet.write_row(position, data)

    def generate_xlsx(self):
        self.workbook.close()

    def generate_heading(self, workbook):

        core_headings = ["Version", "Last version", "", "Vulnerabilities", "Link", \
                        "Type", "Fixed In"
                        ]
        core_alteration_headings = ["File", "Status"
                                    ]
        plugins_headings = ["Status", "Plugin", "Version", "Last version", \
                            "Last release date", "Link", "Code altered", \
                            "CVE", "Vulnerabilities", "Notes"
                            ]
        plugins_alteration_headings = ["Name","File", "Status"
                                        ]

        headings_list = [core_headings, core_alteration_headings, plugins_headings, \
                        plugins_alteration_headings]
        worksheets_list = [self.core_worksheet, self.core_alteration_worksheet, \
                            self.plugins_worksheet, self.plugins_alteration_worksheet]

        for target_worksheet, headings in zip(worksheets_list, headings_list):
            y = 0
            for heading in headings:
                target_worksheet.write(0, y, heading)
                y += 1

    def generate_formating(self, workbook):
        # Bad : Light red fill with dark red text.
        bad = workbook.add_format({'bg_color': '#FFC7CE',
                               'font_color': '#9C0006'})
        # Good :  Green fill with dark green text.
        good = workbook.add_format({'bg_color': '#C6EFCE',
                                'font_color': '#006100'})
        # N/A : When we don't know
        na = workbook.add_format({'bg_color': '#FCD5B4',
                                'font_color': '#974706'})

        #Title of columns
        heading_format = workbook.add_format({'bold': True,
                                'font_size': '13',
                                'bottom': 2,
                                'border_color': '#44546A',
                                'font_color': '#44546A',
                                'text_wrap': True})


        # Write conditionnal formats
        worksheet = self.plugins_worksheet
        worksheet.conditional_format('A1:A300', {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'todo',
                                         'format': bad})
        worksheet.conditional_format('A1:A300', {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'done',
                                         'format': good})
        #Red if the version if "trunk"
        worksheet.conditional_format('C1:C300', {'type': 'cell',
                                         'criteria': '==',
                                         'value': '"trunk"',
                                         'format': bad})

        # Red if no info have been found by the script
        worksheet.conditional_format('J1:J300', {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'Search',
                                         'format': bad})

        # Red if the plugin have been modified
        worksheet.conditional_format('G1:G300', {'type': 'cell',
                                         'criteria': '==',
                                         'value': '"YES"',
                                         'format': bad})
        worksheet.conditional_format('G1:G300', {'type': 'cell',
                                         'criteria': '==',
                                         'value': '"NO"',
                                         'format': good})
        # Red if some CVE exist
        worksheet.conditional_format('H1:H300', {'type': 'cell',
                                         'criteria': '==',
                                         'value': '"YES"',
                                         'format': bad})
        worksheet.conditional_format('H1:H300', {'type': 'cell',
                                         'criteria': '==',
                                         'value': '"NO"',
                                         'format': good})
        # N/A if we don't know for any reason
        worksheet.conditional_format('C1:H300', {'type': 'cell',
                                         'criteria': '==',
                                         'value': '"N/A"',
                                         'format': na})

        # Format WordPress Core worksheet
        worksheet = self.core_worksheet
        worksheet.set_row(0, 15, heading_format)
        worksheet.set_column('A:B', 10)
        worksheet.set_column('C:C', 5)
        worksheet.set_column('D:D', 100)
        worksheet.set_column('E:E', 40)
        worksheet.set_column('F:F', 10)
        worksheet.set_column('G:G', 10)

        # Format WordPress Core Alteration worksheet
        worksheet = self.core_alteration_worksheet
        worksheet.set_row(0, 15, heading_format)
        worksheet.set_column('A:A', 40)
        worksheet.set_column('B:B', 30)

        # Format Plugins worksheet
        worksheet = self.plugins_worksheet
        worksheet.set_row(0, 15, heading_format)
        worksheet.set_column('A:A', 7)
        worksheet.set_column('B:B', 25)
        worksheet.set_column('C:C', 8)
        worksheet.set_column('D:D', 10)
        worksheet.set_column('E:E', 13)
        worksheet.set_column('F:F', 20)
        worksheet.set_column('G:G', 8)
        worksheet.set_column('H:H', 5)
        worksheet.set_column('I:J', 70)

        # Format WordPress Plugins Alteration worksheet
        worksheet = self.plugins_alteration_worksheet
        worksheet.set_row(0, 15, heading_format)
        worksheet.set_column('A:A', 25)
        worksheet.set_column('B:B', 40)
        worksheet.set_column('C:C', 30)


if __name__ == "__main__":
    args = parse_args()

    if args.output:
        output_file = open(args.output, 'w')
    else:
        output_file = None

    if not args.DIR:
        print_cms("alert", "No path received !", "", 0)
        sys.exit()

    dir_path = args.DIR
    verify_path(dir_path)



    # Analyse the CMS
    core_details = get_core_details(dir_path)
    plugins_details = get_plugins_details(dir_path)


    # Save results to a file
    if args.output:
        result_xlsx = ComissionXLSX(args.output)
        result_xlsx.add_data(core_details, plugins_details)

        # Generate result file
        result_xlsx.generate_xlsx()

#!/usr/bin/env python3

import re
import os
import sys
import json
import random
import shutil
import string
import zipfile
import datetime
import argparse
import tempfile
import xlsxwriter
import urllib.request

from checksumdir import dirhash
from distutils.version import LooseVersion

debug = True
quiet = False

def log_debug(msg):
    global debug
    if debug and not quiet:
        time = datetime.datetime.now()
        print("{}: {}".format(time, msg))

def parse_args():
    parser = argparse.ArgumentParser(description='WP Plugins Checker checks \
    plugins in a directory.')
    parser.add_argument('-d', '--dir', dest='DIR', help='WordPress root directory')
    parser.add_argument('-o', '--output', metavar="FILE", help='Path to output \
    file')
    args = parser.parse_args()
    return args

def fetch_plugins(input):
    plugin_dir = input + "wp-content/plugins/"
    if not os.path.exists(plugin_dir):
        print("Plugins path does not exist !")
        exit(-1)
    plugins_name = next(os.walk(plugin_dir))[1]
    return plugins_name

def create_temp_directory():
    while True:
        random_dir_name = ''.join(random.choice(string.ascii_uppercase) for _ in range(5))
        temp_directory = os.path.join(tempfile.gettempdir(), random_dir_name)
        if not os.path.exists(temp_directory):
            os.makedirs(temp_directory)
            break
    return temp_directory

def get_version(plugin_details, dir_path, plugin_name):
    version_file_regexp = re.compile("(?i)Version: (.*)")
    try:
        with open(os.path.join(dir_path, "wp-content", "plugins", plugin_name, plugin_name +".php")) as plugin_info:
            version = ''
            for line in plugin_info:
                version = version_file_regexp.search(line)
                if version:
                    plugin_details["version"] = version.group(1).strip()
                    print("\tVersion : "+ plugin_details["version"])
                    break

    except FileNotFoundError as e:
        msg = "No standard extension file. Search manually !"
        print("\t\033[91m[-] " + msg + "\033[0m")
        plugin_details["notes"] = msg
        return "", e
    return version, None

def get_last_version_info(plugin_details):
    version_web_regexp = re.compile("\"softwareVersion\": \"(.*)\"")
    date_last_release_regexp = re.compile("\"dateModified\": \"(.*)\"")
    releases_url = "https://wordpress.org/plugins/{}/".format(plugin_details["name"])
    last_version = "Not found"
    try:
        response = urllib.request.urlopen(releases_url)
        if response.status == 200:
            page = response.read().decode('utf-8')

            last_version_result = version_web_regexp.search(page)
            date_last_release_result = date_last_release_regexp.search(page)

            if last_version_result and date_last_release_result:
                plugin_details["last_version"] = last_version_result.group(1)
                plugin_details["last_release_date"] = date_last_release_result.group(1).split("T")[0]
                plugin_details["link"] = releases_url

                if plugin_details["last_version"] == plugin_details["version"]:
                    print("\t\033[92mUp to date !\033[0m")
                else:
                    print("\t\033[91mOutdated, last version: " + plugin_details["last_version"] + \
                    "\033[0m ( " + plugin_details["last_release_date"] +" )\n\tCheck : " + releases_url)

    except urllib.error.HTTPError as e:
        #log_debug(e)
        msg = "Plugin not in wordpress official site. Search manually !"
        print("\t\033[91m[-] "+ msg + "\033[0m")
        plugin_details["notes"] = msg
        return "", e
    return plugin_details["last_version"], None

def check_alteration(plugin_details, dir_path, temp_directory):
    plugin_url = "https://downloads.wordpress.org/plugin/{}.{}.zip".format(plugin_details["name"], plugin_details["version"])

    if plugin_details["version"] == "trunk":
        plugin_url = "https://downloads.wordpress.org/plugin/{}.zip".format(plugin_details["name"])

    print("\tTo download the plugin : " + plugin_url)

    try:
        response = urllib.request.urlopen(plugin_url)
        if response.status == 200:
            compressed_plugin = urllib.request.urlretrieve(plugin_url)
            zip_file = zipfile.ZipFile(compressed_plugin[0], 'r')
            zip_file.extractall(temp_directory)
            zip_file.close()
            os.remove(compressed_plugin[0])
            project_dir_hash = dirhash(os.path.join(dir_path, "wp-content", "plugins", plugin_details["name"]), 'sha1')
            ref_dir_hash = dirhash(os.path.join(temp_directory, plugin_details["name"]), 'sha1')

        if project_dir_hash == ref_dir_hash:
            altered = "NO"
            print("\tDifferent from sources : \033[92m" + altered + "\033[0m")
        else:
            altered = "YES"
            print("\tDifferent from sources : \033[91m" + altered + "\033[0m")
        plugin_details["edited"] = altered

    except urllib.error.HTTPError as e:
        msg = "The download link is not standard. Search manually !"
        print("\t"+msg)
        plugin_details["notes"] = msg
        return msg, e
    return altered, None

def check_wpvulndb_plugin(plugin_details):
    cve = ""
    try:
        url = "https://wpvulndb.com/api/v2/plugins/" + plugin_details["name"]
        response = urllib.request.urlopen(url)

        if response.status == 200:
            page = response.read().decode('utf-8')
            page_json = json.loads(page)
            plugin_details["cve"] = "YES"

            vulns = page_json[plugin_details["name"]]["vulnerabilities"]

            for vuln in vulns:
                fixed_version = vuln["fixed_in"]
                try:
                    if LooseVersion(plugin_details["version"]) < LooseVersion(fixed_version):
                        print("\t\033[91m" + vuln["title"] + "\033[0m")
                        plugin_details["cve_details"] = "\n".join([plugin_details["cve_details"], vuln["title"]])

                except TypeError as e:
                    print("\t\033[91m Unable to compare version. Please check this vulnerability :" + vuln["title"] + "\033[0m")
                    plugin_details["cve_details"] = "\n".join([plugin_details["cve_details"], " To check : ", vuln["title"]])

    except urllib.error.HTTPError as e:
        msg = "No entry on wpvulndb."
        print("\t\033[34m[+] " + msg + "\033[0m")
        plugin_details["cve"] = "NO"
        return "", e
    return cve, None

def check_core_version(dir_path):
    version_core_regexp = re.compile("\$wp_version = '(.*)';")
    try:
        with open(os.path.join(dir_path, "wp-includes/" "version.php")) as version_file:
            version_core = ''
            for line in version_file:
                version_core_match = version_core_regexp.search(line)
                if version_core_match:
                    version_core = version_core_match.group(1).strip()
                    print("\t\033[34m[+] Version de WordPress : "+ version_core + "\033[0m")
                    break

    except FileNotFoundError as e:
        msg = "WordPress version not found. Search manually !"
        print("\t\033[91m[-] " + msg + "\033[0m")
        #plugin_details["notes"] += msg
        return "", e
    return version_core, None

def get_core_last_version():
    https://api.wordpress.org/core/version-check/1.7/

def check_wpvulndb_core(version_core):
    vulns_details = []

    version = version_core.replace('.', '')
    url = "https://wpvulndb.com/api/v2/wordpresses/" + version
    url_details = "https://wpvulndb.com/vulnerabilities/"

    try:
        response = urllib.request.urlopen(url)

        if response.status == 200:
            page = response.read().decode('utf-8')
            page_json = json.loads(page)

            vulns = page_json[version_core]["vulnerabilities"]

            for vuln in vulns:
                vuln_details = {"name": vuln["title"], "link": url_details + str(vuln["id"]), \
                                "type": vuln["vuln_type"], "fixed_in": vuln["fixed_in"]
                                }
                print("\t\033[91m" + vuln["title"] + "\033[0m\t"+ str(vuln["fixed_in"]))
                vulns_details.append(vuln_details)

    except urllib.error.HTTPError as e:
        msg = "No entry on wpvulndb."
        print("\t\033[34m[+] " + msg + "\033[0m")
        return "", e
    return vulns_details, None

def get_plugins_details(args):
    plugins_details = []
    temp_directory = create_temp_directory()

    if args.output:
        output_file = open(args.output, 'w')
    else:
        output_file = None

    if not args.DIR:
        print("No plugin path receive !")
        sys.exit()

    dir_path = args.DIR

    # Get the list of plugin to work with
    plugins_name = fetch_plugins(dir_path)

    for plugin_name in plugins_name:
        plugin_details = {"status":"todo","name":"", "version":"","last_version":"", \
                        "last_release_date":"", "link":"", "edited":"", \
                        "cve":"", "cve_details":"", "notes":"" \
                        }
        print("\033[34m[+] " + plugin_name + "\033[0m")
        plugin_details["name"] = plugin_name

        # Get plugin version
        _ , err = get_version(plugin_details, dir_path, plugin_name)
        if err is not None:
            plugins_details.append(plugin_details)
            continue

        # Check plugin last version
        _ , err = get_last_version_info(plugin_details)
        if err is not None:
            plugins_details.append(plugin_details)
            continue

        # Check if there are known CVE in wpvulndb
        _ , err = check_wpvulndb_plugin(plugin_details)
        if err is not None:
            plugins_details.append(plugin_details)
            continue

        # Check if the plugin have been altered
        _ , err = check_alteration(plugin_details, dir_path, temp_directory)
        if err is not None:
            plugins_details.append(plugin_details)
            continue

        plugins_details.append(plugin_details)
    shutil.rmtree(temp_directory, ignore_errors=True)

    return plugins_details

def get_core_details(args):
    dir_path = args.DIR

    # Check for vuln on the WordPress version
    vulns_details , err = check_wpvulndb_core(version_core)

    return vulns_details


class WPPluginXLSX:
    """ WPPlugin XLS Generator """

    def __init__(self, output_filename="output.xlsx"):
        """ generate XLSX """
        self.workbook = xlsxwriter.Workbook(output_filename)
        self.core_worksheet = self.workbook.add_worksheet("Core")
        self.plugins_worksheet = self.workbook.add_worksheet("Plugins")
        self.generate_heading(self.workbook)
        self.generate_formating(self.workbook)

    def add_plugin(self, position, plugin = []):
        self.plugins_worksheet.write_row(position, plugin)

    def add_core_data(self, position, data):
        self.core_worksheet.write_row(position, data)

    def generate_xlsx(self):
        self.workbook.close()

    def generate_heading(self, workbook):
        x = 0
        y = 0

        plugins_headings = ["Status", "Plugin", "Version", \
                    "Last version", "Last release date", "Link", "Code altered", \
                    "CVE", "Vulnerabilities", "Notes"
                    ]
        core_headings = ["Version", "Last version", "", "Vulnerabilities", "Link", \
                    "Type", "Fixed In"
                    ]
        for heading in plugins_headings:
            self.plugins_worksheet.write(x, y, heading)
            y += 1

        x = 0
        y = 0

        for heading in core_headings:
            self.core_worksheet.write(x, y, heading)
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
        # Format Plugin worksheet
        worksheet.set_row(0, 15, heading_format)
        worksheet.set_column('A:A', 7)
        worksheet.set_column('B:B', 25)
        worksheet.set_column('C:C', 10)
        worksheet.set_column('D:D', 12)
        worksheet.set_column('E:E', 14)
        worksheet.set_column('F:F', 20)
        worksheet.set_column('G:G', 8)
        worksheet.set_column('H:H', 5)
        worksheet.set_column('I:J', 70)

        # Format WordPress Core worksheet
        worksheet = self.core_worksheet
        worksheet.set_row(0, 15, heading_format)
        worksheet.set_column('A:B', 10)
        worksheet.set_column('D:D', 80)
        worksheet.set_column('E:E', 40)
        worksheet.set_column('F:F', 8)
        worksheet.set_column('G:G', 12)

if __name__ == "__main__":
    args = parse_args()

    print("\033[34m[+] WordPress Core checking \033[0m")

    # Check current WordPress version
    version_core , err = check_core_version(args.DIR)
    core_details = [version_core, "N/A"]
    core_vulns_details = get_core_details(args)

    plugins_details = get_plugins_details(args)

    if args.output:
        result_xlsx = WPPluginXLSX(args.output)
        y = 2
        x = 2
        for plugin_details in plugins_details:
            plugin_details_list = [plugin_details["status"], plugin_details["name"], \
                                plugin_details["version"], plugin_details["last_version"], \
                                plugin_details["last_release_date"], plugin_details["link"], \
                                plugin_details["edited"], plugin_details["cve"], \
                                plugin_details["cve_details"], plugin_details["notes"] \
                                ]
            result_xlsx.add_plugin('A'+ str(y), plugin_details_list)
            y += 1

        # Add core data
        result_xlsx.add_core_data('A2', core_details)

        # Add core vulns
        for core_vuln_details in core_vulns_details:
            core_vuln_details_list = [core_vuln_details["name"],core_vuln_details["link"], \
                                    core_vuln_details["type"],core_vuln_details["fixed_in"] \
                                    ]
            result_xlsx.add_core_data('D'+ str(x), core_vuln_details_list)
            x += 1

        # Generate result file
        result_xlsx.generate_xlsx()

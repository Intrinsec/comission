#!/usr/bin/env python3

import re
import os
import sys
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
    parser.add_argument('-d', '--dir', dest='DIR', help='Plugins directory')
    parser.add_argument('-o', '--output', metavar="FILE", help='Path to output \
    file')
    args = parser.parse_args()
    return args

def fetch_plugins(input):
    if not os.path.exists(input):
        print("Plugins path does not exist !")
        exit(-1)
    plugins_name = next(os.walk(input))[1]
    return plugins_name

def get_plugins_details(args):

    plugins_details = []

    if args.output:
        output_file = open(args.output, 'w')
    else:
        output_file = None

    if not args.DIR:
        print("No plugin path receive !")
        sys.exit()

    plugins_dir_path = args.DIR
    plugins_name = fetch_plugins(plugins_dir_path)

    while True:
        random_dir_name = ''.join(random.choice(string.ascii_uppercase) for _ in range(5))
        temp_directory = os.path.join(tempfile.gettempdir(), random_dir_name)
        if not os.path.exists(temp_directory):
            os.makedirs(temp_directory)
            break

    version_file_regexp = re.compile("(?i)Stable tag: (.*)")
    version_web_regexp = re.compile("\"softwareVersion\": \"(.*)\"")
    date_last_release_regexp = re.compile("\"dateModified\": \"(.*)\"")

    for plugin_name in plugins_name:
        plugin_details = []
        print("[+] " + plugin_name)
        plugin_details.append("todo")
        plugin_details.append(plugin_name)

        try:
            with open(os.path.join(plugins_dir_path, plugin_name, "readme.txt")) as plugin_info:
                version = ''
                for line in plugin_info:
                    version = version_file_regexp.search(line)
                    if version:
                        version = version.group(1).strip()
                        print("\tVersion : "+ version)
                        plugin_details.append(version)
                        break
                    else:
                        continue

            # Check plugin version
            releases_url = "https://wordpress.org/plugins/{}/".format(plugin_name)
            last_version = "Not found"

            try:
                response = urllib.request.urlopen(releases_url)
                if response.status == 200:
                    page = response.read().decode('utf-8')

                    last_version_result = version_web_regexp.search(page)
                    date_last_release_result = date_last_release_regexp.search(page)

                    if last_version_result and date_last_release_result:
                        last_version = last_version_result.group(1)
                        date_last_release = date_last_release_result.group(1).split("T")[0]

                        if last_version == version:
                            print("\t\033[92mUp to date !\033[0m")
                        else:
                            print("\t\033[91mOutdated, last version: " + last_version + \
                            "\033[0m ( " + date_last_release +" )\n\tCheck : " + releases_url)
                        plugin_details.append(last_version)
                        plugin_details.append(date_last_release)
                        plugin_details.append(releases_url)
                if version == "trunk":
                    plugin_url = "https://downloads.wordpress.org/plugin/{}.zip".format(plugin_name)
                else:
                    plugin_url = "https://downloads.wordpress.org/plugin/{}.{}.zip".format(plugin_name, version)

                print("\t"+plugin_url)
                try:
                    response = urllib.request.urlopen(plugin_url)
                    if response.status == 200:
                        compressed_plugin = urllib.request.urlretrieve(plugin_url)
                        zip_file = zipfile.ZipFile(compressed_plugin[0], 'r')
                        zip_file.extractall(temp_directory)
                        zip_file.close()
                        os.remove(compressed_plugin[0])
                        project_dir_hash = dirhash(os.path.join(plugins_dir_path, plugin_name), 'sha1')
                        ref_dir_hash = dirhash(os.path.join(temp_directory, plugin_name), 'sha1')

                    if project_dir_hash == ref_dir_hash:
                        msg = "NO"
                        print("\tDifferent from sources : \033[92m" + msg + "\033[0m")
                    else:
                        msg = "YES"
                        print("\tDifferent from sources : \033[91m" + msg + "\033[0m")
                    plugin_details.append(msg)

                except urllib.error.HTTPError as e:
                    msg = "The download link is not standard. Search manualy !"
                    print("\t"+msg)
                    plugin_details.append(msg)
            except urllib.error.HTTPError as e:
                #log_debug(e)
                msg = "Plugin not in wordpress official site. Search manualy !"
                print("\t\033[91m[-] "+ msg + "\033[0m")
                plugin_details.append(msg)
        except FileNotFoundError as e:
            msg = "No readme file. Search manualy !"
            print("\t\033[91m[-]" + msg + "\033[0m")
            plugin_details.append(msg)

        plugins_details.append(plugin_details)
    shutil.rmtree(temp_directory, ignore_errors=True)

    return plugins_details

class WPPluginXLSX:
    """ WPPlugin XLS Generator """

    def __init__(self, output_filename="output.xlsx"):
        """ generate XLSX """
        self.workbook = xlsxwriter.Workbook(output_filename)
        self.worksheet = self.workbook.add_worksheet("Plugins")
        self.generate_heading(self.workbook)
        self.generate_formating(self.workbook)

    def add_plugin(self, position, plugin = []):
        self.worksheet.write_row('A'+ str(position), plugin)

    def generate_xlsx(self):
        self.workbook.close()

    def generate_heading(self, workbook):
        x = 0
        y = 0

        headings = ["Status", "Plugin", "Version actuelle", "Dernière version", \
                    "Date de publication", "Lien", "Code modifié", "CVE", \
                    "Vulnérabilités", "Remarques"]

        for heading in headings:
            self.worksheet.write(x, y, heading)
            y += 1

    def generate_formating(self, workbook):
        # Bad : Light red fill with dark red text.
        bad = workbook.add_format({'bg_color': '#FFC7CE',
                               'font_color': '#9C0006'})
        # Good :  Green fill with dark green text.
        good = workbook.add_format({'bg_color': '#C6EFCE',
                                'font_color': '#006100'})
        #Title of columns
        heading_format = workbook.add_format({'bold': True,
                                'font_size': '13',
                                'bottom': 2,
                                'border_color': '#44546A',
                                'font_color': '#44546A'})


        # Write conditionnal formats
        worksheet = workbook.get_worksheet_by_name('Plugins')
        worksheet.conditional_format('A1:A300', {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'todo',
                                         'format': bad})
        #Red if the version if "trunk"
        worksheet.conditional_format('C1:C300', {'type': 'cell',
                                         'criteria': '==',
                                         'value': '"trunk"',
                                         'format': bad})

        # Red if no info have been found by the script
        worksheet.conditional_format('C1:D300', {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'Search',
                                         'format': bad})
        #worksheet.conditional_format('B1:B300', {'type': 'text',
        #                                 'criteria': 'containing',
        #                                 'value': 'ok',
        #                                 'format': good})

        # Red if the plugin have been modified
        worksheet.conditional_format('G1:G300', {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'YES',
                                         'format': bad})
        worksheet.conditional_format('G1:G300', {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'NO',
                                         'format': good})
        # Red if some CVE exist
        worksheet.conditional_format('F1:F300', {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'YES',
                                         'format': bad})
        worksheet.conditional_format('F1:F300', {'type': 'text',
                                         'criteria': 'containing',
                                         'value': 'NO',
                                         'format': good})
        worksheet.set_row(0, 15, heading_format)
        worksheet.set_column('A:H', 20)

if __name__ == "__main__":
    args = parse_args()

    plugins_details = get_plugins_details(args)

    if args.output:
        result_xlsx = WPPluginXLSX(args.output)
        position = 2
        for plugin_details in plugins_details:
            result_xlsx.add_plugin(position, plugin_details)
            position += 1

        # Generate result file
        result_xlsx.generate_xlsx()

#!/usr/bin/env python3

import csv


class ComissionCSV:
    """ CoMisSion CSV Generator """

    def __init__(self, filename="output.csv"):
        self.filename = filename

        self.prepare_files()

        self.core_headings = ["Version", "Last version"]
        self.core_vulns_headings = ["Vulnerabilities", "Link", "Type", "PoC", "Fixed In", "Notes"]
        self.core_alteration_headings = ["Status", "File", "Path", "Alteration", "Notes"]
        self.plugins_headings = [
            "Status",
            "Plugin",
            "Version",
            "Last version",
            "Last release date",
            "Link",
            "MU",
            "Code altered",
            "CVE",
            "Notes",
        ]
        self.plugins_vulns_headings = [
            "Plugin",
            "Vulnerabilities",
            "Link",
            "Type",
            "PoC",
            "Fixed In",
            "Notes",
        ]
        self.plugins_alteration_headings = [
            "Status",
            "Plugin",
            "File",
            "Path",
            "Alteration",
            "Notes",
        ]
        self.themes_headings = [
            "Status",
            "Theme",
            "Version",
            "Last version",
            "Last release date",
            "Link",
            "Code altered",
            "CVE",
            "Notes",
        ]
        self.themes_vulns_headings = [
            "Theme",
            "Vulnerabilities",
            "Link",
            "Type",
            "PoC",
            "Fixed In",
            "Notes",
        ]
        self.themes_alteration_headings = ["Status", "Theme", "File", "Path", "Alteration", "Notes"]

    def prepare_files(self) -> None:
        basename = self.filename.split(".")[0]
        # Core files
        self.core_filename = basename + ".core.csv"
        self.core_vulns_filename = basename + ".core_vulns.csv"
        self.core_alteration_filename = basename + ".core_alterations.csv"
        # Plugins files
        self.plugins_filename = basename + ".plugins.csv"
        self.plugins_vulns_filename = basename + ".plugins_vulns.csv"
        self.plugins_alteration_filename = basename + ".plugins_alterations.csv"
        # Themes files
        self.themes_filename = basename + ".themes.csv"
        self.themes_vulns_filename = basename + ".themes_vulns.csv"
        self.themes_alteration_filename = basename + ".themes_alterations.csv"

    def add_data(self, core_details, plugins, themes) -> None:
        # Add core data
        self.add_core_data_to_file(
            [core_details.version, core_details.last_version], self.core_headings
        )

        # Add core vulns
        x = 2
        core_vuln_lists = []
        for core_vuln in core_details.vulns:
            core_vuln_list = [
                core_vuln.name,
                core_vuln.link,
                core_vuln.type,
                core_vuln.poc,
                core_vuln.fixed_in,
            ]
            core_vuln_lists.append(core_vuln_list)
            x += 1
        self.add_data_to_file(core_vuln_lists, self.core_vulns_filename, self.core_vulns_headings)

        # Add core alteration details
        x = 2
        core_alterations_lists = []
        for core_alteration in core_details.alterations:
            core_alterations_list = [
                core_alteration.status,
                core_alteration.file,
                core_alteration.target,
                core_alteration.type,
            ]
            core_alterations_lists.append(core_alterations_list)
            x += 1
        self.add_data_to_file(
            core_alterations_lists, self.core_alteration_filename, self.core_alteration_headings
        )

        # Add plugins or themes data
        for elements in [plugins, themes]:
            # Add elements details
            x = 2
            addon_lists = []

            for addon in elements:
                # Plugins and Themes or similar except for the field "mu"
                addon_list = addon.get_report_list()
                addon_lists.append(addon_list)
                x += 1

                if addon.type == "plugins":
                    self.add_data_to_file(addon_lists, self.plugins_filename, self.plugins_headings)

                elif addon.type == "themes":
                    self.add_data_to_file(addon_lists, self.themes_filename, self.themes_headings)

            # Add elements vulns
            x = 2
            vuln_lists = []
            for addon in elements:
                for vuln in addon.vulns:
                    vuln_list = [
                        addon.name,
                        vuln["name"],
                        vuln["link"],
                        vuln["type"],
                        vuln["poc"],
                        vuln["fixed_in"],
                    ]
                    vuln_lists.append(vuln_list)
                    x += 1
                if addon.type == "plugins":
                    self.add_data_to_file(
                        vuln_lists, self.plugins_vulns_filename, self.plugins_vulns_headings
                    )
                elif addon.type == "themes":
                    self.add_data_to_file(
                        vuln_lists, self.themes_vulns_filename, self.themes_vulns_headings
                    )
            # Add elements alteration details
            x = 2
            addon_alteration_lists = []
            for addon in elements:
                for addon_alteration in addon.alterations:
                    addon_alteration_list = [
                        addon.status,
                        addon.name,
                        addon_alteration.file,
                        addon_alteration.target,
                        addon_alteration.type,
                    ]
                    addon_alteration_lists.append(addon_alteration_list)
                    x += 1
                if addon.type == "plugins":
                    self.add_data_to_file(
                        addon_alteration_lists,
                        self.plugins_alteration_filename,
                        self.plugins_alteration_headings,
                    )
                elif addon.type == "themes":
                    self.add_data_to_file(
                        addon_alteration_lists,
                        self.themes_alteration_filename,
                        self.themes_alteration_headings,
                    )

    def add_core_data_to_file(self, data, headers) -> None:
        with open(self.core_filename, "w", newline="") as csvfile:
            core_data_writer = csv.writer(
                csvfile, delimiter=";", quotechar="|", quoting=csv.QUOTE_MINIMAL
            )
            core_data_writer.writerow(headers)
            core_data_writer.writerow(data)

    def add_data_to_file(self, data, filename, headers) -> None:
        with open(filename, "w", newline="") as csvfile:
            data_writer = csv.writer(
                csvfile, delimiter=";", quotechar="|", quoting=csv.QUOTE_MINIMAL
            )
            data_writer.writerow(headers)
            data_writer.writerows(data)

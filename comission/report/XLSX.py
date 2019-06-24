#!/usr/bin/env python3

import xlsxwriter


class ComissionXLSX:
    """ CoMisSion XLS Generator """

    def __init__(self, output_filename="output.xlsx"):
        """ Generate XLSX """
        self.workbook = xlsxwriter.Workbook(output_filename)
        self.core_worksheet = self.workbook.add_worksheet("Core")
        self.core_alteration_worksheet = self.workbook.add_worksheet("Core Alteration")

        self.plugins_worksheet = self.workbook.add_worksheet("Plugins")
        self.plugins_vulns_worksheet = self.workbook.add_worksheet("Plugins Vulns")
        self.plugins_alteration_worksheet = self.workbook.add_worksheet("Plugins Alteration")

        self.themes_worksheet = self.workbook.add_worksheet("Themes")
        self.themes_vulns_worksheet = self.workbook.add_worksheet("Themes Vulns")
        self.themes_alteration_worksheet = self.workbook.add_worksheet("Themes Alteration")

        self.generate_heading()
        self.generate_formatting(self.workbook)

    def add_data(self, core_details, plugins, themes) -> None:
        # Add core data
        self.add_core_data("A2", [core_details.version, core_details.last_version])

        # Add core vulns
        x = 2
        for core_vuln in core_details.vulns:
            core_vuln_list = [
                core_vuln.name,
                core_vuln.link,
                core_vuln.type,
                core_vuln.poc,
                core_vuln.fixed_in,
            ]
            self.add_core_data("D" + str(x), core_vuln_list)
            x += 1

        # Add core alteration details
        x = 2
        for core_alteration in core_details.alterations:
            core_alterations_list = [
                core_alteration.status,
                core_alteration.file,
                core_alteration.target,
                core_alteration.type,
            ]
            self.add_core_alteration_data("A" + str(x), core_alterations_list)
            x += 1

        # Add plugins and themes data
        for elements in [plugins, themes]:
            # Add elements details
            x = 2

            for addon in elements:
                # Plugins and Themes or similar except for the field "mu"
                addon_list = addon.get_report_list()
                self.add_addon_data("A" + str(x), addon.type, addon_list)
                x += 1

            # Add elements vulns
            x = 2
            for addon in elements:
                for vuln in addon.vulns:
                    vuln_list = [
                        addon.name,
                        vuln.name,
                        vuln.link,
                        vuln.type,
                        vuln.poc,
                        vuln.fixed_in,
                    ]
                    self.add_addon_vulns_data("A" + str(x), addon.type, vuln_list)
                    x += 1

            # Add elements alteration details
            x = 2
            for addon in elements:
                for addon_alteration in addon.alterations:
                    addon_alteration_list = [
                        addon.status,
                        addon.name,
                        addon_alteration.file,
                        addon_alteration.target,
                        addon_alteration.type,
                    ]
                    self.add_addon_alteration_data(
                        "A" + str(x), addon.type, addon_alteration_list
                    )
                    x += 1

    def add_core_data(self, position, data) -> None:
        self.core_worksheet.write_row(position, data)

    def add_core_alteration_data(self, position, data) -> None:
        self.core_alteration_worksheet.write_row(position, data)

    def add_addon_data(self, position, addon_type, addon=[]) -> None:
        if addon_type == "plugins":
            self.plugins_worksheet.write_row(position, addon)
        elif addon_type == "themes":
            self.themes_worksheet.write_row(position, addon)

    def add_addon_vulns_data(self, position, addon_type, vulns=[]) -> None:
        if addon_type == "plugins":
            self.plugins_vulns_worksheet.write_row(position, vulns)
        elif addon_type == "themes":
            self.themes_vulns_worksheet.write_row(position, vulns)

    def add_addon_alteration_data(self, position, addon_type, data) -> None:
        if addon_type == "plugins":
            self.plugins_alteration_worksheet.write_row(position, data)
        elif addon_type == "themes":
            self.themes_alteration_worksheet.write_row(position, data)

    def generate_xlsx(self) -> None:
        self.workbook.close()

    def generate_heading(self) -> None:

        core_headings = [
            "Version",
            "Last version",
            "",
            "Vulnerabilities",
            "Link",
            "Type",
            "PoC",
            "Fixed In",
            "Notes",
        ]
        core_alteration_headings = ["Status", "File/Folder", "Path", "Alteration", "Notes"]
        plugins_headings = [
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
        plugins_vulns_headings = [
            "Plugin",
            "Vulnerabilities",
            "Link",
            "Type",
            "PoC",
            "Fixed In",
            "Notes",
        ]
        plugins_alteration_headings = [
            "Status",
            "Plugin",
            "File/Folder",
            "Path",
            "Alteration",
            "Notes",
        ]
        themes_headings = [
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
        themes_vulns_headings = [
            "Theme",
            "Vulnerabilities",
            "Link",
            "Type",
            "PoC",
            "Fixed In",
            "Notes",
        ]
        themes_alteration_headings = [
            "Status",
            "Theme",
            "File/Folder",
            "Path",
            "Alteration",
            "Notes",
        ]
        headings_list = [
            core_headings,
            core_alteration_headings,
            plugins_headings,
            plugins_vulns_headings,
            plugins_alteration_headings,
            themes_headings,
            themes_vulns_headings,
            themes_alteration_headings,
        ]
        worksheets_list = [
            self.core_worksheet,
            self.core_alteration_worksheet,
            self.plugins_worksheet,
            self.plugins_vulns_worksheet,
            self.plugins_alteration_worksheet,
            self.themes_worksheet,
            self.themes_vulns_worksheet,
            self.themes_alteration_worksheet,
        ]

        for target_worksheet, headings in zip(worksheets_list, headings_list):
            y = 0
            for heading in headings:
                target_worksheet.write(0, y, heading)
                y += 1

    def generate_formatting(self, workbook) -> None:
        # Bad : Light red fill with dark red text.
        bad = workbook.add_format({"bg_color": "#FFC7CE", "font_color": "#9C0006"})
        # Good : Green fill with dark green text.
        good = workbook.add_format({"bg_color": "#C6EFCE", "font_color": "#006100"})
        # N/A : When we don't know
        na = workbook.add_format({"bg_color": "#FCD5B4", "font_color": "#974706"})
        # Title of columns
        heading_format = workbook.add_format(
            {
                "bold": True,
                "font_size": "13",
                "bottom": 2,
                "border_color": "#44546A",
                "font_color": "#44546A",
                "text_wrap": True,
            }
        )

        # Format Core worksheet
        worksheet = self.core_worksheet
        worksheet.set_row(0, 15, heading_format)
        worksheet.set_column("A:B", 10)
        worksheet.set_column("C:C", 3)
        worksheet.set_column("D:D", 100)
        worksheet.set_column("E:E", 40)
        worksheet.set_column("F:F", 10)
        worksheet.set_column("G:G", 7)
        worksheet.set_column("H:H", 10)
        worksheet.set_column("I:I", 60)
        worksheet.conditional_format(
            "G1:G300", {"type": "cell", "criteria": "==", "value": '"CHECK"', "format": na}
        )
        worksheet.conditional_format(
            "G1:G300", {"type": "cell", "criteria": "==", "value": '"N/A"', "format": na}
        )
        worksheet.conditional_format(
            "G1:G300", {"type": "cell", "criteria": "==", "value": '"YES"', "format": bad}
        )
        worksheet.conditional_format(
            "G1:G300", {"type": "cell", "criteria": "==", "value": '"NO"', "format": good}
        )

        # Format Core Alteration worksheet
        worksheet = self.core_alteration_worksheet
        worksheet.set_row(0, 15, heading_format)
        worksheet.set_column("A:A", 7)
        worksheet.set_column("B:B", 30)
        worksheet.set_column("C:C", 70)
        worksheet.set_column("D:D", 12)
        worksheet.set_column("E:E", 60)
        worksheet.conditional_format(
            "A1:A300", {"type": "text", "criteria": "containing", "value": "todo", "format": bad}
        )
        worksheet.conditional_format(
            "A1:A300", {"type": "text", "criteria": "containing", "value": "done", "format": good}
        )
        worksheet.conditional_format(
            "D1:D300", {"type": "cell", "criteria": "==", "value": '"altered"', "format": bad}
        )
        worksheet.conditional_format(
            "D1:D300", {"type": "cell", "criteria": "==", "value": '"added"', "format": bad}
        )
        worksheet.conditional_format(
            "D1:D300", {"type": "cell", "criteria": "==", "value": '"deleted"', "format": na}
        )

        for worksheet in [self.plugins_worksheet, self.themes_worksheet]:
            # Format Plugins/Themes worksheet
            worksheet.set_row(0, 15, heading_format)
            worksheet.set_column("A:A", 7)
            worksheet.set_column("B:B", 25)
            worksheet.set_column("C:C", 8)
            worksheet.set_column("D:D", 10)
            worksheet.set_column("E:E", 13)
            worksheet.set_column("F:F", 50)
            worksheet.set_column("G:G", 5)
            worksheet.set_column("H:H", 10)
            worksheet.set_column("I:I", 5)
            worksheet.set_column("J:J", 60)
            worksheet.conditional_format(
                "A1:A300",
                {"type": "text", "criteria": "containing", "value": "todo", "format": bad},
            )
            worksheet.conditional_format(
                "A1:A300",
                {"type": "text", "criteria": "containing", "value": "done", "format": good},
            )
            # Red if the version if "trunk"
            worksheet.conditional_format(
                "C1:C300", {"type": "cell", "criteria": "==", "value": '"trunk"', "format": bad}
            )

            # Red if some info are missing
            worksheet.conditional_format(
                "J1:J300",
                {"type": "text", "criteria": "containing", "value": "Search", "format": bad},
            )

            # Red if the plugin have been modified
            worksheet.conditional_format(
                "H1:H300", {"type": "cell", "criteria": "==", "value": '"YES"', "format": bad}
            )
            worksheet.conditional_format(
                "H1:H300", {"type": "cell", "criteria": "==", "value": '"NO"', "format": good}
            )
            # Red if some CVE exist
            worksheet.conditional_format(
                "I1:I300", {"type": "cell", "criteria": "==", "value": '"YES"', "format": bad}
            )
            worksheet.conditional_format(
                "I1:I300", {"type": "cell", "criteria": "==", "value": '"NO"', "format": good}
            )
            # N/A if we don't know for any reason
            worksheet.conditional_format(
                "C1:I300", {"type": "cell", "criteria": "==", "value": '"N/A"', "format": na}
            )

        for worksheet in [self.plugins_vulns_worksheet, self.themes_vulns_worksheet]:
            # Format Plugins/Themes Vulnerabilities worksheet
            worksheet.set_row(0, 15, heading_format)
            worksheet.set_column("A:A", 25)
            worksheet.set_column("B:B", 80)
            worksheet.set_column("C:C", 40)
            worksheet.set_column("D:D", 10)
            worksheet.set_column("E:E", 10)
            worksheet.set_column("F:F", 10)
            worksheet.set_column("G:G", 60)
            worksheet.set_column("H:H", 3)
            worksheet.conditional_format(
                "E1:E300", {"type": "cell", "criteria": "==", "value": '"CHECK"', "format": na}
            )
            worksheet.conditional_format(
                "E1:E300", {"type": "cell", "criteria": "==", "value": '"YES"', "format": bad}
            )
            worksheet.conditional_format(
                "G1:G300", {"type": "cell", "criteria": "==", "value": '"NO"', "format": good}
            )

        for worksheet in [self.plugins_alteration_worksheet, self.themes_alteration_worksheet]:
            # Format CMS Plugins Alteration worksheet
            worksheet.set_row(0, 15, heading_format)
            worksheet.set_column("A:A", 7)
            worksheet.set_column("B:B", 25)
            worksheet.set_column("C:C", 40)
            worksheet.set_column("D:D", 80)
            worksheet.set_column("E:E", 12)
            worksheet.set_column("F:F", 60)
            worksheet.conditional_format(
                "A1:A300",
                {"type": "text", "criteria": "containing", "value": "todo", "format": bad},
            )
            worksheet.conditional_format(
                "A1:A300",
                {"type": "text", "criteria": "containing", "value": "done", "format": good},
            )
            worksheet.conditional_format(
                "E1:E300", {"type": "cell", "criteria": "==", "value": '"altered"', "format": bad}
            )
            worksheet.conditional_format(
                "E1:E300", {"type": "cell", "criteria": "==", "value": '"added"', "format": bad}
            )
            worksheet.conditional_format(
                "E1:E300", {"type": "cell", "criteria": "==", "value": '"deleted"', "format": na}
            )





#!/usr/bin/env python3

import os
import re
import unittest

from context import comission

import comission.defineCMS as dCMS
import comission.utilsCMS as uCMS
import comission.reportCMS as rCMS

from openpyxl import load_workbook

class TestWordPressAnalysis(unittest.TestCase):
    def setUp(self):
        self.cms = dCMS.WP()
        self.dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../test-data-set",
                                     "wordpress")

    def test_get_wp_content(self):
        retrieve_wp_content = self.cms.get_wp_content(self.dir_path)

        self.assertEqual(retrieve_wp_content[0], "renamed-wp-content")

    def test_get_addon_main_file(self):
        pass

    def test_get_core_version(self):
        regex = re.compile("\$wp_version = '(.*)';")
        self.cms.get_core_version(self.dir_path, regex, "wp-includes/version.php")

        self.assertEqual(self.cms.core_details["infos"]["version"], "4.5.1")

    def test_get_addon_version(self):
        regex = re.compile("(?i)Version: (.*)")
        addon = {
                    "name":"w3-total-cache", "filename":"w3-total-cache.php", "version":"",
                    "notes":""
                }
        addons_path = os.path.join(self.dir_path, "renamed-wp-content", "plugins",
                                   "w3-total-cache")
        self.cms.get_addon_version(addon, addons_path, regex)

        self.assertEqual(addon["version"], "0.9.4.1")

    def test_get_core_last_version(self):
        self.cms.get_core_last_version(self.cms.site_api)

        self.assertEqual(self.cms.core_details["infos"]["last_version"], "4.8.1")

    def test_get_addon_last_version(self):
        addon = {
                    "type":"plugins","name":"w3-total-cache", "last_version":"",
                    "last_release_date":"", "link":"", "version":"0.9.4.1",
                    "notes":""
                }
        self.cms.get_addon_last_version(addon)

        self.assertEqual(addon["last_version"], "0.9.5.4")
        self.assertEqual(addon["last_release_date"], "2017-04-26")
        self.assertEqual(addon["link"], "https://wordpress.org/plugins/w3-total-cache/")

    def test_check_core_alteration(self):
        download_core_url = "https://wordpress.org/wordpress-4.5.1.zip"
        version_core = "4.5.1"
        alterations, err = self.cms.check_core_alteration(self.dir_path, version_core,
                                                          download_core_url)

        self.assertEqual(alterations[0]["file"], "wp-config-sample.php")

    def test_check_addon_alteration(self):
        pass

    def test_check_vulns_core(self):
        pass

    def test_check_vulns_addon(self):
        pass

    # Full core analysis test
    @unittest.skip("Skip full core analysis")
    def test_core_analysis(self):
        pass

    # Full addon analysis test
    @unittest.skip("Skip full addon analysis")
    def test_addon_analysis(self):
        for addon_type in ["plugins", "themes"]:
            self.cms.addon_analysis(self.dir_path, addon_type)
        print(self.cms.plugins[0]["version"] + "|")
        self.assertEqual(self.cms.plugins[0]["version"], "2.6")

class TestDrupalAnalysis(unittest.TestCase):
    #def setUp(self):
    #    self.cms = DPL()
    #    self.dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
    #                                    "test-data-set", "drupal")

    def test_get_core_version(self):
        pass

    def test_get_addon_version(self):
        pass

    def test_get_core_last_version(self):
        pass

    def test_get_addon_last_version(self):
        pass

    def test_check_core_alteration(self):
        pass

    def test_check_addon_alteration(self):
        pass

    def test_check_vulns_core(self):
        pass

    def test_check_vulns_addon(self):
        pass

    def test_core_analysis(self):
        pass

    def test_addon_analysis(self):
        pass


class TestReportXLSX(unittest.TestCase):
    def setUp(self):
        report_name = "../test-data-set/test.xlsx"
        self.report = rCMS.ComissionXLSX(report_name)
        alteration = {
                        "status":"todo","target":"", "file":"", "type":""
                    }
        vuln = {
                "name": "Vuln name", "link": "", "type": "",
                "poc": "",  "fixed_in": ""
                }
        core_details = {
                        "infos": {
                                    "version":"4.5.1", "last_version":"4.8"
                                },
                        "alterations": [alteration, alteration, alteration],
                        "vulns": [vuln, vuln, vuln]
                        }
        plugin = {
                    "type":"plugins", "status":"todo", "name":"Name plugin",
                    "version":"1.0", "last_version":"2.0",
                    "last_release_date":"2017-08-25", "link":"https://test.link.addon",
                    "edited":"YES", "cve":"YES", "vulns":[vuln, vuln, vuln],
                    "notes":"", "alterations" : [alteration, alteration, alteration],
                    "filename":""
                }
        theme = {
                    "type":"themes", "status":"todo", "name":"Name theme",
                    "version":"1.0", "last_version":"2.0",
                    "last_release_date":"2017-08-25", "link":"https://test.link.addon",
                    "edited":"YES", "cve":"YES", "vulns":[vuln, vuln, vuln],
                    "notes":"", "alterations" : [alteration, alteration, alteration],
                    "filename":""
                }
        plugins = [plugin, plugin, plugin]
        themes = [theme, theme, theme]

        self.report.add_data(core_details, plugins, themes)
        self.report.generate_xlsx()

        self.workbook = load_workbook(report_name)

    def test_add_data(self):
        pass

    def test_generate_heading(self):
        self.workbook.get_sheet_names()
        pass

    def test_generate_formatting(self):
        pass

#class TestReportCSV(unittest.TestCase):

class TestReportJSON(unittest.TestCase):
    def setUp(self):
        report_name = "test-data-set/test.json"
        self.report = rCMS.ComissionJSON(report_name)

    def test_add_data(self):
        alteration = {
                        "status":"todo","target":"", "file":"", "type":""
                    }
        vuln = {
                "name": "Vuln name", "link": "", "type": "",
                "poc": "",  "fixed_in": ""
                }
        core_details = {
                        "infos": {
                                    "version":"4.5.1", "last_version":"4.8"
                                },
                        "alterations": [alteration, alteration, alteration],
                        "vulns": [vuln, vuln, vuln]
                        }
        plugin = {
                    "type":"plugins", "status":"todo", "name":"Name plugin",
                    "version":"1.0", "last_version":"2.0",
                    "last_release_date":"2017-08-25", "link":"https://test.link.addon",
                    "edited":"YES", "cve":"YES", "vulns":[vuln, vuln, vuln],
                    "notes":"", "alterations" : [alteration, alteration, alteration],
                    "filename":""
                }
        theme = {
                    "type":"themes", "status":"todo", "name":"Name theme",
                    "version":"1.0", "last_version":"2.0",
                    "last_release_date":"2017-08-25", "link":"https://test.link.addon",
                    "edited":"YES", "cve":"YES", "vulns":[vuln, vuln, vuln],
                    "notes":"", "alterations": [alteration, alteration, alteration],
                    "filename":""
                }
        plugins = [plugin, plugin, plugin]
        themes = [theme, theme, theme]

        self.report.add_data(core_details, plugins, themes)
        self.assertEqual(self.report.data['core']["infos"]["version"], "4.5.1")

    def test_generate_json(self):
        pass

if __name__ == '__main__':
    unittest.main()

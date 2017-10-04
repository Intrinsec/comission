#!/usr/bin/env python3

import os
import re
import unittest

from context import comission

import comission.defineCMS as dCMS
import comission.reportCMS as rCMS
import comission.utilsCMS as uCMS

from openpyxl import load_workbook


class DataSet:
    def __init__(self):

        # Dataset specific to WordPress
        self.addon_wp_stage0 = {
                                "type":"plugins", "name":"w3-total-cache", "filename":"", "version":"",
                                "notes":"", "mu":"NO"
                                }
        self.addon_wp_stage1 = {
                                "type":"plugins", "name":"w3-total-cache", "filename":"w3-total-cache.php",
                                "version":"", "notes":"", "mu":"NO"
                               }
        self.addon_wp_stage2 = {
                             "type":"plugins","name":"w3-total-cache", "last_version":"",
                             "last_release_date":"", "link":"", "version":"0.9.4.1",
                             "notes":"", "mu":"NO", "alterations": []
                            }

        # Dataset specific to Drupal analysis
        self.addon_dpl_stage1 = {
                                 "name":"xmlsitemap", "filename":"xmlsitemap.info", "version":"",
                                 "notes":""
                                }
        self.addon_dpl_stage2 = {
                             "type":"plugins","name":"media_youtube", "last_version":"",
                             "last_release_date":"", "link":"", "version":"7.x-3.4",
                             "notes":"", "alterations": []
                            }

        self.alteration = {
                        "status":"todo","target":"", "file":"", "type":""
                    }
        self.vuln = {
                "name": "Vuln name", "link": "", "type": "",
                "poc": "",  "fixed_in": ""
                }
        self.core_details = {
                        "infos": {
                                    "version":"4.5.1", "last_version":"4.8"
                                },
                        "alterations": [self.alteration, self.alteration, self.alteration],
                        "vulns": [self.vuln, self.vuln, self.vuln]
                        }
        self.plugin = {
                    "type":"plugins", "status":"todo", "name":"Name plugin",
                    "version":"1.0", "last_version":"2.0",
                    "last_release_date":"2017-08-25", "link":"https://test.link.addon",
                    "edited":"YES", "mu":"NO", "cve":"YES", "vulns":[self.vuln, self.vuln, self.vuln],
                    "notes":"", "alterations": [self.alteration, self.alteration, self.alteration],
                    "filename":""
                }
        self.muplugin = {
                         "type":"plugins", "status":"todo", "name":"Name plugin",
                         "version":"1.0", "last_version":"2.0",
                         "last_release_date":"2017-08-25", "link":"https://test.link.addon",
                         "edited":"YES",  "mu":"NO","cve":"YES", "vulns":[self.vuln, self.vuln, self.vuln],
                         "notes":"", "alterations":[self.alteration, self.alteration, self.alteration],
                         "filename":""
        }
        self.theme = {
                    "type":"themes", "status":"todo", "name":"Name theme",
                    "version":"1.0", "last_version":"2.0",
                    "last_release_date":"2017-08-25", "link":"https://test.link.addon",
                    "edited":"YES", "cve":"YES", "vulns":[self.vuln, self.vuln, self.vuln],
                    "notes":"", "alterations": [self.alteration, self.alteration, self.alteration],
                    "filename":""
                }
        self.plugins = [self.plugin, self.plugin, self.muplugin]
        self.themes = [self.theme for _ in range(3)]


class TestWordPressAnalysis(unittest.TestCase):
    def setUp(self):
        self.cms = dCMS.WP()
        self.dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../test-data-set",
                                     "wordpress")

    def test_get_wp_content(self):
        retrieve_wp_content = self.cms.get_wp_content(self.dir_path)

        self.assertEqual(retrieve_wp_content[0], "renamed-wp-content")

    def test_get_addon_main_file(self):
        dataset = DataSet()
        addon_path = os.path.join(self.dir_path, "renamed-wp-content", "plugins", "w3-total-cache")
        self.cms.get_addon_main_file(dataset.addon_wp_stage0, addon_path)
        self.assertEqual(dataset.addon_wp_stage0["filename"], "w3-total-cache.php")

    def test_get_core_version(self):
        regex = re.compile("\$wp_version = '(.*)';")
        self.cms.get_core_version(self.dir_path, regex, "wp-includes/version.php")

        self.assertEqual(self.cms.core_details["infos"]["version"], "4.5.1")

    def test_get_addon_version(self):
        regex = re.compile("(?i)Version: (.*)")
        dataset = DataSet()

        addons_path = os.path.join(self.dir_path, "renamed-wp-content", "plugins",
                                   "w3-total-cache")
        self.cms.get_addon_version(dataset.addon_wp_stage1, addons_path, regex)

        self.assertEqual(dataset.addon_wp_stage1["version"], "0.9.4.1")

    def test_get_core_last_version(self):
        self.cms.get_core_last_version(self.cms.site_api)

        self.assertEqual(self.cms.core_details["infos"]["last_version"], "4.8.2")

    def test_get_addon_last_version(self):
        dataset = DataSet()

        self.cms.get_addon_last_version(dataset.addon_wp_stage2)

        self.assertEqual(dataset.addon_wp_stage2["last_version"], "0.9.5.4")
        self.assertEqual(dataset.addon_wp_stage2["last_release_date"], "2017-04-26")
        self.assertEqual(dataset.addon_wp_stage2["link"], "https://wordpress.org/plugins/w3-total-cache/")

    def test_check_core_alteration(self):
        download_core_url = "https://wordpress.org/wordpress-4.5.1.zip"
        alterations, err = self.cms.check_core_alteration(self.dir_path, download_core_url)

        self.assertEqual(alterations[0]["file"], "wp-config-sample.php")

    def test_check_addon_alteration(self):
        dataset = DataSet()
        temp_directory = uCMS.TempDir.create()
        self.cms.wp_content = "renamed-wp-content"

        _, _ = self.cms.check_addon_alteration(dataset.addon_wp_stage2, self.dir_path,
                                               temp_directory)

        uCMS.TempDir.delete_all()

        self.assertIn(dataset.addon_wp_stage2["alterations"][0]["file"], "readme.txt")

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
    def setUp(self):
        self.cms = dCMS.DPL()
        self.dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../test-data-set",
                                     "drupal", "drupal-7.X")

    def test_get_core_version_DPL7(self):
        self.cms.get_core_version(self.dir_path)

        self.assertEqual(self.cms.core_details["infos"]["version"], "7.56")

    def test_get_core_versionDPL8(self):
        dir_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../test-data-set",
                                "drupal", "drupal-8.X")
        self.cms.get_core_version(dir_path)

        self.assertEqual(self.cms.core_details["infos"]["version"], "8.3.7")

    def test_get_addon_version(self):
        regex = re.compile("version = (.*)")
        dataset = DataSet()
        addons_path = os.path.join(self.dir_path, "sites", "all", "modules", "xmlsitemap")

        self.cms.get_addon_version(dataset.addon_dpl_stage1, addons_path, regex)

        self.assertEqual(dataset.addon_dpl_stage1["version"], "7.x-2.3")

    def test_get_core_last_version(self):
        self.cms.get_core_last_version("https://updates.drupal.org/release-history/drupal/", "7.56")

        self.assertEqual(self.cms.core_details["infos"]["last_version"], "7.56")

    def test_get_addon_last_version(self):
        dataset = DataSet()

        self.cms.get_addon_last_version(dataset.addon_dpl_stage2)

        self.assertEqual(dataset.addon_dpl_stage2["last_version"], "7.x-3.5")
        self.assertEqual(dataset.addon_dpl_stage2["last_release_date"], "14 August 2017")
        self.assertEqual(dataset.addon_dpl_stage2["link"], "https://www.drupal.org/project/media_youtube/releases")

    def test_check_core_alteration(self):
        download_core_url = "https://ftp.drupal.org/files/projects/drupal-7.56.zip"
        version_core = "7.56"
        alterations, err = self.cms.check_core_alteration(self.dir_path, version_core,
                                                          download_core_url)

        self.assertEqual(alterations[0]["file"], "cron.php")

    def test_check_addon_alteration(self):
        dataset = DataSet()
        temp_directory = uCMS.TempDir.create()
        addon_path = os.path.join(self.dir_path, "sites", "all", "modules", dataset.addon_dpl_stage2["name"])
        _, _ = self.cms.check_addon_alteration(dataset.addon_dpl_stage2, addon_path, temp_directory)

        uCMS.TempDir.delete_all()

        self.assertIn("media_youtube.test", dataset.addon_dpl_stage2["alterations"][0]["file"])

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

        dataset = DataSet()

        self.report.add_data(dataset.core_details, dataset.plugins, dataset.themes)
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
        dataset = DataSet()

        self.report.add_data(dataset.core_details, dataset.plugins, dataset.themes)
        self.assertEqual(self.report.data['core']["infos"]["version"], "4.5.1")

    def test_generate_json(self):
        pass

if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3

import os
import re
import unittest

from openpyxl import load_workbook
from pathlib import Path

import comission.CMS.WordPress as WordPress
import comission.CMS.Drupal.Drupal7 as Drupal7
import comission.CMS.Drupal.Drupal8 as Drupal8
import comission.utilsCMS as uCMS
from tests.dataset import DataSet
from comission.report.CSV import ComissionCSV
from comission.report.XLSX import ComissionXLSX
from comission.report.JSON import ComissionJSON


class TestWordPressAnalysis(unittest.TestCase):
    def setUp(self):
        self.dir_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "../test-data-set", "wordpress"
        )
        self.cms = WordPress.WP(self.dir_path, "", "", "", "")

    def test_get_wp_content(self):
        retrieve_wp_content = self.cms.get_wp_content(self.dir_path)

        self.assertEqual(retrieve_wp_content[0], "renamed-wp-content")

    def test_get_addon_main_file(self):
        dataset = DataSet()
        addon_path = os.path.join(self.dir_path, "renamed-wp-content", "plugins", "w3-total-cache")
        self.cms.get_addon_main_file(dataset.addon_wp_stage0, addon_path)
        self.assertEqual(dataset.addon_wp_stage0.filename, "w3-total-cache.php")

    def test_get_core_version(self):
        self.cms.get_core_version()

        self.assertEqual(self.cms.core.version, "4.5.1")

    def test_get_addon_version(self):
        regex = re.compile("(?i)Version: (.*)")
        dataset = DataSet()

        addons_path = os.path.join(self.dir_path, "renamed-wp-content", "plugins", "w3-total-cache")
        self.cms.get_addon_version(dataset.addon_wp_stage1, addons_path, regex, " ")

        self.assertEqual(dataset.addon_wp_stage1.version, "0.9.4.1")

    def test_get_core_last_version(self):
        self.cms.get_core_last_version()

        self.assertEqual(self.cms.core.last_version, "5.2.2")

    def test_get_addon_last_version(self):
        dataset = DataSet()

        self.cms.get_addon_last_version(dataset.addon_wp_stage2)

        self.assertEqual(dataset.addon_wp_stage2.last_version, "0.9.7.5")
        self.assertEqual(dataset.addon_wp_stage2.last_release_date, "2019-06-05")
        self.assertEqual(
            dataset.addon_wp_stage2.link, "https://wordpress.org/plugins/w3-total-cache/"
        )

    def test_check_core_alteration(self):
        download_core_url = "https://wordpress.org/wordpress-4.5.1.zip"
        alterations = self.cms.check_core_alteration(download_core_url)

        self.assertEqual(alterations[0].file, "wp-config-sample.php")

    def test_check_addon_alteration(self):
        dataset = DataSet()
        temp_directory = uCMS.TempDir.create()
        self.cms.wp_content = "renamed-wp-content"

        self.cms.check_addon_alteration(
            dataset.addon_wp_stage2, self.dir_path, temp_directory
        )

        uCMS.TempDir.delete_all()

        altered_files = []
        for alteration in dataset.addon_wp_stage2.alterations:
            altered_files.append(alteration.file)

        self.assertIn("readme.txt", altered_files)

    def test_check_vulns_core(self):
        self.cms.core.version = "5.0"
        config = uCMS.parse_conf("test-data-set/test.conf")
        self.cms.wpvulndb_token = config["wpvulndb_token"]
        vulns_details = self.cms.check_vulns_core()
        self.assertEqual(len(vulns_details), 9)
        self.assertEqual(vulns_details[0].name, "WordPress <= 5.0 - Authenticated File Delete")
        self.assertEqual(vulns_details[0].link, "https://wpvulndb.com/vulnerabilities/9169")

    def test_check_vulns_addon(self):
        dataset = DataSet()
        config = uCMS.parse_conf("test-data-set/test.conf")
        self.cms.wpvulndb_token = config["wpvulndb_token"]
        vulns_details = self.cms.check_vulns_addon(dataset.addon_wp_stage2)
        self.assertEqual(len(vulns_details), 11)

    # Full core analysis test
    @unittest.skip("Skip full core analysis")
    def test_core_analysis(self):
        pass

    # Full addon analysis test
    @unittest.skip("Skip full addon analysis")
    def test_addon_analysis(self):
        for addon_type in ["plugins", "themes"]:
            self.cms.addon_analysis(addon_type)
        self.assertEqual(self.cms.plugins[0].version, "0.2")


class TestDrupal7Analysis(unittest.TestCase):
    def setUp(self):
        self.dir_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "../test-data-set", "drupal", "drupal-7.X"
        )
        self.cms = Drupal7.DPL7(self.dir_path, "", "")

    def test_get_core_version(self):
        self.cms.get_core_version()

        self.assertEqual(self.cms.core.version, "7.56")

    def test_get_addon_version(self):
        regex = re.compile("version = (.*)")
        dataset = DataSet()
        addons_path = os.path.join(self.dir_path, "sites", "all", "modules", "xmlsitemap")

        self.cms.get_addon_version(dataset.addon_dpl_stage1, addons_path, regex, '"')

        self.assertEqual(dataset.addon_dpl_stage1.version, "7.x-2.3")

    def test_get_core_last_version(self):
        self.cms.core.version_major = "7"
        self.cms.get_core_last_version()

        self.assertEqual("7.67", self.cms.core.last_version)

    def test_get_addon_last_version(self):
        dataset = DataSet()
        self.cms.get_addon_last_version(dataset.addon_dpl_stage2)

        self.assertEqual("7.x-3.8", dataset.addon_dpl_stage2.last_version)
        self.assertEqual("14 February 2019", dataset.addon_dpl_stage2.last_release_date)
        self.assertEqual(
            dataset.addon_dpl_stage2.link, "https://www.drupal.org/project/media_youtube/releases"
        )

    def test_check_core_alteration(self):
        self.cms.core.version = "7.56"
        download_core_url = "https://ftp.drupal.org/files/projects/drupal-7.56.zip"
        alterations = self.cms.check_core_alteration(download_core_url)

        self.assertEqual(alterations[0].file, "cron.php")

    def test_check_addon_alteration(self):
        dataset = DataSet()
        temp_directory = uCMS.TempDir.create()
        addon_path = os.path.join(
            self.dir_path, Path("sites"), Path("all"), Path("modules"), Path(dataset.addon_dpl_stage2.name)
        )
        self.cms.check_addon_alteration(dataset.addon_dpl_stage2, addon_path, temp_directory)

        uCMS.TempDir.delete_all()

        altered_files = []
        for alteration in dataset.addon_dpl_stage2.alterations:
            altered_files.append(alteration.file)

        self.assertIn("media_youtube.test", altered_files)

class TestDrupal8Analysis(unittest.TestCase):
    def setUp(self):
        self.dir_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "../test-data-set", "drupal", "drupal-8.X"
        )
        self.cms = Drupal8.DPL8(self.dir_path, "", "")

    def test_get_core_version(self):
        self.cms.get_core_version()

        self.assertEqual(self.cms.core.version, "8.3.7")

    def test_get_addon_version(self):
        #TODO
        pass

    def test_get_core_last_version(self):
        self.cms.core.version_major = "8"
        self.cms.get_core_last_version()

        self.assertEqual("8.7.3", self.cms.core.last_version)

    def test_get_addon_last_version(self):
        #TODO
        pass

    def test_check_core_alteration(self):
        self.cms.core.version = "8.3.7"
        download_core_url = "https://ftp.drupal.org/files/projects/drupal-8.3.7.zip"
        alterations = self.cms.check_core_alteration(download_core_url)

        self.assertEqual(alterations[0].file, "core.api.php")

class TestReportXLSX(unittest.TestCase):
    def setUp(self):
        report_name = "test-data-set/test.xlsx"
        self.report = ComissionXLSX(report_name)

        dataset = DataSet()

        self.report.add_data(dataset.core, dataset.plugins, dataset.themes)
        self.report.generate_xlsx()

        self.workbook = load_workbook(report_name)

    def test_add_data(self):
        #TODO
        pass

    def test_generate_heading(self):
        #TODO
        self.workbook.get_sheet_names()
        pass

    def test_generate_formatting(self):
        #TODO
        pass


# class TestReportCSV(unittest.TestCase):


class TestReportJSON(unittest.TestCase):
    def setUp(self):
        report_name = "test-data-set/test.json"
        self.report = ComissionJSON(report_name)

    def test_add_data(self):
        dataset = DataSet()

        self.report.add_data(dataset.core, dataset.plugins, dataset.themes)
        self.assertEqual(self.report.data["core"].version, "4.5.1")

    def test_generate_json(self):
        pass


if __name__ == "__main__":
    unittest.main()

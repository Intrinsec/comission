#!/usr/bin/env python3

import re
import os
from comission.CMS.Drupal.GenericDrupal import GenericDPL


class DPL7(GenericDPL):
    """ DRUPAL 7 object """

    def __init__(self, dir_path, plugins_dir, themes_dir, version="", version_major=""):
        super().__init__(dir_path, plugins_dir, themes_dir, version, version_major)

        self.addons_path = "sites/all/"
        self.addon_extension = ".info"
        self.regex_version_core = re.compile("define\('VERSION', '(.*)'\);")
        self.regex_version_addon = re.compile("version = (.*)")
        self.core_suspect_file_path = "includes/bootstrap.inc"

        # If no custom plugins directory, then it's in default location
        if self.plugins_dir == "":
            self.plugins_dir = os.path.join(self.addons_path + "modules")

        # If no custom themes directory, then it's in default location
        if self.themes_dir == "":
            self.themes_dir = os.path.join(self.addons_path + "themes")

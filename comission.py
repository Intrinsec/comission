#!/usr/bin/env python3

import sys

import comission.CMS.WordPress as WordPress
import comission.CMS.Drupal.Drupal7 as Drupal7
import comission.CMS.Drupal.Drupal8 as Drupal8
import comission.utilsCMS as uCMS
import comission.reportCMS as rCMS

from comission.utils.logging import LOGGER
import comission.utils.logging as logging


def main():
    args = uCMS.parse_args()

    if "conf" in args:
        config = uCMS.parse_conf(args["conf"])
        args = {**config, **args}

    # Colored output ?
    if args["no_color"]:
        LOGGER.set_nocolor_policy(args["no_color"])
    
    if "logfile" in args:
        LOGGER.set_file(args["logfile"])

    if not args["dir"]:
        LOGGER.print_cms("alert", "No path received !", "", 0)
        sys.exit()

    dir_path = args["dir"]

    wp_content = ""
    plugins_dir = ""
    themes_dir = ""
    no_check = False
    wpvulndb_token = ""
    version = ""
    version_major = ""

    if "wp_content" in args:
        wp_content = args["wp_content"]

    if "plugins_dir" in args:
        plugins_dir = args["plugins_dir"]

    if "themes_dir" in args:
        themes_dir = args["themes_dir"]

    if "no_check" in args:
        no_check = args["no_check"]

    if "wpvulndb_token" in args:
        wpvulndb_token = args["wpvulndb_token"]

    if "version" in args:
        version = args["version"]
    
    if "version_major" in args:
        version_major = args["version_major"]

    if "debug" in args:
        logging.DEBUG = True

    # Verify if the CMS is really the one given by the user
    if args["cms"] == "wordpress":
        if not no_check:
            to_check = ["wp-includes", "wp-admin"]
            uCMS.verify_path(dir_path, to_check)
        cms = WordPress.WP(dir_path, wp_content, plugins_dir, themes_dir, wpvulndb_token, version, version_major)

    elif args["cms"] == "drupal":
        if not no_check:
            to_check = ["sites", "modules", "profiles", "themes", "web.config", "update.php"]
            uCMS.verify_path(dir_path, to_check)
        if version_major == "7":
            cms = Drupal7.DPL7(dir_path, plugins_dir, themes_dir, version, version_major)
        elif version_major == "8":
            cms = Drupal8.DPL8(dir_path, plugins_dir, themes_dir, version, version_major)
        else:
            LOGGER.print_cms("alert", "Major Drupal version unknown !", "", 0)
            sys.exit()

    else:
        LOGGER.print_cms("alert", "CMS unknown or unsupported !", "", 0)
        sys.exit()

    # Analyse the core
    if not args["skip_core"]:
        cms.core_analysis()

    # Analyse plugins
    if not args["skip_plugins"]:
        cms.addon_analysis("plugins")

    # Analyse themes
    if not args["skip_themes"]:
        cms.addon_analysis("themes")

    # Save results to a file
    if args["type"] == "CSV" and args["output"]:
        # Initialize the output file
        result_csv = rCMS.ComissionCSV(args["output"])
        # Add data and generate result file
        result_csv.add_data(cms.core, cms.plugins, cms.themes)

    elif args["type"] == "XLSX" and args["output"]:
        # Initialize the output file
        result_xlsx = rCMS.ComissionXLSX(args["output"])
        # Add data
        result_xlsx.add_data(cms.core, cms.plugins, cms.themes)
        # Generate result file
        result_xlsx.generate_xlsx()

    elif args["type"] == "JSON" and args["output"]:
        # Initialize the output file
        result_json = rCMS.ComissionJSON(args["output"])
        # Add data
        result_json.add_data(cms.core, cms.plugins, cms.themes)
        # Generate result file
        result_json.generate_json()

    elif args["type"] == "STDOUT":
        # Do nothing
        pass

    else:
        LOGGER.print_cms("alert", "Output type unknown or missing filename !", "", 0)
        sys.exit()

    # Keep or clean temp dir
    uCMS.TempDir.ask_delete_tmp()


if __name__ == "__main__":
    main()

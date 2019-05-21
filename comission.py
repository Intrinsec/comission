#!/usr/bin/env python3

import sys

import comission.CMS.WordPress as WordPress
import comission.CMS.Drupal as Drupal
import comission.utilsCMS as uCMS
import comission.reportCMS as rCMS

from comission.utilsCMS import Log as log


def main():
    args = uCMS.parse_args()

    if "conf" in args:
        config = uCMS.parse_conf(args["conf"])
        args = {**config, **args}

    # Colored output ?
    if args["no_color"]:
        log.set_nocolor_policy(args["no_color"])

    if not args["dir"]:
        log.print_cms("alert", "No path received !", "", 0)
        sys.exit()

    dir_path = args["dir"]

    wp_content = ""
    plugins_dir = ""
    themes_dir = ""
    wpvulndb_token = ""

    if "wp_content" in args:
        wp_content = args["wp_content"]

    if "plugins_dir" in args:
        plugins_dir = args["plugins_dir"]

    if "themes_dir" in args:
        themes_dir = args["themes_dir"]

    if "wpvulndb_token" in args:
        wpvulndb_token = args["wpvulndb_token"]

    # Verify if the CMS is really the one given by the user
    if args["cms"] == "wordpress":
        to_check = ["wp-includes", "wp-admin"]
        uCMS.verify_path(dir_path, to_check)
        cms = WordPress.WP(dir_path, wp_content, plugins_dir, themes_dir, wpvulndb_token)

    elif args["cms"] == "drupal":
        to_check = ["sites", "modules", "profiles", "themes", "web.config", "update.php"]
        uCMS.verify_path(dir_path, to_check)
        cms = Drupal.DPL(dir_path, plugins_dir, themes_dir)

    else:
        log.print_cms("alert", "CMS unknown or unsupported !", "", 0)
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
        result_csv.add_data(cms.core_details, cms.plugins, cms.themes)

    elif args["type"] == "XLSX" and args["output"]:
        # Initialize the output file
        result_xlsx = rCMS.ComissionXLSX(args["output"])
        # Add data
        result_xlsx.add_data(cms.core_details, cms.plugins, cms.themes)
        # Generate result file
        result_xlsx.generate_xlsx()

    elif args["type"] == "JSON" and args["output"]:
        # Initialize the output file
        result_json = rCMS.ComissionJSON(args["output"])
        # Add data
        result_json.add_data(cms.core_details, cms.plugins, cms.themes)
        # Generate result file
        result_json.generate_json()

    elif args["type"] == "STDOUT":
        # Do nothing
        pass

    else:
        log.print_cms(args.no_color, "alert", "Output type unknown or missing filename !", "", 0)
        sys.exit()

    # Keep or clean temp dir
    uCMS.TempDir.ask_delete_tmp()


if __name__ == "__main__":
    main()

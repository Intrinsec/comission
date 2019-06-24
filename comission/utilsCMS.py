#!/usr/bin/env python3

import argparse
import configparser
import os
import random
import shutil
import string
import sys
import tempfile

from filecmp import dircmp
from typing import Dict, List
from pathlib import Path

from comission.CMS.models.Alteration import Alteration
from comission.utils.logging import LOGGER

def parse_args() -> Dict:
    parser = argparse.ArgumentParser(description="CoMisSion analyse a CMS and plugins used.")
    parser.add_argument("-d", "--dir", dest="dir", required=True, help="CMS root directory")
    parser.add_argument(
        "-c", "--cms", required=True, help="CMS type (drupal, wordpress)"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE", default="output.XLSX", help="Path to output file"
    )
    parser.add_argument(
        "-t",
        "--type",
        metavar="TYPE",
        default="XLSX",
        choices=["CSV", "XLSX", "JSON", "STDOUT"],
        help="Type of output (CSV, XLSX, JSON, STDOUT). Default to XLSX.",
    )
    parser.add_argument(
        "--skip-core", dest="skip_core", action="store_true", help="Set this to skip core analysis"
    )
    parser.add_argument(
        "--skip-plugins",
        dest="skip_plugins",
        action="store_true",
        help="Set this to skip plugins analysis",
    )
    parser.add_argument(
        "--skip-themes",
        dest="skip_themes",
        action="store_true",
        help="Set this to skip themes analysis",
    )
    parser.add_argument(
        "--no-check",
        dest="no_check",
        action="store_true",
        help="Do not check if provided directory is containing the right CMS. Use if files used to check the CMS are missing.",
    )
    parser.add_argument(
        "--no-color",
        dest="no_color",
        default=False,
        action="store_true",
        help="Do not use colors in the output.",
    )
    parser.add_argument("-f", "--file", dest="conf", help="Configuration file. See example.conf.")
    parser.add_argument("--log", dest="logfile", help="Log output in given file.")
    parser.add_argument(
        "--wp-content",
        dest="wp_content",
        help="Set this to force the wp-content directory location. (WordPress only)",
    )
    parser.add_argument(
        "--plugins-dir",
        dest="plugins_dir",
        help="Set this to force the plugins directory location.",
    )
    parser.add_argument(
        "--themes-dir",
        dest="themes_dir",
        help="Set this to force the themes directory location.",
    )
    parser.add_argument(
        "--major-version",
        dest="version_major",
        help="Specify the core major version (eg. 7, 8) when using --skip-core arg. (Drupal only)",
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        help="Specify the core full version (eg. 5.5).",
    )
    parser.add_argument(
        "--wpvulndb-token", dest="wpvulndb_token", help="Set a token to request wpvulndb API. (WordPress only)"
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help="Print debug message to help identify errors.",
    )
    args = parser.parse_args()

    args_dict = {}

    for key, value in vars(args).items():
        if value is not None:
            args_dict[key] = value

    return args_dict


def parse_conf(conf_file: str) -> Dict:
    config = configparser.ConfigParser()
    config_dict = {}

    try:
        with open(Path(conf_file)) as file:
            config.read_file(file)
    except FileNotFoundError:
        LOGGER.print_cms(
            "alert",
            "[-] The conf file does not exist. "
            "Please check the path !",
            "",
            0,
        )
        sys.exit()

    for key, value in config.items("Configuration"):
        config_dict[key] = value

    return config_dict


def verify_path(dir_path: str, to_check: List) -> None:
    for directory in to_check:
        if not os.path.exists(os.path.join(dir_path, directory)):
            LOGGER.print_cms(
                "alert",
                "[-] The path provided does not seem to be a CMS directory. "
                "Please check the path !",
                "",
                0,
            )
            sys.exit()


def fetch_addons(input: str, type: str) -> List[str]:
    plugins_name = []
    if not os.path.exists(input):
        LOGGER.print_cms(
            "alert", f"[+] Addons path {input} does not exist ! (it may be normal)", "", 0
        )
        return []
    if type == "standard":
        plugins_name = next(os.walk(input))[1]
    elif type == "mu":
        plugins_name = [name.split(".php")[0] for name in next(os.walk(input))[2]]

    return plugins_name


def diff_files(dcmp: dircmp, alterations: List, target: str) -> None:
    for name in dcmp.diff_files:
        alteration = Alteration()
        altered_file = os.path.join(target, str(name))
        LOGGER.print_cms("alert", altered_file, " was altered !", 1)
        alteration.target = target
        alteration.file = name
        alteration.type = "altered"

        alterations.append(alteration)

    for name in dcmp.right_only:
        alteration = Alteration()
        altered_file = os.path.join(target, str(name))
        LOGGER.print_cms("warning", altered_file, " has been added !", 1)
        alteration.target = target
        alteration.file = name
        alteration.type = "added"

        alterations.append(alteration)

    for name in dcmp.left_only:
        alteration = Alteration()
        altered_file = os.path.join(target, str(name))
        LOGGER.print_cms("warning", altered_file, " deleted !", 1)
        alteration.target = target
        alteration.file = name
        alteration.type = "deleted"
        alterations.append(alteration)

    for current_dir, sub_dcmp in zip(dcmp.subdirs.keys(), dcmp.subdirs.values()):
        current_target = os.path.join(target, str(current_dir))
        diff_files(sub_dcmp, alterations, current_target)


class TempDir:

    tmp_dir_list = []

    @classmethod
    def create(cls):
        while True:
            random_dir_name = "".join(random.choice(string.ascii_uppercase) for _ in range(5))
            tmp_dir = os.path.join(tempfile.gettempdir(), random_dir_name)
            if not os.path.exists(tmp_dir):
                os.makedirs(tmp_dir)
                cls.tmp_dir_list.append(tmp_dir)
                break
        return tmp_dir

    @classmethod
    def delete_all(cls):
        for tmp_dir in cls.tmp_dir_list:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            cls.tmp_dir_list.clear()

    @classmethod
    def ask_delete_tmp(cls):
        clear_tmp_dir = input(
            "Do you want to keep temp directories containing downloaded core and "
            "plugins for further analysis ? (yes/no) "
        ).lower()

        if clear_tmp_dir == "no":
            LOGGER.print_cms("alert", "Deleting tmp directories !", "", 0)
            cls.delete_all()

        elif clear_tmp_dir == "yes":
            dir_list_str = ""
            for tmp_dir in cls.tmp_dir_list:
                dir_list_str = dir_list_str + "\n" + tmp_dir

            LOGGER.print_cms("info", "Keeping tmp directories ! Here they are :" + dir_list_str, "", 0)

        else:
            cls.ask_delete_tmp()

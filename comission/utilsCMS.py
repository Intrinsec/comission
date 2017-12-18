#!/usr/bin/env python3

import os
import sys
import random
import string
import shutil
import requests
import datetime
import argparse
import tempfile
import configparser

from bs4 import BeautifulSoup

debug = True
quiet = False


def log_debug(msg):
    global debug
    if debug and not quiet:
        time = datetime.datetime.now()
        print("{}: {}".format(time, msg))

def parse_args():
    parser = argparse.ArgumentParser(description="CoMisSion analyse a CMS and plugins used.")
    parser.add_argument("-d", "--dir", dest="dir", required=True, help="CMS root directory")
    parser.add_argument("-c", "--cms", dest="cms", required=True, help="CMS type (drupal, wordpress)")
    parser.add_argument("-o", "--output", metavar="FILE", default="output.XLSX",
                        help="Path to output file")
    parser.add_argument("-t", "--type", metavar="TYPE", default="XLSX",
                        help="Type of output file (CSV, XLSX, JSON). Default to XLSX.")
    parser.add_argument("--skip-core", dest="skip_core", action="store_true",
                        help="Set this to skip core analysis")
    parser.add_argument("--skip-plugins", dest="skip_plugins", action="store_true",
                        help="Set this to skip plugins analysis")
    parser.add_argument("--skip-themes", dest="skip_themes", action="store_true",
                        help="Set this to skip themes analysis")
    parser.add_argument("--no-color", dest="no_color", default=False, action="store_true",
                        help="Do not use colors in the output.")
    parser.add_argument("-f","--file", dest="conf", help="Configuration file. See example.conf.")
    parser.add_argument("--wp-content", dest="wp_content", help="Set this to force the wp-content "
                        "directory location.")
    parser.add_argument("--major", dest="version_major", help="Specify the core major version (eg. "
                                                                "7, 8) when using --skip-core arg.")
    args = parser.parse_args()

    args_dict = {}

    for key, value in vars(args).items():
        if value is not None:
            args_dict[key] = value

    return args_dict

def parse_conf(conf_file):
    config = configparser.ConfigParser()
    config_dict = {}

    with open(conf_file) as file:
        config.read_file(file)

    for key, value in config.items("Configuration"):
        config_dict[key] = value

    return config_dict

def verify_path(dir_path, to_check):
    for directory in to_check:
        if not os.path.exists(os.path.join(dir_path, directory)):
            Log.print_cms("alert", "[-] The path provided does not seem to be a CMS directory. " \
                          "Please check the path !", "", 0)
            sys.exit()

def fetch_addons(input, type):
    if not os.path.exists(input):
        Log.print_cms("alert", "Plugins path does not exist !", "", 0)
        exit(-1)
    if type == "standard":
        plugins_name = next(os.walk(input))[1]
    elif type == "mu":
        plugins_name = [name.split('.php')[0] for name in next(os.walk(input))[2]]

    return plugins_name

def diff_files(dcmp, alterations, target):
    for name in dcmp.diff_files:
        alteration = {"status":"todo","target":"", "file":"", "type":""}
        altered_file = os.path.join(target, name)
        Log.print_cms("alert", altered_file, " was altered !", 1)
        alteration["target"] = target
        alteration["file"] = name
        alteration["type"] = "altered"

        alterations.append(alteration)

    for name in dcmp.right_only:
        alteration = {"status":"todo","target":"", "file":"", "type":""}
        altered_file = os.path.join(target, name)
        Log.print_cms("warning", altered_file, " has been added !", 1)
        alteration["target"] = target
        alteration["file"] = name
        alteration["type"] = "added"

        alterations.append(alteration)

    for name in dcmp.left_only:
        alteration = {"status":"todo","target":"", "file":"", "type":""}
        altered_file = os.path.join(target, name)
        Log.print_cms("warning", altered_file, " deleted !", 1)
        alteration["target"] = target
        alteration["file"] = name
        alteration["type"] = "deleted"

        alterations.append(alteration)

    for current_dir, sub_dcmp in zip(dcmp.subdirs.keys(), dcmp.subdirs.values()):
        current_target = os.path.join(target, current_dir)
        diff_files(sub_dcmp, alterations, current_target)

def get_poc(url):
    r = requests.get(url)
    soup = BeautifulSoup(r.text, "lxml")
    return [el.get_text() for el in soup.findAll("pre", {"class":"poc"})]


class Log:
    NO_COLOR = False

    @classmethod
    def set_nocolor_policy(cls, no_color):
        cls.NO_COLOR = no_color

    @classmethod
    def print_cms(cls, type, msg, msg_default, level, no_color=None):
        # Define color for output
        DEFAULT = "\033[0m"
        BLUE = "\033[34m"
        GREEN = "\033[92m"
        YELLOW = "\033[33m"
        RED = "\033[91m"

        # If the dev really wants to display with color, it can be forced with no_color at False
        if no_color is None:
            no_color = cls.NO_COLOR

        if no_color:
            print('\t'*level + msg + msg_default)

        else:
            if type == "default":
                print(DEFAULT + '\t'*level + msg)
            if type == "info":
                print(BLUE + '\t'*level + msg + DEFAULT + msg_default)
            if type == "good":
                print(GREEN + '\t'*level + msg + DEFAULT + msg_default)
            if type == "warning":
                print(YELLOW + '\t'*level + msg + DEFAULT + msg_default)
            if type == "alert" :
                print(RED + '\t'*level + msg + DEFAULT + msg_default)

class TempDir:

    tmp_dir_list = []

    @classmethod
    def create(cls):
        while True:
            random_dir_name = ''.join(random.choice(string.ascii_uppercase) for _ in range(5))
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
            Log.print_cms("alert", "Deleting tmp directories !", "", 0)
            cls.delete_all()

        elif clear_tmp_dir == "yes":
            dir_list_str = ""
            for tmp_dir in cls.tmp_dir_list:
                dir_list_str = dir_list_str + "\n" + tmp_dir

            Log.print_cms("info", "Keeping tmp directories ! Here they are :" + dir_list_str, "", 0)

        else:
            cls.ask_delete_tmp()

#!/usr/bin/env python3

import os
import sys
import random
import string
import requests
import datetime
import argparse
import tempfile

from bs4 import BeautifulSoup

debug = True
quiet = False

def log_debug(msg):
    global debug
    if debug and not quiet:
        time = datetime.datetime.now()
        print("{}: {}".format(time, msg))

def parse_args():
    parser = argparse.ArgumentParser(description="CoMisSion analyse a CMS \
    and plugins used.")
    parser.add_argument("-d", "--dir", dest="DIR", help="CMS root directory",
                        required=True)
    parser.add_argument("-c", "--cms", dest="CMS", help="CMS type (drupal, wordpress)",
                        required=True)
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
    args = parser.parse_args()
    return args

def verify_path(dir_path, to_check):
    for directory in to_check:
        if not os.path.exists(os.path.join(dir_path, directory)):
            print_cms("alert", "[-] The path provided does not seem to be a " \
                        "CMS directory. Please check the path !", "", 0)
            sys.exit()

def fetch_addons(input):
    if not os.path.exists(input):
        print_cms("alert", "Plugins path does not exist !", "", 0)
        exit(-1)
    plugins_name = next(os.walk(input))[1]
    return plugins_name

def create_temp_directory():
    while True:
        random_dir_name = ''.join(random.choice(string.ascii_uppercase) for _ in range(5))
        temp_directory = os.path.join(tempfile.gettempdir(), random_dir_name)
        if not os.path.exists(temp_directory):
            os.makedirs(temp_directory)
            break
    return temp_directory

def diff_files(dcmp, alterations, target):
    for name in dcmp.diff_files:
        alteration = {"status":"todo","target":"", "file":"", "type":""}
        altered_file = os.path.join(target, name)
        print_cms("alert", altered_file, " was altered !", 1)
        alteration["target"] = target
        alteration["file"] = name
        alteration["type"] = "altered"

        alterations.append(alteration)

    for name in dcmp.right_only:
        alteration = {"status":"todo","target":"", "file":"", "type":""}
        altered_file = os.path.join(target, name)
        print_cms("warning", altered_file, " has been added !", 1)
        alteration["target"] = target
        alteration["file"] = name
        alteration["type"] = "added"

        alterations.append(alteration)

    for name in dcmp.left_only:
        alteration = {"status":"todo","target":"", "file":"", "type":""}
        altered_file = os.path.join(target, name)
        print_cms("warning", altered_file, " deleted !", 1)
        alteration["target"] = target
        alteration["file"] = name
        alteration["type"] = "deleted"

        alterations.append(alteration)

    for current_dir, sub_dcmp in zip(dcmp.subdirs.keys(), dcmp.subdirs.values()):
        current_target = os.path.join(target, current_dir)
        diff_files(sub_dcmp, alterations, current_target)

def print_cms(type, msg, msg_default, level):

    # Define color for output
    DEFAULT = "\033[0m"
    BLUE = "\033[34m"
    GREEN = "\033[92m"
    YELLOW = "\033[33m"
    RED = "\033[91m"

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

def get_poc(url):
    r = requests.get(url)
    soup = BeautifulSoup(r.text, "lxml")
    return [el.get_text() for el in soup.findAll("pre", { "class":"poc"})]

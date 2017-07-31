#!/usr/bin/env python3

import os
import random
import string
import argparse
import tempfile

GREEN = "\033[92m"
BLUE = "\033[34m"
RED = "\033[91m"
YELLOW = "\033[33m"
DEFAULT = "\033[0m"


def log_debug(msg):
    global debug
    if debug and not quiet:
        time = datetime.datetime.now()
        print("{}: {}".format(time, msg))

def parse_args():
    parser = argparse.ArgumentParser(description='CoMisSion analyse a CMS \
    and plugins used.')
    parser.add_argument('-d', '--dir', dest='DIR', help='CMS root directory')
    parser.add_argument('-o', '--output', metavar="FILE", help='Path to output \
    file')
    args = parser.parse_args()
    return args

def verify_path(dir_path):
    to_check = ["wp-content", "wp-includes", "wp-admin"]

    for directory in to_check:
        if not os.path.exists(os.path.join(dir_path, directory)):
            print(RED + "[-] The path provided does not seem to be a wordpress "
                        "directory. Please check the path !"+ DEFAULT)
            sys.exit()

def fetch_plugins(input):
    plugin_dir = input + "wp-content/plugins/"
    if not os.path.exists(plugin_dir):
        print(RED + "Plugins path does not exist !" + DEFAULT)
        exit(-1)
    plugins_name = next(os.walk(plugin_dir))[1]
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
        alteration = {"target":"", "file":"", "status":""}
        print(RED + "\t" + name + DEFAULT + " was altered !")
        alteration["target"] = target
        alteration["file"] = name
        alteration["status"] = "altered"

        alterations.append(alteration)

    for name in dcmp.right_only:
        alteration = {"target":"", "file":"", "status":""}
        print(YELLOW + "\t" + name + DEFAULT + " not present in base wordpress !")
        alteration["target"] = target
        alteration["file"] = name
        alteration["status"] = "not present in base wordpress"

        alterations.append(alteration)

    for sub_dcmp in dcmp.subdirs.values():
        diff_files(sub_dcmp, alterations, target)

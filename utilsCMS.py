#!/usr/bin/env python3

import os
import sys
import random
import string
import datetime
import argparse
import tempfile

debug = True
quiet = False

def log_debug(msg):
    global debug
    if debug and not quiet:
        time = datetime.datetime.now()
        print("{}: {}".format(time, msg))

def parse_args():
    parser = argparse.ArgumentParser(description='CoMisSion analyse a CMS \
    and plugins used.')
    parser.add_argument('-d', '--dir', dest='DIR', help='CMS root directory')
    parser.add_argument('-c', '--cms', dest='CMS', help='CMS type (Drupal, WordPress)')
    parser.add_argument('-o', '--output', metavar="FILE", help='Path to output \
    file')
    args = parser.parse_args()
    return args

def verify_path(dir_path):
    to_check = ["wp-content", "wp-includes", "wp-admin"]

    for directory in to_check:
        if not os.path.exists(os.path.join(dir_path, directory)):
            print_cms("alert", "[-] The path provided does not seem to be a " \
                        "wordpress directory. Please check the path !", "", 0)
            sys.exit()

def fetch_plugins(input):
    plugin_dir = input + "/wp-content/plugins/"
    if not os.path.exists(plugin_dir):
        print_cms("alert", "Plugins path does not exist !", "", 0)
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
        #print(RED + "\t" + name + DEFAULT + " was altered !")
        print_cms("alert", name, " was altered !", 1)
        alteration["target"] = target
        alteration["file"] = name
        alteration["status"] = "altered"

        alterations.append(alteration)

    for name in dcmp.right_only:
        alteration = {"target":"", "file":"", "status":""}
        #print(YELLOW + "\t" + name + DEFAULT + " not present in base wordpress !")
        print_cms("warning", name, " not present in base wordpress !", 1)
        alteration["target"] = target
        alteration["file"] = name
        alteration["status"] = "not present in base wordpress"

        alterations.append(alteration)

    for sub_dcmp in dcmp.subdirs.values():
        diff_files(sub_dcmp, alterations, target)

def print_cms(type, msg, msg_default, level):

    # Define color for output
    DEFAULT = "\033[0m"
    BLUE = "\033[34m"
    GREEN = "\033[92m"
    YELLOW = "\033[33m"
    RED = "\033[91m"

    if type == "default":
        print(DEFAULT + '\t'*level +  msg)
    if type == "info":
        print(BLUE + '\t'*level +  msg + DEFAULT + msg_default)
    if type == "good":
        print(GREEN + '\t'*level +  msg + DEFAULT + msg_default)
    if type == "warning":
        print(YELLOW + '\t'*level +  msg + DEFAULT + msg_default)
    if type == "alert" :
        print(RED + '\t'*level +  msg + DEFAULT + msg_default)

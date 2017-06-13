import argparse
import os
import random
import re
import shutil
import string
import tempfile
import urllib.request
import zipfile

from checksumdir import dirhash

parser = argparse.ArgumentParser(description='Plugins Checker checks plugins in the directory dir.')
parser.add_argument('DIR', nargs=1, help='Plugins directory')
parser.add_argument('-o', '--output', metavar="FILE", help='Path to output file')
args = parser.parse_args()

if args.output:
    output_file = open(args.output, 'w')
else:
    output_file = None

plugins_dir_path = args.DIR[0]
if not os.path.exists(plugins_dir_path):
    print("Plugins path does not exist")
    exit(-1)
plugins_name = next(os.walk(plugins_dir_path))[1]

while True:
    random_dir_name = ''.join(random.choice(string.ascii_uppercase) for _ in range(5))
    temp_directory = os.path.join(tempfile.gettempdir(), random_dir_name)
    if not os.path.exists(temp_directory):
        os.makedirs(temp_directory)
        break
version_file_regexp = re.compile("version: '(.+?)'")
version_web_regexp = re.compile("<h2><a href=\"(.*?)\">(.+?) (.+?)</a></h2>")

print("Plugins:")
for plugin_name in plugins_name:
    with open(os.path.join(plugins_dir_path, plugin_name, plugin_name + ".info.yml")) as plugin_info:
        version = ''
        for line in plugin_info:
            version = version_file_regexp.search(line)
            if version:
                version = version.group(1)
                break
        else:
            print("     Error can't find version for plugin: " + plugin_name)
            continue

    plugin_url = "https://ftp.drupal.org/files/projects/{}-{}.zip".format(plugin_name, version)
    compressed_plugin = urllib.request.urlretrieve(plugin_url)
    zip_file = zipfile.ZipFile(compressed_plugin[0], 'r')
    zip_file.extractall(temp_directory)
    zip_file.close()
    os.remove(compressed_plugin[0])
    project_dir_hash = dirhash(os.path.join(plugins_dir_path, plugin_name), 'sha1')
    ref_dir_hash = dirhash(os.path.join(temp_directory, plugin_name), 'sha1')

    # Check plugin version
    releases_url = "https://www.drupal.org/project/{}/releases".format(plugin_name)
    response = urllib.request.urlopen(releases_url)
    last_version = "Not found"
    if response.status == 200:
        page = response.read().decode('utf-8')
        last_version_result =version_web_regexp.search(page)
        if version_web_regexp:
            last_version = last_version_result.groups()[2]
            if last_version == version:
                last_version = "Up to date"
            else:
                last_version = "Outdated, last version: " + last_version + "; check " + releases_url

    output = "{}:\n   Version: {} ({})\n   Different from sources: {}".format(plugin_name, version, last_version, "NO" if project_dir_hash == ref_dir_hash else "YES")
    print(output)
    if output_file:
        print(output, file=output_file)

shutil.rmtree(temp_directory, ignore_errors=True)

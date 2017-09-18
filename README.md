# CoMisSion - WhiteBox CMS analysis

CoMisSion is a tool to quickly analyze a CMS setup. The tool:
- checks for the core version;
- checks for modifications made on the core (additions, alterations, deletions) with a fresh archive downloaded from CMS official website;
- looks for the last core version;
- looks for vulnerabilities in core version used;
- checks for plugins and themes version;
- checks for modifications made on each plugin and each theme (additions, alterations, deletions) with a fresh archive downloaded from CMS official website;
- looks for vulnerabilities in plugins and themes version used.

:fire: Attention: CoMisSion is not looking for vulnerabilities by analysing the source code. Vulnerabilities are gathered from public databases like wpvulndb. Finding new vulnerabilities is not the purpose of this tool.


A complete report can be generated in following format:
- XLSX
- CSV
- JSON (to allow the tool to be used in a CI process)

The tool has been tested on Linux only. Colored output plus some other things should not work. Feel free to provide feedback on this topic if you try :).


## Example

```
./commision.py -c wordpress -d /cms_dir -o report.xlsx -t XLSX
```

## Installation

```
git clone https://github.com/Intrinsec/comission
pip install -r requirements.txt
```

## Usage

```
usage: comission.py [-h] -d DIR -c CMS [-o FILE] [-t TYPE] [--skip-core] [--skip-plugins]
                    [--skip-themes] [-f CONF]

  -h, --help              show this help message and exit
  -d DIR, --dir DIR       CMS root directory
  -c CMS, --cms CMS       CMS type (drupal, wordpress)
  -o FILE, --output FILE  Path to output file
  -t TYPE, --type TYPE    Type of output file (CSV, XLSX, JSON). Default to XLSX.
  --skip-core             Set this to skip core analysis
  --skip-plugins          Set this to skip plugins analysis
  --skip-themes           Set this to skip themes analysis
  -f CONF, --file CONF  Configuration file. See example.conf.
```

You can provide a configuration file. See `example.conf` for reference.

## CMS supported

* Wordpress
* Drupal (no vulnerability checks)


## Docker

We are not publishing any official image yet.
To use the tool with docker, you can build an image. In the project folder, build with:

```
docker build -t isec/comission .
```

Then run it with :

```
docker run -it --rm -v /TARGET_PATH/:/cms_path/ -v /OUTPUT_DIR/:/output/ isec/comission -d /cms_path/ -c drupal -o /output/test_docker.xlsx -t XLSX
```
Be careful to change the path "TARGET_PATH" and "OUTPUT_DIR" to match your folders.

## Author

**Paul Mars** (Intrinsec)

Based on an idea of **Etienne Boursier** (Intrinsec)


## Copyright - License - WPVULNDB

This tools is distributed under the GPLv3 license. But be careful, the tool uses the [wpvulndb API](https://wpvulndb.com/api) to gather information on WordPress core and plugins.

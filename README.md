# CoMisSion - WhiteBox CMS analysis

CoMisSion is a tool to quickly analyze a CMS setup. The tool:
- checks for the core version;
- checks for modifications made on the core (additions, alterations, deletions) with a fresh archive downloaded from CMS official website;
- looks for the last core version;
- looks for vulnerabilities in core version used (WordPress only);
- checks for plugins and themes version;
- checks for modifications made on each plugin and each theme (additions, alterations, deletions) with a fresh archive downloaded from CMS official website;
- looks for vulnerabilities in plugins and themes version used.

:fire: Attention: CoMisSion is not looking for vulnerabilities by analysing the source code. Vulnerabilities are gathered from public databases like wpvulndb. Finding new vulnerabilities is **not** the purpose of this tool.


A complete report can be generated in following formats:
- XLSX
- CSV
- JSON (to allow the tool to be used in a CI process)

The tool has been tested on Linux and Windows. To avoid output pollution, I recommend setting `--no-color` option on Windows.


## Example

```
./commision.py -c wordpress -d /cms_dir -o report.xlsx -t XLSX
```

## Installation

The tool needs at least python3.6.

```
git clone https://github.com/Intrinsec/comission
pip install -r requirements.txt
```

## Usage

```
usage: comission.py [-h] -d DIR -c CMS [-o FILE] [-t TYPE] [--skip-core]
                    [--skip-plugins] [--skip-themes] [--no-color] [-f CONF]
                    [--log LOGFILE] [--wp-content WP_CONTENT]
                    [--plugins-dir PLUGINS_DIR] [--themes-dir THEMES_DIR]
                    [--major VERSION_MAJOR] [-v VERSION]
                    [--wpvulndb-token WPVULNDB_TOKEN] [--debug]

CoMisSion analyse a CMS and plugins used.

optional arguments:
  -h, --help            show this help message and exit
  -d DIR, --dir DIR     CMS root directory
  -c CMS, --cms CMS     CMS type (drupal, wordpress)
  -o FILE, --output FILE
                        Path to output file
  -t TYPE, --type TYPE  Type of output (CSV, XLSX, JSON, STDOUT). Default to
                        XLSX.
  --skip-core           Set this to skip core analysis
  --skip-plugins        Set this to skip plugins analysis
  --skip-themes         Set this to skip themes analysis
  --no-color            Do not use colors in the output.
  -f CONF, --file CONF  Configuration file. See example.conf.
  --log LOGFILE         Log output in given file.
  --wp-content WP_CONTENT
                        Set this to force the wp-content directory location.
  --plugins-dir PLUGINS_DIR
                        Set this to force the plugins directory location.
  --themes-dir THEMES_DIR
                        Set this to force the themes directory location.
  --major VERSION_MAJOR
                        Specify the core major version (eg. 7, 8) when using
                        --skip-core arg. Works only for Drupal.
  -v VERSION, --version VERSION
                        Specify the core full version (eg. 5.5).
  --wpvulndb-token WPVULNDB_TOKEN
                        Set a token to request wpvulndb API.
  --debug               Print debug message to help identify errors.
```

:fire: In order to get vulnerabilities for WordPress, you have to set the `--wpvulndb_token` arg. You can get one token with an account on [wpvulndb](https://wpvulndb.com/).

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

## Tests

Unit tests are available in `tests` folder. Before launching test, you should create a `test-data-set` directory containing `drupal` and `wordpress` subdirectories, and a `test.conf` file containing at least a `wpvulndb_token` value.


## Author

**Paul Mars** (Intrinsec)

Based on an idea of **Etienne Boursier** (Intrinsec)


## Copyright - License - WPVULNDB

This tools is distributed under the GPLv3 license. But be careful, the tool uses the [wpvulndb API](https://wpvulndb.com/api) to gather information on WordPress core and plugins.

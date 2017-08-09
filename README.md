# CoMisSion - WhiteBox CMS analysis

CoMisSion is a tool to quickly analyse a CMS installation. The tool:
- checks for the core version;
- looks for the last core version;
- looks for vulnerabilities in core version used;
- checks for plugins version;
- looks for vulnerabilities in plugins version used;

A XLSX report can be generated.

## Example

```
./commision.py -c wordpress -d cms_dir -o comission_report.xlsx
```

## Installation

```
git clone https://github.com/Intrinsec/comission
pip install -r requirements.txt
```

## Usage

usage: comission.py [-h] -d DIR -c CMS [-o FILE]

  -h, --help              show this help message and exit
  -d DIR, --dir DIR       CMS root directory
  -c CMS, --cms CMS       CMS type (Drupal, WordPress)
  -o FILE, --output FILE  Path to output file

## CMS supported

* Wordpress
* Drupal

## Docker

We are not publishing any official image yet.
To use the tool with docker, you can build an image. In the project folder, build with:

```
docker build -t isec/comission .
```

Then run it with :

```
docker run -it --rm -v /TARGET_PATH/:/cms_path/ -v /OUTPUT_DIR/:/output/ isec/comission -d /cms_path/ -c drupal -o /output/test_docker.xlsx
```

### Copyright and License

## WPVULNDB
The tool uses the [wpvulndb API](https://wpvulndb.com/api) to gather information on WordPress core and plugins.

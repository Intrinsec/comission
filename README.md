# CoMisSion - WhiteBox CMS analysis

CoMisSion is a tool to quickly analyse a wordpress installation. The tool :
- checks for the core version;
- look for the last core version;
- look for vulnerabilities in core version used;
- checks for plugins version;
- look for vulnerabilities in plugins version used;

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

## Arguments

    -d | --dir        CMS root directory
    -c | --cms        CMS type (Drupal, WordPress)
    -o | --output     Path to output file

## CMS supported

* Wordpress
* Drupal

## Docker

We are not publishing any official image yet.
To use the tool with docker, you can build an image with :

```
docker build -t intrinsec/comission .
```

Then run it with :

```
docker run -it --rm -v /TARGET_PATH/:/cms_path/ -v /OUTPUT_DIR/:/output/ intrinsec/comission -d /cms_path/ -c drupal -o /output/test_docker.xlsx
```

### Copyright and License

## WPVULNDB
The tool uses the [wpvulndb API](https://wpvulndb.com/api) to gather information on WordPress core and plugins.

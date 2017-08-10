#!/bin/bash

docker build -t isec/comission .
docker run -it --rm -v /root/wpchecker-test-data/:/cms_path/ -v /root/:/output/ isec/comission -d /cms_path/ -c wordpress -o /output/test.xlsx

#!/bin/bash

docker build -t isec/comission .
docker run -it --rm -v /root/projets/CMS_Checker/test-data-set/wordpress:/cms_path/ -v /root/projets/CMS_Checker/:/output/ isec/comission -d /cms_path/ -c wordpress -o /output/test.json

#!/bin/bash

docker build -t intrinsec/comission .
docker run -it --rm -v /root/wpchecker-test-data/:/cms_path intrinsec/comission -d /cms_path

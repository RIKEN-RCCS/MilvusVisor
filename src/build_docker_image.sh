#!/bin/bash

# Copyright (c) 2022 RIKEN
# All rights reserved.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

IMG_NAME="rust-build-thin-hypervisor" 
timestamp=$(date +%Y%m%d_%H%M%S) 

docker build -f Dockerfile -t "${IMG_NAME}:${timestamp}" . \
	&& docker tag "${IMG_NAME}:${timestamp}" "${IMG_NAME}:latest"

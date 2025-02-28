#!/bin/bash
 
# Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
# All rights reserved.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

BUILD_CMDLINE="cd /workspace && cargo xtask build $@"

docker run -it --rm -v ${PWD}:/workspace rust:latest /bin/bash -c "${BUILD_CMDLINE}"

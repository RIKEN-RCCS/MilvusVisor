 #!/bin/bash
 
# Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
# All rights reserved.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

BUILD_CMDLINE="rustup default nightly && rustup component add rust-src && cd /workspace && make $@"

docker run -it --rm -v ${PWD}:/workspace rust:latest /bin/bash -c "${BUILD_CMDLINE}"

#!/bin/bash

# Copyright (c) 2022 RIKEN
# All rights reserved.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

cd $(dirname $0)
PWD="$(pwd)"
CONTAINER_NAME="rust-build-thin-hypervisor"
IMG_NAME="rust-build-thin-hypervisor"

do_clean=false

while (( $# > 0 ))
do
    case $1 in
        --clean)
            do_clean=true
            ;;
        *)
            echo "Unknow argument"
            exit 1
            ;;
    esac
    shift 1
done

build_cmdline='cd /workspace && make'
if $do_clean; then
    build_cmdline="${build_cmdline} clean"
fi

docker run -it --rm --name ${CONTAINER_NAME} \
       -v ${PWD}:/workspace \
       ${IMG_NAME}:latest \
       bash -c "${build_cmdline}"

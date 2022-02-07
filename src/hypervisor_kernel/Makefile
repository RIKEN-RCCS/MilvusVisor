# Copyright (c) 2022 RIKEN
# All rights reserved.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

NAME = hypervisor_kernel
TARGET = aarch64-none
TARGET_JSON = config/$(TARGET).json

CARGO = cargo


all:  .FORCE
	$(CARGO) xbuild --release --target $(TARGET_JSON)

clean:
	$(CARGO) clean

fmt:
	$(CARGO) fmt

default:
	$(MAKE) all

.FORCE:

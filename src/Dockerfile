# Copyright (c) 2022 RIKEN
# All rights reserved.
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

FROM rust:latest

RUN rustup default nightly \
	&&  rustup component add rust-src
RUN rustup update
RUN apt-get update && apt-get install -y \
  build-essential make \
  && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-xbuild

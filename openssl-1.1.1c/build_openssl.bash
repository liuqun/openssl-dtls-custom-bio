#!/bin/bash

PREFIX=`pwd`
build_dir=build

if [ ! -d "$build_dir" ] ; then
  ./download_openssl.bash
fi

if [ -d "$build_dir" ] ; then
  pushd $build_dir
  ./config enable-sm2 enable-sm3 enable-sm4 --prefix="$PREFIX" \
    && make \
    && make install_dev \
    && echo "OpenSSL build OK!"
  popd
fi

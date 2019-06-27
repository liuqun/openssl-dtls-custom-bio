#!/bin/bash

tarball_version="1.1.1c"
tarball_filename="openssl-$tarball_version.tar.gz"
download_from_url="https://www.openssl.org/source/$tarball_filename"
wget --continue $download_from_url
if ! sha256sum -c SHA256SUM.txt ; then
  echo "OpenSSL源码包 $tarball_filename 下载失败, 请重新下载!"
  exit 255
fi

build_dir=build
if [ ! -d "$build_dir" ] ; then
  tar xf $tarball_filename
  mv "openssl-$tarball_version" "$build_dir"
  echo "已解压到 $build_dir 目录"
fi

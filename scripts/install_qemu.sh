#!/bin/bash

wget https://download.qemu.org/qemu-4.1.0.tar.xz -O /tmp/

tar xaf /tmp/qemu-4.1.0.tar.xz

apt-get install libglib2.0-dev libpixman-1-dev -y

cd /tmp/qemu-4.1.0/
./configure --target-list=sparc-softmmu --enable-debug
make install
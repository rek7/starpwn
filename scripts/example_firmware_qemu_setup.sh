#!/bin/bash

# Modified from https://github.com/solar-wine/tools-for-hack-a-sat-2020/blob/master/qemu-vm/launch-qemu.sh
qemu-system-sparc -no-reboot -nographic -M leon3_generic -m 512M \
    -monitor "unix:./monitor.sock,server,nowait" \
    -serial stdio \
    -serial "unix:./radio.sock,server,nowait" \
    -serial "unix:./atmega.sock,server,nowait" \
    -kernel ../example_firmware/firmware1.prom \
    || exit $?
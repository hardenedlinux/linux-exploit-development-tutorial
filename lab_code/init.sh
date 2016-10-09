#!/bin/bash

su root -c 'echo 0 > /proc/sys/kernel/randomize_va_space'
su root -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'
ulimit -c unlimited


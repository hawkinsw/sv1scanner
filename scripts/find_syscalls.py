#!/usr/bin/env python

#   Copyright (c) 2016-2018 Red Hat.
#
#   This is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published
#   by the Free Software Foundation; either version 3, or (at your
#   option) any later version.
#
#   It is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.  */
#
# Written by Mark Salter.

# This is a simple python script for finding the syscall entry
# points to an AArch64 kernel.  To use it pass in the output
# of disassembling the kernel, like this:
#
#  aarch64-linux-gnu-objdump -d vmlinux | find_syscalls.py 

import sys
import re

syscall_re = re.compile(r'^([0-9a-f]+) <SyS_([A-Za-z0-9_]+)>:$')

for line in sys.stdin:
    m = syscall_re.match(line)
    if m:
        print('{} @ {}'.format(m.group(2), m.group(1)))

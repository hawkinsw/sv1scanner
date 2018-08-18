#!/bin/bash

if [[ $# != 1 ]] || [[ ! -e $1 ]]; then
	echo missing 'vmlinux' arg
	exit 1
fi

vmlinux=$1

while read line; do
	addr=${line/ */}
	name=${line/* /}
	echo $addr $name:
	~/omega-scanner/x86_64-scanner --start-address=$addr --variant=7 vmlinux
	echo
done < <(gdb --batch --ex="set print elements 0" --ex="set print array on" --ex="print sys_call_table" --ex="print ia32_sys_call_table" vmlinux |sed 's/^.*{//; s/^  //; s/<//; s/>.*//' | sort -n | uniq)

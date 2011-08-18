#!/bin/bash
# quick hack to check which tools are missing from manpage

man_tools_=""
tainted_man_tools_=$(grep '^.B ' debian/thc-ipv6.8 |awk '{print $2}' |sort)
for i in $tainted_man_tools_; do
    test -f ${i} && man_tools_="$man_tools_ $i"
done

for i in `find -maxdepth 1 -perm '-u=x' -type f -printf '%f\n' |sort`; do
    found_="false"
    for j in $man_tools_; do
        if [[ $i == $j ]]; then found_="true"; break; fi
    done
    if [[ $found_ == "false" ]]; then
        echo $i
    fi
done

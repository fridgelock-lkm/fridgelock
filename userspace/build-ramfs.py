#!/usr/bin/env python3

import os
import subprocess
import re

#LDD_RE = re.compile(b"=> (.*) \(")
LDD_RE = re.compile(b"\W(/[\w/.\\-]*) ")

bins = "cryptsetup bash strace"
def run(cmd):
    print("+ " + cmd)
    subprocess.check_call(cmd, shell=True)

run("mkdir -p ramfs/usr/bin ramfs/usr/lib ramfs/sys ramfs/proc ramfs/dev ramfs/run")

# Change into ramfs dir
os.chdir("ramfs")
run("ln -s usr/bin")

bins = bins.split(" ")

def my_whereis(bin):
    for c in os.environ["PATH"].split(":"):
        candidate = c + "/" + bin
        if os.path.exists(candidate):
            return candidate

def get_deps(bin):
    deps_str = subprocess.check_output("ldd {}".format(bin), shell=True)
    deps = []
    for l in deps_str.split(b"\n"):
        m = LDD_RE.search(l)
        if m:
            deps.append(m.group(1).decode())
    return deps

for b in bins:
    p = my_whereis(b)
    print(p)
    target = os.path.basename(p)
    run("cp {} bin/{}".format(p, target))

    deps = get_deps(p)
    for d in deps:
        target = os.path.dirname(d)[1:]
        run("mkdir -p {}".format(target))
        run("cp {} {}".format(d, target))

run("cp /usr/lib/libgcc_s.so usr/lib/")
run("cp /usr/lib/libgcc_s.so.1 usr/lib/")

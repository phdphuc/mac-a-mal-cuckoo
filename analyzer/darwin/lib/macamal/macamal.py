#!/usr/bin/env python
# Copyright (C) 2017 Phamous
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import os
import json
from getpass import getuser
from collections import namedtuple
from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile
import time,re
from common import *
import shlex
import logging
log = logging.getLogger(__name__)
syscall = namedtuple("syscall", "name args result errno timestamp pid")
apicall = namedtuple("apicall", "api args retval timestamp pid ppid tid errno procname uid")

def macamal(target, **kwargs):
    """Returns a list of syscalls made by a target.

    Every syscall is a named tuple with the following properties:
    name (string), args (list), result (int), errno (int),
    timestamp(int) and pid(int).
    """

    #grey-cuckoo: timeout (seconds); Notice: We need extra time to obtain log and send back to host.
    timeout = str(int(kwargs.get("gctimeout", 120)))
    log.warning("timeout: %s", timeout)

    if not target:
        raise Exception("Invalid target")

    output_file = NamedTemporaryFile()

    if "runas" in kwargs:
        runas = kwargs["runas"]
    else:
        runas = False
    log.warning("sudo /tmp/grey-cuckoo /usr/bin/open %s %s", timeout, output_file.name)
    if "args" in kwargs:
        target_cmd = "\"%s\" %s" % (target, " ".join(kwargs["args"]))
    else:
        target_cmd = target
    
    target_cmd = target_cmd.strip()
    target = target.strip()

    if target.endswith('.app') or target.endswith('.docx') or target.endswith('.doc') or target.endswith('.dmg') or target.endswith('.pkg'):
        p1 = Popen(["sudo", "/tmp/grey-cuckoo","/usr/bin/open", timeout, output_file.name], cwd=current_directory(), stdout=PIPE )
    elif target.endswith('.pl'):
        p1 = Popen(["sudo", "/tmp/grey-cuckoo","/usr/bin/perl", timeout, output_file.name], cwd=current_directory(), stdout=PIPE )
    elif target.endswith('.jar'):
        p1 = Popen(["sudo", "/tmp/grey-cuckoo","/usr/bin/java", timeout, output_file.name], cwd=current_directory(), stdout=PIPE )
    else:
        p1 = Popen(["sudo", "/tmp/grey-cuckoo",target, timeout, output_file.name], cwd=current_directory(), stdout=PIPE )
    #Wait for p1 initialization
    time.sleep(2)
    log.warning("target_cmd: %s ; target: %s; shlex: %s", target_cmd, target, shlex.split(target_cmd))
    if runas:
        #Set the whole running directory for executable
        parentdir = os.path.dirname(target)
        if parentdir!="/tmp" and parentdir!="/tmp/" and parentdir.startswith('/usr'):
            Popen(["chown", "-R", runas+":"+runas, parentdir], cwd=current_directory())
            print "Chown parent!"
        Popen(["chown", "-R", runas+":"+runas, target], cwd=current_directory())
        print "Chown target!"
        if target.endswith('.pl'):
            #This one is quick dirty. perl / python / .. must be handled in package class instead.
            p2 = Popen(["sudo", "-u", runas, "perl", target], cwd=current_directory())  
        elif target == '/usr/bin/python':
            p2 = Popen(("sudo -u " + runas +" "+ target_cmd.replace('"/usr/bin/python"', '/usr/bin/python')).split(), cwd=current_directory())
        elif target == '/usr/bin/java':
            p2 = Popen(("sudo -u " + runas +" "+ target_cmd.replace('"/usr/bin/java"', '/usr/bin/java')).split(), cwd=current_directory())
        elif target == '/bin/bash':
            p2 = Popen(("sudo -u " + runas +" "+ target_cmd.replace('"/bin/bash"', '/bin/bash')).split(), cwd=current_directory())
        else:
            p2 = Popen(["sudo", "-u", runas, "open", target], cwd=current_directory())

    else:
        if target.endswith('.pl'):
            p2 = Popen([ "perl", target_cmd], cwd=current_directory())    
        elif target.endswith('.jar'):
            p2 = Popen((target_cmd.replace('"/usr/bin/java"', '/usr/bin/java')).split(), cwd=current_directory(), stdout=subprocess.PIPE)
        else:
            p2 = Popen([ "open", target_cmd], cwd=current_directory()) # Open sandbox drops root priv. to normal user priv.
            # p2 = Popen([target], cwd=current_directory())

    p1.communicate()
    for entry in output_file.read().split("{\"sc\":"):
        value = "{\"sc\":"+unicode(entry.strip(), errors='replace')
        if len(value) == 0:
            continue
        syscall = _parse_syscall(value)
        if syscall is None:
            continue
        yield syscall
    output_file.close()

#
# Parsing implementation details
#

def _parse_syscall(string):
    regex = r'\\(?!\")'
    string = re.sub(regex, r'\\\\', string)
    string = string.replace("\\0", "").replace("\n", "\\n").replace("\t", "\\t").replace('{"sc":{"sc"','{"sc"')
    if "\\nSTOP!" in string:
        string = string[:string.find("\\nSTOP")]
    try:
        parsed = json.loads(string,strict=False)
        name = parsed["sc"].replace("SYS_", "")
        args = parsed["a"]
        result = parsed["r"]
        ppid = parsed["pp"]
        pid = parsed["p"]
        timestamp = parsed["t"]
        uid = parsed["u"]
        procname = parsed["pn"]
        tid=0
        errno=0
        if pid == None : print parsed, string
        return apicall(api=name, args=args, retval=result, timestamp=timestamp, pid=pid, uid=uid, ppid=ppid, tid=0, errno=0, procname=procname)
    except Exception as e:
        # print e,string
        return None
    
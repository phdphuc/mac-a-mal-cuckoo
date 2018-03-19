#!/usr/bin/env python
# Copyright (C) 2018 phdphuc
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import logging
from shutil import move
from os import path, environ
from random import SystemRandom
from string import ascii_letters
from subprocess import check_output
from zipfile import ZipFile, BadZipfile
from lib.core.packages import Package, choose_package_class
from subprocess import Popen, PIPE
import glob
import time
log = logging.getLogger(__name__)

def current_directory():
    return path.dirname(path.abspath(__file__))

class Dmg(Package):

    real_package = None

    def prepare(self):
        password = self.options.get("password")
        files = self._extract(self.target, password)
        if not files or len(files) == 0:
            raise Exception("Invalid (or empty) DMG %s" % self.target)
        # Look for a file to analyse
        target_name = self.options.get("file")
        if not target_name:
            # If no file name is provided via option, take the first file
            target_name = files[0]
            log.debug("Missing file option, auto executing: %s", target_name)
        else:
            for file in files:
                if target_name in file:
                    target_name = file

        # Remove the trailing slash (if any)
        if target_name.endswith("/"):
            self.target = target_name[:-1]
        else:
            self.target = target_name

        # Since we don't know what kind of file we're going to analyse, let's
        # detect it automatically and create an appropriate analysis package
        # for this file
        file_info = _fileinfo(self.target)
        pkg_class = choose_package_class(file_info, target_name)

        if not pkg_class:
            raise Exception("Unable to detect analysis package for the file %s" % target_name)
        else:
            log.debug("Analysing file \"%s\" using package \"%s\"", target_name, pkg_class.__name__)

        kwargs = {
            "options" : self.options,
            "timeout" : self.timeout
        }
        # We'll forward start() method invocation to the proper package later
        self.real_package = pkg_class(self.target, self.host, **kwargs)

    def start(self):
        # We have nothing to do here; let the proper package do it's job
        self.prepare()
        if not self.real_package:
            raise Exception("Invalid analysis package, aborting")
        self.real_package.start()

    def _extract(self, filename, password):
     
        # Extraction.
        extract_path = environ.get("TEMP", "/tmp")
        filepath = path.join(extract_path, filename+".bar")
        mountpoint = path.join(extract_path, "mountpoint")
        print extract_path, filepath, mountpoint

        p1 = Popen(["/usr/bin/hdiutil", "convert","-quiet", filename, "-format", "UDTO", "-o",  filepath], cwd=current_directory(), stdout=PIPE )
        p1.communicate()

        p2 = Popen(["/usr/bin/hdiutil", "attach","-quiet", "-nobrowse", "-noverify", "-noautoopen", "-mountpoint", mountpoint, filepath+".cdr"], cwd=current_directory(), stdout=PIPE )
        p2.communicate()

        return glob.glob(mountpoint + '/*.app') + glob.glob(mountpoint + '/*.dmg')


def _fileinfo(target):
    raw = check_output(["file", target])
    # The utility has the following output format: "%filename%: %description%",
    # so we just skip everything before the actual description
    return raw[raw.index(":")+2:]

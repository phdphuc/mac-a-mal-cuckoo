#!/usr/bin/env python
# Copyright (C) 2018 phdphuc
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from os import system, path
from lib.core.packages import Package
from plistlib import readPlist


class App(Package):
    """ OS X application analysis package. """

    def prepare(self):
        system("/bin/chmod -R +x \"%s\"" % self.target)

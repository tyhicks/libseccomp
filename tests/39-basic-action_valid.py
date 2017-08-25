#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2017 Canonical Ltd.
# Author: Tyler Hicks <tyhicks@canonical.com>
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License as
# published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

import errno

import util

from seccomp import *

def test():
    set_attr(Attr.CTL_KCHECKACTS, 0)

    if action_valid(KILL) != 0:
        raise RuntimeError("Failed validating KILL")

    if action_valid(TRAP) != 0:
        raise RuntimeError("Failed validating TRAP")

    if action_valid(ERRNO(errno.EPERM)) != 0:
        raise RuntimeError("Failed validating ERRNO")

    if action_valid(TRACE(1234)) != 0:
        raise RuntimeError("Failed validating TRACE")

    if action_valid(LOG) != 0:
        raise RuntimeError("Failed validating LOG")

    if action_valid(ALLOW) != 0:
        raise RuntimeError("Failed validating ALLOW")

    # Negative test by attempting to check an invalid action. There may be a
    # time in the future when KILL + 1 is valid and this test will fail. Until
    # then, it is good test for action_valid().
    try:
        action_valid(KILL + 1)
    except ValueError:
        pass
    else:
        raise RuntimeError("Failed invalidating (KILL + 1)")

test()

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;

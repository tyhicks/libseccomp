/**
 * Seccomp Library test program
 *
 * Copyright (c) 2017 Canonical Ltd.
 * Author: Tyler Hicks <tyhicks@canonical.com>
 */

/*
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses>.
 */

#include <errno.h>
#include <stdlib.h>

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc;

	rc = seccomp_attr_set(NULL, SCMP_GLBATR_CTL_KCHECKACTS, 0);
	if (rc != 0)
		goto out;

	rc = seccomp_action_valid(SCMP_ACT_KILL);
	if (rc != 0)
		goto out;

	rc = seccomp_action_valid(SCMP_ACT_TRAP);
	if (rc != 0)
		goto out;

	rc = seccomp_action_valid(SCMP_ACT_ERRNO(EPERM));
	if (rc != 0)
		goto out;

	rc = seccomp_action_valid(SCMP_ACT_TRACE(1234));
	if (rc != 0)
		goto out;

	rc = seccomp_action_valid(SCMP_ACT_LOG);
	if (rc != 0)
		goto out;

	rc = seccomp_action_valid(SCMP_ACT_ALLOW);
	if (rc != 0)
		goto out;

	/* Negative test by attempting to check an invalid action. There may be
	 * a time in the future when SCMP_ACT_KILL + 1 is valid and this test
	 * will fail. Until then, it is good test for seccomp_action_valid(). */
	rc = seccomp_action_valid(SCMP_ACT_KILL + 1);
	if (rc != -EINVAL)
		goto out;

	rc = 0;
out:
	return (rc < 0 ? -rc : rc);
}

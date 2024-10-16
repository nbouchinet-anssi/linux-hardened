// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Hardened sysctl tests
 */

#include "../kselftest_harness.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024)

static int open_or_die(const char *filename, int flags)
{
	int fd = open(filename, flags);

	if (fd < 0)
		ksft_exit_fail_msg("Failed to open '%s'; "
			"check prerequisites are available\n", filename);
	return fd;
}

static void check_user_id(int needed_uid)
{
	int actual_uid = getuid();
	if (actual_uid != needed_uid) {
		ksft_exit_fail_msg("invalid uid, got %i instead of %i", actual_uid, needed_uid);
	}
}

static int dummy(void *arg){
	return 0;
}

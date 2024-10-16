// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Hardened sysctl tests
 */

#include "../kselftest_harness.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/capability.h>
#include <linux/sched.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <asm/termbits.h>
#include <linux/limits.h>

#define STACK_SIZE (1024 * 1024)

static int open_or_die(const char *filename, int flags)
{
	int fd = open(filename, flags);

	if (fd < 0) {
		ksft_exit_fail_perror(filename);
	}
	return fd;
}

static void check_user_id(int needed_uid)
{
	int actual_uid = geteuid();
	if (actual_uid != needed_uid) {
		ksft_exit_fail_msg("invalid euid, got %i instead of %i", actual_uid, needed_uid);
	}
}

static pid_t clone3(struct clone_args *args, size_t size)
{
	fflush(stdout);
	fflush(stderr);
	return syscall(__NR_clone3, args, size);
}

static int drop_cap_sys_admin()
{
	cap_t caps = cap_get_proc();
	cap_value_t cap_list[CAP_LAST_CAP + 1];

	if (caps == NULL)
		return -1;

	cap_list[0] = CAP_SYS_ADMIN;
	if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_CLEAR) < 0) {
		cap_free(caps);
		return -1;
	}

	if (cap_set_proc(caps) < 0) {
		cap_free(caps);
		return -1;
	}

	cap_free(caps);
	return 0;
}

static int set_cap_sys_admin()
{
	cap_t caps = cap_get_proc();
	cap_value_t cap_list[CAP_LAST_CAP + 1];

	if (caps == NULL)
		return -1;

	cap_list[0] = CAP_SYS_ADMIN;
	if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) < 0) {
		cap_free(caps);
		return -1;
	}

	if (cap_set_proc(caps) < 0) {
		cap_free(caps);
		return -1;
	}

	cap_free(caps);
	return 0;
}

static int dummy(void *arg){
	return 0;
}

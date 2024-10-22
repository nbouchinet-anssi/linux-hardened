// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Hardened sysctl tests
 */

#include "common.h"
#define PROCFS_DIR "/proc/sys"

static int open_sysctl(struct __test_metadata *const _metadata, const char *const sysctl_path)
{
	const int fd = open_or_die(sysctl_path, O_RDWR);

	return fd;
}

static void close_sysctl_fd(struct __test_metadata *const _metadata, int fd)
{
	close(fd);
}

/*
 * Generic sysctl tests
 */

FIXTURE(sysctl) {
	int fd;
	char cur;
};

FIXTURE_VARIANT(sysctl) {
	char default_value;
	const char min;
	const char max;
	const char *const sysctl_path;
	bool sys_admin;
};

FIXTURE_VARIANT_ADD(sysctl, io_uring) {
	.sysctl_path = PROCFS_DIR "/kernel/io_uring_disabled",
	.default_value = '1',
	.min = '2',
	.max = '2',
};

FIXTURE_VARIANT_ADD(sysctl, unprivileged_userns_clone) {
	.sysctl_path = PROCFS_DIR "/kernel/unprivileged_userns_clone",
	.default_value = '0',
	.min = '0',
	.max = '1',
};

FIXTURE_VARIANT_ADD(sysctl, tcp_simult_connect) {
	.sysctl_path = PROCFS_DIR "/net/ipv4/tcp_simult_connect",
	.default_value = '0',
	.min = '0',
	.max = '1',
};

FIXTURE_VARIANT_ADD(sysctl, tiocsti_restrict) {
	.sysctl_path = PROCFS_DIR "/dev/tty/tiocsti_restrict",
	.default_value = '1',
	.min = '0',
	.max = '1',
	.sys_admin = 1,
};

FIXTURE_VARIANT_ADD(sysctl, device_sidechannel_restrict) {
	.sysctl_path = PROCFS_DIR "/fs/device_sidechannel_restrict",
	.default_value = '1',
	.min = '0',
	.max = '1',
	.sys_admin = 1,
};

FIXTURE_VARIANT_ADD(sysctl, deny_new_usb) {
	.sysctl_path = PROCFS_DIR "/kernel/deny_new_usb",
	.default_value = '0',
	.min = '0',
	.max = '1',
	.sys_admin = 1,
};

FIXTURE_SETUP(sysctl)
{
	check_user_id(0);
	self->fd = open_sysctl(_metadata, variant->sysctl_path);
	ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
	ASSERT_EQ(1, read(self->fd, &self->cur, 1));
}

FIXTURE_TEARDOWN(sysctl)
{
	close_sysctl_fd(_metadata, self->fd);
}

TEST_F(sysctl, file_exists)
{
	struct stat statbuf;

	ASSERT_EQ(0, stat(variant->sysctl_path, &statbuf));
}


TEST_F(sysctl, default_value)
{
	ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
	ASSERT_EQ(1, read(self->fd, &self->cur, 1));
	ASSERT_EQ(variant->default_value, self->cur);
}

TEST_F(sysctl, write_inc)
{
	if (variant->min < variant->max) {
		char cur = variant->min;
		while(cur++ < variant->max) {
			ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
			ASSERT_EQ(1, write(self->fd, &cur, 1));
			ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
			ASSERT_EQ(1, read(self->fd, &self->cur, 1));
			ASSERT_EQ(cur, self->cur);
		}
	}
}

TEST_F(sysctl, write_inc_oob)
{
	char cur = variant->max;
	while(cur++ <= variant->max) {
		ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
		ASSERT_EQ(-1, write(self->fd, &cur, 1));
		ASSERT_EQ(EINVAL, errno);
	}
}

TEST_F(sysctl, write_dec)
{
	if (variant->min < variant->max) {
		char cur = variant->max;
		while(cur-- > variant->min) {
			ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
			ASSERT_EQ(1, write(self->fd, &cur, 1));
			ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
			ASSERT_EQ(1, read(self->fd, &self->cur, 1));
			ASSERT_EQ(cur, self->cur);
		}
	}
}

TEST_F(sysctl, write_dec_oob)
{
	char cur = variant->min;
	while(cur-- >= variant->min) {
		ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
		ASSERT_EQ(-1, write(self->fd, &cur, 1));
		ASSERT_EQ(EINVAL, errno);
	}
}

TEST_F(sysctl, drop_cap)
{
	ASSERT_EQ(0, drop_cap_sys_admin());
	if (variant->min < variant->max) {
		char cur = variant->min;
		while (cur++ < variant->max) {
			ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
			if (variant->sys_admin) {
				ASSERT_EQ(-1, write(self->fd, &cur, 1));
				ASSERT_EQ(EPERM, errno);
			} else {
				ASSERT_EQ(1, write(self->fd, &cur, 1));
				ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
				ASSERT_EQ(1, read(self->fd, &self->cur, 1));
				ASSERT_EQ(cur, self->cur);
			}
		}
	}
	ASSERT_EQ(0, set_cap_sys_admin());
}

TEST_F(sysctl, drop_uid)
{
	ASSERT_EQ(0, setresuid(-1, 1000, -1));
	if (variant->min < variant->max) {
		char cur = variant->min;
		while(cur++ < variant->max) {
			ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
			ASSERT_EQ(-1, write(self->fd, &cur, 1));
			ASSERT_EQ(EPERM, errno);
		}
	}
	ASSERT_EQ(0, setresuid(-1, 0, -1));
}

 /*
 * Check if sysctl is effectively in its final state and can't be switched of anymore.
 * A sysctl is final if its min and max are equal and the default value differs.
 * Writing should result to a EINVAL errno.
 *
 * FIXME: Test should fail if sysctl can be set out of min..max scope, not only if min equals to max.
 */
TEST_F(sysctl, terminal_state)
{
	if (variant->min == variant->max && variant->default_value < variant->max) {
		char cur = self->cur;
		while(cur-- > variant->min) {
			ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
			ASSERT_EQ(-1, write(self->fd, &cur, 1));
			ASSERT_EQ(EINVAL, errno);
		}
	}
}

/*
 * Clone and unshare tests
 */

FIXTURE(unprivileged_userns_clone) {
	int fd;
	const char *sysctl_path;
	char cur;
	void *stack;
	void *stack_top;
};

FIXTURE_VARIANT(unprivileged_userns_clone) {
	char *authorized;
};

FIXTURE_VARIANT_ADD(unprivileged_userns_clone, disabled) {
	.authorized = "0",
};

FIXTURE_VARIANT_ADD(unprivileged_userns_clone, enabled) {
	.authorized = "1",
};

FIXTURE_SETUP(unprivileged_userns_clone)
{
	check_user_id(0);
	self->fd = open_sysctl(_metadata, PROCFS_DIR "/kernel/unprivileged_userns_clone");
	ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
	ASSERT_EQ(1, read(self->fd, &self->cur, 1));
	ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
	ASSERT_EQ(1, write(self->fd, variant->authorized, 1));

	/*
	 * Drop privileges
	 */
	ASSERT_EQ(0, setresuid(-1, 1000, -1));
	self->stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	ASSERT_NE(MAP_FAILED, self->stack);
	self->stack_top = self->stack + STACK_SIZE;
}

FIXTURE_TEARDOWN(unprivileged_userns_clone)
{
	ASSERT_EQ(0, munmap(self->stack, STACK_SIZE));
	ASSERT_EQ(0, setresuid(-1, 0, -1));
	ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
	ASSERT_EQ(1, write(self->fd, &self->cur, 1)); // Put sysctl back in its initial state.
	close_sysctl_fd(_metadata, self->fd);
}

TEST_F(unprivileged_userns_clone, clone)
{
	pid_t pid = clone(&dummy, self->stack_top, CLONE_NEWUSER | SIGCHLD | CLONE_FILES, 0);

	if (pid < 0) {
		if (atoi(variant->authorized))
			ksft_exit_fail_perror("clone");
		ASSERT_EQ(EPERM, errno);
	}
	ASSERT_EQ(pid, waitpid(pid, NULL, 0));
}

TEST_F(unprivileged_userns_clone, clone3)
{
	struct clone_args cl_args = {
		.flags = CLONE_NEWUSER | CLONE_FILES,
		.exit_signal = SIGCHLD,
		.stack = (__u64)self->stack_top,
		.stack_size = STACK_SIZE,
	};

	pid_t pid = clone3(&cl_args, sizeof(cl_args));

	if (pid < 0) {
		if (atoi(variant->authorized))
			ksft_exit_fail_perror("clone3");
		ASSERT_EQ(EPERM, errno);
	} else if (pid == 0) {
		exit(0);
	} else {
		ASSERT_EQ(pid, waitpid(pid, NULL, 0));
	}
}

TEST_F(unprivileged_userns_clone, unshare)
{

	int ret;

	pid_t pid = fork();

	if (pid < 0) {
		ksft_exit_fail_perror("fork");
	} else if (pid == 0) {
		ret = unshare(CLONE_NEWUSER);

		if (!atoi(variant->authorized)) {
			ASSERT_EQ(-1, ret);
			ASSERT_EQ(EPERM, errno);
		} else {
			ASSERT_LT(-1, ret);
		}
		exit(0);
	} else {
		ASSERT_EQ(pid, waitpid(pid, NULL, 0));

	}
}


/*
 * io_uring tests.
 */


/*
 * tiocsti_restrict
 */

/*
 * Copied from tty/tty_tstamp_update.c selftest
 */
#define MIN_TTY_PATH_LEN 8

static bool tty_valid(char *tty)
{
	if (strlen(tty) < MIN_TTY_PATH_LEN)
		return false;

	if (strncmp(tty, "/dev/tty", MIN_TTY_PATH_LEN) == 0 ||
	    strncmp(tty, "/dev/pts", MIN_TTY_PATH_LEN) == 0)
		return true;

	return false;
}

static int open_tty(struct __test_metadata *const _metadata)
{
	int fd;
	char tty[PATH_MAX];

	ASSERT_LE(-1, readlink("/proc/self/fd/0", tty, PATH_MAX));
	if (!tty_valid(tty)) {
		SKIP(return -1, "%s is not a valid tty", tty);
	}
	fd = open(tty, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		SKIP(return -1, "%s", strerror(errno));
	}

	return fd;
}

FIXTURE(tiocsti_restrict) {
	int fd;
	const char *sysctl_path;
	char cur;
};

FIXTURE_VARIANT(tiocsti_restrict) {
	char *authorized;
};

FIXTURE_VARIANT_ADD(tiocsti_restrict, disabled) {
	.authorized = "1", // tiocsti_restrict denies when sysctl value is `1`.
};

FIXTURE_VARIANT_ADD(tiocsti_restrict, enabled) {
	.authorized = "0",
};

FIXTURE_SETUP(tiocsti_restrict)
{
	check_user_id(0);
	self->fd = open_sysctl(_metadata, PROCFS_DIR "/dev/tty/tiocsti_restrict");
	ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
	ASSERT_EQ(1, read(self->fd, &self->cur, 1));
	ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
	ASSERT_EQ(1, write(self->fd, variant->authorized, 1));

	int fd;
	char val = '1';
	fd = open_sysctl(_metadata, PROCFS_DIR "/dev/tty/legacy_tiocsti");
	ASSERT_EQ(0, lseek(fd, 0, SEEK_SET));
	ASSERT_EQ(1, write(fd, &val, 1));
	close(fd);
}

FIXTURE_TEARDOWN(tiocsti_restrict)
{
	ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
	ASSERT_EQ(1, write(self->fd, &self->cur, 1));
	close_sysctl_fd(_metadata, self->fd);

	int fd;
	char val = '0';
	fd = open_sysctl(_metadata, PROCFS_DIR "/dev/tty/legacy_tiocsti");
	ASSERT_EQ(0, lseek(self->fd, 0, SEEK_SET));
	ASSERT_EQ(1, write(self->fd, &val , 1));
	close(fd);
}

TEST_F(tiocsti_restrict, drop_cap)
{
	int fd;
	char buf[128];

	fd = open_tty(_metadata);
	if (fd < 0) {
		return;
	}
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, drop_cap_sys_admin());
	bzero(&buf, sizeof(buf));
	if (!atoi(variant->authorized)) {
		ASSERT_EQ(0, ioctl(fd, TIOCSTI , &buf));
	} else {
		ASSERT_EQ(-1, ioctl(fd, TIOCSTI, &buf));
		ASSERT_EQ(EPERM, errno);
	}
	ASSERT_EQ(0, set_cap_sys_admin());
}

TEST_HARNESS_MAIN

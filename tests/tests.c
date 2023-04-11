/*
 *
 * Copyright (c) 2023 Steve Langasek <vorlon@dodds.net>
 *
 * pam_session_timelimit is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 3 of the
 * License, or (at your option) any later version.
 *
 * pam_session_timelimit is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <dlfcn.h>

#include <security/_pam_types.h>

#include <CUnit/Basic.h>

#include "time-util.h"

typedef struct pam_handle {
	char *username;
	char *limit;
	time_t *start_time;
	unsigned int get_item_calls;
	unsigned int set_data_calls;
	unsigned int syslog_calls;
} pam_handle_t;

typedef int (*pam_module_fn)(pam_handle_t *handle,
                             int flags,
                             int argc, const char **argv);

static pam_module_fn acct_mgmt, open_session, close_session;
static pam_handle_t pamh;


int pam_set_data(pam_handle_t *pamh, const char *module_data_name,
                 void *data,
                 void (*cleanup)(pam_handle_t *pamh, void *data, int error_status))
{
	pamh->set_data_calls++;

	if (!strcmp(module_data_name,"systemd.runtime_max_sec")) {
		pamh->limit = data;
		return PAM_SUCCESS;
	} else if (!strcmp(module_data_name,"timelimit.session_start")) {
		pamh->start_time = data;
		return PAM_SUCCESS;
	}
	return PAM_BAD_ITEM;
}


int pam_get_item(const pam_handle_t *pamh, int item_type,
                 const void **item)
{
	((pam_handle_t *)pamh)->get_item_calls++;

	if (item_type == PAM_USER)
	{
		if (!pamh->username)
			return PAM_BAD_ITEM;
		*item = pamh->username;
		return PAM_SUCCESS;
	}
	return PAM_BAD_ITEM;
}


void pam_syslog(pam_handle_t *pamh, int priority,
                const char *fmt, ...)
{
/*
	va_list argp;

	va_start(argp, fmt);
	vprintf(fmt, argp);
	va_end(argp);
	printf("\n");
*/

	pamh->syslog_calls++;
}


static void setup_pam_state(void) {
	memset(&pamh, '\0', sizeof(pam_handle_t));
}


static void cleanup_pam_state(void) {
	unlink("data/state");
	free(pamh.limit);
	free(pamh.start_time);
}


static int initialize_state_file(char *username, time_t base_time,
                                 usec_t timeval)
{
	char buf[1024];
	ssize_t bytes;
	int fd;

	fd = open("data/state", O_RDWR | O_CREAT, 0600);
	if (fd < 0)
		return -1;

	strncpy(buf, "Format: ", 9);

	*((uint32_t *)(buf+8)) = 1;
	bytes = write(fd, buf, 12);
	if (bytes != 12) {
		close(fd);
		unlink("data/state");
		return -1;
	}

	memset(buf, '\0', NAME_MAX+1+sizeof(time_t)+sizeof(usec_t));

	strncpy(buf, username, NAME_MAX+1);
	*((time_t *)(buf+NAME_MAX+1)) = base_time;
	*((usec_t *)(buf+NAME_MAX+1+sizeof(time_t))) = timeval;
	bytes = write(fd, buf, NAME_MAX+1+sizeof(time_t)+sizeof(usec_t));
	close(fd);

	if (bytes != NAME_MAX+1+sizeof(time_t)+sizeof(usec_t)) {
		unlink("data/state");
		return -1;
	}

	return 0;
}


static void invalid_module_argument(void)
{
	const char *arg = "something_broken";

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 1, &arg) == PAM_PERM_DENIED);
	CU_ASSERT(pamh.get_item_calls == 0);
	CU_ASSERT(pamh.set_data_calls == 0);
	CU_ASSERT(pamh.syslog_calls == 1);
}


static void no_valid_user(void)
{
	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 0, NULL) == PAM_BAD_ITEM);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 0);
}


static void no_config_file(void)
{
	const char *arg = "path=data/non-existent";

	pamh.username = "ted";

	CU_ASSERT(acct_mgmt(&pamh, 0, 1, &arg) == PAM_IGNORE);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 0);
	CU_ASSERT(pamh.syslog_calls == 1);
}


static void config_not_at_start_of_line(void)
{
	const char *arg = "path=data/broken_whitespace";

	pamh.username = "ted";

	CU_ASSERT(acct_mgmt(&pamh, 0, 1, &arg) == PAM_PERM_DENIED);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 0);
	CU_ASSERT(pamh.syslog_calls == 1);
}


static void config_only_comments(void)
{
	const char *arg = "path=data/only_comments";

	pamh.username = "ted";

	CU_ASSERT(acct_mgmt(&pamh, 0, 1, &arg) == PAM_IGNORE);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 0);
}


static void config_missing_limit(void)
{
	const char *arg = "path=data/missing_limit";

	pamh.username = "ted";

	CU_ASSERT(acct_mgmt(&pamh, 0, 1, &arg) == PAM_PERM_DENIED);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 0);
	CU_ASSERT(pamh.syslog_calls == 1);
}


static void config_commented_limit(void)
{
	const char *arg = "path=data/commented_limit";

	pamh.username = "ted";

	CU_ASSERT(acct_mgmt(&pamh, 0, 1, &arg) == PAM_PERM_DENIED);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 0);
}


static void config_comment_after_entry(void)
{
	const char *args[] = {
		"path=data/comment_after_entry",
		"statepath=data/state"
	};

	pamh.username = "ted";

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 2, args) == PAM_SUCCESS);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 1);
	CU_ASSERT(!strncmp(pamh.limit, "5h", 3));
}


static void match_last_entry(void)
{
	const char *args[] = {
		"path=data/match_last_entry",
		"statepath=data/state"
	};

	pamh.username = "ted";

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 2, args) == PAM_SUCCESS);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 1);
	CU_ASSERT(pamh.syslog_calls == 3);
	CU_ASSERT(!strcmp(pamh.limit, "12h"));
}


static void limit_with_spaces(void)
{
	const char *args[] = {
		"path=data/limit_with_spaces",
		"statepath=data/state"
	};

	pamh.username = "ted";

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 2, args) == PAM_SUCCESS);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 1);
	CU_ASSERT(!strcmp(pamh.limit, "5h 12min"));
}


static void invalid_time_spec(void)
{
	const char *arg = "path=data/invalid_time_spec";

	pamh.username = "ted";

	CU_ASSERT(acct_mgmt(&pamh, 0, 1, &arg) == PAM_PERM_DENIED);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 0);
}


static void state_file_exists_no_match(void)
{
	int retval;
	const char *args[] = {
		"path=data/limit_with_spaces",
		"statepath=data/state"
	};

	pamh.username = "ted";

	retval = initialize_state_file("bob", time(NULL), 5*USEC_PER_HOUR);
	CU_ASSERT_FATAL(retval == 0);

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 2, args) == PAM_SUCCESS);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 1);
	CU_ASSERT(!strcmp(pamh.limit, "5h 12min"));
}


static void state_file_exists_with_match(void)
{
	int retval;
	const char *args[] = {
		"path=data/limit_with_spaces",
		"statepath=data/state"
	};

	pamh.username = "ted";

	retval = initialize_state_file(pamh.username, time(NULL),
	                               5*USEC_PER_HOUR);
	CU_ASSERT_FATAL(retval == 0);

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 2, args) == PAM_SUCCESS);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 1);
	CU_ASSERT(!strcmp(pamh.limit, "12min"));
}


static void state_file_ignore_stale_entry(void)
{
	int retval;
	const char *args[] = {
		"path=data/limit_with_spaces",
		"statepath=data/state"
	};

	pamh.username = "ted";

	retval = initialize_state_file(pamh.username, 0,
	                               5*USEC_PER_HOUR);
	CU_ASSERT_FATAL(retval == 0);

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 2, args) == PAM_SUCCESS);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 1);
	CU_ASSERT(!strcmp(pamh.limit, "5h 12min"));
}


static void state_file_no_crash_on_truncation(void)
{
	int retval;
	const char *args[] = {
		"path=data/limit_with_spaces",
		"statepath=data/state"
	};

	pamh.username = "ted";

	retval = initialize_state_file(pamh.username, time(NULL),
	                               5*USEC_PER_HOUR);
	CU_ASSERT_FATAL(retval == 0);

	CU_ASSERT_FATAL(truncate("data/state", 50) == 0);

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 2, args) == PAM_SUCCESS);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 1);
	CU_ASSERT(!strcmp(pamh.limit, "5h 12min"));
}


static void state_file_no_crash_on_missing_NUL(void)
{
	int retval;
	const char *args[] = {
		"path=data/limit_with_spaces",
		"statepath=data/state"
	};
	char username[NAME_MAX+2];

	pamh.username = "ted";

	memset(username, 'A', NAME_MAX+1);
	username[NAME_MAX+1] = '\0';

	retval = initialize_state_file(username, time(NULL), 5*USEC_PER_HOUR);
	CU_ASSERT_FATAL(retval == 0);

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 2, args) == PAM_SUCCESS);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 1);
	CU_ASSERT(!strcmp(pamh.limit, "5h 12min"));
}


static void open_session_sets_time() {
	CU_ASSERT_FATAL(open_session(&pamh, 0, 0, NULL) == PAM_SUCCESS);
	CU_ASSERT(pamh.set_data_calls == 1);

	CU_ASSERT(pamh.start_time != NULL);
	CU_ASSERT(*pamh.start_time <= time(NULL));
	// If this takes longer than a minute, something has gone wrong...
	CU_ASSERT(*pamh.start_time >= time(NULL)-60);
}


int main(int argc, char **argv)
{
	void *handle;
	unsigned int failures;
	CU_ErrorCode retval;
	CU_TestInfo tests[] = {
		{ "invalid module argument", invalid_module_argument },
		{ "no config file", no_config_file },
		{ "no PAM_USER", no_valid_user },
		{ "config not at start of line", config_not_at_start_of_line },
		{ "config file has only comments and whitespace",
		  config_only_comments },
		{ "config file with missing limit", config_missing_limit },
		{ "config file with commented-out limit",
		  config_commented_limit },
		{ "config file with in-line comment after entry",
		  config_comment_after_entry },
		{ "limit set to last matching user entry",
		  match_last_entry },
		{ "limit can have spaces", limit_with_spaces },
		{ "invalid time specification", invalid_time_spec },
		{ "state file exists with no matching entry",
		  state_file_exists_no_match },
		{ "state file exists with matching entry",
		  state_file_exists_with_match },
		{ "no crash on truncated state file",
		  state_file_no_crash_on_truncation },
		{ "no crash on username overflow in state file",
		  state_file_no_crash_on_missing_NUL },
		{ "ignore state file entries with stale timestamp",
		  state_file_ignore_stale_entry },
		{ "open_session() sets time",
		  open_session_sets_time },
		CU_TEST_INFO_NULL,
	};
	CU_SuiteInfo suites[] = {
		{ "pam", NULL, NULL, setup_pam_state, cleanup_pam_state,
		  tests },
		CU_SUITE_INFO_NULL,
	};

	/* Make sure we can open our DSO before bothering to set up CUnit */
	handle = dlopen("../.libs/pam_session_timelimit.so", RTLD_NOW);

	if (!handle) {
		fprintf(stderr, "Failed to load PAM module: %s\n", dlerror());
		exit(1);
	}

	acct_mgmt = (pam_module_fn) dlsym(handle, "pam_sm_acct_mgmt");
	if (!acct_mgmt) {
		fprintf(stderr, "Failed to resolve PAM symbol: %s\n",
		        dlerror());
		exit(1);
	}
	open_session = (pam_module_fn) dlsym(handle, "pam_sm_open_session");
	if (!open_session) {
		fprintf(stderr, "Failed to resolve PAM symbol: %s\n",
		        dlerror());
		exit(1);
	}
	close_session = (pam_module_fn) dlsym(handle, "pam_sm_close_session");
	if (!open_session) {
		fprintf(stderr, "Failed to resolve PAM symbol: %s\n",
		        dlerror());
		exit(1);
	}


        /* Initialize the CUnit test registry. */
        if (CUE_SUCCESS != CU_initialize_registry())
                return CU_get_error();

	retval = CU_register_suites(suites);
	if (retval != CUE_SUCCESS) {
		CU_cleanup_registry();
		return retval;
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);

	CU_basic_run_tests();

	failures = CU_get_number_of_tests_failed();

	CU_cleanup_registry();

	exit (CU_get_error() != CUE_SUCCESS || failures != 0);
}

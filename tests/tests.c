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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>

#include <security/_pam_types.h>

#include <CUnit/Basic.h>

typedef struct pam_handle {
	char *username;
	char *limit;
	unsigned int get_item_calls;
	unsigned int set_data_calls;
	unsigned int syslog_calls;
} pam_handle_t;

typedef int (*pam_module_fn)(pam_handle_t *handle,
                             int flags,
                             int argc, const char **argv);

static pam_module_fn acct_mgmt;
static pam_handle_t pamh;


int pam_set_data(pam_handle_t *pamh, const char *module_data_name,
                 void *data,
                 void (*cleanup)(pam_handle_t *pamh, void *data, int error_status))
{
	pamh->set_data_calls++;

	if (!strcmp(module_data_name,"systemd.runtime_max_sec")) {
		pamh->limit = data;
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
*/
	printf("\n");

	pamh->syslog_calls++;
}


static void setup_pam_state(void) {
	memset(&pamh, '\0', sizeof(pam_handle_t));
}


static void cleanup_pam_state(void) {
	/* FIXME: need handler to delete state path between tests */
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
	CU_ASSERT(!strcmp(pamh.limit, "5h 12m"));
}


static void invalid_time_spec(void)
{
	const char *arg = "path=data/invalid_time_spec";

	pamh.username = "ted";

	CU_ASSERT(acct_mgmt(&pamh, 0, 1, &arg) == PAM_PERM_DENIED);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 0);
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

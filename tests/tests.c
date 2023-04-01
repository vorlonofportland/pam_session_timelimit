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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>

#include <security/_pam_types.h>

#include <CUnit/Basic.h>

typedef struct pam_handle {
	char *username;
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
	return PAM_SUCCESS;
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
	pamh->syslog_calls++;
}


static void invalid_module_argument(void)
{
	const char *arg = "something_broken";

	memset(&pamh, '\0', sizeof(pam_handle_t));

	CU_ASSERT_FATAL(acct_mgmt(&pamh, 0, 1, &arg) == PAM_PERM_DENIED);
	CU_ASSERT(pamh.get_item_calls == 0);
	CU_ASSERT(pamh.set_data_calls == 0);
	CU_ASSERT(pamh.syslog_calls == 1);
}


static void no_config_file(void)
{
	const char *arg = "path=data/non-existent";

	memset(&pamh, '\0', sizeof(pam_handle_t));
	pamh.username = strdup("ted");

	CU_ASSERT(acct_mgmt(&pamh, 0, 1, &arg) == PAM_IGNORE);
	CU_ASSERT(pamh.get_item_calls == 1);
	CU_ASSERT(pamh.set_data_calls == 0);
	CU_ASSERT(pamh.syslog_calls == 1);
}


int main(int argc, char **argv)
{
	void *handle;
	CU_pSuite suite = NULL;
	unsigned int failures;

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

	suite = CU_add_suite("pam", NULL, NULL);
	if (!suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_add_test(suite, "invalid module argument", invalid_module_argument);
	CU_add_test(suite, "no config file", no_config_file);

	CU_basic_set_mode(CU_BRM_VERBOSE);

	CU_basic_run_tests();

	failures = CU_get_number_of_tests_failed();

	CU_cleanup_registry();

	exit (CU_get_error() != CUE_SUCCESS || failures != 0);
}

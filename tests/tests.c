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

#include <dlfcn.h>

#include <CUnit/Basic.h>

/* functions to implement:
   (LIBPAM_EXTENSION_1.0) pam_syslog
   (LIBPAM_1.0) pam_get_item
   (LIBPAM_1.0) pam_set_data
*/

typedef struct pam_handle {
	unsigned int get_item_calls;
	unsigned int set_data_calls;
} pam_handle_t;

typedef int (*pam_module_fn)(pam_handle_t *handle,
                             int flags,
                             int argc, const char **argv);


int main(int argc, char **argv)
{
	void *handle;
	pam_module_fn acct_mgmt;
	pam_handle_t pamh;
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

	CU_basic_set_mode(CU_BRM_VERBOSE);

//	acct_mgmt(&pamh, 0, 0, NULL);

}

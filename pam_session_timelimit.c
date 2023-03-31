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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>


#define UNUSED __attribute__((unused))

/* FIXME: this will be a configurable directory */
#define DEFAULT_CONFIG_PATH "/etc/security/time_limits.conf"


static void cleanup(pam_handle_t *handle UNUSED, void *data, int err UNUSED)
{
	if (!data)
		return;
	free(data);
}


static int parse_config_line(char *line, char **user, char **limit)
{
	size_t length;
	int ret, i;
	char *comment;

	*user = NULL;
	*limit = NULL;

	length = strlen(line);
	/* line >= 1024 chars, go away */
	if (line[length-1] != '\n')
		return PAM_BUF_ERR;

	/* remove trailing newline */
	line[--length] = '\0';

	/* strip comments */
	comment = strchr(line, '#');
	if (comment) {
		*comment = '\0';
		length = comment - line;
	}

	/* eat trailing whitespace */
	while (isspace(line[length-1]))
		line[--length] = '\0';

	/* comment-only or empty line */
	if (!length)
		return PAM_SUCCESS;

	/* find the end of the username */
	for (i = 0; i <= length; i++) {
		if (isspace(line[i]))
			break;
	}

	/* no leading whitespace allowed */
	if (!i)
		return PAM_SYSTEM_ERR;

	*user = malloc(i+1);
	if (!strncpy(*user, line, i)) {
		return PAM_BUF_ERR;
	}
	(*user)[i] = '\0';

	/* skip whitespace to find the start of the limit */
	line += i;
	while (isspace(*line))
		line++;

	/* no limit specified */
	if (*line == '\0') {
		free(*user);
		*user = NULL;
		return PAM_SYSTEM_ERR;
	}

	*limit = strdup(line);

	return PAM_SUCCESS;
}


static int parse_config_file(pam_handle_t *handle, const char *path,
                             char ***user_table)
{
	FILE *config_file;
	struct stat statbuf;
	int usercount = 0;
	char line[1024];
	char **results;

	*user_table = NULL;

	if (stat(path, &statbuf)) {
		pam_syslog(handle, LOG_INFO,
		           "No config file for module, ignoring.");
		return PAM_IGNORE;
	}

	config_file = fopen(path, "r");
	if (config_file == NULL) {
		pam_syslog(handle, LOG_ERR,
		           "Failed to open config file '%s': %s",
		           path, strerror(errno));
		return PAM_PERM_DENIED;
	}

	results = malloc(sizeof(char *));
	results[0] = NULL;

	while (fgets(line, sizeof(line), config_file)) {
		int ret;
		char *user = NULL;
		char *limit = NULL;
		char **newresults;

		ret = parse_config_line(line, &user, &limit);
		if (ret != PAM_SUCCESS) {
			pam_syslog(handle, LOG_ERR, "invalid config file '%s'",
			           path);
			return PAM_PERM_DENIED;
		}
		if (!user || !limit)
			continue;

		newresults = reallocarray(results, sizeof(char *),
		                          ++usercount * 2 + 1);
		if (!newresults) {
			free(user);
			free(limit);
			free(results);
			return PAM_BUF_ERR;
		}
		results = newresults;
		results[(usercount - 1) * 2] = user;
		results[(usercount - 1) * 2 + 1] = limit;
		results[usercount * 2] = NULL;
	}
	if (!usercount) {
		free(results);
		return PAM_IGNORE;
	}
	*user_table = results;
	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *handle,
                                int flags,
                                int argc, const char **argv)
{
	const char *runtime_max_sec = NULL, *path = NULL, *username = NULL;
	const char **user_table;
	unsigned int i;
	int retval;

	for (; argc-- > 0; ++argv) {
		if (strncmp(*argv, "path=", strlen("path=")) == 0) {
			path = strdup(*argv + strlen("path="));
		} else {
			pam_syslog(handle, LOG_ERR,
			           "Unknown module argument: %s", *argv);
			return PAM_PERM_DENIED;
		}
	}

	if (!path)
		path = strdup(DEFAULT_CONFIG_PATH);

	retval = pam_get_item(handle, PAM_USER, (const void **)&username);

	/* Uh we don't know the user we're acting for?  Yeah, bail. */
	if (retval != PAM_SUCCESS)
		return retval;

	if (!username)
		return PAM_PERM_DENIED;

	retval = parse_config_file(handle, path, &user_table);
	if (retval != PAM_SUCCESS)
		return retval;

	for (i = 0; user_table[i]; i += 2)
	{
		if (!strcmp(user_table[i], username))
		{
			runtime_max_sec = user_table[i+1];
			pam_syslog(handle, LOG_INFO,
			           "Limiting user login time for '%s' to '%s'",
			           username, runtime_max_sec);
		}
	}

	/* FIXME: as annoying as it will be to reimplement systemd's time
	   parsing here, we want the limit to apply to all sessions in the
	   day, so need some way to catch the total session time at the end,
	   save that in a state file, and subtract any used session time from
	   the total limit so that the user can't get around the limit by
	   just logging in again.
	 */

	if (!runtime_max_sec)
		return PAM_IGNORE;

        retval = pam_set_data(handle, "systemd.runtime_max_sec",
	                      (void *)runtime_max_sec, cleanup);
	if (retval != PAM_SUCCESS)
		return PAM_PERM_DENIED;

	return PAM_SUCCESS;
}

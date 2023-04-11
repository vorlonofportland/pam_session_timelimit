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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "time-util.h"

#define UNUSED __attribute__((unused))

#define DEFAULT_CONFIG_PATH CONFIGDIR "/time_limits.conf"
#define DEFAULT_STATE_PATH LOCALSTATEDIR "/lib/session_times"


static void cleanup(pam_handle_t *handle UNUSED, void *data, int err UNUSED)
{
	if (!data)
		return;
	free(data);
}


/* returns fd, or -1 on failure */
static int open_state_path (const pam_handle_t *handle, const char *statepath)
{
	int fd, retval;
	ssize_t bytes;
	char buf[12];

	if (geteuid() == 0) {
		/* must set the real uid to 0 so the helper will not error
		   out if pam is called from setuid binary (su, sudo...) */
		if (setuid(0) == -1) {
			pam_syslog(handle, LOG_ERR,
			           "Could not gain root privilege: %s",
			           strerror(errno));
			return -1;
		}
	}

	fd = open(statepath, O_RDWR);

	if (fd < 0 && errno == ENOENT) {
		fd = open(statepath, O_RDWR|O_CREAT, 0600);
		if (fd < 0) {
			pam_syslog(handle, LOG_ERR,
			           "Could not create statefile: %s",
			           strerror(errno));
			return -1;
		}

		retval = flock(fd, LOCK_EX);
		if (retval < 0) {
			pam_syslog(handle, LOG_ERR,
			           "Could not lock statefile: %s",
			           strerror(errno));
			close(fd);
			return -1;
		}

		strncpy(buf, "Format: ", 9);
		/* This file format is not portable between systems of
		   different endianness */
		*((uint32_t *)(buf+8)) = 1;
		bytes = write(fd, buf, 12);
		if (bytes != 12) {
			pam_syslog(handle, LOG_ERR,
			           "Could not initialize statefile: %s",
			           strerror(errno));
			close(fd);
			return -1;
		}
		return fd;
	}
	if (fd < 0) {
		pam_syslog(handle, LOG_ERR, "Could not open statefile: %s",
		           strerror(errno));
		return -1;
	}

	retval = flock(fd, LOCK_EX);
	if (retval < 0) {
		pam_syslog(handle, LOG_ERR,
		           "Could not lock statefile: %s",
		           strerror(errno));
		close(fd);
		return -1;
	}

	bytes = read(fd, buf, 12);

	if (bytes != 12) {
		pam_syslog(handle, LOG_ERR, "Could not read from statefile: %s",
		           strerror(errno));
		close(fd);
		return -1;
	}

	if (strncmp(buf, "Format: ", 8) != 0
	    || *((uint32_t *)(buf+8)) != 1)
	{
		pam_syslog(handle, LOG_ERR, "Unknown statefile format");
		close(fd);
		return -1;
	}

	return fd;
}


static time_t time_today(void) {
	struct tm current_tm;
	time_t current_time = time(NULL);

	if (localtime_r(&current_time, &current_tm) == NULL) {
		return -1;
	}
	// get the time at 00:00:00 today
	current_tm.tm_sec = current_tm.tm_min = current_tm.tm_hour = 0;
	// we query the local time, but we write in GMT so that the session
	// limits don't get reset if the system timezone changes
	return timegm(&current_tm);
}


static int get_used_time_for_user(const pam_handle_t *handle,
                                  const char *statepath,
                                  const char *username,
                                  usec_t *used_time)
{
	char buf[NAME_MAX+1 + sizeof(time_t) + sizeof(usec_t)];
	ssize_t read_bytes, buf_bytes = 0;
	int retval = PAM_SUCCESS;
	int state_file = open_state_path(handle, statepath);

	*used_time = 0;

	if (state_file < 0)
		return PAM_SYSTEM_ERR;

	do {
		if (buf_bytes == sizeof(buf)) {
			// found the record for this user
			if (!strncmp(username, buf, NAME_MAX+1)) {
				time_t last_seen;
				memcpy(&last_seen, buf + NAME_MAX+1,
				       sizeof(time_t));
				/* record is for a different day, so doesn't
				   count against us */
				if (last_seen < time_today())
					break;
				memcpy(used_time,
				       buf + NAME_MAX+1 + sizeof(time_t),
				       sizeof(usec_t));
				break;
			}
			buf_bytes = 0;
		}
		read_bytes = read(state_file, buf, sizeof(buf) - buf_bytes);
		if (read_bytes < 0) {
			if (errno == EINTR)
				continue;
			retval = PAM_SYSTEM_ERR;
		}
		buf_bytes += read_bytes;
	} while (read_bytes != 0);

	close(state_file);

	return retval;
}


static int set_used_time_for_user(const pam_handle_t *handle,
                                  const char *statepath,
                                  const char *username,
                                  usec_t used_time)
{
	char buf[NAME_MAX+1 + sizeof(time_t) + sizeof(usec_t)];
	ssize_t read_bytes, buf_bytes = 0;
	int state_file = open_state_path(handle, statepath);

	if (state_file < 0)
		return PAM_SYSTEM_ERR;

	do {
		if (buf_bytes == sizeof(buf)) {
			// found the record for this user
			if (!strncmp(username, buf, NAME_MAX+1)) {
				// found our record, so rewind to the start
				lseek(state_file, -sizeof(buf), SEEK_CUR);
				break;
			}
			buf_bytes = 0;
		}
		read_bytes = read(state_file, buf, sizeof(buf) - buf_bytes);
		if (read_bytes < 0) {
			if (errno == EINTR)
				continue;
			close(state_file);
			return PAM_SYSTEM_ERR;
		}
		buf_bytes += read_bytes;
	} while (read_bytes != 0);

	memset(buf, '\0', sizeof(buf));

	strncpy(buf, username, NAME_MAX+1);
	*((time_t *)(buf + NAME_MAX + 1)) = time_today();
	*((usec_t *)(buf + NAME_MAX + 1 + sizeof(time_t))) = used_time;

	buf_bytes = write(state_file, buf, sizeof(buf));

	close(state_file);

	if (buf_bytes != sizeof(buf)) {
		pam_syslog(handle, LOG_ERR,
		           "Could not update statefile: %s",
		           strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	return PAM_SUCCESS;
}


static void free_config_file(char **user_table)
{
	int i;

	for (i = 0; user_table[i]; i += 2)
	{
		free(user_table[i]);
		free(user_table[i+1]);
	}
	free(user_table);
}


static int parse_config_line(char *line, char **user, char **limit)
{
	size_t length;
	int i;
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
	if (!*user)
		return PAM_BUF_ERR;

	if (!strncpy(*user, line, i)) {
		free(*user);
		*user = NULL;
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
			free_config_file(results);
			pam_syslog(handle, LOG_ERR, "invalid config file '%s'",
			           path);
			return PAM_PERM_DENIED;
		}
		if (!user || !limit)
		{
			free(user);
			free(limit);
			continue;
		}

		newresults = reallocarray(results, sizeof(char *),
		                          ++usercount * 2 + 1);
		if (!newresults) {
			free(user);
			free(limit);
			free_config_file(results);
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


PAM_EXTERN int pam_sm_open_session(pam_handle_t *handle,
                                   int flags,
                                   int argc, const char **argv)
{
	int retval;
	time_t *current_time = malloc(sizeof(time_t));

	if (!current_time)
		return PAM_BUF_ERR;

	*current_time = time(NULL);

	retval = pam_set_data(handle, "timelimit.session_start",
	                      (void *)current_time, cleanup);

	if (retval != PAM_SUCCESS) {
		free(current_time);
		return PAM_SYSTEM_ERR;
	}
	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_close_session(pam_handle_t *handle,
                                    int flags,
                                    int argc, const char **argv)
{
	int retval;
	const char *statepath = NULL, *username = NULL;
	usec_t elapsed_time, used_time = 0;
	time_t *start_time, end_time = time(NULL);
	char *runtime_max_sec = NULL;

	// if no time limit is set for us, then short-circuit to avoid
	// creating an unnecessarily large state file
        retval = pam_get_data(handle, "systemd.runtime_max_sec",
	                      (const void **)&runtime_max_sec);
	if (retval != PAM_SUCCESS || runtime_max_sec == NULL)
		return PAM_SUCCESS;

	retval = pam_get_data(handle, "timelimit.session_start",
	                      (const void **)&start_time);

	for (; argc-- > 0; ++argv) {
		if (strncmp(*argv, "statepath=", strlen("statepath="))
		      == 0)
			statepath = *argv + strlen("statepath=");
		else {
			pam_syslog(handle, LOG_ERR,
			           "Unknown module argument: %s", *argv);
			return PAM_SYSTEM_ERR;
		}
	}

	if (!statepath)
		statepath = DEFAULT_STATE_PATH;

	retval = pam_get_data(handle, "timelimit.session_start",
	                      (const void **)&start_time);

	if (retval != PAM_SUCCESS) {
		pam_syslog(handle, LOG_ERR, "start time missing from session");
		return PAM_SESSION_ERR;
	}

	if (end_time < *start_time) {
		pam_syslog(handle, LOG_ERR, "session start time in the future");
		return PAM_SESSION_ERR;
	}

	elapsed_time = (end_time - *start_time) * USEC_PER_SEC;

	retval = pam_get_item(handle, PAM_USER, (const void **)&username);
	if (retval != PAM_SUCCESS)
		return retval;
	if (!username)
		return PAM_SESSION_ERR;

	retval = get_used_time_for_user(handle, statepath, username,
	                                &used_time);
	if (retval != PAM_SUCCESS) {
		return PAM_SESSION_ERR;
	}

	if (USEC_INFINITY - used_time < elapsed_time)
		elapsed_time = USEC_INFINITY;
	else
		elapsed_time += used_time;

	retval = set_used_time_for_user(handle, statepath, username,
	                                elapsed_time);

	if (retval != PAM_SUCCESS)
		return PAM_SESSION_ERR;

	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *handle,
                                int flags,
                                int argc, const char **argv)
{
	const char *path = NULL, *statepath = NULL, *username = NULL;
	char *runtime_max_sec = NULL;
	char **user_table;
	unsigned int i;
	int retval;
	usec_t timeval = 0, used_time = 0;

	for (; argc-- > 0; ++argv) {
		if (strncmp(*argv, "path=", strlen("path=")) == 0)
			path = *argv + strlen("path=");
		else if (strncmp(*argv, "statepath=", strlen("statepath="))
		           == 0)
			statepath = *argv + strlen("statepath=");
		else {
			pam_syslog(handle, LOG_ERR,
			           "Unknown module argument: %s", *argv);
			return PAM_PERM_DENIED;
		}
	}

	if (!path)
		path = DEFAULT_CONFIG_PATH;
	if (!statepath)
		statepath = DEFAULT_STATE_PATH;

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

	if (!runtime_max_sec) {
		free_config_file(user_table);
		return PAM_IGNORE;
	}

	retval = parse_time(runtime_max_sec, &timeval, USEC_PER_SEC);

	free_config_file(user_table);

	if (retval) {
		pam_syslog(handle, LOG_ERR,
		           "Invalid time limit '%s'", runtime_max_sec);
		return PAM_PERM_DENIED;
	}

	retval = get_used_time_for_user(handle, statepath, username,
	                                &used_time);
	if (retval != PAM_SUCCESS) {
		return PAM_PERM_DENIED;
	}

	if (timeval <= used_time)
		return PAM_PERM_DENIED;

	timeval -= used_time;

	runtime_max_sec = malloc(FORMAT_TIMESPAN_MAX);
	if (!format_timespan(runtime_max_sec, FORMAT_TIMESPAN_MAX, timeval,
	                     USEC_PER_SEC)) {
		free((void *)runtime_max_sec);
		return PAM_PERM_DENIED;
	}

        retval = pam_set_data(handle, "systemd.runtime_max_sec",
	                      (void *)runtime_max_sec, cleanup);
	if (retval != PAM_SUCCESS) {
		free((void *)runtime_max_sec);
		retval = PAM_PERM_DENIED;
	}

	return retval;
}

/*
 *
 * Copyright (c) 2015 Lennart Poettering,
 *               2016 Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl>,
 *               2023 Yu Watanabe,
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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "time-util.h"

/* What is interpreted as whitespace? */
#define WHITESPACE          " \t\n\r"
#define DIGITS              "0123456789"

#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)

#define ELEMENTSOF(x)                                                   \
        (__builtin_choose_expr(                                         \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                               \
                ((void)0)))


static char *startswith(const char *s, const char *prefix) {
	size_t l;

	assert(s);
	assert(prefix);

	l = strlen(prefix);
	if (!strneq(s, prefix, l))
		return NULL;

	return (char*) s + l;
}


static const char* extract_multiplier(const char *p, usec_t *ret) {
        static const struct {
                const char *suffix;
                usec_t usec;
        } table[] = {
                { "seconds", USEC_PER_SEC    },
                { "second",  USEC_PER_SEC    },
                { "sec",     USEC_PER_SEC    },
                { "s",       USEC_PER_SEC    },
                { "minutes", USEC_PER_MINUTE },
                { "minute",  USEC_PER_MINUTE },
                { "min",     USEC_PER_MINUTE },
                { "months",  USEC_PER_MONTH  },
                { "month",   USEC_PER_MONTH  },
                { "M",       USEC_PER_MONTH  },
                { "msec",    USEC_PER_MSEC   },
                { "ms",      USEC_PER_MSEC   },
                { "m",       USEC_PER_MINUTE },
                { "hours",   USEC_PER_HOUR   },
                { "hour",    USEC_PER_HOUR   },
                { "hr",      USEC_PER_HOUR   },
                { "h",       USEC_PER_HOUR   },
                { "days",    USEC_PER_DAY    },
                { "day",     USEC_PER_DAY    },
                { "d",       USEC_PER_DAY    },
                { "weeks",   USEC_PER_WEEK   },
                { "week",    USEC_PER_WEEK   },
                { "w",       USEC_PER_WEEK   },
                { "years",   USEC_PER_YEAR   },
                { "year",    USEC_PER_YEAR   },
                { "y",       USEC_PER_YEAR   },
                { "usec",    1ULL            },
                { "us",      1ULL            },
                { "µs",      1ULL            },
        };

        assert(p);
        assert(ret);

        for (size_t i = 0; i < ELEMENTSOF(table); i++) {
                char *e;

                e = startswith(p, table[i].suffix);
                if (e) {
                        *ret = table[i].usec;
                        return e;
                }
        }

        return p;
}


int parse_time(const char *t, usec_t *usec, usec_t default_unit) {
        const char *p, *s;
        usec_t r = 0;
        bool something = false;

        assert(t);
        assert(default_unit > 0);

        p = t;

        p += strspn(p, WHITESPACE);
        s = startswith(p, "infinity");
        if (s) {
                s += strspn(s, WHITESPACE);
                if (*s != 0)
                        return -EINVAL;

                if (usec)
                        *usec = USEC_INFINITY;
                return 0;
        }

        for (;;) {
                usec_t multiplier = default_unit, k;
                long long l;
                char *e;

                p += strspn(p, WHITESPACE);

                if (*p == 0) {
                        if (!something)
                                return -EINVAL;

                        break;
                }

                if (*p == '-') /* Don't allow "-0" */
                        return -ERANGE;

                errno = 0;
                l = strtoll(p, &e, 10);
                if (errno > 0)
                        return -errno;
                if (l < 0)
                        return -ERANGE;

                if (*e == '.') {
                        p = e + 1;
                        p += strspn(p, DIGITS);
                } else if (e == p)
                        return -EINVAL;
                else
                        p = e;

                s = extract_multiplier(p + strspn(p, WHITESPACE), &multiplier);
                if (s == p && *s != '\0')
                        /* Don't allow '12.34.56', but accept '12.34 .56' or '12.34s.56' */
                        return -EINVAL;

                p = s;

                if ((usec_t) l >= USEC_INFINITY / multiplier)
                        return -ERANGE;

                k = (usec_t) l * multiplier;
                if (k >= USEC_INFINITY - r)
                        return -ERANGE;

                r += k;

                something = true;

                if (*e == '.') {
                        usec_t m = multiplier / 10;
                        const char *b;

                        for (b = e + 1; *b >= '0' && *b <= '9'; b++, m /= 10) {
                                k = (usec_t) (*b - '0') * m;
                                if (k >= USEC_INFINITY - r)
                                        return -ERANGE;

                                r += k;
                        }

                        /* Don't allow "0.-0", "3.+1", "3. 1", "3.sec" or "3.hoge" */
                        if (b == e + 1)
                                return -EINVAL;
                }
        }

        if (usec)
                *usec = r;
        return 0;
}

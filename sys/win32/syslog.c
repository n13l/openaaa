#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "syslog.h"

static HANDLE event;

void openlog(const char *ident, int logopt, int facility)
{
	event = RegisterEventSourceA(NULL, ident);
}

void syslog(int priority, const char *fmt, ...)
{
	WORD type;
	char *str, *pos;
	int len;
	va_list ap;

	if (!event)
		return;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if (len < 0)
		return;

	if (!(str = malloc(len + 1)))
		return;

	va_start(ap, fmt);
	vsnprintf(str, len + 1, fmt, ap);
	va_end(ap);

	while ((pos = strstr(str, "%1")) != NULL) {
		str = realloc(str, ++len + 1);
		if (!str)
			return;

		memmove(pos + 2, pos + 1, strlen(pos));
		pos[1] = ' ';
	}

	switch (priority) {
	case LOG_EMERG:
	case LOG_ALERT:
	case LOG_CRIT:
	case LOG_ERR:
		type = EVENTLOG_ERROR_TYPE;
		break;
	case LOG_WARNING:
		type = EVENTLOG_WARNING_TYPE;
		break;
	case LOG_NOTICE:
	case LOG_INFO:
	case LOG_DEBUG:
	default:
		type = EVENTLOG_INFORMATION_TYPE;
		break;
	}

	ReportEventA(event, type, 0, 0, NULL, 1, 0, (const char **)&str, NULL);
	free(str);
}

void
closelog(void)
{
}

/*
 * Provides an implementation of the "basename" function, conforming
 * to SUSv3, with extensions to accommodate Win32 drive designators,
 * and suitable for use on native Microsoft(R) Win32 platforms.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <locale.h>

char * 
basename(char *path)
{
	char *locale = setlocale (LC_CTYPE, NULL);
	static char *rvf = NULL;
	size_t len;

	if (locale)
		locale = strdup(locale);
	setlocale (LC_CTYPE, "");

	if (!path || !*path)
		goto done;

	wchar_t *rcopy = malloc(2 + (len = mbstowcs(NULL, path, 0)) * sizeof(wchar_t));
	wchar_t *rpath = rcopy;

	if ((len = mbstowcs(rpath, path, len)) > 1 && rpath[1] == L':')
		rpath += 2;

	rcopy[len] = L'\0';

	if (!*rpath)
		goto done;
	
	wchar_t *rname;

	for (rname = rpath; *rpath; ++rpath) {
		if (*rpath == L'/' || *rpath == L'\\') {
			while (*rpath == L'/' || *rpath == L'\\')
				++rpath;

			if (*rpath)
				rname = rpath;
			else
				while (rpath > rname && 
				      (*--rpath == L'/' || *rpath == L'\\'))
					*rpath = L'\0';
		}
	}


	if (*rname) {
		if ((len = wcstombs(path, rcopy, len)) != (size_t)(-1))
			path[len] = '\0';
		*rname = L'\0';
		if ((len = wcstombs(NULL, rcopy, 0 )) != (size_t)(-1))
			path += len;
	} else {
		rvf = realloc(rvf, len = 1 + wcstombs (NULL, L"/", 0));
		wcstombs(path = rvf, L"/", len);
	}

	setlocale(LC_CTYPE, locale);
	free(locale);
	free(rcopy);
	return path;
done:  
	rvf = realloc(rvf, len = 1 + wcstombs( NULL, L".", 0));
	wcstombs(rvf, L".", len);

	setlocale(LC_CTYPE, locale);
	free(locale);
	return rvf;
}

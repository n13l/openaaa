/*
 * Provides an implementation of the "dirname" function, conforming
 * to SUSv3, with extensions to accommodate Win32 drive designators,
 * and suitable for use on native Microsoft(R) Win32 platforms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <locale.h>

char *
dirname(char *path)
{
	char *locale = setlocale (LC_CTYPE, NULL);
	static char *retfail = NULL;
	size_t len;

	if (locale != NULL)
		locale = strdup (locale);
	setlocale (LC_CTYPE, "");

	if (!path && !*path)
		goto done;

	wchar_t *refcopy = malloc(2 + (len = mbstowcs(NULL, path, 0)) * sizeof(wchar_t));
	wchar_t *refpath = refcopy;

	len = mbstowcs (refpath, path, len);
	refcopy[len] = L'\0';

	if (len > 1 && (refpath[0] == L'/' || refpath[0] == L'\\')) {
		if (refpath[1] == refpath[0] && refpath[2] == L'\0') {
			setlocale(LC_CTYPE, locale);
			free(locale);
			free(refcopy);
			return path;
		}
	} else if (len > 1 && refpath[1] == L':')
		refpath += 2;

	if (!*refpath)
	      goto done;

	wchar_t *refname, *basename;
	for (refname = basename = refpath; *refpath; ++refpath) {
		if (*refpath == L'/' || *refpath == L'\\') {
			while (*refpath == L'/' || *refpath == L'\\')
				++refpath;
			if (*refpath)
				basename = refpath;
			else
				break;
		}
	}

	  if (basename > refname)
	    {
	      do --basename;
	      while (basename > refname && (*basename == L'/' || *basename == L'\\'));
	      if (basename == refname && (refname[0] == L'/' || refname[0] == L'\\')
		  && refname[1] == refname[0] && refname[2] != L'/' && refname[2] != L'\\')
		++basename;
	      *++basename = L'\0';
	      refpath = refcopy;
	      while ((*refpath == L'/' || *refpath == L'\\'))
		++refpath;
	      if ((refpath - refcopy) > 2 || refcopy[1] != refcopy[0])
		refpath = refcopy;
	      refname = refpath;
	      while (*refpath)
	        {
		  if ((*refname++ = *refpath) == L'/' || *refpath++ == L'\\')
		    {
		      while (*refpath == L'/' || *refpath == L'\\')
			++refpath;
		    }
	        }
	      *refname = L'\0';
	      if ((len = wcstombs( path, refcopy, len )) != (size_t)(-1))
		path[len] = '\0';
	    }
	  else
	    {
	      if (*refname == L'/' || *refname == L'\\')
	        {
		  ++refname;
	        }
	      else
	        {
		  *refname++ = L'.';
	        }
	      *refname = L'\0';
	      retfail = realloc (retfail, len = 1 + wcstombs (NULL, refcopy, 0));
	      wcstombs (path = retfail, refcopy, len);
	    }
	  setlocale (LC_CTYPE, locale);
	  free (locale);
    free (refcopy);
	  return path;

done:  
	retfail = realloc (retfail, len = 1 + wcstombs (NULL, L".", 0));
	wcstombs (retfail, L".", len);
	setlocale (LC_CTYPE, locale);
	free (locale);
	return retfail;
}

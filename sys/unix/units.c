
#include <sys/compiler.h>
#include <sys/log.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#define UNITK_MAX (1024)
#define UNITM_MAX (1024 * 1024)
#define UNITG_MAX (1024 * 1024)

size_t
val_units(const char *s)
{
	double v = atof(s);
	char c = s[strlen(s) - 1];

	switch (c) {
	case 'G': 
	case 'g':
	default:  v *= 1024 * 1024; break;
	case 'M': 
	case 'm': v *= 1024; break;
	case 'K': 
	case 'k': v *= 1; break;
	}

	return (size_t)v;
}

void
str_units(size_t v, char *str, size_t maxsize)
{
	size_t modulo = v % UNITG_MAX;
	printf("module: %u\n", (unsigned int)modulo);
}

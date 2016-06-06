#include <sys/compiler.h>
#include <stdlib.h>
#include <ctype.h>

static const byte b64_tab[] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
};

static const byte b64_pad = '=';

unsigned int
b64_enc(byte *dst, const byte *src, unsigned int len)
{
	byte *d = dst;
	const byte *c = src;
	unsigned int i = 0;

	while (len > 2) {
		d[i++] = b64_tab[c[0] >> 2];
		d[i++] = b64_tab[((c[0] & 0x03) << 4) + (c[1] >> 4)];
		d[i++] = b64_tab[((c[1] & 0x0f) << 2) + (c[2] >> 6)];
		d[i++] = b64_tab[c[2] & 0x3f];
		c += 3;
		len -= 3;
	}
	
	if (len != 0) {
		d[i++] = b64_tab[c[0] >> 2];
		if (len > 1) {
			d[i++] = b64_tab[((c[0] & 0x03) << 4) + (c[1] >> 4)];
			d[i++] = b64_tab[(c[1] & 0x0f) << 2];
			d[i++] = b64_pad;
		} else {
			d[i++] = b64_tab[(c[0] & 0x03) << 4];
			d[i++] = b64_pad;
			d[i++] = b64_pad;
		}
	}

	return i;
}

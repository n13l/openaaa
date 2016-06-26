#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/unaligned.h>
#include <string.h>
#include <crypto/sha1.h>

struct sha1 {                                                                   
	u32 h0, h1, h2, h3, h4;
	u32 nblocks;
	byte buf[64];
	int count;
};                                                                              
                                                                                
struct sha1_hmac {                                                              
	struct sha1 ictx;                                                       
	struct sha1 octx;                                                       
};

void
sha1_init(struct sha1 *sha1)
{
	sha1->h0 = 0x67452301;
	sha1->h1 = 0xefcdab89;
	sha1->h2 = 0x98badcfe;
	sha1->h3 = 0x10325476;
	sha1->h4 = 0xc3d2e1f0;
	sha1->nblocks = 0;
	sha1->count = 0;
}

static void
transform(struct sha1 *sha1, const byte *data)
{
	u32 a,b,c,d,e,tm;
	u32 x[16];

	a = sha1->h0;
	b = sha1->h1;
	c = sha1->h2;
	d = sha1->h3;
	e = sha1->h4;
	
#ifdef CPU_BIG_ENDIAN
	memcpy(x, data, 64);
#else
	{
	for (int i=0; i<16; i++)
		x[i] = get_u32_be(data+4*i);
	}
#endif


#define K1  0x5A827999L
#define K2  0x6ED9EBA1L
#define K3  0x8F1BBCDCL
#define K4  0xCA62C1D6L
#define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )
#define F2(x,y,z)   ( x ^ y ^ z )
#define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )
#define F4(x,y,z)   ( x ^ y ^ z )


#define M(i) ( tm =   x[i&0x0f] ^ x[(i-14)&0x0f] \
	                        ^ x[(i-8)&0x0f] ^ x[(i-3)&0x0f] \
	                       , (x[i&0x0f] = rol(tm, 1)) )

#define R(a,b,c,d,e,f,k,m)  do { e += rol( a, 5 )     \
				      + f( b, c, d )  \
				      + k	      \
				      + m;	      \
				 b = rol( b, 30 );    \
			       } while(0)
	R( a, b, c, d, e, F1, K1, x[ 0] );
	R( e, a, b, c, d, F1, K1, x[ 1] );
	R( d, e, a, b, c, F1, K1, x[ 2] );
	R( c, d, e, a, b, F1, K1, x[ 3] );
	R( b, c, d, e, a, F1, K1, x[ 4] );
	R( a, b, c, d, e, F1, K1, x[ 5] );
	R( e, a, b, c, d, F1, K1, x[ 6] );
	R( d, e, a, b, c, F1, K1, x[ 7] );
	R( c, d, e, a, b, F1, K1, x[ 8] );
	R( b, c, d, e, a, F1, K1, x[ 9] );
	R( a, b, c, d, e, F1, K1, x[10] );
	R( e, a, b, c, d, F1, K1, x[11] );
	R( d, e, a, b, c, F1, K1, x[12] );
	R( c, d, e, a, b, F1, K1, x[13] );
	R( b, c, d, e, a, F1, K1, x[14] );
	R( a, b, c, d, e, F1, K1, x[15] );
	R( e, a, b, c, d, F1, K1, M(16) );
	R( d, e, a, b, c, F1, K1, M(17) );
	R( c, d, e, a, b, F1, K1, M(18) );
	R( b, c, d, e, a, F1, K1, M(19) );
	R( a, b, c, d, e, F2, K2, M(20) );
	R( e, a, b, c, d, F2, K2, M(21) );
	R( d, e, a, b, c, F2, K2, M(22) );
	R( c, d, e, a, b, F2, K2, M(23) );
	R( b, c, d, e, a, F2, K2, M(24) );
	R( a, b, c, d, e, F2, K2, M(25) );
	R( e, a, b, c, d, F2, K2, M(26) );
	R( d, e, a, b, c, F2, K2, M(27) );
	R( c, d, e, a, b, F2, K2, M(28) );
	R( b, c, d, e, a, F2, K2, M(29) );
	R( a, b, c, d, e, F2, K2, M(30) );
	R( e, a, b, c, d, F2, K2, M(31) );
	R( d, e, a, b, c, F2, K2, M(32) );
	R( c, d, e, a, b, F2, K2, M(33) );
	R( b, c, d, e, a, F2, K2, M(34) );
	R( a, b, c, d, e, F2, K2, M(35) );
	R( e, a, b, c, d, F2, K2, M(36) );
	R( d, e, a, b, c, F2, K2, M(37) );
	R( c, d, e, a, b, F2, K2, M(38) );
	R( b, c, d, e, a, F2, K2, M(39) );
	R( a, b, c, d, e, F3, K3, M(40) );
	R( e, a, b, c, d, F3, K3, M(41) );
	R( d, e, a, b, c, F3, K3, M(42) );
	R( c, d, e, a, b, F3, K3, M(43) );
	R( b, c, d, e, a, F3, K3, M(44) );
	R( a, b, c, d, e, F3, K3, M(45) );
	R( e, a, b, c, d, F3, K3, M(46) );
	R( d, e, a, b, c, F3, K3, M(47) );
	R( c, d, e, a, b, F3, K3, M(48) );
	R( b, c, d, e, a, F3, K3, M(49) );
	R( a, b, c, d, e, F3, K3, M(50) );
	R( e, a, b, c, d, F3, K3, M(51) );
	R( d, e, a, b, c, F3, K3, M(52) );
	R( c, d, e, a, b, F3, K3, M(53) );
	R( b, c, d, e, a, F3, K3, M(54) );
	R( a, b, c, d, e, F3, K3, M(55) );
	R( e, a, b, c, d, F3, K3, M(56) );
	R( d, e, a, b, c, F3, K3, M(57) );
	R( c, d, e, a, b, F3, K3, M(58) );
	R( b, c, d, e, a, F3, K3, M(59) );
	R( a, b, c, d, e, F4, K4, M(60) );
	R( e, a, b, c, d, F4, K4, M(61) );
	R( d, e, a, b, c, F4, K4, M(62) );
	R( c, d, e, a, b, F4, K4, M(63) );
	R( b, c, d, e, a, F4, K4, M(64) );
	R( a, b, c, d, e, F4, K4, M(65) );
	R( e, a, b, c, d, F4, K4, M(66) );
	R( d, e, a, b, c, F4, K4, M(67) );
	R( c, d, e, a, b, F4, K4, M(68) );
	R( b, c, d, e, a, F4, K4, M(69) );
	R( a, b, c, d, e, F4, K4, M(70) );
	R( e, a, b, c, d, F4, K4, M(71) );
	R( d, e, a, b, c, F4, K4, M(72) );
	R( c, d, e, a, b, F4, K4, M(73) );
	R( b, c, d, e, a, F4, K4, M(74) );
	R( a, b, c, d, e, F4, K4, M(75) );
	R( e, a, b, c, d, F4, K4, M(76) );
	R( d, e, a, b, c, F4, K4, M(77) );
	R( c, d, e, a, b, F4, K4, M(78) );
	R( b, c, d, e, a, F4, K4, M(79) );

	sha1->h0 += a;
	sha1->h1 += b;
	sha1->h2 += c;
	sha1->h3 += d;
	sha1->h4 += e;
}

void
sha1_update(struct sha1 *sha1, const byte *buf, unsigned int len)
{
	if (sha1->count == 64) {
		transform(sha1, sha1->buf);
		sha1->count = 0;
		sha1->nblocks++;
	}

	if (sha1->count) {
		for (;len && sha1->count < 64; len--)
			sha1->buf[sha1->count++] = *buf++;
		sha1_update(sha1, NULL, 0);
		if (!len)
			return;
	}

	while (len >= 64) {
		transform(sha1, buf);
		sha1->count = 0;
		sha1->nblocks++;
		len -= 64;
		buf += 64;
	}

	for (; len && sha1->count < 64; len-- )
		sha1->buf[sha1->count++] = *buf++;
}

byte *
sha1_final(struct sha1 *sha1)
{
	u32 t, msb, lsb;
	byte *p;

	sha1_update(sha1, NULL, 0);

	t = sha1->nblocks;
	lsb = t << 6;
	msb = t >> 26;
	t = lsb;

	if ((lsb += sha1->count) < t)
		msb++;

	t = lsb;
	lsb <<= 3;
	msb <<= 3;
	msb |= t >> 29;

	if (sha1->count < 56) {
		sha1->buf[sha1->count++] = 0x80;
		while(sha1->count < 56)
			sha1->buf[sha1->count++] = 0;
	} else {
		sha1->buf[sha1->count++] = 0x80;
		while (sha1->count < 64)
			sha1->buf[sha1->count++] = 0;
		sha1_update(sha1, NULL, 0);
		memset(sha1->buf, 0, 56 );
	}

	sha1->buf[56] = msb >> 24;
	sha1->buf[57] = msb >> 16;
	sha1->buf[58] = msb >>  8;
	sha1->buf[59] = msb;
	sha1->buf[60] = lsb >> 24;
	sha1->buf[61] = lsb >> 16;
	sha1->buf[62] = lsb >>  8;
	sha1->buf[63] = lsb;
	transform(sha1, sha1->buf);

	p = sha1->buf;
#define X(a) do { put_u32_be(p, sha1->h##a); p += 4; } while(0)
	X(0);
	X(1);
	X(2);
	X(3);
	X(4);
#undef X

	return sha1->buf;
}

void
sha1_hash(byte *outbuf, const byte *buf, unsigned int len)
{
	struct sha1 sha1;

	sha1_init(&sha1);
	sha1_update(&sha1, buf, len);
	memcpy(outbuf, sha1_final(&sha1), SHA1_SIZE);
}

void
sha1_hmac_init(struct sha1_hmac *hmac, const byte *key, unsigned int len)
{
	byte keybuf[SHA1_BLOCK_SIZE], buf[SHA1_BLOCK_SIZE];

	if (len <= SHA1_BLOCK_SIZE) {
		memcpy(keybuf, key, len);
		memset(keybuf + len, 0, SHA1_BLOCK_SIZE - len);
	} else {
		sha1_hash(keybuf, key, len);
		memset(keybuf + SHA1_SIZE, 0, SHA1_BLOCK_SIZE - SHA1_SIZE);
	}

	sha1_init(&hmac->ictx);
	for (int i = 0; i < SHA1_BLOCK_SIZE; i++)
		buf[i] = keybuf[i] ^ 0x36;
	sha1_update(&hmac->ictx, buf, SHA1_BLOCK_SIZE);

	sha1_init(&hmac->octx);
	for (int i = 0; i < SHA1_BLOCK_SIZE; i++)
		buf[i] = keybuf[i] ^ 0x5c;
	sha1_update(&hmac->octx, buf, SHA1_BLOCK_SIZE);
}

void
sha1_hmac_update(struct sha1_hmac *hmac, const byte *data, unsigned int len)
{
	sha1_update(&hmac->ictx, data, len);
}

byte *
sha1_hmac_final(struct sha1_hmac *hmac)
{
	byte *isha = sha1_final(&hmac->ictx);
	sha1_update(&hmac->octx, isha, SHA1_SIZE);
	return sha1_final(&hmac->octx);
}

void
sha1_hmac(byte *buf, const byte *key, unsigned int klen, 
          const byte *data, unsigned int dlen)
{
	struct sha1_hmac sha1_hmac;
	sha1_hmac_init(&sha1_hmac, key, klen);
	sha1_hmac_update(&sha1_hmac, data, dlen);

	memcpy(buf, sha1_hmac_final(&sha1_hmac), SHA1_SIZE);
}

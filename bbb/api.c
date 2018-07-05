#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <mem/pool.h>
#include <bbb/lib.h>
#include <bbb/prv.h>
#include <list.h>
#include <dict.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nghttp2/nghttp2.h>

enum { IO_NONE, WANT_READ, WANT_WRITE };
#define MAKE_NV(NAME, VALUE) \
{ \
	(u8 *)NAME, (u8 *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1, \
	NGHTTP2_NV_FLAG_NONE \
}

#define MAKE_NV_CS(NAME, VALUE) \
{ \
	(u8 *)NAME, (u8 *)VALUE, sizeof(NAME) - 1, strlen(VALUE), \
	NGHTTP2_NV_FLAG_NONE  \
}

static int http2_initialized = 0;

struct Connection {
	SSL *ssl;
	nghttp2_session *session;
	int want_io;
};

struct Request {
	char *host;
	char *path;
	char *hostport;
	s32 stream_id;
	u16 port;
};

struct URI {
	const char *host;
	const char *path;
	size_t pathlen;
	const char *hostport;
	size_t hostlen;
	size_t hostportlen;
	uint16_t port;
};

static char *
strcopy(const char *s, size_t len) 
{
	char *dst = malloc(len + 1);
	memcpy(dst, s, len);
	dst[len] = '\0';
	return dst;
}

static ssize_t
send_callback(nghttp2_session *session, const u8 *buf,
              size_t len, int flags, void *user) 
{
	struct Connection *connection;
	int rv;
	(void)session;
	(void)flags;

	connection = (struct Connection *)user;
	connection->want_io = IO_NONE;
	ERR_clear_error();
	rv = SSL_write(connection->ssl, buf, (int)len);
	if (rv <= 0) {
		int err = SSL_get_error(connection->ssl, rv);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			connection->want_io =
			(err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
			rv = NGHTTP2_ERR_WOULDBLOCK;
		} else {
			rv = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}
	return rv;
}

static ssize_t 
recv_callback(nghttp2_session *session, u8 *buf, size_t len, int flags, void *user) 
{
	struct Connection *connection;
	int rv;
	(void)session;
	(void)flags;

	connection = (struct Connection *)user;
	connection->want_io = IO_NONE;
	ERR_clear_error();
	rv = SSL_read(connection->ssl, buf, (int)len);
	if (rv < 0) {
		int err = SSL_get_error(connection->ssl, rv);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			connection->want_io =
		        (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
			rv = NGHTTP2_ERR_WOULDBLOCK;
		} else {
			rv = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	} else if (rv == 0) {
		rv = NGHTTP2_ERR_EOF;
	}
	return rv;
}

static int
on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user) 
{
	size_t i;
	(void)user;

	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
			const nghttp2_nv *nva = frame->headers.nva;
			info("[INFO] C ----------------------------> S (HEADERS)");
			for (i = 0; i < frame->headers.nvlen; ++i) {
				fwrite(nva[i].name, 1, nva[i].namelen, stdout);
			printf(": ");
			fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
			printf("\n");
		}
	}
	break;
	case NGHTTP2_RST_STREAM:
		info("[INFO] C ----------------------------> S (RST_STREAM)");
		break;
	case NGHTTP2_GOAWAY:
		info("[INFO] C ----------------------------> S (GOAWAY)");
		break;
	}
	return 0;
}

static int
on_frame_recv_callback(nghttp2_session *session,
const nghttp2_frame *frame, void *user_data) 
{
	size_t i;
	(void)user_data;

	switch (frame->hd.type) {
	case NGHTTP2_HEADERS:
		if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
			const nghttp2_nv *nva = frame->headers.nva;
			struct Request *req;
			req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
			if (!req) break;
			info("[INFO] C <---------------------------- S (HEADERS)");
			for (i = 0; i < frame->headers.nvlen; ++i) {
				fwrite(nva[i].name, 1, nva[i].namelen, stdout);
				printf(": ");
				fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
				printf("\n");
			}
		}
		break;
	case NGHTTP2_RST_STREAM:
		info("[INFO] C <---------------------------- S (RST_STREAM)");
		break;
	case NGHTTP2_GOAWAY:
		info("[INFO] C <---------------------------- S (GOAWAY)");
		break;
	}
	return 0;
}

static int
on_stream_close_callback(nghttp2_session *session, s32 stream_id,
u32 error_code, void *user) 
{
	struct Request *req;
	(void)error_code;
	(void)user;
	req = nghttp2_session_get_stream_user_data(session, stream_id);
	if (req) {
		int rv;
		rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
		if (rv != 0) {
			info("http2_session_terminate_session");
			return -1;
		}
	}
	return 0;
}

static int
on_data_chunk_recv_callback(nghttp2_session *session, u8 flags,
s32 stream_id, const u8 *data, size_t len, void *user) 
{
	struct Request *req;
	(void)flags;
	(void)user;

	req = nghttp2_session_get_stream_user_data(session, stream_id);
	if (req) {
		info("[INFO] C <---------------------------- S (DATA chunk)\n"
		"%lu bytes", (unsigned long int)len);
		fwrite(data, 1, len, stdout);
		printf("\n");
	}
	return 0;
}

static void 
setup_nghttp2_callbacks(nghttp2_session_callbacks *c) 
{
	nghttp2_session_callbacks_set_send_callback(c, send_callback);
	nghttp2_session_callbacks_set_recv_callback(c, recv_callback);
	nghttp2_session_callbacks_set_on_frame_send_callback(c, on_frame_send_callback);
	nghttp2_session_callbacks_set_on_frame_recv_callback(c, on_frame_recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(c, on_stream_close_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(c, on_data_chunk_recv_callback);
}

#ifndef OPENSSL_NO_NEXTPROTONEG
static int
select_next_proto_cb(SSL *ssl, unsigned char **out,
unsigned char *outlen, const unsigned char *in,
unsigned int inlen, void *arg) 
{
	int rv;
	(void)ssl;
	(void)arg;

	rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
	if (rv <= 0) {
		error("Server did not advertise HTTP/2 protocol");
		return -1;
	}
	return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

static void 
init_ssl_ctx(SSL_CTX *ssl_ctx) {
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

#ifndef OPENSSL_NO_NEXTPROTONEG
	SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
}

static int
ssl_handshake(SSL *ssl, int fd) 
{
	int rv;
	if (SSL_set_fd(ssl, fd) == 0) {
		error("ssl: %s ", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	ERR_clear_error();
	rv = SSL_connect(ssl);
	if (rv <= 0) {
		error("ssl: %s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	return 0;
}

static int 
connect_to(const char *host, u16 port) 
{
	struct addrinfo hints;
	int fd = -1;
	int rv;
	char service[NI_MAXSERV];
	struct addrinfo *res, *rp;

	snprintf(service, sizeof(service), "%u", port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rv = getaddrinfo(host, service, &hints, &res);
	if (rv != 0) {
		error("getaddrinfo: %s", gai_strerror(rv));
		return -1;
	}
	for (rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		while ((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 && errno == EINTR);
		if (rv == 0)
			break;
		
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

static void
make_non_block(int fd)
{
	int flags, rv;
	while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
	if (flags == -1) {
		error("fcntl: %s", strerror(errno));
	}

	while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
	if (rv == -1) {
		error("fcntl: %s", strerror(errno));
	}
}

static void
set_tcp_nodelay(int fd) 
{
	int val = 1;
	int rv;
	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
	if (rv == -1) {
		error("setsockopt: %s", strerror(errno));
	}
}

static void 
ctl_poll(struct pollfd *pollfd, struct Connection *connection) 
{
	pollfd->events = 0;
	if (nghttp2_session_want_read(connection->session) ||
		connection->want_io == WANT_READ) {
			pollfd->events |= POLLIN;
	}
	if (nghttp2_session_want_write(connection->session) ||
		connection->want_io == WANT_WRITE) {
			pollfd->events |= POLLOUT;
	}
}

static void 
submit_request(struct Connection *connection, struct Request *req) 
{
	s32 stream_id;

	const nghttp2_nv nva[] = {MAKE_NV(":method", "GET"),
	MAKE_NV_CS(":path", req->path),
	MAKE_NV(":scheme", "https"),
	MAKE_NV_CS(":authority", req->hostport),
	MAKE_NV("accept", "*/*"),
	MAKE_NV("user-agent", "nghttp2/" NGHTTP2_VERSION)};

	stream_id = nghttp2_submit_request(connection->session, NULL, nva,
	                              sizeof(nva) / sizeof(nva[0]), NULL, req);

	if (stream_id < 0) {
		error("nghttp2_submit_request sid=%d", stream_id);
	}

	req->stream_id = stream_id;
	info("[INFO] Stream ID = %d", stream_id);
}

static void 
exec_io(struct Connection *connection) 
{
	int rv = nghttp2_session_recv(connection->session);
	if (rv != 0) {
		error("nghttp2_session_recv");
	}
	rv = nghttp2_session_send(connection->session);
	if (rv != 0) {
		error("nghttp2_session_send");
	}
}

static void 
request_init(struct Request *req, const struct URI *uri) {
req->host = strcopy(uri->host, uri->hostlen);
req->port = uri->port;
req->path = strcopy(uri->path, uri->pathlen);
req->hostport = strcopy(uri->hostport, uri->hostportlen);
req->stream_id = -1;
}

static void 
request_free(struct Request *req) {
	free(req->host);
	free(req->path);
	free(req->hostport);
}

/*
 *  * Fetches the resource denoted by |uri|.
 *   */
static void 
fetch_uri(const struct URI *uri) 
{
	nghttp2_session_callbacks *callbacks;
	int fd;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	struct Request req;
	struct Connection connection;
	int rv;
	nfds_t npollfds = 1;
	struct pollfd pollfds[1];

	request_init(&req, uri);

	/* Establish connection and setup SSL */
	fd = connect_to(req.host, req.port);
	if (fd == -1) {
		error("Could not open file descriptor");
	}
	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if (ssl_ctx == NULL) {
		error("ssl: %s", ERR_error_string(ERR_get_error(), NULL));
	}
	init_ssl_ctx(ssl_ctx);
	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		error("ssl: %s", ERR_error_string(ERR_get_error(), NULL));
	}
	ssl_handshake(ssl, fd);

	connection.ssl = ssl;
	connection.want_io = IO_NONE;

	make_non_block(fd);
	set_tcp_nodelay(fd);

	info("[INFO] SSL/TLS handshake completed");

	rv = nghttp2_session_callbacks_new(&callbacks);
	if (rv != 0) {
		error("nghttp2_session_callbacks_new");
	}

	setup_nghttp2_callbacks(callbacks);
	rv = nghttp2_session_client_new(&connection.session, callbacks, &connection);
	nghttp2_session_callbacks_del(callbacks);
	if (rv != 0) {
		error("nghttp2_session_client_new");
	}

	rv = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_NONE, NULL, 0);

	if (rv != 0) {
		error("nghttp2_submit_settings");
	}

	/* Submit the HTTP request to the outbound queue. */
	submit_request(&connection, &req);

	pollfds[0].fd = fd;
	ctl_poll(pollfds, &connection);

	/* Event loop */
	while (nghttp2_session_want_read(connection.session) ||
		nghttp2_session_want_write(connection.session)) {
		int nfds = poll(pollfds, npollfds, -1);
		if (nfds == -1) {
			error("poll: %s", strerror(errno));
		}
		if (pollfds[0].revents & (POLLIN | POLLOUT)) {
			exec_io(&connection);
		}
		if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
			error("Connection error");
		}
		ctl_poll(pollfds, &connection);
	}
	/* Resource cleanup */
	nghttp2_session_del(connection.session);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ssl_ctx);
	shutdown(fd, SHUT_WR);
	close(fd);
	request_free(&req);
}

static int 
parse_uri(struct URI *res, const char *uri) 
{

	size_t len, i, offset;
	int ipv6addr = 0;
	memset(res, 0, sizeof(struct URI));
	len = strlen(uri);
	if (len < 9 || memcmp("https://", uri, 8) != 0) {
		return -1;
	}
	offset = 8;
	res->host = res->hostport = &uri[offset];
	res->hostlen = 0;
	if (uri[offset] == '[') {
		++offset;
		++res->host;
		ipv6addr = 1;
		for (i = offset; i < len; ++i) {
			if (uri[i] == ']') {
				res->hostlen = i - offset;
				offset = i + 1;
				break;
			}
		}
	} else {
		const char delims[] = ":/?#";
		for (i = offset; i < len; ++i) {
		if (strchr(delims, uri[i]) != NULL) {
			break;
		}
	}
	res->hostlen = i - offset;
	offset = i;
	}
	if (res->hostlen == 0) {
		return -1;
	}

	res->port = 443;
	if (offset < len) {
		if (uri[offset] == ':') {

			const char delims[] = "/?#";
			int port = 0;
			++offset;
			for (i = offset; i < len; ++i) {
				if (strchr(delims, uri[i]) != NULL) {
					break;
				}
				if ('0' <= uri[i] && uri[i] <= '9') {
					port *= 10;
					port += uri[i] - '0';
					if (port > 65535) {
						return -1;
					}
				} else {
					return -1;
				}
			}
			if (port == 0) {
				return -1;
			}
			offset = i;
			res->port = (uint16_t)port;
		}
	}
	res->hostportlen = (size_t)(uri + offset + ipv6addr - res->host);
	for (i = offset; i < len; ++i) {
		if (uri[i] == '#') {
			break;
		}
	}
	if (i - offset == 0) {
		res->path = "/";
		res->pathlen = 1;
	} else {
		res->path = &uri[offset];
		res->pathlen = i - offset;
	}
	return 0;
}

struct http2 *
http2_new(void)
{
	if (!http2_initialized) {
		http2_initialized = 1;
	}

	struct mm_pool *mp = mm_pool_create(CPU_PAGE_SIZE, 0);
	struct http2 *http2 = mm_pool_zalloc(mp, sizeof(*http2));

	http2->mp = mp;
	http2->mp_attrs = mm_pool_create(CPU_PAGE_SIZE, 0);
	return http2;
}

void
http2_free(struct http2 *http2)
{
	mm_pool_destroy(http2->mp_attrs);
	mm_pool_destroy(http2->mp);
}

int
http2_connect(struct http2 *http2, const char *uri)
{
	mm_pool_flush(http2->mp_attrs);
	return 0;
}

int
http2_disconnect(struct http2 *http2)
{
	return 0;
}

int
http2_read(struct http2 *http2, char *buf, int size)
{
	return 0;
}
	
int
http2_write(struct http2 *http2, char *buf, int size)
{
	return 0;
}
	
int
http2_attr_set(struct http2 *http2, const char *attr, const char *value)
{
	if (!attr || !value)
		return -EINVAL;

	return 0;
}

const char *
http2_attr_get(struct http2 *http2, const char *attr)
{
	return NULL;
}

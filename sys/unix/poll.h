#ifndef __UNIX_POLL_H__
#define __UNIX_POLL_H__

struct pollfd;
struct nfds_t;
typedef struct nfds_t nfds_t;

int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#endif

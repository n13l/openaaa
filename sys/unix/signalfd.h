#ifndef __UNIX_SIGNALFD_H__
#define __UNIX_SIGNALFD_H__

/*
 * The signalfd_siginfo structure
 *
 * The format of the signalfd_siginfo structure(s) returned by read(2)s from a 
 * signalfd file descriptor is as follows:
 */

struct signalfd_siginfo {
	uint32_t ssi_signo;   /* Signal number */
	int32_t  ssi_errno;   /* Error number (unused) */
	int32_t  ssi_code;    /* Signal code */
	uint32_t ssi_pid;     /* PID of sender */
	uint32_t ssi_uid;     /* Real UID of sender */
	int32_t  ssi_fd;      /* File descriptor (SIGIO) */
	uint32_t ssi_tid;     /* Kernel timer ID (POSIX timers) */
	uint32_t ssi_band;    /* Band event (SIGIO) */
	uint32_t ssi_overrun; /* POSIX timer overrun count */
	uint32_t ssi_trapno;  /* Trap number that caused signal */
	int32_t  ssi_status;  /* Exit status or signal (SIGCHLD) */
	int32_t  ssi_int;     /* Integer sent by sigqueue(3) */
	uint64_t ssi_ptr;     /* Pointer sent by sigqueue(3) */
	uint64_t ssi_utime;   /* User CPU time consumed (SIGCHLD) */
	uint64_t ssi_stime;   /* System CPU time consumed (SIGCHLD) */
	uint64_t ssi_addr;    /* Address that generated signal
	(for hardware-generated signals) */
	uint8_t  pad[X];      /* Pad size to 128 bytes (allow for
	additional fields in the future) */
};

struct sigset_t;
typedef struct sigset_t sigset_t;

int signalfd(int fd, const sigset_t *mask, int flags);

#endif

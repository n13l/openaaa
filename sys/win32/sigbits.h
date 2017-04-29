#ifndef __SYS_SIGNAL_BITS_H__
#define __SYS_SIGNAL_BITS_H__

#define _SIGSET_NWORDS (1024 / (8 * sizeof (unsigned long int)))                  
typedef struct {                                                                                
	unsigned long int __val[_SIGSET_NWORDS];                                       
} __sigset_t;                                                                    
typedef __sigset_t sigset_t;                                                                                   

typedef void (*__sighandler_t) (int);

typedef struct {
	int si_signo; 
	int si_errno; 
	int si_code;
} siginfo_t;

/* Bits in `sa_flags'.  */                                                      
#define SA_NOCLDSTOP  1          /* Don't send SIGCHLD when children stop.  */  
#define SA_NOCLDWAIT  2          /* Don't create zombie on child death.  */     
#define SA_SIGINFO    4          /* Invoke signal-catching function with        
                                    three arguments instead of one.  */

/* Structure describing the action to be taken when a signal arrives.  */       
struct sigaction {
	void (*sa_sigaction) (int, siginfo_t *, void *);                        
	__sigset_t sa_mask;                                                         
	int sa_flags;                                                               
	void (*sa_restorer) (void);                                                 
};

/* Values for the HOW argument to `sigprocmask'.  */                            
#define SIG_BLOCK     0          /* Block signals.  */                          
#define SIG_UNBLOCK   1          /* Unblock signals.  */                        
#define SIG_SETMASK   2          /* Set the set of blocked signals.  */

#ifndef SIGHUP
#define SIGHUP          1       /* Hangup (POSIX).  */
#endif

#ifndef SIGINT
#define SIGINT          2       /* Interrupt (ANSI).  */
#endif

#ifndef SIGPIPE
#define SIGPIPE         13       /* Interrupt (ANSI).  */
#endif

#ifndef SIGUSR1
#define SIGUSR1         10       /* Interrupt (ANSI).  */
#endif

#ifndef SIGUSR2
#define SIGUSR2         11       /* Interrupt (ANSI).  */
#endif


int sigsetmask (int __mask);

/* Get and/or change the set of blocked signals.  */                            
int sigprocmask (int __how, const sigset_t *__set, sigset_t *__oset) ;

/* Get and/or set the action for signal SIG.  */                                
int sigaction (int __sig, const struct sigaction *__act, struct sigaction *__oact); 

int sigismember (const __sigset_t *, int);
int sigemptyset(__sigset_t *);
int sigaddset (__sigset_t *, int);                                     
int sigdelset (__sigset_t *, int);

#endif

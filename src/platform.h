/* platform.h - OS abstraction: threads, mutexes, process spawn, misc */
#ifndef NS_PLATFORM_H
#define NS_PLATFORM_H

#include <stddef.h>

#if defined(_WIN32)
  #define NS_WINDOWS 1
#else
  #define NS_POSIX 1
#endif

/* ---------------- threads & mutexes ---------------- */
#if defined(NS_WINDOWS)
  /* winsock2.h must precede windows.h, and WIN32_LEAN_AND_MEAN stops windows.h
     from pulling in the legacy winsock.h — otherwise this header and
     mongoose (which uses winsock2) clash when both are included in one TU. */
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <windows.h>
  typedef HANDLE           ns_thread;
  typedef CRITICAL_SECTION ns_mutex;
#else
  #include <pthread.h>
  typedef pthread_t       ns_thread;
  typedef pthread_mutex_t ns_mutex;
#endif

typedef void *(*ns_thread_fn)(void *arg);

int  ns_thread_start(ns_thread *t, ns_thread_fn fn, void *arg);
void ns_thread_join(ns_thread t);

void ns_mutex_init(ns_mutex *m);
void ns_mutex_destroy(ns_mutex *m);
void ns_mutex_lock(ns_mutex *m);
void ns_mutex_unlock(ns_mutex *m);

void ns_sleep_ms(int ms);

/* ---------------- child process ----------------
   Spawns `argv[0]` with argv (NULL-terminated), redirecting the child's
   stdout to a pipe we can read. stderr is merged into stdout. No shell is
   involved on any platform, so target/argument strings are never interpreted
   by a shell. */
typedef struct ns_proc ns_proc;

/* Returns NULL on failure (errbuf filled). argv must be NULL-terminated. */
ns_proc *ns_proc_spawn(char *const argv[], char *errbuf, size_t errsz);

/* Blocking read of up to n bytes from the child's stdout.
   Returns >0 bytes read, 0 on EOF, <0 on error. */
long ns_proc_read(ns_proc *p, void *buf, size_t n);

/* Ask the child to terminate (SIGTERM / TerminateProcess). */
void ns_proc_kill(ns_proc *p);

/* Reap the child, returning its exit code (or -1). Closes handles. */
int  ns_proc_wait(ns_proc *p);

void ns_proc_free(ns_proc *p);

/* ---------------- misc ---------------- */
/* Open the user's default browser at `url` (best-effort). */
void ns_open_browser(const char *url);

/* Resolve the directory containing the running executable (best effort).
   Writes into out; returns 1 on success. */
int  ns_exe_dir(char *out, size_t outsz);

#endif

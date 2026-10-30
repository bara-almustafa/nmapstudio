#include "platform.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================ POSIX */
#if defined(NS_POSIX)
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

struct ns_proc {
    pid_t pid;
    int   out_fd;   /* read end of child's stdout */
    int   reaped;
    int   status;
};

int ns_thread_start(ns_thread *t, ns_thread_fn fn, void *arg) {
    return pthread_create(t, NULL, fn, arg) == 0 ? 0 : -1;
}
void ns_thread_join(ns_thread t) { pthread_join(t, NULL); }
void ns_mutex_init(ns_mutex *m)    { pthread_mutex_init(m, NULL); }
void ns_mutex_destroy(ns_mutex *m) { pthread_mutex_destroy(m); }
void ns_mutex_lock(ns_mutex *m)    { pthread_mutex_lock(m); }
void ns_mutex_unlock(ns_mutex *m)  { pthread_mutex_unlock(m); }
void ns_sleep_ms(int ms) { struct timespec ts = { ms/1000, (long)(ms%1000)*1000000L }; nanosleep(&ts, NULL); }

ns_proc *ns_proc_spawn(char *const argv[], char *errbuf, size_t errsz) {
    int fds[2];
    if (pipe(fds) != 0) {
        if (errbuf) snprintf(errbuf, errsz, "pipe: %s", strerror(errno));
        return NULL;
    }
    pid_t pid = fork();
    if (pid < 0) {
        if (errbuf) snprintf(errbuf, errsz, "fork: %s", strerror(errno));
        close(fds[0]); close(fds[1]);
        return NULL;
    }
    if (pid == 0) {
        /* child */
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[0]);
        close(fds[1]);
        execvp(argv[0], argv);
        /* if we get here exec failed */
        fprintf(stderr, "exec %s failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    /* parent */
    close(fds[1]);
    ns_proc *p = xmalloc(sizeof *p);
    p->pid = pid;
    p->out_fd = fds[0];
    p->reaped = 0;
    p->status = -1;
    return p;
}

long ns_proc_read(ns_proc *p, void *buf, size_t n) {
    for (;;) {
        ssize_t r = read(p->out_fd, buf, n);
        if (r < 0 && errno == EINTR) continue;
        return (long)r;
    }
}

void ns_proc_kill(ns_proc *p) { if (p && p->pid > 0) kill(p->pid, SIGTERM); }

int ns_proc_wait(ns_proc *p) {
    if (!p) return -1;
    if (p->out_fd >= 0) { close(p->out_fd); p->out_fd = -1; }
    if (!p->reaped) {
        int st = 0;
        while (waitpid(p->pid, &st, 0) < 0 && errno == EINTR) {}
        p->status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        p->reaped = 1;
    }
    return p->status;
}

void ns_proc_free(ns_proc *p) {
    if (!p) return;
    if (p->out_fd >= 0) close(p->out_fd);
    if (!p->reaped) { int st; waitpid(p->pid, &st, WNOHANG); }
    free(p);
}

void ns_open_browser(const char *url) {
    pid_t pid = fork();
    if (pid == 0) {
#if defined(__APPLE__)
        execlp("open", "open", url, (char*)NULL);
#else
        execlp("xdg-open", "xdg-open", url, (char*)NULL);
#endif
        _exit(127);
    }
}

int ns_exe_dir(char *out, size_t outsz) {
#if defined(__APPLE__)
    (void)out; (void)outsz; return 0;
#else
    ssize_t n = readlink("/proc/self/exe", out, outsz - 1);
    if (n <= 0) return 0;
    out[n] = 0;
    char *slash = strrchr(out, '/');
    if (slash) *slash = 0;
    return 1;
#endif
}

#endif /* NS_POSIX */

/* ============================================================ WINDOWS */
#if defined(NS_WINDOWS)
#include <process.h>
#include <shellapi.h>   /* ShellExecuteA (excluded by WIN32_LEAN_AND_MEAN) */

struct ns_proc {
    PROCESS_INFORMATION pi;
    HANDLE out_rd;     /* read end of child's stdout */
    int    reaped;
    int    status;
};

/* thread trampoline so we can keep the ns_thread_fn (void*->void*) signature */
typedef struct { ns_thread_fn fn; void *arg; } tramp_t;
static DWORD WINAPI thread_tramp(LPVOID p) {
    tramp_t t = *(tramp_t *)p;
    free(p);
    t.fn(t.arg);
    return 0;
}
int ns_thread_start(ns_thread *t, ns_thread_fn fn, void *arg) {
    tramp_t *tr = xmalloc(sizeof *tr);
    tr->fn = fn; tr->arg = arg;
    HANDLE h = CreateThread(NULL, 0, thread_tramp, tr, 0, NULL);
    if (!h) { free(tr); return -1; }
    *t = h;
    return 0;
}
void ns_thread_join(ns_thread t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
void ns_mutex_init(ns_mutex *m)    { InitializeCriticalSection(m); }
void ns_mutex_destroy(ns_mutex *m) { DeleteCriticalSection(m); }
void ns_mutex_lock(ns_mutex *m)    { EnterCriticalSection(m); }
void ns_mutex_unlock(ns_mutex *m)  { LeaveCriticalSection(m); }
void ns_sleep_ms(int ms) { Sleep((DWORD)ms); }

/* Quote one argument per the CommandLineToArgvW / CRT rules. */
static void win_quote_arg(strbuf *sb, const char *arg) {
    int need = (*arg == 0);
    for (const char *s = arg; *s; s++)
        if (*s == ' ' || *s == '\t' || *s == '"') { need = 1; break; }
    if (!need) { sb_puts(sb, arg); return; }
    sb_putc(sb, '"');
    for (const char *s = arg;; s++) {
        int nbs = 0;
        while (*s == '\\') { nbs++; s++; }
        if (*s == 0) { for (int i = 0; i < nbs*2; i++) sb_putc(sb, '\\'); break; }
        else if (*s == '"') { for (int i = 0; i < nbs*2+1; i++) sb_putc(sb, '\\'); sb_putc(sb, '"'); }
        else { for (int i = 0; i < nbs; i++) sb_putc(sb, '\\'); sb_putc(sb, *s); }
    }
    sb_putc(sb, '"');
}

ns_proc *ns_proc_spawn(char *const argv[], char *errbuf, size_t errsz) {
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        if (errbuf) snprintf(errbuf, errsz, "CreatePipe failed (%lu)", GetLastError());
        return NULL;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    strbuf cmd; sb_init(&cmd);
    for (int i = 0; argv[i]; i++) { if (i) sb_putc(&cmd, ' '); win_quote_arg(&cmd, argv[i]); }

    STARTUPINFOA si; ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError  = wr;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof pi);
    BOOL ok = CreateProcessA(NULL, cmd.buf, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    sb_free(&cmd);
    CloseHandle(wr);
    if (!ok) {
        if (errbuf) snprintf(errbuf, errsz, "CreateProcess failed (%lu)", GetLastError());
        CloseHandle(rd);
        return NULL;
    }
    ns_proc *p = xmalloc(sizeof *p);
    p->pi = pi; p->out_rd = rd; p->reaped = 0; p->status = -1;
    return p;
}

long ns_proc_read(ns_proc *p, void *buf, size_t n) {
    DWORD got = 0;
    if (!ReadFile(p->out_rd, buf, (DWORD)n, &got, NULL)) {
        DWORD e = GetLastError();
        if (e == ERROR_BROKEN_PIPE) return 0;
        return -1;
    }
    return (long)got;
}

void ns_proc_kill(ns_proc *p) { if (p) TerminateProcess(p->pi.hProcess, 1); }

int ns_proc_wait(ns_proc *p) {
    if (!p) return -1;
    if (p->out_rd) { CloseHandle(p->out_rd); p->out_rd = NULL; }
    if (!p->reaped) {
        WaitForSingleObject(p->pi.hProcess, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(p->pi.hProcess, &code);
        p->status = (int)code;
        p->reaped = 1;
    }
    return p->status;
}

void ns_proc_free(ns_proc *p) {
    if (!p) return;
    if (p->out_rd) CloseHandle(p->out_rd);
    if (p->pi.hProcess) CloseHandle(p->pi.hProcess);
    if (p->pi.hThread)  CloseHandle(p->pi.hThread);
    free(p);
}

void ns_open_browser(const char *url) { ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL); }

int ns_exe_dir(char *out, size_t outsz) {
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)outsz);
    if (n == 0 || n >= outsz) return 0;
    char *slash = strrchr(out, '\\');
    if (slash) *slash = 0;
    return 1;
}

#endif /* NS_WINDOWS */

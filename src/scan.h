/* scan.h - run one nmap scan in a worker thread, stream results */
#ifndef NS_SCAN_H
#define NS_SCAN_H

#include <stddef.h>

/* Called with a heap-allocated JSON string; the callback takes ownership
   (must free it, e.g. by enqueuing then freeing after broadcast). */
typedef void (*scan_emit_fn)(void *ud, char *json);

typedef struct Scan Scan;

/* Start a scan. `args` is a raw nmap argument string (space separated, quotes
   honored); it is tokenized internally and executed via argv (never a shell).
   `targets` is appended as separate argv entries. Returns NULL on failure. */
Scan *scan_start(const char *nmap_path, const char *db_path, int run_id,
                 const char *targets, const char *args,
                 scan_emit_fn emit, void *ud, char *errbuf, size_t errsz);

int  scan_running(Scan *s);
void scan_stop(Scan *s);        /* request termination */
void scan_join_free(Scan *s);   /* join worker + free */

/* tokenize a command string into argv honoring '...' and "..." quoting.
   Returns NULL-terminated argv (caller frees via argv_free). */
char **argv_split(const char *s, int *argc_out);
void   argv_free(char **argv);

#endif

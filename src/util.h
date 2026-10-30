/* util.h - growable string buffer, JSON writing/escaping, tiny JSON reader */
#ifndef NS_UTIL_H
#define NS_UTIL_H

#include <stddef.h>

/* ---- growable string buffer ---- */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} strbuf;

void  sb_init(strbuf *s);
void  sb_free(strbuf *s);
void  sb_reset(strbuf *s);
void  sb_putc(strbuf *s, char c);
void  sb_putn(strbuf *s, const char *p, size_t n);
void  sb_puts(strbuf *s, const char *p);
void  sb_printf(strbuf *s, const char *fmt, ...);
/* append a JSON string literal (with surrounding quotes), escaping as needed.
   NULL is emitted as an empty JSON string "" */
void  sb_json_str(strbuf *s, const char *p);
/* detach the buffer; caller owns the returned malloc'd string */
char *sb_detach(strbuf *s);

/* emit callback used by streaming producers: takes ownership of `json`. */
typedef void (*emit_fn)(void *ud, char *json);

/* ---- misc ---- */
char *xstrdup(const char *s);
void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);

/* ---- minimal JSON reader for flat command objects ----
   These operate on a NUL-terminated JSON object string and find top-level keys.
   They are intentionally small: good enough for {"cmd":"scan","targets":"..."} */

/* Copy the string value of `key` into out (NUL-terminated, JSON-unescaped).
   Returns 1 on success, 0 if key missing / not a string. */
int  json_get_str(const char *json, const char *key, char *out, size_t outsz);
/* Return integer value of `key`, or defval if missing. */
long json_get_int(const char *json, const char *key, long defval);

#endif

#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { fprintf(stderr, "out of memory\n"); abort(); }
    return p;
}
void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, "out of memory\n"); abort(); }
    return q;
}
char *xstrdup(const char *s) {
    if (!s) s = "";
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}

void sb_init(strbuf *s) { s->buf = xmalloc(64); s->len = 0; s->cap = 64; s->buf[0] = 0; }
void sb_free(strbuf *s) { free(s->buf); s->buf = NULL; s->len = s->cap = 0; }
void sb_reset(strbuf *s) { s->len = 0; if (s->buf) s->buf[0] = 0; }

static void sb_grow(strbuf *s, size_t extra) {
    if (s->len + extra + 1 > s->cap) {
        while (s->len + extra + 1 > s->cap) s->cap *= 2;
        s->buf = xrealloc(s->buf, s->cap);
    }
}
void sb_putc(strbuf *s, char c) { sb_grow(s, 1); s->buf[s->len++] = c; s->buf[s->len] = 0; }
void sb_putn(strbuf *s, const char *p, size_t n) {
    if (!n) return;
    sb_grow(s, n);
    memcpy(s->buf + s->len, p, n);
    s->len += n;
    s->buf[s->len] = 0;
}
void sb_puts(strbuf *s, const char *p) { if (p) sb_putn(s, p, strlen(p)); }

void sb_printf(strbuf *s, const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { va_end(ap2); return; }
    sb_grow(s, (size_t)n);
    vsnprintf(s->buf + s->len, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    s->len += (size_t)n;
}

void sb_json_str(strbuf *s, const char *p) {
    sb_putc(s, '"');
    if (p) {
        for (; *p; p++) {
            unsigned char c = (unsigned char)*p;
            switch (c) {
                case '"':  sb_putn(s, "\\\"", 2); break;
                case '\\': sb_putn(s, "\\\\", 2); break;
                case '\b': sb_putn(s, "\\b", 2);  break;
                case '\f': sb_putn(s, "\\f", 2);  break;
                case '\n': sb_putn(s, "\\n", 2);  break;
                case '\r': sb_putn(s, "\\r", 2);  break;
                case '\t': sb_putn(s, "\\t", 2);  break;
                default:
                    if (c < 0x20) {
                        char tmp[8];
                        snprintf(tmp, sizeof tmp, "\\u%04x", c);
                        sb_puts(s, tmp);
                    } else {
                        sb_putc(s, (char)c);
                    }
            }
        }
    }
    sb_putc(s, '"');
}

char *sb_detach(strbuf *s) {
    char *b = s->buf;
    s->buf = NULL; s->len = s->cap = 0;
    return b;
}

/* ---------- minimal flat JSON reader ---------- */

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* find the position just after "key" : returning pointer to the value start,
   searching only at object top level (depth-aware, skips nested objects/arrays
   and strings so a nested key with the same name is not matched). */
static const char *find_value(const char *json, const char *key) {
    const char *p = json;
    size_t keylen = strlen(key);
    int depth = 0;
    p = skip_ws(p);
    if (*p != '{') return NULL;
    p++;
    while (*p) {
        p = skip_ws(p);
        if (*p == '}') return NULL;
        if (*p != '"') { /* malformed; bail */ return NULL; }
        /* read key */
        const char *kstart = ++p;
        strbuf k; /* decode key */
        sb_init(&k);
        while (*p && *p != '"') {
            if (*p == '\\' && p[1]) { p++; }
            sb_putc(&k, *p++);
        }
        if (*p == '"') p++;
        p = skip_ws(p);
        if (*p != ':') { sb_free(&k); return NULL; }
        p++;
        p = skip_ws(p);
        int match = (k.len == keylen && memcmp(k.buf, key, keylen) == 0);
        sb_free(&k);
        (void)kstart;
        if (match) return p;
        /* skip value */
        if (*p == '"') {
            p++;
            while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
            if (*p == '"') p++;
        } else if (*p == '{' || *p == '[') {
            depth = 1; char open = *p; char close = (open == '{') ? '}' : ']';
            p++;
            while (*p && depth) {
                if (*p == '"') { p++; while (*p && *p != '"') { if (*p=='\\'&&p[1]) p++; p++; } if(*p)p++; continue; }
                if (*p == open) depth++;
                else if (*p == close) depth--;
                p++;
            }
        } else {
            while (*p && *p != ',' && *p != '}') p++;
        }
        p = skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') return NULL;
    }
    return NULL;
}

int json_get_str(const char *json, const char *key, char *out, size_t outsz) {
    if (!outsz) return 0;
    out[0] = 0;
    const char *p = find_value(json, key);
    if (!p || *p != '"') return 0;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < outsz) {
        if (*p == '\\' && p[1]) {
            p++;
            char c = *p;
            switch (c) {
                case 'n': out[o++] = '\n'; break;
                case 't': out[o++] = '\t'; break;
                case 'r': out[o++] = '\r'; break;
                case 'b': out[o++] = '\b'; break;
                case 'f': out[o++] = '\f'; break;
                case '/': out[o++] = '/';  break;
                case '"': out[o++] = '"';  break;
                case '\\':out[o++] = '\\'; break;
                case 'u': {
                    /* basic BMP handling -> UTF-8 (good enough for our inputs) */
                    if (p[1] && p[2] && p[3] && p[4]) {
                        char hex[5] = { p[1], p[2], p[3], p[4], 0 };
                        unsigned cp = (unsigned)strtoul(hex, NULL, 16);
                        p += 4;
                        if (cp < 0x80) { out[o++] = (char)cp; }
                        else if (cp < 0x800) {
                            if (o + 2 < outsz) { out[o++] = (char)(0xC0 | (cp >> 6)); out[o++] = (char)(0x80 | (cp & 0x3F)); }
                        } else {
                            if (o + 3 < outsz) { out[o++] = (char)(0xE0 | (cp >> 12)); out[o++] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[o++] = (char)(0x80 | (cp & 0x3F)); }
                        }
                    }
                    break;
                }
                default: out[o++] = c;
            }
            p++;
        } else {
            out[o++] = *p++;
        }
    }
    out[o] = 0;
    return 1;
}

long json_get_int(const char *json, const char *key, long defval) {
    const char *p = find_value(json, key);
    if (!p) return defval;
    if (*p == '"') p++;
    char *end;
    long v = strtol(p, &end, 10);
    if (end == p) return defval;
    return v;
}

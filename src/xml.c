#include "xml.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_ATTRS 48

void xml_init(xml_parser *xp, xml_open_fn on_open, xml_close_fn on_close, void *ud) {
    xp->on_open = on_open;
    xp->on_close = on_close;
    xp->ud = ud;
    sb_init(&xp->pending);
}
void xml_free(xml_parser *xp) { sb_free(&xp->pending); }

const char *xml_get(const xml_attr_t *attrs, int nattrs, const char *name) {
    for (int i = 0; i < nattrs; i++)
        if (strcmp(attrs[i].name, name) == 0) return attrs[i].value;
    return NULL;
}

/* append decoded XML entity text into sb */
static void decode_into(strbuf *sb, const char *p, const char *end) {
    while (p < end) {
        if (*p == '&') {
            const char *semi = memchr(p, ';', (size_t)(end - p));
            if (!semi) { sb_putc(sb, '&'); p++; continue; }
            size_t elen = (size_t)(semi - (p + 1));
            if (p[1] == '#') {
                long cp;
                if (p[2] == 'x' || p[2] == 'X') cp = strtol(p + 3, NULL, 16);
                else                             cp = strtol(p + 2, NULL, 10);
                if (cp < 0x80) sb_putc(sb, (char)cp);
                else if (cp < 0x800) { sb_putc(sb,(char)(0xC0|(cp>>6))); sb_putc(sb,(char)(0x80|(cp&0x3F))); }
                else { sb_putc(sb,(char)(0xE0|(cp>>12))); sb_putc(sb,(char)(0x80|((cp>>6)&0x3F))); sb_putc(sb,(char)(0x80|(cp&0x3F))); }
            } else if (elen == 2 && !memcmp(p+1,"lt",2)) sb_putc(sb,'<');
            else if (elen == 2 && !memcmp(p+1,"gt",2)) sb_putc(sb,'>');
            else if (elen == 3 && !memcmp(p+1,"amp",3)) sb_putc(sb,'&');
            else if (elen == 4 && !memcmp(p+1,"quot",4)) sb_putc(sb,'"');
            else if (elen == 4 && !memcmp(p+1,"apos",4)) sb_putc(sb,'\'');
            else sb_putn(sb, p, (size_t)(semi - p + 1)); /* unknown: keep literal */
            p = semi + 1;
        } else {
            sb_putc(sb, *p++);
        }
    }
}

/* Parse one complete tag body (between '<' and '>', exclusive) and dispatch.
   `body` points at first char after '<'; `blen` excludes the '>'. */
static void dispatch_tag(xml_parser *xp, const char *body, size_t blen) {
    if (blen == 0) return;
    if (body[0] == '?' || body[0] == '!') return; /* PI / DOCTYPE: ignore */

    int closing = (body[0] == '/');
    const char *p = body + (closing ? 1 : 0);
    const char *end = body + blen;
    int self_closing = 0;
    if (!closing && blen && body[blen - 1] == '/') { self_closing = 1; end--; }

    while (p < end && isspace((unsigned char)*p)) p++;
    const char *ns = p;
    while (p < end && !isspace((unsigned char)*p) && *p != '/') p++;
    size_t nlen = (size_t)(p - ns);
    if (nlen == 0) return;

    char name[64];
    if (nlen >= sizeof name) nlen = sizeof name - 1;
    memcpy(name, ns, nlen); name[nlen] = 0;

    if (closing) { if (xp->on_close) xp->on_close(xp->ud, name); return; }

    /* parse attributes */
    xml_attr_t attrs[MAX_ATTRS];
    int nattrs = 0;
    while (p < end && nattrs < MAX_ATTRS) {
        while (p < end && (isspace((unsigned char)*p) || *p == '/')) p++;
        if (p >= end) break;
        const char *as = p;
        while (p < end && *p != '=' && !isspace((unsigned char)*p)) p++;
        size_t alen = (size_t)(p - as);
        if (alen == 0) break;
        while (p < end && isspace((unsigned char)*p)) p++;
        char *aname = xmalloc(alen + 1);
        memcpy(aname, as, alen); aname[alen] = 0;
        char *aval;
        if (p < end && *p == '=') {
            p++;
            while (p < end && isspace((unsigned char)*p)) p++;
            char q = (p < end) ? *p : 0;
            if (q == '"' || q == '\'') {
                p++;
                const char *vs = p;
                while (p < end && *p != q) p++;
                strbuf d; sb_init(&d);
                decode_into(&d, vs, p);
                aval = sb_detach(&d);
                if (p < end) p++; /* closing quote */
            } else {
                const char *vs = p;
                while (p < end && !isspace((unsigned char)*p)) p++;
                strbuf d; sb_init(&d);
                decode_into(&d, vs, p);
                aval = sb_detach(&d);
            }
        } else {
            aval = xstrdup("");
        }
        attrs[nattrs].name = aname;
        attrs[nattrs].value = aval;
        nattrs++;
    }

    if (xp->on_open) xp->on_open(xp->ud, name, attrs, nattrs, self_closing);
    if (self_closing && xp->on_close) xp->on_close(xp->ud, name);

    for (int i = 0; i < nattrs; i++) { free(attrs[i].name); free(attrs[i].value); }
}

void xml_feed(xml_parser *xp, const char *data, size_t n) {
    sb_putn(&xp->pending, data, n);

    char *buf = xp->pending.buf;
    size_t len = xp->pending.len;
    size_t pos = 0;

    for (;;) {
        /* locate next '<' */
        char *lt = memchr(buf + pos, '<', len - pos);
        if (!lt) { pos = len; break; }
        size_t start = (size_t)(lt - buf);

        /* handle comment / CDATA explicitly (may contain '>') */
        if (len - start >= 4 && memcmp(buf + start, "<!--", 4) == 0) {
            char *e = NULL;
            for (size_t i = start + 4; i + 3 <= len; i++)
                if (buf[i]=='-'&&buf[i+1]=='-'&&buf[i+2]=='>') { e = buf + i + 3; break; }
            if (!e) { pos = start; break; }         /* wait for more */
            pos = (size_t)(e - buf); continue;
        }
        if (len - start >= 9 && memcmp(buf + start, "<![CDATA[", 9) == 0) {
            char *e = NULL;
            for (size_t i = start + 9; i + 3 <= len; i++)
                if (buf[i]==']'&&buf[i+1]==']'&&buf[i+2]=='>') { e = buf + i + 3; break; }
            if (!e) { pos = start; break; }
            pos = (size_t)(e - buf); continue;
        }

        /* find the terminating '>' not inside a quoted attribute value */
        size_t i = start + 1;
        char quote = 0;
        int found = 0;
        for (; i < len; i++) {
            char c = buf[i];
            if (quote) { if (c == quote) quote = 0; }
            else if (c == '"' || c == '\'') quote = c;
            else if (c == '>') { found = 1; break; }
        }
        if (!found) { pos = start; break; }         /* incomplete tag: wait */

        dispatch_tag(xp, buf + start + 1, i - (start + 1));
        pos = i + 1;
    }

    /* compact: drop everything we consumed */
    if (pos > 0) {
        memmove(xp->pending.buf, xp->pending.buf + pos, len - pos);
        xp->pending.len = len - pos;
        xp->pending.buf[xp->pending.len] = 0;
    }
}

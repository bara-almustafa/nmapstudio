/* xml.h - incremental (streaming) XML tokenizer.
   Feed it bytes as they arrive; it emits element open/close events once a
   complete tag is buffered. Attribute values are entity-decoded. Text nodes
   are ignored (Nmap's XML carries its data in attributes). */
#ifndef NS_XML_H
#define NS_XML_H

#include "util.h"

typedef struct { char *name; char *value; } xml_attr_t;

typedef void (*xml_open_fn)(void *ud, const char *name,
                            const xml_attr_t *attrs, int nattrs, int self_closing);
typedef void (*xml_close_fn)(void *ud, const char *name);

typedef struct {
    xml_open_fn  on_open;
    xml_close_fn on_close;
    void        *ud;
    strbuf       pending;
} xml_parser;

void xml_init(xml_parser *xp, xml_open_fn on_open, xml_close_fn on_close, void *ud);
void xml_free(xml_parser *xp);
void xml_feed(xml_parser *xp, const char *data, size_t n);

/* attribute lookup helper */
const char *xml_get(const xml_attr_t *attrs, int nattrs, const char *name);

#endif

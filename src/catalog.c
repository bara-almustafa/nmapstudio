#include "catalog.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- built-in scan profiles (mirrors Zenmap's spirit, extended) ---- */
typedef struct { const char *name, *args, *desc; } Profile;
static const Profile PROFILES[] = {
  {"Quick scan",            "-T4 -F",                                   "Fast scan of the 100 most common ports."},
  {"Quick scan plus",       "-sV -T4 -O -F --version-light",            "Fast scan with OS + version (light)."},
  {"Intense scan",          "-T4 -A -v",                                "OS + version + script + traceroute."},
  {"Intense scan, all TCP", "-p 1-65535 -T4 -A -v",                     "All 65535 TCP ports, aggressive."},
  {"Intense scan, no ping", "-T4 -A -v -Pn",                            "Treat all hosts as online (skip host discovery)."},
  {"Ping scan",             "-sn",                                      "Host discovery only, no port scan."},
  {"Regular scan",          "",                                         "Default nmap with no extra options."},
  {"Service + version",     "-sV",                                      "Probe open ports for service/version info."},
  {"UDP scan (top)",        "-sU --top-ports 50 -T4",                   "Top 50 UDP ports (needs root)."},
  {"SYN stealth",           "-sS -T4",                                  "Half-open TCP SYN scan (needs root)."},
  {"Vuln scripts",          "-sV --script vuln",                        "Run the NSE 'vuln' category against services."},
  {"Full aggressive",       "-p- -sV -sC -O -T4 -Pn --min-rate 1000",   "Everything: all ports, scripts, OS, fast."},
};

char *catalog_profiles_json(void) {
    strbuf s; sb_init(&s);
    sb_puts(&s, "{\"type\":\"profiles\",\"profiles\":[");
    int n = (int)(sizeof PROFILES / sizeof PROFILES[0]);
    for (int i = 0; i < n; i++) {
        if (i) sb_putc(&s, ',');
        sb_putc(&s, '{');
        sb_puts(&s, "\"name\":"); sb_json_str(&s, PROFILES[i].name);
        sb_puts(&s, ",\"args\":"); sb_json_str(&s, PROFILES[i].args);
        sb_puts(&s, ",\"desc\":"); sb_json_str(&s, PROFILES[i].desc);
        sb_putc(&s, '}');
    }
    sb_puts(&s, "]}");
    return sb_detach(&s);
}

/* ---- NSE catalog ---- */
static const char *CANDIDATES[] = {
    "/usr/share/nmap/scripts",
    "/usr/local/share/nmap/scripts",
    "/opt/homebrew/share/nmap/scripts",
    "/opt/local/share/nmap/scripts",
    "C:\\Program Files (x86)\\Nmap\\scripts",
    "C:\\Program Files\\Nmap\\scripts",
    NULL
};

#if defined(_WIN32)
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

static int dir_exists(const char *path) {
#if defined(_WIN32)
    DWORD a = GetFileAttributesA(path);
    return (a != INVALID_FILE_ATTRIBUTES) && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

/* read a whole (small) file into a malloc'd NUL-terminated buffer */
static char *read_file(const char *path, long maxbytes) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    if (sz > maxbytes) sz = maxbytes;
    char *b = xmalloc((size_t)sz + 1);
    size_t got = fread(b, 1, (size_t)sz, f);
    b[got] = 0;
    fclose(f);
    return b;
}

/* extract categories {"a","b"} and description [[ ... ]] from an .nse file */
static void parse_nse(const char *src, strbuf *cats_json, strbuf *desc) {
    /* categories */
    sb_puts(cats_json, "[");
    const char *c = strstr(src, "categories");
    if (c) {
        const char *brace = strchr(c, '{');
        const char *close = brace ? strchr(brace, '}') : NULL;
        if (brace && close) {
            int first = 1;
            const char *p = brace + 1;
            while (p < close) {
                const char *q = strchr(p, '"');
                if (!q || q >= close) break;
                const char *r = strchr(q + 1, '"');
                if (!r || r > close) break;
                if (!first) sb_putc(cats_json, ',');
                first = 0;
                strbuf t; sb_init(&t);
                sb_putn(&t, q + 1, (size_t)(r - q - 1));
                sb_json_str(cats_json, t.buf);
                sb_free(&t);
                p = r + 1;
            }
        }
    }
    sb_puts(cats_json, "]");

    /* description = [[ ... ]] */
    const char *d = strstr(src, "description");
    if (d) {
        const char *open = strstr(d, "[[");
        if (open) {
            open += 2;
            const char *end = strstr(open, "]]");
            size_t len = end ? (size_t)(end - open) : strlen(open);
            if (len > 400) len = 400;
            /* trim leading whitespace/newlines */
            while (len && (*open == '\n' || *open == '\r' || *open == ' ')) { open++; len--; }
            sb_putn(desc, open, len);
        }
    }
}

/* batching context */
typedef struct {
    emit_fn emit;
    void   *ud;
    int     batch_size;
    int     inbatch;     /* scripts in the current batch */
    int     total;
    strbuf  buf;         /* comma-separated script objects for current batch */
} nse_ctx;

static void nse_flush(nse_ctx *x) {
    if (x->inbatch == 0) return;
    strbuf m; sb_init(&m);
    sb_puts(&m, "{\"type\":\"nse_batch\",\"scripts\":[");
    sb_puts(&m, x->buf.buf);
    sb_puts(&m, "]}");
    x->emit(x->ud, sb_detach(&m));
    sb_reset(&x->buf);
    x->inbatch = 0;
}

/* read, parse and append one .nse file to the current batch */
static void nse_add(nse_ctx *x, const char *dir, const char *fname, char sep) {
    size_t L = strlen(fname);
    if (L < 5 || strcmp(fname + L - 4, ".nse") != 0) return;
    char full[1200];
    snprintf(full, sizeof full, "%s%c%s", dir, sep, fname);
    char *src = read_file(full, 65536);
    if (!src) return;

    strbuf cats; sb_init(&cats);
    strbuf desc; sb_init(&desc);
    parse_nse(src, &cats, &desc);
    free(src);

    if (x->inbatch) sb_putc(&x->buf, ',');
    sb_putc(&x->buf, '{');
    strbuf id; sb_init(&id);
    sb_putn(&id, fname, L - 4);           /* drop ".nse" */
    sb_puts(&x->buf, "\"id\":"); sb_json_str(&x->buf, id.buf);
    sb_free(&id);
    sb_puts(&x->buf, ",\"categories\":"); sb_puts(&x->buf, cats.buf);
    sb_puts(&x->buf, ",\"desc\":"); sb_json_str(&x->buf, desc.buf);
    sb_putc(&x->buf, '}');
    sb_free(&cats); sb_free(&desc);

    x->inbatch++; x->total++;
    if (x->inbatch >= x->batch_size) nse_flush(x);
}

void catalog_nse_emit(const char *override_dir, int batch_size, emit_fn emit, void *ud) {
    const char *dir = NULL;
    if (override_dir && *override_dir && dir_exists(override_dir)) dir = override_dir;
    else for (int i = 0; CANDIDATES[i]; i++) if (dir_exists(CANDIDATES[i])) { dir = CANDIDATES[i]; break; }

    /* begin */
    {
        strbuf b; sb_init(&b);
        sb_puts(&b, "{\"type\":\"nse_begin\",\"dir\":");
        sb_json_str(&b, dir ? dir : "");
        sb_putc(&b, '}');
        emit(ud, sb_detach(&b));
    }

    nse_ctx x = { emit, ud, batch_size > 0 ? batch_size : 60, 0, 0, {0,0,0} };
    sb_init(&x.buf);

    if (dir) {
#if defined(_WIN32)
        char pat[1200]; snprintf(pat, sizeof pat, "%s\\*.nse", dir);
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(pat, &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do { nse_add(&x, dir, fd.cFileName, '\\'); }
            while (FindNextFileA(h, &fd));
            FindClose(h);
        }
#else
        DIR *dp = opendir(dir);
        if (dp) {
            struct dirent *de;
            while ((de = readdir(dp)) != NULL) nse_add(&x, dir, de->d_name, '/');
            closedir(dp);
        }
#endif
    }
    nse_flush(&x);
    sb_free(&x.buf);

    /* end */
    {
        strbuf b; sb_init(&b);
        sb_printf(&b, "{\"type\":\"nse_end\",\"count\":%d}", x.total);
        emit(ud, sb_detach(&b));
    }
}

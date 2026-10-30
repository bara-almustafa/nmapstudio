#include "server.h"
#include "scan.h"
#include "db.h"
#include "catalog.h"
#include "mqueue.h"
#include "util.h"
#include "platform.h"
#include "mongoose.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#if defined(NS_HAVE_EMBEDDED_WEB)
#include "embedded_web.h"
#endif

typedef struct {
    struct mg_mgr mgr;
    mqueue        outq;
    Scan         *scan;
    int           run_id;
    sqlite3      *db;
    const ServerOpts *opt;
} App;

static volatile int g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

/* scan thread -> enqueue for broadcast (takes ownership of json) */
static void scan_emit(void *ud, char *json) {
    App *a = ud;
    mq_push(&a->outq, json);
}

static void broadcast(App *a, const char *msg, size_t len) {
    for (struct mg_connection *c = a->mgr.conns; c; c = c->next)
        if (c->is_websocket)
            mg_ws_send(c, msg, len, WEBSOCKET_OP_TEXT);
}

/* All WS replies go through the paced out-queue (drained by the poll loop a
   bounded amount at a time) so a connection's send buffer never balloons past
   what the client can absorb in one read window. Takes ownership of json. */
static void reply(App *a, char *json_owned) {
    mq_push(&a->outq, json_owned);
}

/* emit_fn adapter for streaming producers (NSE catalog, replay): ud is App* */
static void emit_to_conn(void *ud, char *json) {
    reply((App *)ud, json);
}

/* ---- content type by extension ---- */
static const char *ctype_for(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return "application/octet-stream";
    if (!strcmp(dot, ".html")) return "text/html; charset=utf-8";
    if (!strcmp(dot, ".js"))   return "application/javascript; charset=utf-8";
    if (!strcmp(dot, ".css"))  return "text/css; charset=utf-8";
    if (!strcmp(dot, ".svg"))  return "image/svg+xml";
    if (!strcmp(dot, ".json")) return "application/json";
    return "text/plain; charset=utf-8";
}

static void serve_asset(struct mg_connection *c, const char *uri) {
    const char *name = (!strcmp(uri, "/")) ? "/index.html" : uri;
#if defined(NS_HAVE_EMBEDDED_WEB)
    for (int i = 0; i < WEB_ASSETS_COUNT; i++) {
        if (!strcmp(WEB_ASSETS[i].name, name)) {
            mg_printf(c, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
                         "Cache-Control: no-cache\r\nContent-Length: %u\r\n\r\n",
                      WEB_ASSETS[i].ctype ? WEB_ASSETS[i].ctype : ctype_for(name),
                      WEB_ASSETS[i].len);
            mg_send(c, WEB_ASSETS[i].data, WEB_ASSETS[i].len);
            c->is_resp = 0;   /* response complete: let the connection serve more */
            return;
        }
    }
#endif
    mg_http_reply(c, 404, "Content-Type: text/plain\r\n", "not found: %s\n", name);
}

/* ---- WebSocket command dispatch ---- */
static void handle_command(App *a, struct mg_connection *c, const char *json) {
    char cmd[64] = {0};
    if (!json_get_str(json, "cmd", cmd, sizeof cmd)) return;

    (void)c;
    if (!strcmp(cmd, "scan")) {
        if (a->scan && scan_running(a->scan)) {
            reply(a, xstrdup("{\"type\":\"log\",\"level\":\"error\",\"msg\":\"a scan is already running\"}"));
            return;
        }
        if (a->scan) { scan_join_free(a->scan); a->scan = NULL; }

        char targets[2048] = {0}, args[2048] = {0}, name[256] = {0};
        json_get_str(json, "targets", targets, sizeof targets);
        json_get_str(json, "args", args, sizeof args);
        json_get_str(json, "name", name, sizeof name);

        int run_id = db_create_run(a->db, name[0] ? name : "scan", args, targets);
        a->run_id = run_id;

        char err[256] = {0};
        Scan *s = scan_start(a->opt->nmap_path, a->opt->db_path, run_id,
                             targets, args, scan_emit, a, err, sizeof err);
        if (!s) {
            strbuf b; sb_init(&b);
            sb_puts(&b, "{\"type\":\"log\",\"level\":\"error\",\"msg\":");
            sb_json_str(&b, err[0] ? err : "failed to start scan");
            sb_putc(&b, '}');
            reply(a, sb_detach(&b));
            return;
        }
        a->scan = s;
        strbuf b; sb_init(&b);
        sb_printf(&b, "{\"type\":\"started\",\"scan\":%d,\"targets\":", run_id);
        sb_json_str(&b, targets);
        sb_puts(&b, ",\"args\":"); sb_json_str(&b, args);
        sb_putc(&b, '}');
        reply(a, sb_detach(&b));

    } else if (!strcmp(cmd, "stop")) {
        if (a->scan) scan_stop(a->scan);

    } else if (!strcmp(cmd, "history")) {
        reply(a, db_runs_json(a->db));

    } else if (!strcmp(cmd, "load")) {
        int id = (int)json_get_int(json, "scan", 0);
        db_replay_emit(a->db, id, emit_to_conn, a);

    } else if (!strcmp(cmd, "diff")) {
        int x = (int)json_get_int(json, "a", 0);
        int y = (int)json_get_int(json, "b", 0);
        reply(a, db_diff_json(a->db, x, y));

    } else if (!strcmp(cmd, "inventory")) {
        reply(a, db_inventory_json(a->db));

    } else if (!strcmp(cmd, "profiles")) {
        reply(a, catalog_profiles_json());

    } else if (!strcmp(cmd, "nse")) {
        catalog_nse_emit(a->opt->nse_dir, 40, emit_to_conn, a);
    }
}

static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    App *a = (App *)c->fn_data;
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *)ev_data;
        if (mg_match(hm->uri, mg_str("/ws"), NULL)) {
            mg_ws_upgrade(c, hm, NULL);
            return;
        }
        if (a->opt->webdir) {
            struct mg_http_serve_opts opts = {0};
            opts.root_dir = a->opt->webdir;
            mg_http_serve_dir(c, hm, &opts);
            return;
        }
        char uri[512];
        size_t n = hm->uri.len < sizeof uri - 1 ? hm->uri.len : sizeof uri - 1;
        memcpy(uri, hm->uri.buf, n); uri[n] = 0;
        serve_asset(c, uri);
    } else if (ev == MG_EV_WS_MSG) {
        struct mg_ws_message *wm = (struct mg_ws_message *)ev_data;
        char *j = xmalloc(wm->data.len + 1);
        memcpy(j, wm->data.buf, wm->data.len);
        j[wm->data.len] = 0;
        handle_command(a, c, j);
        free(j);
    }
}

int server_run(const ServerOpts *opts) {
    App app;
    memset(&app, 0, sizeof app);
    app.opt = opts;
    mq_init(&app.outq);
    app.db = db_open(opts->db_path);
    if (!app.db) { fprintf(stderr, "cannot open database %s\n", opts->db_path); return 1; }

    signal(SIGINT, on_sigint);
#if !defined(_WIN32)
    signal(SIGPIPE, SIG_IGN);
#endif

    mg_log_set(MG_LL_ERROR);
    mg_mgr_init(&app.mgr);
    struct mg_connection *l = mg_http_listen(&app.mgr, opts->listen, ev_handler, &app);
    if (!l) { fprintf(stderr, "cannot listen on %s\n", opts->listen); return 1; }

    const char *url = strstr(opts->listen, "://");
    url = url ? url + 3 : opts->listen;
    printf("\n  Nmap Studio  ->  http://%s\n", url);
    printf("  database: %s\n", opts->db_path);
    printf("  (Ctrl-C to stop)\n\n");

    if (opts->open_browser) {
        char u[256]; snprintf(u, sizeof u, "http://%s", url);
        ns_open_browser(u);
    }

    while (!g_stop) {
        mg_mgr_poll(&app.mgr, 50);

        /* Paced drain: feed the out-queue to clients a bounded amount per
           poll so no connection's send buffer balloons past what the client
           can absorb in one read window (some environments reset the socket
           otherwise). Skip entirely while any WS client is still backed up. */
        size_t maxpending = 0;
        for (struct mg_connection *c = app.mgr.conns; c; c = c->next)
            if (c->is_websocket && c->send.len > maxpending) maxpending = c->send.len;

        if (maxpending < 8 * 1024) {
            size_t budget = 0;
            char *msg;
            while (budget < 8 * 1024 && (msg = mq_pop(&app.outq)) != NULL) {
                size_t n = strlen(msg);
                broadcast(&app, msg, n);
                budget += n;
                free(msg);
            }
        }

        /* reap finished scan */
        if (app.scan && !scan_running(app.scan)) {
            scan_join_free(app.scan);
            app.scan = NULL;
        }
    }

    printf("\nshutting down...\n");
    if (app.scan) { scan_stop(app.scan); scan_join_free(app.scan); }
    mg_mgr_free(&app.mgr);
    mq_destroy(&app.outq);
    db_close(app.db);
    return 0;
}

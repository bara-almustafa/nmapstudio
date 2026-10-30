/* server.h - embedded HTTP + WebSocket server */
#ifndef NS_SERVER_H
#define NS_SERVER_H

typedef struct {
    const char *listen;     /* e.g. "http://127.0.0.1:8777" */
    const char *db_path;
    const char *nmap_path;
    const char *nse_dir;    /* optional override, may be NULL */
    const char *webdir;     /* optional on-disk web root for dev, may be NULL */
    int         open_browser;
} ServerOpts;

/* Runs the server loop until SIGINT. Returns process exit code. */
int server_run(const ServerOpts *opts);

#endif

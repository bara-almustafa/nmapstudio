#include "server.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *p) {
    printf(
"Nmap Studio - a modern cross-platform Nmap frontend\n\n"
"Usage: %s [options]\n\n"
"  --host ADDR      bind address (default 127.0.0.1)\n"
"  --port N         listen port (default 8777)\n"
"  --db PATH        SQLite database file (default ./nmapstudio.db)\n"
"  --nmap PATH      path to the nmap binary (default: nmap in PATH)\n"
"  --scripts DIR    override the NSE scripts directory\n"
"  --webdir DIR     serve UI from disk instead of the embedded copy (dev)\n"
"  --no-open        do not launch a browser on startup\n"
"  -h, --help       show this help\n\n", p);
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    int port = 8777;
    const char *db = "nmapstudio.db";
    const char *nmap = "nmap";
    const char *scripts = NULL;
    const char *webdir = NULL;
    int open_browser = 1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--host") && i+1 < argc) host = argv[++i];
        else if (!strcmp(a, "--port") && i+1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(a, "--db") && i+1 < argc) db = argv[++i];
        else if (!strcmp(a, "--nmap") && i+1 < argc) nmap = argv[++i];
        else if (!strcmp(a, "--scripts") && i+1 < argc) scripts = argv[++i];
        else if (!strcmp(a, "--webdir") && i+1 < argc) webdir = argv[++i];
        else if (!strcmp(a, "--no-open")) open_browser = 0;
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown option: %s\n", a); usage(argv[0]); return 2; }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);   /* line-buffered: show the banner at once */

    char listen[128];
    snprintf(listen, sizeof listen, "http://%s:%d", host, port);

    ServerOpts opts = {0};
    opts.listen = listen;
    opts.db_path = db;
    opts.nmap_path = nmap;
    opts.nse_dir = scripts;
    opts.webdir = webdir;
    opts.open_browser = open_browser;

    return server_run(&opts);
}

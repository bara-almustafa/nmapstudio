# Nmap Studio

A modern, cross-platform **Nmap frontend written in C** — a spiritual successor to
Zenmap. The engine is portable C (process control, a streaming Nmap-XML parser,
SQLite storage, scan diffing). It serves a rich web UI over a local HTTP +
WebSocket server, so you get live-updating tables, an interactive topology graph,
a visual command builder, an NSE browser, scan history & diffing — all from a
single self-contained binary on **Linux, macOS, and Windows**.

```
┌──────────────────────────────────────────────────────────┐
│  nmapstudio (one native binary)                           │
│                                                            │
│   nmap -oX -  ──▶  streaming XML parser  ──▶  model        │
│       │                                        │          │
│       │                                        ▼          │
│   (worker thread)                        SQLite (history) │
│       │                                        │          │
│       ▼                                        ▼          │
│   thread-safe queue ──▶ HTTP + WebSocket server (mongoose) │
│                                   │                        │
└───────────────────────────────────┼────────────────────────┘
                                     ▼
                         your browser  (embedded UI)
```

## Features

**Engine (C)**
- **Live streaming results** — drives `nmap -oX - --stats-every 2s` and parses the
  XML *incrementally* with a hand-written streaming tokenizer, so hosts/ports
  appear as they are discovered instead of after the scan finishes.
- **Real progress bar** — parses `<taskprogress>` for percent + ETC.
- **Safe process execution** — builds an `argv` array and spawns Nmap directly
  (`fork`/`execvp` on POSIX, `CreateProcess` on Windows). **No shell** is ever
  involved, so targets/arguments can't be shell-injected.
- **SQLite persistence** — every scan is stored as an immutable run (hosts,
  ports, services, raw XML) so history and diffing come for free.
- **Scan diffing** — compare any two runs: new open ports, ports gone/closed,
  and services whose version changed.
- **Host inventory** — every host ever seen, aggregated across all scans.

**UI (served from the binary)**
- Live **host / port table** with filtering and NSE script output inline.
- Interactive **topology graph** (force-directed canvas; node size = open ports).
- **Visual command builder** — toggle flags/timing/ports and watch the `nmap`
  command update live; the command box is editable and is what gets executed.
- Built-in **scan profiles** (Quick, Intense, Vuln scripts, Full aggressive, …).
- **NSE script browser** — searchable catalog of the ~600 scripts with their
  categories and descriptions (read straight from the `.nse` headers); click to
  add `--script=`.
- **Scan history** + one-click reload of any past scan.
- **Diff view** and **inventory view**.
- **Tool chaining** — right-click (the `⋯` button) a port to copy ready-to-run
  commands: `whatweb`, `nuclei`, `ffuf`, `searchsploit`, `ncat`, `smbclient`,
  `ssh`, a focused `nmap -sCV`, etc.
- **Export** the current results to **HTML / CSV / JSON**.

## Building

You need a C compiler and CMake ≥ 3.15. The two third-party single-file
dependencies (SQLite amalgamation + Mongoose) are vendored under `third_party/`.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The result is a single binary: `build/nmapstudio` (`build/nmapstudio.exe` on
Windows). The web UI is embedded into it at build time, so there are no other
files to ship.

### Platform notes
- **Linux**: needs pthreads (standard). `apt install cmake build-essential`.
- **macOS**: `xcode-select --install`, then the same CMake commands. Works with
  both Apple-Silicon (`/opt/homebrew`) and Intel Nmap install paths.
- **Windows**: build with MSVC (`cmake --build build --config Release`) or
  MinGW. Links against `ws2_32`.

> The UI is embedded by default. To iterate on the web assets without rebuilding,
> pass `--webdir web` to serve them from disk.

## Usage

```bash
./build/nmapstudio                 # listens on 127.0.0.1:8777 and opens a browser
./build/nmapstudio --no-open       # don't auto-open a browser
./build/nmapstudio --port 9000
./build/nmapstudio --db engagement.db          # choose where scans are stored
./build/nmapstudio --nmap /usr/local/bin/nmap  # custom nmap path
./build/nmapstudio --scripts /usr/share/nmap/scripts   # override NSE dir
```

Then enter targets (e.g. `scanme.nmap.org`, `192.168.1.0/24`, `10.0.0.1-50`),
pick a profile or toggle flags, and hit **Scan**.

### Privileges
SYN (`-sS`), OS detection (`-O`) and UDP (`-sU`) scans require raw-socket
privileges. Run the tool (or grant Nmap the capability) accordingly:

```bash
sudo ./build/nmapstudio
# or, grant nmap raw-socket caps once (Linux):
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

## Command-line options

| Option | Description |
|---|---|
| `--host ADDR` | Bind address (default `127.0.0.1`) |
| `--port N` | Listen port (default `8777`) |
| `--db PATH` | SQLite database file (default `./nmapstudio.db`) |
| `--nmap PATH` | Path to the `nmap` binary |
| `--scripts DIR` | Override the NSE scripts directory |
| `--webdir DIR` | Serve the UI from disk instead of the embedded copy |
| `--no-open` | Do not launch a browser on startup |

## Project layout

```
src/
  main.c        CLI + startup
  server.c      HTTP + WebSocket server, command dispatch, paced broadcast
  scan.c        worker thread: spawn nmap, feed parser, persist, emit events
  xml.c         incremental (streaming) XML tokenizer
  model.c       Host/Port/Service/Script/Hop model + JSON serialization
  db.c          SQLite schema, persistence, replay, diffing, inventory
  catalog.c     scan profiles + NSE script catalog scanner
  platform.c    threads/mutex + process spawn (POSIX & Windows) + browser open
  mqueue.c      thread-safe message queue
  util.c        string builder, JSON writer/escaper, tiny JSON reader
web/            index.html / app.js / style.css  (embedded into the binary)
third_party/    sqlite3, mongoose  (vendored single-file libraries)
cmake/embed.cmake   turns web/ into a C header at build time
```

## Security / authorization

Only scan hosts and networks you are authorized to test. This is a frontend for
Nmap; it inherits Nmap's capabilities and your responsibilities.

## License

The application code in `src/`, `web/`, and `cmake/` is provided as-is. Vendored
dependencies keep their own licenses: SQLite is public domain; Mongoose is dual
GPLv2 / commercial — review Mongoose's license before redistributing binaries.

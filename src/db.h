/* db.h - SQLite persistence: scan history + results + diffing */
#ifndef NS_DB_H
#define NS_DB_H

#include "model.h"
#include "sqlite3.h"

sqlite3 *db_open(const char *path);   /* opens, enables WAL, creates schema */
void     db_close(sqlite3 *db);

/* create a new scan run row, returns its id (>0) or -1 */
int  db_create_run(sqlite3 *db, const char *name, const char *args, const char *targets);
void db_finish_run(sqlite3 *db, int run_id, double elapsed, const char *summary,
                   int up, int down, const char *status, const char *raw_xml);
void db_insert_host(sqlite3 *db, int run_id, const Host *h);

/* JSON producers (caller frees) */
char *db_runs_json(sqlite3 *db);                 /* [{id,name,targets,started,...}] */
char *db_diff_json(sqlite3 *db, int a, int b);   /* {type:"diff",added:[],removed:[],changed:[]} */
char *db_inventory_json(sqlite3 *db);            /* aggregated host inventory across runs */

/* Replay a stored scan as a stream of small messages (so no frame is huge):
     {type:"replay_begin",scan:id}
     {type:"host",...}          (one per stored host, reusing the live shape)
     {type:"replay_end",scan:id}   */
void db_replay_emit(sqlite3 *db, int run_id, emit_fn emit, void *ud);

#endif

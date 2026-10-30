/* catalog.h - scan profiles + NSE script catalog */
#ifndef NS_CATALOG_H
#define NS_CATALOG_H

#include "util.h"   /* emit_fn */

/* Returns JSON {type:"profiles",profiles:[...]} (caller frees). Small. */
char *catalog_profiles_json(void);

/* Scan the Nmap scripts dir for *.nse and stream the catalog to `emit` in
   small batches (so no single WebSocket frame gets huge). Emits:
     {type:"nse_begin",dir:"..."}
     {type:"nse_batch",scripts:[...]}   (repeated)
     {type:"nse_end",count:N}
   `override_dir` may be NULL (auto-detect). */
void catalog_nse_emit(const char *override_dir, int batch_size, emit_fn emit, void *ud);

#endif

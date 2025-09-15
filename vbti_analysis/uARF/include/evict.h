/**
 * Functionality related to eviction.
 *
 * Provides means to build evictions sets, reduce and access them.
 */

#include "dll.h"
#include <stdbool.h>
#include <stdint.h>

typedef UarfDll Es;
typedef UarfDllNode EsElem;

void uarf_es_init(Es **es, size_t es_size);
void uarf_es_deinit(Es *es);
void uarf_es_access_fbf(Es *es, size_t num_rep);
void uarf_es_access_local(Es *es, size_t num_rep);
float uarf_es_effectiveness(Es *es, void *victim, size_t reps, bool is_in_cache(void *),
                            void es_access(Es *es, size_t num_rep));
size_t uarf_es_reduce(Es *es, void *victim,
                      float es_eff(Es *es, void *victim, size_t reps,
                                   void es_access(Es *es, size_t num_rep)),
                      void es_access(Es *es, size_t num_rep));

#ifndef dissect_omap_h_
#define dissect_omap_h_

#include "buffer.h"
#include "util.h"

struct omap;
typedef struct omap OrderedMap;

OrderedMap *orderedMap_Create();
void orderedMap_AddKey(OrderedMap *map, char *key);
bool orderedMap_HasKey(OrderedMap *map, char *key);
Buffer *orderedMap_Get(OrderedMap *map, char *key);
char *orderedMap_GetKeyAtIndex(OrderedMap *map, int index);
int orderedMap_GetNumberOfKeys(OrderedMap *map);

void orderedMap_Put(OrderedMap *map, char *key, Buffer *value);
void orderedMap_DropAll(OrderedMap *map);

#endif

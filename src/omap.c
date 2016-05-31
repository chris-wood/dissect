#include "omap.h"

struct omap {
    int numEntries;
    char **keys;
    Buffer **values;
};

OrderedMap *
orderedMap_Create()
{
    OrderedMap *map = (OrderedMap *) malloc(sizeof(OrderedMap));
    if (map != NULL) {
        map->numEntries = 0;
        map->keys = NULL;
        map->values = NULL;
    }
    return map;
}

bool
orderedMap_HasKey(OrderedMap *map, char *key)
{
    for (int i = 0; i < map->numEntries; i++) {
        if (strcmp(map->keys[i], key) == 0) {
            return true;
        }
    }
    return false;
}

Buffer *
orderedMap_Get(OrderedMap *map, char *key)
{
    for (int i = 0; i < map->numEntries; i++) {
        if (strcmp(map->keys[i], key) == 0) {
            return map->values[i];
        }
    }

    return NULL;
}

char *
orderedMap_GetKeyAtIndex(OrderedMap *map, int index)
{
    if (index < map->numEntries) {
        return map->keys[index];
    }
    return NULL;
}

int
orderedMap_GetNumberOfKeys(OrderedMap *map)
{
    return map->numEntries;
}

void
orderedMap_AddKey(OrderedMap *map, char *key)
{
    map->numEntries++;

    if (map->numEntries == 0) {
        map->keys = (char **) malloc(sizeof(char *) * map->numEntries);
        map->values = (Buffer **) malloc(sizeof(Buffer *) * map->numEntries);
    } else {
        map->keys = (char **) realloc(map->keys, sizeof(char *) * map->numEntries);
        map->values = (Buffer **) realloc(map->values, sizeof(Buffer *) * map->numEntries);
    }

    map->values[map->numEntries - 1] = NULL;

    map->keys[map->numEntries - 1] = (char *) malloc(strlen(key));
    strcpy(map->keys[map->numEntries - 1], key);
}

void
orderedMap_Put(OrderedMap *map, char *key, Buffer *value)
{
    if (orderedMap_HasKey(map, key)) {
        for (int i = 0; i < map->numEntries; i++) {
            if (strcmp(map->keys[i], key) == 0) {
                map->values[i] = value;
            }
        }
    }
}

void
orderedMap_DropAll(OrderedMap *map)
{
    for (int i = 0; i < map->numEntries; i++) {
        map->values[i] = NULL;
    }
}

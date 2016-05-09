#include "types.h"

static char *
_types_SearchTree(uint32_t numberOfTypes, uint16_t type[numberOfTypes])
{
    return NULL;
}

static char *
_types_TreeToStringWithIndex(TypespaceTreeNode *root, uint32_t numberOfTypes, uint16_t type[numberOfTypes], uint32_t index)
{
    for (size_t i = 0; i < root->numTypes; i++) {
        if (type[index] == root->types[i]) {
            if (numberOfTypes == index + 1) {
                return root->typeStrings[i];
            } else if (root->children != NULL) {
                for (size_t j = 0; j < root->numChildren; j++) {
                    char *result = _types_TreeToStringWithIndex(root->children[j], numberOfTypes, type, index + 1);
                    if (result != NULL) {
                        return result;
                    }
                }
            }
        }
    }

    return NULL;
}

char *
types_TreeToString(uint32_t numberOfTypes, uint16_t type[numberOfTypes])
{
    return _types_TreeToStringWithIndex(&top_level_types_node, numberOfTypes, type, 0);
}

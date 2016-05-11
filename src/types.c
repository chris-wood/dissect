#include "types.h"

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

static bool
_types_IsLeaf(TypespaceTreeNode *root, uint32_t numberOfTypes, uint16_t type[numberOfTypes], uint32_t index)
{
    bool result = false;

    for (size_t i = 0; i < root->numTypes; i++) {
        if (type[index] == root->types[i]) {
            if (numberOfTypes == index + 1) {
                return root->isLeaf;
            } else if (root->children != NULL) {
                for (size_t j = 0; j < root->numChildren; j++) {
                    result |= _types_IsLeaf(root->children[j], numberOfTypes, type, index + 1);
                }
            }
        }
    }

    return result;
}

char *
types_TreeToString(uint32_t numberOfTypes, uint16_t type[numberOfTypes])
{
    return _types_TreeToStringWithIndex(&top_level_types_node, numberOfTypes, type, 0);
}

bool
types_IsLeaf(uint32_t numberOfTypes, uint16_t type[numberOfTypes])
{
    return _types_IsLeaf(&top_level_types_node, numberOfTypes, type, 0);
}

void
types_ParseStringTree(char *treeString, uint32_t *numberOfTypes, uint16_t **type)
{
    TypespaceTreeNode *root = &top_level_types_node;

    uint32_t numTypes = 0;
    char *token = strtok(treeString, " ");

    // TODO: we should assert this to be true
    *type = NULL;

    while (token) {
        bool match = false;
        for (int i = 0; i < root->numTypes; i++) {
            if (strcmp(token, root->typeStrings[i]) == 0) {
                numTypes++;
                if (*type == NULL) {
                    *type = malloc(numTypes * sizeof(**type));
                } else {
                    *type = realloc(*type, numTypes * sizeof(**type));
                }
                *type[numTypes - 1] = root->types[i];

                match = true;
            }
        }
        if (!match) {
            if (*type != NULL) {
                free(*type);
                *type = NULL;
            }
            *numberOfTypes = 0;
            return;
        }

        // Continue down the tree.
        token = strtok(NULL, " ");
    }
}

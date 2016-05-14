#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "buffer.h"
#include "reporter.h"
#include "types.h"
#include "cJSON.h"

typedef struct {
    FILE *fp;
    size_t numPackets;
} _FileReporterContext;

typedef struct {
    _FileReporterContext *fileContext;
    cJSON *currentPacket;
} _JSONReporterContext;

struct reporter {
    void (*start)(void *);
    void (*end)(void *);
    void (*reportFunction)(void *, uint32_t , uint16_t *, Buffer *);
    void (*destroy)(void **);

    FILE *(*getFileDescriptor)(void *);
    void *context; // sloppy
    bool hasFilter;
};

FILE *
_fileReporter_GetFileDescriptor(_FileReporterContext *context)
{
    return context->fp;
}

FILE *
_jsonReporter_GetFileDescriptor(_JSONReporterContext *context)
{
    return context->fileContext->fp;
}

static void
_fileReporter_Report(_FileReporterContext *context, uint32_t numberOfTypes, uint16_t type[numberOfTypes], Buffer *buffer)
{
    for (uint32_t i = 0; i < numberOfTypes; i++) {
        fprintf(context->fp, " ");
    }

    char *typeString = types_TreeToString(numberOfTypes, type);
    if (typeString != NULL) {
        if (buffer != NULL) {
            char *bufferString = buffer_ToString(buffer);
            fprintf(context->fp, "%s: %s\n", typeString, bufferString);
            free(bufferString);
        } else {
            fprintf(context->fp, "%s: \n", typeString);
        }
    }

    fprintf(context->fp, "\n");
}

static void
_fileReporter_Start(_FileReporterContext *context)
{
    fprintf(context->fp, "#### PACKET %zu\n", context->numPackets);
}

static void
_fileReporter_End(_FileReporterContext *context)
{
    fprintf(context->fp, "\n");
}

static void
_fileReporter_Destroy(_FileReporterContext **contextPtr)
{
    _FileReporterContext *reporter = *contextPtr;
    free(reporter);
    *contextPtr = NULL;
}

static void
_jsonReporter_Report(_JSONReporterContext *context, uint32_t numberOfTypes, uint16_t type[numberOfTypes], Buffer *buffer)
{
    cJSON *root = context->currentPacket;

    bool isLeaf = types_IsLeaf(numberOfTypes, type);

    for (int i = 1; i <= numberOfTypes; i++) {
        char *key = types_TreeToString(i, type);
        cJSON *item = cJSON_GetObjectItem(root, key);

        if (item != NULL) { // recurse into the tree
            if (isLeaf && i == numberOfTypes) {
                char *bufferString = buffer_ToString(buffer);
                if (bufferString != NULL && strlen(bufferString) > 0) {
                    cJSON_AddStringToObject(item, key, bufferString);
                }
                free(bufferString);
            }

            root = item;
        } else { // create a new node in the tree
            cJSON *newItem = cJSON_CreateObject();

            if (isLeaf && i == numberOfTypes) {
                char *bufferString = buffer_ToString(buffer);
                if (bufferString != NULL && strlen(bufferString) > 0) {
                    cJSON_AddStringToObject(newItem, key, bufferString);
                }
                free(bufferString);
            }

            cJSON_AddItemToObject(root, key, newItem);
            root = newItem;
        }
    }
}

static void
_jsonReporter_Start(_JSONReporterContext *context)
{
    context->currentPacket = cJSON_CreateObject();
}

static void
_jsonReporter_End(_JSONReporterContext *context)
{
    char *packetString = cJSON_Print(context->currentPacket);
    fprintf(context->fileContext->fp, "%s\n", packetString);
    free(packetString);
    cJSON_Delete(context->currentPacket);
    context->currentPacket = NULL;
}

static void
_jsonReporter_Destroy(_JSONReporterContext **contextPtr)
{
    _JSONReporterContext *reporter = *contextPtr;
    if (reporter->currentPacket != NULL) {
        cJSON_Delete(reporter->currentPacket);
    }
    _fileReporter_Destroy(&reporter->fileContext);
    free(reporter);
    *contextPtr = NULL;
}

// TODO: CSV repoter writes a single header out to the file (based on filter) and then,
//   for each packet, collects the list of buffers to write and then writes it out when "finalized"

Reporter *
reporter_CreateRawFileReporter(FILE *fd)
{
    Reporter *reporter = malloc(sizeof(Reporter));
    reporter->reportFunction = (void (*)(void *, uint32_t, uint16_t *, Buffer *)) _fileReporter_Report;
    reporter->start = (void (*)(void *)) _fileReporter_Start;
    reporter->end = (void (*)(void *)) _fileReporter_End;
    reporter->destroy = (void (*)(void **)) _fileReporter_Destroy;
    reporter->getFileDescriptor = (FILE *(*)(void *)) _fileReporter_GetFileDescriptor;
    reporter->hasFilter = false;

    _FileReporterContext *context = malloc(sizeof(_FileReporterContext));
    context->fp = fd;
    context->numPackets = 0;
    reporter->context = context;

    return reporter;
}

Reporter *
reporter_CreateJSONFileReporter(FILE *fd)
{
    Reporter *reporter = malloc(sizeof(Reporter));
    reporter->reportFunction = (void (*)(void *, uint32_t, uint16_t *, Buffer *)) _jsonReporter_Report;
    reporter->start = (void (*)(void *)) _jsonReporter_Start;
    reporter->end = (void (*)(void *)) _jsonReporter_End;
    reporter->destroy = (void (*)(void **)) _jsonReporter_Destroy;
    reporter->getFileDescriptor = (FILE *(*)(void *)) _jsonReporter_GetFileDescriptor;
    reporter->hasFilter = false;

    _JSONReporterContext *context = malloc(sizeof(_JSONReporterContext));
    context->currentPacket = NULL;

    _FileReporterContext *fileContext = malloc(sizeof(_FileReporterContext));
    fileContext->fp = fd;
    fileContext->numPackets = 0;
    context->fileContext = fileContext;

    reporter->context = context;

    return reporter;
}

void
reporter_Destroy(Reporter **reporterPtr)
{
    Reporter *reporter = *reporterPtr;

    reporter->destroy(&reporter->context);
    free(reporter);

    *reporterPtr = NULL;
}

void
reporter_StartPacket(Reporter *reporter)
{
    reporter->start(reporter->context);
}

void
reporter_EndPacket(Reporter *reporter)
{
    reporter->end(reporter->context);
}

void
reporter_ReportTLV(Reporter *reporter, uint32_t numberOfTypes, uint16_t type[numberOfTypes], Buffer *value)
{
    reporter->reportFunction(reporter->context, numberOfTypes, type, value);
}

bool
reporter_IsRaw(Reporter *reporter)
{
    return !reporter->hasFilter;
}

FILE *
reporter_GetFileDescriptor(Reporter *reporter)
{
    return reporter->getFileDescriptor(reporter->context);
}

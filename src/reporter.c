#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "buffer.h"
#include "reporter.h"
#include "types.h"
#include "cJSON.h"
#include "omap.h"
#include "processor.h"
#include "packet.h"

typedef struct {
    size_t numPackets;
    FILE *fp;
} _FileReporterContext;

typedef struct {
    _FileReporterContext *fileContext;
    cJSON *currentPacket;
} _JSONReporterContext;

typedef struct {
    _FileReporterContext *fileContext;
    OrderedMap *map;
} _CSVReporterContext;

struct reporter {
    void (*start)(void *);
    void (*end)(void *);
    void (*addFilter)(void *, uint32_t , uint16_t *);
    void (*report)(void *, uint32_t , uint16_t *, Buffer *);
    void (*destroy)(void **);

    FILE *(*getFileDescriptor)(void *);

    int numberOfFilters;
    uint32_t *filterNumbers;
    uint16_t **filterTrees;

    bool isRaw;

    void *context; // sloppy
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

FILE *
_csvReporter_GetFileDescriptor(_CSVReporterContext *context)
{
    return context->fileContext->fp;
}

void
_csvReporter_AddFilter(_CSVReporterContext *context, uint32_t numberOfTypes, uint16_t type[numberOfTypes])
{
    char *typeString = types_TreeToString(numberOfTypes, type);
    orderedMap_AddKey(context->map, typeString);
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

static void
_csvReporter_Report(_CSVReporterContext *context, uint32_t numberOfTypes, uint16_t type[numberOfTypes], Buffer *buffer)
{
    char *typeString = types_TreeToString(numberOfTypes, type);
    orderedMap_Put(context->map, typeString, buffer);
}

static void
_csvReporter_Start(_CSVReporterContext *context)
{
    orderedMap_DropAll(context->map);
}

static void
_csvReporter_PrintValueAtIndex(_CSVReporterContext *context, int index)
{
    char *key = orderedMap_GetKeyAtIndex(context->map, index);
    if (key != NULL) {
        Buffer *value = orderedMap_Get(context->map, key);
        if (value != NULL) {
            char *bufferString = buffer_ToString(value);
            if (bufferString != NULL && strlen(bufferString) > 0) {
                fprintf(context->fileContext->fp, "%s", bufferString);
            }
            free(bufferString);
        }
    }
}

static void
_csvReporter_End(_CSVReporterContext *context)
{
    int numKeys = orderedMap_GetNumberOfKeys(context->map);

    for (int i = 0; i < numKeys - 1; i++) {
        _csvReporter_PrintValueAtIndex(context, i);
        fprintf(context->fileContext->fp, ",");
    }

    _csvReporter_PrintValueAtIndex(context, numKeys - 1);
    fprintf(context->fileContext->fp, "\n");
}

static void
_csvReporter_Destroy(_CSVReporterContext **contextPtr)
{
    _CSVReporterContext *reporter = *contextPtr;
    _fileReporter_Destroy(&reporter->fileContext);
    free(reporter);
    *contextPtr = NULL;
}

Reporter *
reporter_CreateRawFileReporter(FILE *fd)
{
    Reporter *reporter = malloc(sizeof(Reporter));
    reporter->report = (void (*)(void *, uint32_t, uint16_t *, Buffer *)) _fileReporter_Report;
    reporter->start = (void (*)(void *)) _fileReporter_Start;
    reporter->end = (void (*)(void *)) _fileReporter_End;
    reporter->destroy = (void (*)(void **)) _fileReporter_Destroy;
    reporter->getFileDescriptor = (FILE *(*)(void *)) _fileReporter_GetFileDescriptor;
    reporter->addFilter = NULL;
    reporter->isRaw = false;

    reporter->numberOfFilters = 0;
    reporter->filterNumbers = NULL;
    reporter->filterTrees = NULL;

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
    reporter->report = (void (*)(void *, uint32_t, uint16_t *, Buffer *)) _jsonReporter_Report;
    reporter->start = (void (*)(void *)) _jsonReporter_Start;
    reporter->end = (void (*)(void *)) _jsonReporter_End;
    reporter->destroy = (void (*)(void **)) _jsonReporter_Destroy;
    reporter->getFileDescriptor = (FILE *(*)(void *)) _jsonReporter_GetFileDescriptor;
    reporter->addFilter = NULL;
    reporter->isRaw = true;

    reporter->numberOfFilters = 0;
    reporter->filterNumbers = NULL;
    reporter->filterTrees = NULL;

    _JSONReporterContext *context = malloc(sizeof(_JSONReporterContext));
    context->currentPacket = NULL;

    _FileReporterContext *fileContext = malloc(sizeof(_FileReporterContext));
    fileContext->fp = fd;
    fileContext->numPackets = 0;
    context->fileContext = fileContext;

    reporter->context = context;

    return reporter;
}

Reporter *
reporter_CreateCSVFileReporter(FILE *fd)
{
    Reporter *reporter = malloc(sizeof(Reporter));
    reporter->report = (void (*)(void *, uint32_t, uint16_t *, Buffer *)) _csvReporter_Report;
    reporter->start = (void (*)(void *)) _csvReporter_Start;
    reporter->end = (void (*)(void *)) _csvReporter_End;
    reporter->destroy = (void (*)(void **)) _csvReporter_Destroy;
    reporter->getFileDescriptor = (FILE *(*)(void *)) _csvReporter_GetFileDescriptor;
    reporter->addFilter = (void (*)(void *, uint32_t, uint16_t *)) _csvReporter_AddFilter;
    reporter->isRaw = true;

    reporter->numberOfFilters = 0;
    reporter->filterNumbers = NULL;
    reporter->filterTrees = NULL;

    _CSVReporterContext *context = malloc(sizeof(_CSVReporterContext));

    _FileReporterContext *fileContext = malloc(sizeof(_FileReporterContext));
    fileContext->fp = fd;
    fileContext->numPackets = 0;

    context->fileContext = fileContext;
    context->map = orderedMap_Create();

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
    bool process = true; // show all by default if no filters are specified
    if (reporter->numberOfFilters > 0) {
        process = false;
        for (int i = 0; i < reporter->numberOfFilters; i++) {
            if (numberOfTypes >= reporter->filterNumbers[i]) {
                bool allMatch = true;
                for (int j = 0; j < reporter->filterNumbers[i]; j++) {
                    if (reporter->filterTrees[i][j] != type[j]) {
                        allMatch = false;
                        break;
                    }
                }
                if (allMatch) {
                    process = true;
                    break;
                }
            }
        }
    }

    if (process) {
        reporter->report(reporter->context, numberOfTypes, type, value);
    }
}

bool
reporter_IsRaw(Reporter *reporter)
{
    return !reporter->isRaw;
}

FILE *
reporter_GetFileDescriptor(Reporter *reporter)
{
    return reporter->getFileDescriptor(reporter->context);
}

static void
_reporter_AddFilter(Reporter *reporter, uint32_t numberOfTypes, uint16_t types[numberOfTypes])
{
    if (reporter->addFilter != NULL) {
        reporter->addFilter(reporter->context, numberOfTypes, types);
    }
}

bool
reporter_AddFilterByTypeTree(Reporter *reporter, uint32_t numberOfTypes, uint16_t types[numberOfTypes])
{
    // Add the new filter to the list
    reporter->numberOfFilters++;

    if (reporter->filterNumbers == NULL) {
        reporter->filterNumbers = (uint32_t *) malloc(reporter->numberOfFilters * sizeof(uint32_t));
    } else {
        reporter->filterNumbers = (uint32_t *) realloc(reporter->filterNumbers, reporter->numberOfFilters * sizeof(uint32_t));
    }
    reporter->filterNumbers[reporter->numberOfFilters - 1] = numberOfTypes;

    if (reporter->filterTrees == NULL) {
        reporter->filterTrees = (uint16_t **) malloc(reporter->numberOfFilters * sizeof(uint16_t*));
    } else {
        reporter->filterTrees = (uint16_t **) realloc(reporter->filterTrees, reporter->numberOfFilters * sizeof(uint16_t*));
    }

    reporter->filterTrees[reporter->numberOfFilters - 1] = (uint16_t *) malloc(numberOfTypes * sizeof(uint16_t));
    memcpy(reporter->filterTrees[reporter->numberOfFilters - 1], types, sizeof(uint16_t) * numberOfTypes);

    // Add the filter to the concrete reporter context
    _reporter_AddFilter(reporter, numberOfTypes, types);

    return true;
}

bool
reporter_AddFilterByString(Reporter *reporter, char *filter)
{
    uint32_t numberOfTypes;
    uint16_t *types;
    types_ParseStringTree(filter, &numberOfTypes, &types);

    return reporter_AddFilterByTypeTree(reporter, numberOfTypes, types);
}

void 
reporter_ProcessPacket(Reporter *reporter, Packet *packet)
{
    packet_Report(packet, reporter);
}

ProcessorInterface *ReporterAsProcessor = &(ProcessorInterface) {
    .Init = NULL,
    .ProcessPacket = (void (*)(void *, Packet *)) reporter_ProcessPacket,
    .Finalize = NULL,
};

Processor *
reporter_AsProcessor(Reporter *reporter)
{
    Processor *processor = processor_Create(reporter, ReporterAsProcessor);
    return processor;
}

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "buffer.h"
#include "reporter.h"
#include "types.h"

typedef struct {
    FILE *fp;
} _FileReporterContext;

struct reporter {
    void (*reportFunction)(void *, uint32_t , uint16_t *, Buffer *);
    FILE *(*getFileDescriptor)(void *);
    void *context; // sloppy
    bool hasFilter;
};

FILE *
_fileReporter_GetFileDescriptor(_FileReporterContext *context)
{
    return context->fp;
}

void
_fileReporter_Report(_FileReporterContext *context, uint32_t numberOfTypes, uint16_t type[numberOfTypes], Buffer *buffer)
{
    // packet_Display(packet, context->fp, 0);
    // fprintf(context->fp, )

    // TODO: print "type strings (separated by /), =, value"
    // e.g., Message/Interest/Name = helloworld
    // TODO: indent by the number of types in the tree
}

// TODO: need to write destructor functions

// TODO: JSON reporter just writes nested JSON with the value at the end
// TODO: CSV repoter writes a single header out to the file (based on filter) and then, for each packet, collects the list of buffers to write and then writes it out when "finalized"

Reporter *
reporter_CreateRawFileReporter(FILE *fd)
{
    Reporter *reporter = malloc(sizeof(Reporter));
    reporter->reportFunction = (void (*)(void *, uint32_t, uint16_t *, Buffer *)) _fileReporter_Report;
    reporter->getFileDescriptor = (FILE *(*)(void *)) _fileReporter_GetFileDescriptor;
    reporter->hasFilter = false;

    _FileReporterContext *context = malloc(sizeof(_FileReporterContext));
    context->fp = fd;
    reporter->context = context;

    return reporter;
}

void
reporter_StartPacket(Reporter *reporter)
{
    // TODO: add function for start method
}

void
reporter_EndPacket(Reporter *reporter)
{
    // TODO: add function for end method
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

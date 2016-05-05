#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "buffer.h"
#include "reporter.h"
#include "packet_field.h"

typedef struct {
    FILE *fp;
} _FileReporterContext;

struct reporter {
    void (*reportFunction)(void *, PacketField field, Buffer *);
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
_fileReporter_Report(_FileReporterContext *context, PacketField field, Buffer *buffer)
{
    // packet_Display(packet, context->fp, 0);
    // fprintf(context->fp, )
}

// TODO: need to write destructor functions

Reporter *
reporter_CreateRawFileReporter(FILE *fd)
{
    Reporter *reporter = malloc(sizeof(Reporter));
    reporter->reportFunction = (void (*)(void *, PacketField, Buffer *)) _fileReporter_Report;
    reporter->getFileDescriptor = (FILE *(*)(void *)) _fileReporter_GetFileDescriptor;
    reporter->hasFilter = false;

    _FileReporterContext *context = malloc(sizeof(_FileReporterContext));
    context->fp = fd;
    reporter->context = context;

    return reporter;
}

void
reporter_Report(Reporter *reporter, PacketField field, Buffer *value)
{
    // if field in set of fields, pass value to the reporter
    reporter->reportFunction(reporter->context, field, value);
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

// void
// reporter_Report(Reporter *reporter, Packet *packet)
// {
//     reporter->reportFunction(reporter->context, packet);
// }

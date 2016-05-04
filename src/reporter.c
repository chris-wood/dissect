#include <stdio.h>
#include <stdlib.h>

#include "reporter.h"

typedef struct {
    FILE *fp;
} _FileReporterContext;

struct reporter {
    void (*reportFunction)(void *, Packet *);
    void *context; // sloppy!
}

_fileReporter_Report(_FileReporterContext *context, Packet *packet)
{
    packet_Display(packet, context->fp, 0);
}

// TODO: need to write destructor functions

Reporter *
reporter_CreateRawFileReporter(FILE *fd)
{
    Reporter *reporter = malloc(sizeof(Reporter));
    reporter->reportFunction = _fileReporter_Report;

    _FileReporterContext *context = malloc(sizeof(_FileReporterContext));
    context->fp = fd;
    reporter->context = context;

    return reporter;
}

void
reporter_Report(Reporter *reporter, Packet *packet)
{
    reporter->reportFunction(reporter->context, packet);
}

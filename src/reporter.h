#ifndef dissect_reporter_h_
#define dissect_reporter_h_

#include "packet_field.h"
#include "buffer.h"

struct reporter;
typedef struct reporter Reporter;

Reporter *reporter_CreateRawFileReporter(FILE *fd);

bool reporter_IsRaw(Reporter *reporter);
FILE *reporter_GetFileDescriptor(Reporter *reporter);

void reporter_ReportField(Reporter *reporter, PacketField field, Buffer *buffer);

#endif // dissect_reporter_h_

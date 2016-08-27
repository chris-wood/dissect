#ifndef dissect_reporter_h_
#define dissect_reporter_h_

#include "types.h"
#include "buffer.h"
#include "processor.h"

struct reporter;
typedef struct reporter Reporter;

extern ProcessorInterface *ReporterAsProcessor;

Reporter *reporter_CreateRawFileReporter(FILE *fd);
Reporter *reporter_CreateJSONFileReporter(FILE *fd);
Reporter *reporter_CreateCSVFileReporter(FILE *fd);

void reporter_Destroy(Reporter **reporterPtr);

bool reporter_IsRaw(Reporter *reporter);
FILE *reporter_GetFileDescriptor(Reporter *reporter);

// TODO: need a function to set a filter for the reporter (i.e., what types to report and not)
bool reporter_AddFilterByString(Reporter *reporter, char *filter); // --> add a function to types.h to parse a string like "/interest/name/" to a type tree
bool reporter_AddFilterByTypeTree(Reporter *reporter, uint32_t numTypes, uint16_t types[numTypes]);

void reporter_StartPacket(Reporter *reporter);
void reporter_ReportTLV(Reporter *reporter, uint32_t numberOfTypes, uint16_t type[numberOfTypes], Buffer *value);
void reporter_EndPacket(Reporter *reporter);

#endif // dissect_reporter_h_

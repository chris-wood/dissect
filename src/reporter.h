#ifndef dissect_reporter_h_
#define dissect_reporter_h_

#include "packet.h"

struct reporter;
typedef struct reporter Reporter;

Reporter *reporter_CreateRawFileReporter(FILE *fd);

void reporter_Report(Reporter *reporter, Packet *packet);

#endif // dissect_reporter_h_

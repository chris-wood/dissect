#ifndef dissect_capture_h_
#define dissect_capture_h_

#include <stdio.h>
#include <stdlib.h>

#include "reporter.h"

void captureFromFile(Reporter *reporter, FILE *file);

void captureFromDevice(Reporter *reporter, char *device, char *filter);

#endif // dissect_capture_h_

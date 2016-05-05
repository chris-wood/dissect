#ifndef dissect_capture_h_
#define dissect_capture_h_

#include <stdio.h>
#include <stdlib.h>

#include "reporter.h"

int captureFromFile(Reporter *reporter, FILE *file);

int captureFromDevice(Reporter *reporter, char *device, char *filter);

#endif // dissect_capture_h_

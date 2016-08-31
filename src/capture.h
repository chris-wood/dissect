#ifndef dissect_capture_h_
#define dissect_capture_h_

#include <stdio.h>
#include <stdlib.h>

#include "processor.h"
#include "packet.h"

int captureFromFile(Processor *processor, FILE *file);

int captureFromDevice(Processor *processor, char *device, char *filter);

#endif // dissect_capture_h_

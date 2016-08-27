#ifndef dissect_processor_h_
#define dissect_processor_h_

#include "types.h"

// Necessary forward declaration to avoid the circular dependency
struct packet;

struct processor;
typedef struct processor Processor;

typedef struct {
    void (*Init)(void *);
    void (*ProcessPacket)(void *, struct packet *);
    void (*Finalize)(void *);
} ProcessorInterface;

Processor *processor_Create(void *instance, ProcessorInterface *interface);

void processor_Init(Processor *proc);
void processor_ProcessPacket(Processor *proc, struct packet *thePacket);
void processor_Finalize(Processor *proc);

#endif // dissect_processor_h_

#include "processor.h"

struct processor {
    void *instance;
    ProcessorInterface *interface;
};

Processor *
processor_Create(void *instance, ProcessorInterface *interface)
{
    Processor *proc = (Processor *) malloc(sizeof(Processor));
    if (proc != NULL) {
        proc->instance = instance;
        proc->interface = interface;
    }
    return proc;
}

void 
processor_Init(Processor *proc)
{
    proc->interface->Init(proc->instance);
}

void 
processor_ProcessPacket(Processor *proc, struct packet *thePacket)
{
    proc->interface->ProcessPacket(proc->instance, thePacket);
}

void 
processor_Finalize(Processor *proc)
{
    proc->interface->Finalize(proc->instance);
}


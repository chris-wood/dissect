#include "digester.h"

struct digester {
    DigestAlgorithm alg;
};

Digester *
digester_Create(DigestAlgorithm alg)
{
    Digester *dig = (Digester *) malloc(sizeof(Digester));
    if (dig != NULL) {
        dig->alg = alg;
    }
    return dig;
}

void 
digester_ProcessPacket(Reporter *reporter, Packet *packet)
{
    // 1. compute the digest
    // 2. print the digest
}

ProcessorInterface *DigesterAsProcessor = &(ProcessorInterface) {
    .Init = NULL,
    .ProcessPacket = (void (*)(void *, Packet *)) digester_ProcessPacket,
    .Finalize = NULL,
};


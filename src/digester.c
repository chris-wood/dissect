#include "digester.h"
#include "buffer.h"

#include "lib-sha256.h"

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
digester_ProcessPacket(Digester *digester, Packet *packet)
{
    Buffer *payload = packet_GetProtectedRegion(packet);
    Buffer *md = NULL;
    switch (digester->alg) {
        case DigestAlgorithm_SHA256: {
            md = SHA256(payload);
            break;
        }
        default: {
            break;
        }
    }

    if (md != NULL) {
        buffer_DisplayHex(md, 0);
        buffer_Destroy(&md);
    }

    if (payload != NULL) {
        buffer_Destroy(&payload);
    }
}

ProcessorInterface *DigesterAsProcessor = &(ProcessorInterface) {
    .Init = NULL,
    .ProcessPacket = (void (*)(void *, Packet *)) digester_ProcessPacket,
    .Finalize = NULL,
};

Processor *
digester_AsProcessor(Digester *digester)
{
    Processor *processor = processor_Create(digester, DigesterAsProcessor);
    return processor;
}


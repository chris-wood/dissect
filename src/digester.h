#ifndef dissect_digester_h_
#define dissect_digester_h_

#include "packet.h"
#include "reporter.h"

typedef enum {
    DigestAlgorithm_SHA256,
    DigestAlgorithm_Invalid
} DigestAlgorithm;

struct digester;
typedef struct digester Digester;

extern ProcessorInterface *DigesterAsProcessor;

Digester *digester_Create(DigestAlgorithm alg);

#endif // dissect_digester_h_

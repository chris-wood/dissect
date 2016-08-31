#ifndef dissect_digester_h_
#define dissect_digester_h_

#include "packet.h"
#include "reporter.h"
#include "digester.h"

typedef enum {
    DigestAlgorithm_SHA256,
    DigestAlgorithm_Invalid
} DigestAlgorithm;

struct digester;
typedef struct digester Digester;

Digester *digester_Create(DigestAlgorithm alg);
Processor *digester_AsProcessor(Digester *digester);

#endif // dissect_digester_h_

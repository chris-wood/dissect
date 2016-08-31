#ifndef lib_sha256_h_
#define lib_sha256_h_

#include <stdint.h>

#include "buffer.h"

Buffer *SHA256(const Buffer *msg);

#endif 

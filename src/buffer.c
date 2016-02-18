#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "buffer.h"

struct buffer {
    uint8_t *bytes;
    uint32_t length;
};

struct buffer_overlay {
    uint8_t *bytes;
    uint32_t length;
    uint32_t offset;
};

BufferOverlay *
bufferOverlay_CreateFromBuffer(Buffer *b, uint32_t offset, uint32_t length)
{
    BufferOverlay *overlay = (BufferOverlay *) malloc(sizeof(BufferOverlay));

    overlay->bytes = b->bytes;
    overlay->offset = offset;
    overlay->length = length;

    return overlay;
}

uint8_t *
bufferOverlay_Overlay(BufferOverlay *overlay)
{
    return (uint8_t *) (overlay->bytes + overlay->offset);
}

void
buffer_Display(FILE *fp, Buffer *b)
{
    for (int i = 0; i < b->length; i++) {
        fprintf(fp, "%x", b->bytes[i]);
    }
    fprintf(fp, "\n");
}

Buffer *
buffer_CreateEmpty()
{
    Buffer *buffer = (Buffer *) malloc(sizeof(Buffer));
    buffer->length = 0;
    buffer->bytes = NULL;
    return buffer;
}

Buffer *
buffer_CreateFromArray(uint8_t *bytes, size_t length)
{
    Buffer *buffer = (Buffer *) malloc(sizeof(Buffer));
    buffer->length = length;
    buffer->bytes = (uint8_t *) malloc(length);
    memcpy(buffer->bytes, bytes, length);
    return buffer;
}

Buffer *
buffer_Copy(Buffer *copy)
{
    Buffer *buffer = (Buffer *) malloc(sizeof(Buffer));
    buffer->length = copy->length;
    buffer->bytes = (uint8_t *) malloc(copy->length);
    memcpy(buffer->bytes, copy->bytes, copy->length);
    return buffer;
}

int
buffer_Compare(Buffer *this, Buffer *other)
{
    if (other == NULL || this == NULL) {
        return -1;
    } else if (this->length > other->length) {
        return 1;
    } else if (this->length < other->length) {
        return -1;
    } else {
        return memcmp(this->bytes, other->bytes, other->length);
    }
}

size_t buffer_Size(Buffer *buffer)
{
    return buffer->length;
}

uint8_t *
buffer_Overlay(Buffer *buffer)
{
    return buffer->bytes;
}

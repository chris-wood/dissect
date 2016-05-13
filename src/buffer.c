#include "util.h"
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

    overlay->length = length;
    overlay->bytes = b->bytes + offset;

    // overlay->bytes = malloc(length); //&(b->bytes[offset]);
    // for (int i = 0; i < length; i++) {
    //     overlay->bytes[i] = b->bytes[i + offset];
    // }
    // // overlay->offset = offset;

    return overlay;
}

void
bufferOverlay_Destroy(BufferOverlay **bufferOverlayPtr)
{
    BufferOverlay *overlay = *bufferOverlayPtr;
    free(overlay);
    *bufferOverlayPtr = NULL;
}

Buffer *
bufferOverlay_CreateBuffer(BufferOverlay *overlay)
{
    Buffer *buffer = buffer_CreateFromArray(overlay->bytes, overlay->length);
    return buffer;
}

uint8_t *
bufferOverlay_Overlay(BufferOverlay *overlay)
{
    return overlay->bytes;
}

uint32_t
bufferOverlay_Length(BufferOverlay *overlay)
{
    return overlay->length;
}

uint16_t
bufferOverlay_GetWordAtOffset(BufferOverlay *b, uint32_t offset)
{
    uint16_t word = (((uint16_t)(b->bytes[offset]) << 8) & 0xFF00) | ((uint16_t)(b->bytes[offset + 1]) & 0x00FF);
    return word;
}

uint64_t
bufferOverlay_GetUint64(BufferOverlay *buffer, size_t offset)
{
    return -1;
}

uint32_t
bufferOverlay_GetUint32(BufferOverlay *buffer, size_t offset)
{
    return -1;
}

uint16_t
bufferOverlay_GetUint16(BufferOverlay *buffer, size_t offset)
{
    // TODO: assert that offset + 1 is in bounds
    uint16_t value = ((uint16_t)(buffer->bytes[offset]) << 8) | (uint16_t)(buffer->bytes[offset + 1]);
    return value;
}

uint8_t
bufferOverlay_GetUint8(BufferOverlay *buffer, size_t offset)
{
    return buffer->bytes[offset];
}

char *
buffer_ToString(Buffer *b)
{
    char *string = malloc(b->length + 1);
    for (int i = 0; i < b->length; i++) {
        string[i] = b->bytes[i];
    }
    string[b->length] = '\0';
    return string;
}

void
buffer_Display(Buffer *b, int indentation)
{
    for (int i = 0; i < indentation; i++) {
        printf("  ");
    }
    for (int i = 0; i < b->length; i++) {
        printf("%c", b->bytes[i]);
    }
    printf("\n");
}

void
buffer_DisplayHex(Buffer *b, int indentation)
{
    for (int i = 0; i < indentation; i++) {
        printf("  ");
    }
    for (int i = 0; i < b->length; i++) {
        printf("%c", b->bytes[i]);
    }
    printf("\n");
}

void
buffer_Destroy(Buffer **bufferPtr)
{
    Buffer *buffer = *bufferPtr;
    free(buffer->bytes);
    free(buffer);
    *bufferPtr = NULL;
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

uint16_t
buffer_GetWordAtOffset(Buffer *b, uint32_t offset)
{
    uint16_t word = ((uint16_t)(b->bytes[offset]) << 8) | (uint16_t)(b->bytes[offset + 1]);
    return word;
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

uint64_t
buffer_GetUint64(Buffer *buffer, size_t offset)
{
    return 0;
}

uint32_t
buffer_GetUint32(Buffer *buffer, size_t offset)
{
    return 0;
}

uint16_t
buffer_GetUint16(Buffer *buffer, size_t offset)
{
    uint16_t value = ((uint16_t)(buffer->bytes[offset]) << 8) | (uint16_t)(buffer->bytes[offset + 1]);
    return value;
}

uint8_t
buffer_GetUint8(Buffer *buffer, size_t offset)
{
    uint16_t value = buffer->bytes[offset];
    return value;
}

// TODO: move this redundant code to a single function

void
buffer_PutUint8(Buffer *buffer, size_t offset, uint8_t value)
{
    memcpy((void *) (buffer->bytes + offset), (void *) &value, sizeof(value));
}

void
buffer_PutUint16(Buffer *buffer, size_t offset, uint16_t value)
{
    memcpy((void *) (buffer->bytes + offset), (void *) &value, sizeof(value));
}

void
buffer_PutUint32(Buffer *buffer, size_t offset, uint32_t value)
{
    memcpy((void *) (buffer->bytes + offset), (void *) &value, sizeof(value));
}

void
buffer_PutUint64(Buffer *buffer, size_t offset, uint64_t value)
{
    memcpy((void *) (buffer->bytes + offset), (void *) &value, sizeof(value));
}

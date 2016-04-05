//
// Created by cwood on 1/31/16.
//

#ifndef DISSECT_BUFFER_H
#define DISSECT_BUFFER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

struct buffer;
typedef struct buffer Buffer;

struct buffer_overlay;
typedef struct buffer_overlay BufferOverlay;

BufferOverlay *bufferOverlay_CreateFromBuffer(Buffer *b, uint32_t offset, uint32_t length);
Buffer *bufferOverlay_CreateBuffer(BufferOverlay *overlay);
uint8_t *bufferOverlay_Overlay(BufferOverlay *overlay);
uint32_t bufferOverlay_Length(BufferOverlay *overlay);
uint64_t bufferOverlay_GetUint64(BufferOverlay *buffer, size_t offset);
uint32_t bufferOverlay_GetUint32(BufferOverlay *buffer, size_t offset);
uint16_t bufferOverlay_GetUint16(BufferOverlay *buffer, size_t offset);
uint8_t bufferOverlay_GetUint8(BufferOverlay *buffer, size_t offset);

uint16_t buffer_GetWordAtOffset(Buffer *b, uint32_t offset);
uint16_t bufferOverlay_GetWordAtOffset(BufferOverlay *b, uint32_t offset);

void buffer_Display(Buffer *b, int indentation);
void buffer_DisplayHex(Buffer *b, int indentation);
Buffer *buffer_CreateEmpty();
Buffer *buffer_CreateFromArray(uint8_t *bytes, size_t length);
Buffer *buffer_Copy(Buffer *copy);
int buffer_Compare(Buffer *this, Buffer *other);

size_t buffer_Size(Buffer *buffer);
uint8_t *buffer_Overlay(Buffer *buffer);

uint64_t buffer_GetUint64(Buffer *buffer, size_t offset);
uint32_t buffer_GetUint32(Buffer *buffer, size_t offset);
uint16_t buffer_GetUint16(Buffer *buffer, size_t offset);
uint8_t buffer_GetUint8(Buffer *buffer, size_t offset);

void buffer_PutUint8(Buffer *buffer, size_t offset, uint8_t value);
void buffer_PutUint16(Buffer *buffer, size_t offset, uint16_t value);
void buffer_PutUint32(Buffer *buffer, size_t offset, uint32_t value);
void buffer_PutUint64(Buffer *buffer, size_t offset, uint64_t value);


#endif // DISSECT_BUFFER_H

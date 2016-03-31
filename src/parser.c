#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"

//===== Header functions

uint16_t
getWordFromOffset(uint8_t *buffer, int offset)
{
    uint16_t word = ((uint16_t)(buffer[offset]) << 8) | (uint16_t)(buffer[offset + 1]);
    return word;
}

uint8_t
getPacketVersion(uint8_t *buffer, size_t length)
{
    return (buffer[0] & 0xFF);
}

uint8_t
getPacketType(uint8_t *buffer, size_t length)
{
    return (buffer[1] & 0xFF);
}

uint16_t
getPacketLength(uint8_t *buffer, size_t length)
{
    return getWordFromOffset(buffer, 2);
}

// TODO: add functions to get packet specific fields

uint16_t
getHeaderLength(uint8_t *buffer, size_t length)
{
    return (buffer[7] & 0xFF);
}

//===== Message functions

size_t
_getNameLength(uint8_t *buffer, size_t length)
{
    int offset = 6; // 4 for TL, 2 for T of the name
    uint16_t len = ((uint16_t)(buffer[offset]) << 8) | (uint16_t)(buffer[offset + 1]);
    return (size_t) len;
}

size_t
_getNameIndex(uint8_t *buffer, size_t length)
{
    return 8; // 8 + 4 + 4
}

size_t
_getContentHashIndex(uint8_t *buffer, size_t length) // skip past the name
{
    return _getNameIndex(buffer, length) + _getNameLength(buffer, length) + 4;
}

size_t
_getContentHashLength(uint8_t *buffer, size_t length) // skip past the name
{
    int offset = _getNameIndex(buffer, length) + _getNameLength(buffer, length) + 2;
    uint16_t len = ((uint16_t)(buffer[offset]) << 8) | (uint16_t)(buffer[offset + 1]);
    return (size_t) len;
}

Buffer *
_readName(uint8_t *buffer, size_t length)
{
    size_t len = _getNameLength(buffer, length);
    Buffer *b = buffer_CreateFromArray(buffer + _getNameIndex(buffer, length), len);
    return b;
}

Buffer *
_readContentObjectHash(uint8_t *buffer, size_t length)
{
    size_t len = _getContentHashLength(buffer, length);
    Buffer *b = buffer_CreateFromArray(buffer + _getContentHashIndex(buffer, length), len);
    return b;
}
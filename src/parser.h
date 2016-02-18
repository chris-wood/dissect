//
// Created by cwood on 2/17/16.
//

#ifndef DISSECT_PARSER_H
#define DISSECT_PARSER_H

#include "buffer.h"

uint16_t getWordFromOffset(uint8_t *buffer, int offset);
uint8_t getPacketVersion(uint8_t *buffer, size_t length);
uint8_t getPacketType(uint8_t *buffer, size_t length);
uint16_t getPacketLength(uint8_t *buffer, size_t length);

// TODO: add functions to get packet specific fields

uint16_t getHeaderLength(uint8_t *buffer, size_t length);

size_t _getNameLength(uint8_t *buffer, size_t length);

size_t _getNameIndex(uint8_t *buffer, size_t length);

size_t _getContentHashIndex(uint8_t *buffer, size_t length); // skip past the name;

size_t _getContentHashLength(uint8_t *buffer, size_t length); // skip past the name

Buffer *_readName(uint8_t *buffer, size_t length);

Buffer *_readContentObjectHash(uint8_t *buffer, size_t length);

#endif //DISSECT_PARSER_H

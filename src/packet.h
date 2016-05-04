//
// Created by cwood on 2/6/16.
//

#ifndef DISSECT_PACKET_H
#define DISSECT_PACKET_H

#include "buffer.h"
#include "util.h"
#include "tlv.h"

struct packet;
typedef struct packet Packet;

typedef enum {
    PacketVersion_V0,
    PacketVersion_V1,
    PacketVersion_Invalid
} PacketVersion;

typedef enum {
    PacketType_Request = 0x00,
    PacketType_Response = 0x01,
    PacketType_RequestReturn = 0x02,
    PacketType_Invalid
} PacketType;

typedef enum {
    // Message "header"
    PacketField_Name,
    PacketField_KeyIdRestriction,
    PacketField_ContentObjectHashRestriction,

    // Message internals (payload)
    PacketField_Payload,

    // ValidationAlgorithm
    PacketField_ValidationAlgKeyId,
    PacketField_ValidationAlgPublicKey,
    PacketField_ValidationAlgCert,
    PacketField_ValidationAlgKeyName,
    PacketField_ValidationAlgSigTime,

    // ValidationPayload
    PacketField_ValidationPayload,

    PacketField_Invalid
} PacketField;

Packet *packet_CreateFromBuffer(Buffer *buffer);

// general packet stuff
PacketVersion packet_GetVersion(Packet *packet);
PacketType packet_GetType(Packet *packet);
uint16_t packet_GetLength(Packet *packet);
uint16_t packet_GetHeaderLength(Packet *packet);

// debug
void packet_Display(Packet *packet, FILE *fp, int indentation);

// absolute packet fields
Buffer *packet_GetFieldValue(Packet *packet, PacketField field);

// TLV iterator and query functions
TLV *packet_GetNextTLV(Packet *packet, uint32_t offset, uint32_t length);
bool packet_HasNextTLV(Packet *packet, uint32_t offset);
//TLV *packet_FindTLV(TLV *tlv, uint16_t type);
TLV *packet_FindNestedTLV(Packet *packet, uint32_t numberOfTypes, uint16_t type[numberOfTypes]);

// Packet query functions

#endif //DISSECT_PACKET_H

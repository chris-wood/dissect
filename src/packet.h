//
// Created by cwood on 2/6/16.
//

#ifndef DISSECT_PACKET_H
#define DISSECT_PACKET_H

#include "buffer.h"
#include "util.h"

struct packet;
typedef struct packet Packet;

struct TLV;
typedef struct tlv TLV;

typedef enum {
    PacketVersion_V0,
    PacketVersion_V1,
    PacketVersion_Invalid
} PacketVersion;

typedef enum {
    PacketType_Request,
    PacketType_Response,
    PacketType_RequestReturn,
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

// absolute packet fields
Buffer *packet_GetFieldLength(Packet *packet, PacketField field);
Buffer *packet_GetFieldValue(Packet *packet, PacketField field);

// TLV iterator functions
TLV *packet_GetNextTLV(Packet *packet);
bool packet_HasNextTLV(Packet *packet);

uint16_t tlv_Type(TLV *tlv);
uint16_t tlv_Length(TLV *tlv);
uint8_t *tlv_Value(TLV *tlv);

#endif //DISSECT_PACKET_H

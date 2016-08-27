//
// Created by cwood on 2/6/16.
//

#ifndef dissect_packet_h_
#define dissect_packet_h_

#include "buffer.h"
#include "util.h"
#include "tlv.h"
#include "reporter.h"

struct packet;
typedef struct packet Packet;

typedef enum {
    PacketVersion_V0 = 0x00,
    PacketVersion_V1 = 0x01,
    PacketVersion_Invalid
} PacketVersion;

typedef enum {
    PacketType_Request = 0x00,
    PacketType_Response = 0x01,
    PacketType_RequestReturn = 0x02,
    PacketType_Invalid
} PacketType;

typedef enum {
    PacketField_PacketType,
    PacketField_PacketLength,
    PacketField_HeaderLength,

    PacketField_OptionalHeaders_InterestLifetime,
    PacketField_OptionalHeaders_RecommendedCacheTime,
    PacketField_OptionalHeaders_InterestFragment,
    PacketField_OptionalHeaders_ContentObjectFragment,

    // Message "header"
    PacketField_MessageType,
    PacketField_Name,
    PacketField_KeyIdRestriction,
    PacketField_ContentObjectHashRestriction,
    PacketField_PayloadType,
    PacketField_ExpiryTime,
    PacketField_EndChunkNumber,

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
void packet_Destroy(Packet **packetPtr);

// general packet stuff
PacketVersion packet_GetVersion(Packet *packet);
PacketType packet_GetType(Packet *packet);
uint16_t packet_GetLength(Packet *packet);
uint16_t packet_GetHeaderLength(Packet *packet);

// displaying and reporting functions
void packet_Display(Packet *packet, FILE *fp, int indentation);
void packet_Report(Packet *packet, Reporter *reporter);

// absolute packet fields
Buffer *packet_GetFieldValue(Packet *packet, PacketField field);
Buffer *packet_GetFixedHeader(Packet *packet);
Buffer *packet_GetOptionalHeader(Packet *packet);
Buffer *packet_GetMessage(Packet *packet);
Buffer *packet_GetProtectedRegion(Packet *packet);

// TLV iterator and query functions
TLV *packet_GetNextTLV(Packet *packet, uint16_t offset, uint16_t length);
bool packet_HasNextTLV(Packet *packet, uint16_t offset);
TLV *packet_FindNestedTLV(Packet *packet, uint32_t numberOfTypes, uint16_t type[numberOfTypes]);

#endif //dissect_packet_h_

//
// Created by cwood on 2/6/16.
//

#include <stdlib.h>

#include "packet.h"
#include "parser.h"

struct packet {
    size_t offset;
    Buffer *packet;
    TLV *startTLV;
};

struct tlv {
    // The type and length of thi TLV
    uint16_t type;
    uint16_t length;

    // Overlay onto packet buffer that stores the value
    BufferOverlay *value;

    // The offset of this TLV in the packet buffer
    uint32_t offset;

    // Pointer to the next TLV in the packet
    struct tlv **children;
};

static TLV *
tlv_Create(Packet *packet, uint16_t offset, uint16_t type, uint16_t length)
{
    TLV *tlv = (TLV *) malloc(sizeof(TLV));
    tlv->type = type;
    tlv->length = length;
    tlv->offset = offset;
    tlv->value = bufferOverlay_CreateFromBuffer(packet->packet, offset, length);
    return tlv;
}

// TLV iterator functions
TLV *
packet_GetNextTLV(Packet *packet)
{
    if (packet_HasNextTLV(packet)) {
        uint16_t type = getWordFromOffset(buffer_Overlay(packet->packet), packet->offset);
        packet->offset += 2;

        uint16_t length = getWordFromOffset(buffer_Overlay(packet->packet), packet->offset);
        packet->offset += 2;

        TLV *tlv  = tlv_Create(type, length, packet, packet->offset);
        packet->offset += length;

        tlv->children = NULL;

        return tlv;
    } else {
        return NULL;
    }
}

Packet *
packet_CreateFromBuffer(Buffer *buffer)
{
    Packet *packet = (Packet *) malloc(sizeof(packet));
    packet->offset = 0;
    packet->packet = buffer;

    // Create the *tree* of TLVs
    packet->startTLV = packet_GetNextTLV(packet);
    TLV *prev = packet->startTLV;
    while (packet_HasNextTLV(packet)) {
        TLV *nextTLV = packet_GetNextTLV(packet);


//        prev->nextTLV = nextTLV;
        prev = nextTLV;
    }

    return packet;
}

// general packet stuff
PacketVersion
packet_GetVersion(Packet *packet)
{
    switch (getPacketVersion(buffer_Overlay(packet->packet), buffer_Size(packet->packet))) {
        case PacketVersion_V0:
            return PacketVersion_V0;
        case PacketVersion_V1:
            return PacketVersion_V1;
    }
    return PacketVersion_Invalid;
}

PacketType
packet_GetType(Packet *packet)
{
    switch (getPacketType(buffer_Overlay(packet->packet), buffer_Size(packet->packet))) {
        case PacketType_Request:
            return PacketType_Request;
        case PacketType_Response:
            return PacketType_Response;
        case PacketType_RequestReturn:
            return PacketType_RequestReturn;
    }
    return PacketType_Invalid;
}

uint16_t
packet_GetLength(Packet *packet)
{
    return getPacketLength(buffer_Overlay(packet->packet), buffer_Size(packet->packet));
}

uint16_t
packet_GetHeaderLength(Packet *packet)
{
    return getHeaderLength(buffer_Overlay(packet->packet), buffer_Size(packet->packet));
}

// Absolute packet fields
Buffer *
packet_GetFieldValue(Packet *packet, PacketField field)
{
    switch (field) {
        PacketField_Name:
            return _readName(buffer_Overlay(packet->packet), buffer_Size(packet->packet));
        PacketField_ContentObjectHashRestriction:
            return _readContentObjectHash(buffer_Overlay(packet->packet), buffer_Size(packet->packet));
        PacketField_KeyIdRestriction:
            break;
        PacketField_Payload:
            break;
        PacketField_ValidationAlgCert:
            break;
        PacketField_ValidationAlgKeyId:
            break;
        PacketField_ValidationAlgPublicKey:
            break;
        PacketField_ValidationAlgSigTime:
            break;
        PacketField_ValidationPayload:
            break;
    }
    return NULL;
}

bool
packet_HasNextTLV(Packet *packet)
{
    return (packet->offset < buffer_Size(packet->packet));
}

static TLV *
_packet_FindTLVInBounds(Packet *packet, uint16_t type, uint32_t low, uint32_t high)
{
    TLV *curr = packet->startTLV;
    uint32_t offset = 0;

    while (curr != NULL) {
        if (curr->type == type) {
            return curr;
        }
        curr = curr->nextTLV;
    }

    return NULL;
}

// This function should take bounds for the search so we can re-use it for the nested TLV search
TLV *
packet_FindTLV(Packet *packet, uint16_t type)
{

}

TLV *
packet_FindNestedTLV(Packet *packet, uint32_t numberOfTypes, uint16_t type[numberOfTypes])
{
    return NULL;
}

uint16_t
tlv_Type(TLV *tlv)
{
    return tlv->type;
}

uint16_t
tlv_Length(TLV *tlv)
{
    return tlv->length;
}

uint8_t *
tlv_Value(TLV *tlv)
{
    return bufferOverlay_Overlay(tlv->value);
}

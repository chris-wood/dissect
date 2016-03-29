//
// Created by cwood on 2/6/16.
//

#include <stdlib.h>

#include "packet.h"
#include "parser.h"

struct packet {
    size_t offset;
    Buffer *packet;
    TLV *startTlv;
};

struct tlv {
    uint16_t type;
    uint16_t length;
    BufferOverlay *overlay;
};

static TLV *
tlv_Create(Packet *packet, uint16_t offset, uint16_t type, uint16_t length)
{
    TLV *tlv = (TLV *) malloc(sizeof(TLV));
    tlv->type = type;
    tlv->length = length;
    tlv->overlay = bufferOverlay_CreateFromBuffer(packet->packet, offset, length);
    return tlv;
}

Packet *
packet_CreateFromBuffer(Buffer *buffer)
{
    Packet *packet = (Packet *) malloc(sizeof(packet));
    packet->offset = 0;
    packet->packet = buffer;

    // The first TLV is right after the fixed header, which is 8 bytes long
    uint16_t firstTlvType = buffer_GetUint16(packet->packet, 8);
    uint16_t firstTlvLength = buffer_GetUint16(packet->packet, 10);
    packet->startTlv = tlv_Create(packet, 12, firstTlvType, firstTlvLength);

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

        return tlv;
    } else {
        return NULL;
    }
}

bool
packet_HasNextTLV(Packet *packet)
{
    return (packet->offset < buffer_Size(packet->packet));
}

// TODO: this should return the first TLV of the specified type
// TODO: a user can provide a hierarchy of types (as an array) -- to do a DFS for the type (since each type has its own namespace)
//TLV *
//packet_FindTLV(Packet *packet, uint16_t type)
//{
//    TLV *start = packet->startTlv;
//    if (start->type == type) {
//
//    }
//}

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
    return bufferOverlay_Overlay(tlv->overlay);
}

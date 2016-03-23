//
// Created by cwood on 2/6/16.
//

#include <stdlib.h>

#include "packet.h"
#include "parser.h"

struct packet {
    size_t offset;
    Buffer *packet;
};

struct tlv {
    uint16_t type;
    uint16_t length;
    BufferOverlay *overlay;
};

static TLV *
tlv_Create(uint16_t type, uint16_t length, Packet *packet)
{
    TLV *tlv = (TLV *) malloc(sizeof(TLV));
    tlv->type = type;
    tlv->length = length;
    tlv->overlay = bufferOverlay_CreateFromBuffer(packet->packet, packet->offset, length);
    return tlv;
}

Packet *
packet_CreateFromBuffer(Buffer *buffer)
{
    Packet *packet = (Packet *) malloc(sizeof(packet));
    packet->offset = 0;
    packet->packet = buffer;
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

// absolute packet fields
Buffer *
packet_GetFieldType(Packet *packet, PacketField field)
{
    // TODO
    return NULL;
}

Buffer *
packet_GetFieldValue(Packet *packet, PacketField field)
{
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

        TLV *tlv  = tlv_Create(type, length, packet);
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

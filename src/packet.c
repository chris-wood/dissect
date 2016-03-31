//
// Created by cwood on 2/6/16.
//

#include <stdlib.h>

#include "packet.h"
#include "parser.h"

struct packet {
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
    struct tlv *sibling;

    // Pointer to inner (children) TLVs contained inside the value
    // of this packet
    struct tlv **children;
    size_t numberOfChildren;
};

void
tlv_Display(TLV *tlv, size_t indentation)
{
    for (size_t i = 0; i < indentation; i++) {
        printf("  ");
    }
    printf("%d %d\n", tlv->type, tlv->length);
    for (size_t i = 0; i < tlv->numberOfChildren; i++) {
        tlv_Display(tlv->children[i], indentation + 1);
    }
}

bool
tlv_HasInnerTLV(TLV *tlv, uint32_t limit)
{
    // If a TLV value has an inner TLV, then it must at least
    // store the 4 bytes for the T and L.
    if (tlv->length < 4) {
        return false;
    }

    // Peek and read the type and length
    uint16_t type = getWordFromOffset(bufferOverlay_Overlay(tlv->value), 0);
    uint16_t length = getWordFromOffset(bufferOverlay_Overlay(tlv->value), 2);

    // If the length of the inner TLV is less than the limit, then there *could*
    // be another TLV inside.
    if (length < limit) {
        return true;
    } else {
        return false;
    }
}

static TLV *
tlv_Create(Buffer *packet, uint16_t type, uint16_t length, uint32_t offset)
{
    TLV *tlv = (TLV *) malloc(sizeof(TLV));
    tlv->type = type;
    tlv->length = length;

    tlv->offset = offset;
    tlv->value = bufferOverlay_CreateFromBuffer(packet, offset, length);

    if (tlv_HasInnerTLV(tlv, length)) {
        // Attempt to create an array of children. Rewind and fail if something goes wrong.
        tlv->children = (TLV **) malloc(sizeof(TLV *));
        tlv->numberOfChildren = 0;

        while (offset < length) {
            uint16_t inner_type = getWordFromOffset(bufferOverlay_Overlay(tlv->value), offset);
            uint16_t inner_length = getWordFromOffset(bufferOverlay_Overlay(tlv->value), offset + 2);

            if (offset + inner_length >= length) {
                // Failure.
                tlv->numberOfChildren = 0;
                tlv->children = NULL;
                return tlv;
            } else {
                tlv->numberOfChildren++;
                tlv->children = (TLV **) realloc(tlv->children, tlv->numberOfChildren * sizeof(TLV *));

                TLV *child = tlv_Create(packet, inner_type, inner_length, offset + 4);
                tlv->children[tlv->numberOfChildren - 1] = child;
            }

            offset += 4 + inner_length;
        }
    } else {
        tlv->children = NULL;
        tlv->numberOfChildren = 0;
    }

    return tlv;
}

// TLV iterator functions
TLV *
packet_GetNextTLV(Packet *packet, uint32_t offset, uint32_t limit)
{
    uint16_t type = getWordFromOffset(buffer_Overlay(packet->packet), offset);
    offset += 2;

    uint16_t length = getWordFromOffset(buffer_Overlay(packet->packet), offset);
    offset += 2;

    TLV *tlv  = tlv_Create(packet->packet, type, length, offset);
    tlv->sibling = NULL;

    return tlv;
}

bool
packet_HasInnerTLVs(Packet *packet, uint32_t offset, uint32_t length)
{
    return offset < length;
}

Packet *
packet_CreateFromBuffer(Buffer *buffer)
{
    Packet *packet = (Packet *) malloc(sizeof(packet));
    packet->packet = buffer;

    // TOOD: extract the fixed header stuff

    // Create the *tree* of TLVs
    uint32_t offset = 8; // skip past the fixed header
    packet->startTLV = packet_GetNextTLV(packet, offset, buffer_Size(buffer));
    TLV *prev = packet->startTLV;

    while ((prev->offset + prev->length) < buffer_Size(buffer)) {
        TLV *next = packet_GetNextTLV(packet, prev->offset + prev->length, buffer_Size(buffer));
        prev->sibling = next;
        prev = next;
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
packet_HasNextTLV(Packet *packet, uint32_t offset)
{
    return (offset < buffer_Size(packet->packet));
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
        //curr = curr->nextTLV;
    }

    return NULL;
}

// This function should take bounds for the search so we can re-use it for the nested TLV search
TLV *
packet_FindTLV(TLV *root, uint16_t type)
{
    return NULL;
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

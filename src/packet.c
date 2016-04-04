//
// Created by cwood on 2/6/16.
//

#include <stdlib.h>

#include "packet.h"
#include "parser.h"
#include "types.h"

// Static type space tree
static uint16_t header_types[4] = {
    CCNxTypespace_OptionalHeaders_InterestLifetime,
    CCNxTypespace_OptionalHeaders_RecommendedCacheTime,
    CCNxTypespace_OptionalHeaders_InterestFragment,
    CCNxTypespace_OptionalHeaders_ContentObjectFragment
};

static uint16_t top_level_types[6] = {
    CCNxTypespace_MessageType_Interest,
    CCNxTypespace_MessageType_ContentObject,
    CCNxTypespace_MessageType_ValidationAlg,
    CCNxTypespace_MessageType_ValidationPayload,
    CCNxTypespace_MessageType_Manifest,
    CCNxTypespace_MessageType_Control
};

static uint16_t message_types[8] = {
    CCNxTypespace_CCNxMessage_Name,
    CCNxTypespace_CCNxMessage_Payload,
    CCNxTypespace_CCNxMessage_KeyIdRestriction,
    CCNxTypespace_CCNxMessage_ContentObjectHashRestriction,
    CCNxTypespace_CCNxMessage_PayloadType,
    CCNxTypespace_CCNxMessage_ExpiryTime,
    CCNxTypespace_CCNxMessage_HashGroup,
    CCNxTypespace_CCNxMessage_EndChunkNumber
};

static uint16_t validation_alg_types[9] = {
    CCNxTypespace_ValidationAlg_CRC32C,
    CCNxTypespace_ValidationAlg_HMAC_SHA256,
    CCNxTypespace_ValidationAlg_RSA_SHA256,
    CCNxTypespace_ValidationAlg_EC_SECP_256K1,
    CCNxTypespace_ValidationAlg_KeyId,
    CCNxTypespace_ValidationAlg_PublicKey,
    CCNxTypespace_ValidationAlg_Cert,
    CCNxTypespace_ValidationAlg_KeyName,
    CCNxTypespace_ValidationAlg_SigTime
};

///////
// TODO: finish the rest of the typespace here
///////

// A generic node that we can use to stich together the typespace tree
struct typespace_tree_node;
typedef struct typespace_tree_node {
    uint16_t *types;
    uint16_t numTypes;

    struct typespace_tree_node **children;
    uint16_t numChildren;
} TypespaceTreeNode;

static TypespaceTreeNode header_root = {
    .types = header_types,
    .numTypes = sizeof(header_types),
    .children = NULL,
    .numChildren = 0
};

static TypespaceTreeNode validation_alg_types_node = {
    .types = top_level_types,
    .numTypes = sizeof(top_level_types),
    .children = NULL,
    .numChildren = 0
};

static TypespaceTreeNode message_types_node = { //&(TypespaceTreeNode) {
    .types = message_types,
    .numTypes = sizeof(message_types),
    .children = NULL,
    .numChildren = 0
};

static TypespaceTreeNode *top_level_type_children[2] = {
    &message_types_node,
    &validation_alg_types_node
};

static TypespaceTreeNode top_level_types_node = { // }&(TypespaceTreeNode) {
    .types = top_level_types,
    .numTypes = sizeof(top_level_types),
    .children = top_level_type_children,
    .numChildren = sizeof(top_level_type_children)
};

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
    uint16_t type = bufferOverlay_GetWordAtOffset(tlv->value, 0);
    uint16_t length = bufferOverlay_GetWordAtOffset(tlv->value, 2);

    // If the length of the inner TLV is less than the limit, then there *could*
    // be another TLV inside.
    if (length < limit) {
        return true;
    } else {
        return false;
    }
}

static TLV *
tlv_Create(Buffer *packet, uint16_t type, uint16_t length, uint32_t offset, uint32_t limit)
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
            uint16_t inner_type = buffer_GetWordAtOffset(packet, offset);
            uint16_t inner_length = buffer_GetWordAtOffset(packet, offset + 2);

            if (offset + inner_length > limit) {
                // Failure.
                tlv->numberOfChildren = 0;
                tlv->children = NULL;
                return tlv;
            } else {
                tlv->numberOfChildren++;
                tlv->children = (TLV **) realloc(tlv->children, tlv->numberOfChildren * sizeof(TLV *));

                TLV *child = tlv_Create(packet, inner_type, inner_length, offset + 4, limit);
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
    uint16_t type = buffer_GetWordAtOffset(packet->packet, offset);
    offset += 2;

    uint16_t length = buffer_GetWordAtOffset(packet->packet, offset);
    offset += 2;

    TLV *tlv  = tlv_Create(packet->packet, type, length, offset, limit);
    tlv->sibling = NULL;

    return tlv;
}

void
packet_Display(Packet *packet, int indentation)
{

    TLV *curr = packet->startTLV;
    while (curr != NULL) {
        tlv_Display(curr, indentation);
        curr = curr->sibling;
    }
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
    switch (buffer_GetWordAtOffset(packet->packet, 0)) {
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
    switch (buffer_GetWordAtOffset(packet->packet, 1)) {
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
    return buffer_GetWordAtOffset(packet->packet, 2);
}

uint16_t
packet_GetHeaderLength(Packet *packet)
{
    return buffer_GetWordAtOffset(packet->packet, 7);
}

static Buffer *
_packet_GetFieldValueFromTypeTree(Packet *packet, uint32_t numberOfTypes, uint16_t type[numberOfTypes])
{
    TLV *tlv = packet_FindNestedTLV(packet, numberOfTypes, type);
    if (tlv != NULL) {
        return bufferOverlay_CreateBuffer(tlv->value);
    } else {
        return NULL;
    }
}

// Absolute packet fields
// TODO: make these type trees static
Buffer *
packet_GetFieldValue(Packet *packet, PacketField field)
{
    switch (field) {
        case PacketField_Name: {
            uint16_t typeTree[2] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_CCNxMessage_Name};
            return _packet_GetFieldValueFromTypeTree(packet, 2, typeTree);
        }
        case PacketField_ContentObjectHashRestriction: {
            uint16_t typeTree[2] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_CCNxMessage_ContentObjectHashRestriction};
            return _packet_GetFieldValueFromTypeTree(packet, 2, typeTree);
        }
        case PacketField_KeyIdRestriction: {
            uint16_t typeTree[2] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_CCNxMessage_KeyIdRestriction};
            return _packet_GetFieldValueFromTypeTree(packet, 2, typeTree);
        }
        case PacketField_Payload: {
            uint16_t typeTree[2] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_CCNxMessage_Payload};
            return _packet_GetFieldValueFromTypeTree(packet, 2, typeTree);
        }
        case PacketField_ValidationAlgCert: {
            uint16_t typeTree[3] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_MessageType_ValidationAlg, CCNxTypespace_ValidationAlg_Cert};
            return _packet_GetFieldValueFromTypeTree(packet, 3, typeTree);
        }
        case PacketField_ValidationAlgKeyId: {
            uint16_t typeTree[3] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_MessageType_ValidationAlg, CCNxTypespace_ValidationAlg_KeyId};
            return _packet_GetFieldValueFromTypeTree(packet, 3, typeTree);
        }
        case PacketField_ValidationAlgPublicKey: {
            uint16_t typeTree[3] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_MessageType_ValidationAlg, CCNxTypespace_ValidationAlg_PublicKey};
            return _packet_GetFieldValueFromTypeTree(packet, 3, typeTree);
        }
        case PacketField_ValidationAlgSigTime: {
            uint16_t typeTree[3] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_MessageType_ValidationAlg, CCNxTypespace_ValidationAlg_SigTime};
            return _packet_GetFieldValueFromTypeTree(packet, 3, typeTree);
        }
        case PacketField_ValidationAlgKeyName: {
            uint16_t typeTree[3] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_MessageType_ValidationAlg, CCNxTypespace_ValidationAlg_KeyName};
            return _packet_GetFieldValueFromTypeTree(packet, 3, typeTree);
        }
        case PacketField_ValidationPayload: {
            uint16_t typeTree[2] = {CCNxTypespace_MessageType_Interest, CCNxTypespace_MessageType_ValidationPayload};
            return _packet_GetFieldValueFromTypeTree(packet, 2, typeTree);
        }
        case PacketField_Invalid:
        default:
            break;
    }
    return NULL;
}

// This function should take bounds for the search so we can re-use it for the nested TLV search
static TLV *
_packet_FindTLV(TLV *tlv, uint32_t numberOfTypes, uint16_t type[numberOfTypes], size_t typeOffset)
{
    uint16_t target = type[typeOffset];

    while (tlv != NULL) {
        if (tlv->type == target) {
            if (numberOfTypes == 1) {
                return tlv;
            } else { // go into the type space
                for (int i = 0; i < tlv->numberOfChildren; i++) {
                    TLV *child = tlv->children[i];
                    TLV *result = _packet_FindTLV(child, numberOfTypes - 1, type, typeOffset + 1);
                    if (result != NULL) {
                        return result;
                    }
                }
            }
        }
        tlv = tlv->sibling;
    }

    return NULL;
}

TLV *
packet_FindNestedTLV(Packet *packet, uint32_t numberOfTypes, uint16_t type[numberOfTypes])
{
    TLV *tlv = packet->startTLV;
    return _packet_FindTLV(tlv, numberOfTypes, type, 0);
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

//
// Created by cwood on 2/6/16.
//

#include <stdlib.h>

#include "packet.h"
#include "types.h"
#include "tlv.h"

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

// TLV iterator functions
TLV *
packet_GetNextTLV(Packet *packet, uint32_t offset, uint32_t limit)
{
    uint16_t type = buffer_GetWordAtOffset(packet->packet, offset);
    offset += 2;

    uint16_t length = buffer_GetWordAtOffset(packet->packet, offset);
    offset += 2;

    TLV *tlv  = tlv_Create(packet->packet, type, length, offset, limit);

    return tlv;
}

static void
_packet_DisplayFixedHeader(Packet *packet, int indentation)
{
    // Print
    printf("%04x  Version    = %d\n", 0x00, packet_GetVersion(packet));
    printf("%04x  PacketType = %d\n", 0x01, packet_GetType(packet));
    printf("%04x  PacketLen  = %d\n", 0x02, packet_GetLength(packet));
    printf("%04x  HeaderLen  = %d\n", 0x07, packet_GetHeaderLength(packet));
    printf("%04x  HeaderEnd\n", 0x08);
}

static void
_packet_DisplayBody(TLV *root, int indentation)
{
    uint16_t type = tlv_Type(root);
    uint8_t t1 = (type >> 8) & 0xFF;
    uint8_t t2 = type & 0xFF;
    uint16_t length = tlv_Length(root);
    uint8_t l1 = (length >> 8) & 0xFF;
    uint8_t l2 = length & 0xFF;

    uint32_t offset = tlv_AbsoluteOffset(root);
    printf("%04x  ", offset - 4);
    for (int i = 0; i < indentation; i++) {
        printf(" ");
    }
    printf("%02x %02x %02x %02x\n", t1, t2, l1, l2);
    if (tlv_GetNumberOfChildren(root) > 0) {
        for (int i = 0; i < tlv_GetNumberOfChildren(root); i++) {
            TLV *child = tlv_GetChildByIndex(root, i);
            _packet_DisplayBody(child, indentation + 2);
        }
    } else {
        while (length > 0) {
            printf("%04x  ", offset);
            for (int i = 0; i < indentation + 2; i++) {
                printf(" ");
            }

            for (int i = 0; i < 8 && length > 0; i++) {
                printf("%02x ", bufferOverlay_GetUint8(tlv_Value(root), offset));
                length--;
                offset++;
            }
            printf("\n");
        }
    }

    // Now display the sibling at the same depth
    TLV *sibling = tlv_GetSibling(root);
    if (sibling != NULL) {
        _packet_DisplayBody(sibling, indentation);
    }

    // while (curr != NULL) {
    //     tlv_Display(curr, indentation);
    //     curr = tlv_GetSibling(curr);
    // }
}

// 5 columns for hex offset
// 40 columns for packet data
// 12 columns for raw output
void
packet_Display(Packet *packet, int indentation)
{
    _packet_DisplayFixedHeader(packet, indentation);
    _packet_DisplayBody(packet->startTLV, indentation);
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

    while (tlv_AbsoluteLength(prev) < buffer_Size(buffer)) {
        TLV *next = packet_GetNextTLV(packet, tlv_AbsoluteLength(prev), buffer_Size(buffer));
        tlv_SetSibling(prev, next);
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
        return bufferOverlay_CreateBuffer(tlv_Value(tlv));
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
        if (tlv_Type(tlv) == target) {
            if (numberOfTypes == 1) {
                return tlv;
            } else { // go into the type space
                for (int i = 0; i < tlv_GetNumberOfChildren(tlv); i++) {
                    TLV *child = tlv_GetChildByIndex(tlv, i);
                    TLV *result = _packet_FindTLV(child, numberOfTypes - 1, type, typeOffset + 1);
                    if (result != NULL) {
                        return result;
                    }
                }
            }
        }
        tlv = tlv_GetSibling(tlv);
    }

    return NULL;
}

TLV *
packet_FindNestedTLV(Packet *packet, uint32_t numberOfTypes, uint16_t type[numberOfTypes])
{
    TLV *tlv = packet->startTLV;
    return _packet_FindTLV(tlv, numberOfTypes, type, 0);
}

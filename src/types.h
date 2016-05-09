#ifndef types_h_
#define types_h_

#include "util.h"

typedef enum rta_tlv_schema_v1_packet_type {
    CCNxTypespace_PacketType_Interest = 0x00,
    CCNxTypespace_PacketType_ContentObject = 0x01,
    CCNxTypespace_PacketType_InterestReturn = 0x02,
    CCNxTypespace_PacketType_Control = 0xA4,
} CCNxTypespace_PacketType;

typedef enum rta_tlv_schema_v1_message_type {
    CCNxTypespace_MessageType_Interest = 0x0001,
    CCNxTypespace_MessageType_ContentObject = 0x0002,
    CCNxTypespace_MessageType_ValidationAlg = 0x0003,
    CCNxTypespace_MessageType_ValidationPayload = 0x0004,
    CCNxTypespace_MessageType_Manifest = 0x0006,
    CCNxTypespace_MessageType_Control = 0xBEEF,
} CCNxTypespace_MessageType;

typedef enum rta_tlv_schema_v1_optional_headers_types {
    CCNxTypespace_OptionalHeaders_InterestLifetime = 0x0001,
    CCNxTypespace_OptionalHeaders_RecommendedCacheTime = 0x0002,
    CCNxTypespace_OptionalHeaders_InterestFragment = 0x0003,
    CCNxTypespace_OptionalHeaders_ContentObjectFragment = 0x0004,
} CCNxTypespace_OptionalHeaders;

typedef enum rta_tlv_schema_v1_payloadtype_types {
    CCNxTypespace_PayloadType_Data = 0x00,
    CCNxTypespace_PayloadType_Key = 0x01,
    CCNxTypespace_PayloadType_Link = 0x02,
} CCNxTypespace_PayloadType;

typedef enum rta_tlv_schema_v1_ccnxmessage_types {
    CCNxTypespace_CCNxMessage_Name = 0x0000,
    CCNxTypespace_CCNxMessage_Payload = 0x0001,
    CCNxTypespace_CCNxMessage_KeyIdRestriction = 0x0002,
    CCNxTypespace_CCNxMessage_ContentObjectHashRestriction = 0x0003,
    CCNxTypespace_CCNxMessage_PayloadType = 0x0005,
    CCNxTypespace_CCNxMessage_ExpiryTime = 0x0006,
    CCNxTypespace_CCNxMessage_HashGroup = 0x0007,
    CCNxTypespace_CCNxMessage_EndChunkNumber = 0x0019,
} CCNxTypespace_CCNxMessage;

typedef enum rta_tlv_schema_v1_ccnxname_types {
    CCNxTypespace_CCNxName_NameSegment = 0x0001,
    CCNxTypespace_CCNxName_PayloadID = 0x0002,
} CCNxTypespace_CCNxName;

typedef enum rta_tlv_schema_v1_ccnxmanifest_hashgroup_types {
    CCNxTypespace_CCNxManifestHashGroup_Metadata = 0x0001,
    CCNxTypespace_CCNxManifestHashGroup_DataPointer = 0x0002,
    CCNxTypespace_CCNxManifestHashGroup_ManifestPointer = 0x0003,
} CCNxTypespace_CCNxManifestHashGroup;

typedef enum rta_tlv_schema_v1_ccnxmanifest_hashgroup_metadata_types {
    CCNxTypespace_CCNxManifestHashGroupMetadata_Locator = 0x0000,
    CCNxTypespace_CCNxManifestHashGroupMetadata_ExternalMetadata = 0x0001,
    CCNxTypespace_CCNxManifestHashGroupMetadata_BlockSize = 0x0002,
    CCNxTypespace_CCNxManifestHashGroupMetadata_OverallDataSize = 0x0003,
    CCNxTypespace_CCNxManifestHashGroupMetadata_OverallDataSha256 = 0x0004,
} CCNxTypespace_CCNxManifestHashGroupMetadata;

typedef enum rta_tlv_schema_v1_validation_alg {
    CCNxTypespace_ValidationAlg_CRC32C = 0x0002,
    CCNxTypespace_ValidationAlg_HMAC_SHA256 = 0x0004,
    CCNxTypespace_ValidationAlg_RSA_SHA256 = 0x0006,
    CCNxTypespace_ValidationAlg_EC_SECP_256K1 = 0x0007,

    CCNxTypespace_ValidationAlg_KeyId = 0x0009,
    CCNxTypespace_ValidationAlg_PublicKey = 0x000B,
    CCNxTypespace_ValidationAlg_Cert = 0x000C,
    CCNxTypespace_ValidationAlg_KeyName = 0x000E,
    CCNxTypespace_ValidationAlg_SigTime = 0x000F,
} CCNxTypespace_ValidationAlg;

typedef enum rta_tlv_schema_v1_link_types {
    CCNxTypespace_Link_Name = 0x0000,
    CCNxTypespace_Link_KeyIdRestriction = 0x0001,
    CCNxTypespace_Link_ContentObjectHashRestriction = 0x0002,
} CCNxTypespace_Link;

typedef enum rta_tlv_schema_v1_interestreturncode_types {
    CCNxTypespace_InterestReturnCode_NoRoute = 0x01,
    CCNxTypespace_InterestReturnCode_HopLimitExceeded = 0x02,
    CCNxTypespace_InterestReturnCode_NoResources = 0x03,
    CCNxTypespace_InterestReturnCode_PathError = 0x04,
    CCNxTypespace_InterestReturnCode_Prohibited = 0x05,
    CCNxTypespace_InterestReturnCode_Congestion = 0x06,
    CCNxTypespace_InterestReturnCode_MTUTooLarge = 0x07,
} CCNxTypespace_InterestReturnCode;

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

static char *top_level_type_strings[6] = {
    "CCNxTypespace_MessageType_Interest",
    "CCNxTypespace_MessageType_ContentObject",
    "CCNxTypespace_MessageType_ValidationAlg",
    "CCNxTypespace_MessageType_ValidationPayload",
    "CCNxTypespace_MessageType_Manifest",
    "CCNxTypespace_MessageType_Control"
};

static uint16_t message_types[7] = {
    CCNxTypespace_CCNxMessage_Name,
    CCNxTypespace_CCNxMessage_Payload,
    CCNxTypespace_CCNxMessage_KeyIdRestriction,
    CCNxTypespace_CCNxMessage_ContentObjectHashRestriction,
    CCNxTypespace_CCNxMessage_PayloadType,
    CCNxTypespace_CCNxMessage_ExpiryTime,
    CCNxTypespace_CCNxMessage_EndChunkNumber
};

static char *message_type_strings[8] = {
    "CCNxTypespace_CCNxMessage_Name",
    "CCNxTypespace_CCNxMessage_Payload",
    "CCNxTypespace_CCNxMessage_KeyIdRestriction",
    "CCNxTypespace_CCNxMessage_ContentObjectHashRestriction",
    "CCNxTypespace_CCNxMessage_PayloadType",
    "CCNxTypespace_CCNxMessage_ExpiryTime",
    "CCNxTypespace_CCNxMessage_EndChunkNumber"
};

static uint16_t name_types[2] = {
    CCNxTypespace_CCNxName_NameSegment,
    CCNxTypespace_CCNxName_PayloadID,
};

static char *name_type_strings[8] = {
    "CCNxTypespace_CCNxName_NameSegment",
    "CCNxTypespace_CCNxName_PayloadID",
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

static char *validation_alg_type_strings[9] = {
    "CCNxTypespace_ValidationAlg_CRC32C",
    "CCNxTypespace_ValidationAlg_HMAC_SHA256",
    "CCNxTypespace_ValidationAlg_RSA_SHA256",
    "CCNxTypespace_ValidationAlg_EC_SECP_256K1",
    "CCNxTypespace_ValidationAlg_KeyId",
    "CCNxTypespace_ValidationAlg_PublicKey",
    "CCNxTypespace_ValidationAlg_Cert",
    "CCNxTypespace_ValidationAlg_KeyName",
    "CCNxTypespace_ValidationAlg_SigTime"
};


// A generic node that we can use to stich together the typespace tree
struct typespace_tree_node;
typedef struct typespace_tree_node {
    uint16_t *types;
    char **typeStrings;
    uint16_t numTypes;

    struct typespace_tree_node **children;
    uint16_t numChildren;
} TypespaceTreeNode;

// TODO: remove the header part... it's not in the rest of the TLV tree space
static TypespaceTreeNode header_root = {
    .types = header_types,
    .typeStrings = NULL,
    .numTypes = sizeof(header_types) / sizeof(uint16_t),
    .children = NULL,
    .numChildren = 0
};

static TypespaceTreeNode validation_alg_types_node = {
    .types = validation_alg_types,
    .typeStrings = validation_alg_type_strings,
    .numTypes = sizeof(validation_alg_types) / sizeof(uint16_t),
    .children = NULL,
    .numChildren = 0
};

static TypespaceTreeNode name_types_node = {
    .types = name_types,
    .typeStrings = name_type_strings,
    .numTypes = sizeof(name_types) / sizeof(uint16_t),
    .children = NULL,
    .numChildren = 0
};

static TypespaceTreeNode *message_type_children[1] = {
    &name_types_node,
};

static TypespaceTreeNode message_types_node = {
    .types = message_types,
    .typeStrings = message_type_strings,
    .numTypes = sizeof(message_types) / sizeof(uint16_t),
    .children = message_type_children,
    .numChildren = sizeof(message_type_children) / sizeof(TypespaceTreeNode *)
};

static TypespaceTreeNode *top_level_type_children[2] = {
    &message_types_node,
    &validation_alg_types_node
};

static TypespaceTreeNode top_level_types_node = {
    .types = top_level_types,
    .typeStrings = top_level_type_strings,
    .numTypes = sizeof(top_level_types) / sizeof(uint16_t),
    .children = top_level_type_children,
    .numChildren = sizeof(top_level_type_children) / sizeof(TypespaceTreeNode *)
};

char *types_TreeToString(uint32_t numberOfTypes, uint16_t type[numberOfTypes]);

#endif

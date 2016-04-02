#ifndef types_h_
#define types_h_

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

#endif

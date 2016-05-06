#ifndef dissect_packetfield_h_
#define dissect_packetfield_h_

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

#endif // dissect_packetfield_h_

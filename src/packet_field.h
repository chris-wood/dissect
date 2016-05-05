#ifndef dissect_packetfield_h_
#define dissect_packetfield_h_

typedef enum {
    // Message "header"
    PacketField_Name,
    PacketField_KeyIdRestriction,
    PacketField_ContentObjectHashRestriction,

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

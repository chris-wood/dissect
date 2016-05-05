#ifndef tlv_h_
#define tlv_h_

#include "packet_field.h"
#include "buffer.h"
#include "util.h"

struct tlv;
typedef struct tlv TLV;

TLV *tlv_Create(Buffer *packet, uint16_t type, uint16_t length, uint32_t offset, uint32_t limit);

void tlv_Display(TLV *tlv, size_t indentation);

uint16_t tlv_Type(TLV *tlv);

uint16_t tlv_Length(TLV *tlv);

BufferOverlay *tlv_Value(TLV *tlv);

TLV *tlv_GetSibling(TLV *tlv);

void tlv_SetSibling(TLV *tlv, TLV *sibling);

size_t tlv_GetNumberOfChildren(TLV *tlv);
TLV *tlv_GetChildByIndex(TLV *tlv, size_t index);

size_t tlv_AbsoluteOffset(TLV *tlv);

size_t tlv_AbsoluteLength(TLV *tlv);

#endif // tlv_h_

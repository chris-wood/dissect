#include <stdlib.h>
#include "tlv.h"

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

static void
_tlv_ReportTree(TLV *tlv, Reporter *reporter, uint32_t numberOfTypes, uint16_t parentTypes[numberOfTypes])
{
    uint16_t *types = malloc(sizeof(numberOfTypes) * (numberOfTypes + 1));
    if (numberOfTypes > 0) {
        for (int i = 0; i < numberOfTypes; i++) {
            types[i] = parentTypes[i];
        }
    }

    types[numberOfTypes] = tlv_Type(tlv);
    Buffer *value = tlv_ValueBuffer(tlv);

    reporter_ReportTLV(reporter, numberOfTypes + 1, types, value);
    buffer_Destroy(&value);

    for (size_t i = 0; i < tlv_GetNumberOfChildren(tlv); i++) {
        TLV *child = tlv_GetChildByIndex(tlv, i);
        _tlv_ReportTree(child, reporter, numberOfTypes + 1, types);
    }

    if (tlv_GetSibling(tlv) != NULL) {
        _tlv_ReportTree(tlv_GetSibling(tlv), reporter, numberOfTypes, parentTypes);
    }

    free(types);
}

void
tlv_Report(TLV *tlv, Reporter *reporter)
{
    _tlv_ReportTree(tlv, reporter, 0, NULL);
}

static bool
_tlv_HasInnerTLV(TLV *tlv, uint32_t limit)
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

TLV *
tlv_Create(Buffer *packet, uint16_t type, uint16_t length, uint32_t offset, uint32_t limit)
{
    TLV *tlv = (TLV *) malloc(sizeof(TLV));
    tlv->type = type;
    tlv->length = length;
    tlv->sibling = NULL;

    tlv->offset = offset; // this is an absolute offset into the packet buffer
    tlv->value = bufferOverlay_CreateFromBuffer(packet, offset, length);

    if (_tlv_HasInnerTLV(tlv, length)) {
        // Attempt to create an array of children. Rewind and fail if something goes wrong.
        tlv->children = NULL;
        tlv->numberOfChildren = 0;

        while (offset < (tlv->offset + length)) {
            uint16_t inner_type = buffer_GetWordAtOffset(packet, offset);
            offset += 2;
            uint16_t inner_length = buffer_GetWordAtOffset(packet, offset);
            offset += 2;

            if (offset + inner_length > limit) {
                // Failure.
                tlv->numberOfChildren = 0;
                if (tlv->children != NULL) {
                    free(tlv->children);
                }
                tlv->children = NULL;
                return tlv;
            } else {
                tlv->numberOfChildren++;
                tlv->children = (TLV **) realloc(tlv->children, tlv->numberOfChildren * sizeof(TLV *));

                TLV *child = tlv_Create(packet, inner_type, inner_length, offset, limit);
                tlv->children[tlv->numberOfChildren - 1] = child;
            }

            offset += inner_length;
        }
    } else {
        tlv->children = NULL;
        tlv->numberOfChildren = 0;
    }

    return tlv;
}

void
tlv_Destroy(TLV **tlvPtr)
{
    TLV *tlv = *tlvPtr;

    bufferOverlay_Destroy(&tlv->value);
    if (tlv->sibling != NULL) {
        tlv_Destroy(&tlv->sibling);
    }
    for (size_t i = 0; i < tlv->numberOfChildren; i++) {
        tlv_Destroy(&tlv->children[i]);
    }

    free(tlv);
    *tlvPtr = NULL;
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

BufferOverlay *
tlv_Value(TLV *tlv)
{
    return tlv->value;
}

Buffer *
tlv_ValueBuffer(TLV *tlv)
{
    return bufferOverlay_CreateBuffer(tlv->value);
}

size_t
tlv_AbsoluteOffset(TLV *tlv)
{
    return tlv->offset;
}

size_t
tlv_AbsoluteLength(TLV *tlv)
{
    return tlv->offset + tlv->length;
}

TLV *
tlv_GetSibling(TLV *tlv)
{
    return tlv->sibling;
}

void
tlv_SetSibling(TLV *tlv, TLV *sibling)
{
    tlv->sibling = sibling;
}

size_t
tlv_GetNumberOfChildren(TLV *tlv)
{
    return tlv->numberOfChildren;
}

TLV *
tlv_GetChildByIndex(TLV *tlv, size_t index)
{
    if (index < tlv->numberOfChildren) {
        return tlv->children[index];
    }
    return NULL;
}

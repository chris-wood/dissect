//
// Created by cwood on 2/23/16.
//

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <sys/stat.h>
#include <stdbool.h>

#include "../packet.c"

// interest = 0100001E40000008000100120000000E00010003666F6F00010003626172
// data = 0101004EFF000008000200420000000E00010003666F6F000100036261720001002C68756765207061796C6F6164206D616E20616E6420736F6D652068656C6C6F20776F726C642073747566660A

static size_t 
_fileSize(char *fname)
{
    size_t fileSize = 0;

    struct stat st;
    if (stat(fname, &st) == 0) {
        fileSize = st.st_size;
    }

    return fileSize;
}

static bool
_readFile(char *fname, uint8_t **array, size_t *length)
{
    size_t size = _fileSize(fname);
    
    FILE *fp = fopen(fname, "rb");    
    *array = (uint8_t *) malloc(size);

    uint8_t numRead = fread(*array, 1, size, fp);

    if (numRead == size) {
        *length = size;
        return true;
    } else {
        return false;
    }
}

static void test_packet_Create(void **state) 
{
    uint8_t *array;
    size_t length;

    if (_readFile("test_interest.bin", &array, &length)) {
        Buffer *buffer = buffer_CreateFromArray(array, length);
        Packet *packet= packet_CreateFromBuffer(buffer);
        assert_true(packet != NULL);


    } else {
        assert_true(false);
    }
}

static void test_packet_GetVersion(void **state) {
    // TODO
}

static void test_packet_GetType(void **state) {
    // TOOD
}

static void test_tlv_leaf_create(void **state) {
    // This is a single TLV with no children.
    uint8_t array[8] = {0, 0, 0, 4, 1, 2, 3, 4};
    Buffer *buffer = buffer_CreateFromArray(array, sizeof(array));
    TLV *leaf = tlv_Create(buffer, 0, 4, 2);

    assert_true(leaf != NULL);
    assert_true(leaf->children == NULL);
    assert_true(leaf->numberOfChildren == 0);
}

static void test_tlv_tree_create(void **state) {
    // This is a TLV with two inner children
    uint8_t array[16] = {0, 0, 0, 12, 0, 1, 0, 2, 1, 1, 0, 2, 0, 2, 3, 3};

    Buffer *buffer = buffer_CreateFromArray(array, sizeof(array));
    TLV *root = tlv_Create(buffer, 0, 12, 2);

    assert_true(root != NULL);
    assert_true(root->children != NULL);
    assert_true(root->numberOfChildren == 2);
}

static void test_tlv_tree_create_invalid(void **state) {
    // This is a TLV with two inner children
    uint8_t array[16] = {0, 0, 0, 12, 0, 1, 0, 12, 1, 1, 0, 2, 0, 2, 3, 3};

    Buffer *buffer = buffer_CreateFromArray(array, sizeof(array));
    TLV *root = tlv_Create(buffer, 0, 12, 2);

    assert_true(root != NULL);
    assert_true(root->children == NULL);
    assert_true(root->numberOfChildren == 0);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_packet_Create),
        cmocka_unit_test(test_tlv_leaf_create),
        cmocka_unit_test(test_tlv_tree_create),
        cmocka_unit_test(test_tlv_tree_create_invalid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
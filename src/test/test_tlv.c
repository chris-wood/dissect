#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <sys/stat.h>
#include <stdbool.h>

#include "../tlv.c"

static void test_tlv_leaf_create(void **state) {
    // This is a single TLV with no children.
    uint8_t array[8] = {0, 0, 0, 4, 1, 2, 3, 4};
    Buffer *buffer = buffer_CreateFromArray(array, sizeof(array));
    TLV *leaf = tlv_Create(buffer, 0, 4, 2, sizeof(array));

    assert_true(leaf != NULL);
    assert_true(leaf->children == NULL);
    assert_true(leaf->numberOfChildren == 0);
}

static void test_tlv_tree_create(void **state) {
    // This is a TLV with two inner children
    uint8_t array[16] = {0, 0, 0, 12, 0, 1, 0, 2, 1, 1, 0, 2, 0, 2, 3, 3};

    Buffer *buffer = buffer_CreateFromArray(array, sizeof(array));
    TLV *root = tlv_Create(buffer, 0, 12, 4, sizeof(array));

    assert_true(root != NULL);
    assert_true(root->children != NULL);
    assert_true(root->numberOfChildren == 2);
}

static void test_tlv_tree_create_invalid(void **state) {
    // This is a TLV with two inner children
    uint8_t array[16] = {0, 0, 0, 12, 0, 1, 0, 12, 1, 1, 0, 2, 0, 2, 3, 3};

    Buffer *buffer = buffer_CreateFromArray(array, sizeof(array));
    TLV *root = tlv_Create(buffer, 0, 12, 4, sizeof(array));

    assert_true(root != NULL);
    assert_true(root->children == NULL);
    assert_true(root->numberOfChildren == 0);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tlv_leaf_create),
        cmocka_unit_test(test_tlv_tree_create),
        cmocka_unit_test(test_tlv_tree_create_invalid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

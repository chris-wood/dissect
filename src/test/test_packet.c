//
// Created by cwood on 2/23/16.
//

#include <unistd.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include "../packet.c"

// interest = 0100001E40000008000100120000000E00010003666F6F00010003626172
// data = 0101004EFF000008000200420000000E00010003666F6F000100036261720001002C68756765207061796C6F6164206D616E20616E6420736F6D652068656C6C6F20776F726C642073747566660A

static void test_packet_Create(void **state) {
    uint8_t array[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    Buffer *buffer = buffer_CreateFromArray(array, 16);
    Packet *packet= packet_CreateFromBuffer(buffer);
    assert_true(packet != NULL);

    // TODO: memory management
}

static void test_packet_GetVersion(void **state) {
    // TODO
}

static void test_packet_GetType(void **state) {
    // TOOD
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_packet_Create),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
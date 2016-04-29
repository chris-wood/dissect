//
// Created by cwood on 1/31/16.
//

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "packet.h"
#include "capture.h"

// usage:
// - read from stdin and dump to stdout
// - specify filters (as SQL query or a list of fields to extract)
// - specify different output formats per packet (CSV, JSON, etc)

typedef enum {
    _OutputFormat_JSON,
    _OutputFormat_CSV,
    _OutputFormat_Invalid
} _OutputFormat;

typedef enum {
    _Protocol_TCP = 0x00,
    _Protocol_UDP = 0x01,
    _Protocol_ETF = 0x02,
} _Protocol;

void
_showUsage(char *programName)
{
    printf("%s: CCNx packet dissector.\n", programName);
    printf("\n");
    printf("Usage: %s [-c [<device>:]<protocol>] [-h] [-o (json | csv)]\n", programName);
    printf("\n");
    printf("  -c:          capture CCNx packets sent over the given protocol and optionally captured\n");
    printf("               by the specified interface device, e.g., eth0\n");
    printf("  -o <format>: output the packet data in <format>, where <format> is JSON or CSV. \n");
    printf("  -h:          display this usage message\n");
}

#define BUFFER_SIZE 64000

int
main(int argc, char **argv)
{
    bool showUsage = false;
    char *cvalue = NULL;
    char *deviceAndProtocol = NULL;
    _OutputFormat outputFormat = _OutputFormat_Invalid;
    int value = 0;

    while ((value = getopt (argc, argv, "o:c:h")) != -1) {
        switch (value) {
            case 'o':
                cvalue = optarg;
                if (strcmp(cvalue, "json") == 0) {
                    outputFormat = _OutputFormat_JSON;
                } else if (strcmp(cvalue, "csv") == 0) {
                    outputFormat = _OutputFormat_CSV;
                } else {
                    showUsage = true;
                }
                break;
            case 'c':
                strcpy(deviceAndProtocol, optarg);
                // TODO: parse using strtok
                break;
            case 'h':
            default:
                showUsage = true;
                break;
        }
    }

    if (showUsage) {
        _showUsage(argv[0]);
        exit(0);
    }

    // The buffer to store a single packet at a time (64KB is the max packet size).
    char buffer[BUFFER_SIZE];

    // Start reading from the command line
    while (fgets(buffer, BUFFER_SIZE, stdin)) {
        // Peek at length
        uint16_t length = ((uint16_t)(buffer[2]) << 8) | (uint16_t)(buffer[3]);

        // Create and display the packet
        Buffer *packetBuffer = buffer_CreateFromArray((uint8_t *) buffer, length);
        Packet *packet = packet_CreateFromBuffer(packetBuffer);
        packet_Display(packet, 0);

        // TODO: need to write code that will peek on next packet, if it's in the buffer
        // TODO: this is where we would implement the reporter
    }

    capture();
}

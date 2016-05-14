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

static void
_showUsage(char *programName)
{
    printf("%s: CCNx packet dissector.\n", programName);
    printf("\n");
    printf("Usage: %s [-h] [-c <device>] [-t <pcap filter>] [-f <file name>] [-o (json | csv)]\n", programName);
    printf("\n");
    printf("  -c <device>:                the device from which to capture live packets \n");
    printf("  -t <traffic filter string>: filter traffic for the live capture with this filter string (see pcap_filter() for details).\n");
    printf("  -f <file name>:             name of the file from which to read packets.\n");
    printf("  -o <format>:                output the packet data in <format>, where <format> is JSON or CSV. \n");
    printf("  -h:                         display this usage message\n");
}

int
main(int argc, char **argv)
{
    bool showUsage = false;
    char *cvalue = NULL;
    char *deviceString = NULL;
    char *filterString = NULL;
    char *fileName = NULL;
    int value = 0;
    bool liveMode = false;
    bool fileMode = false;

    _OutputFormat outputFormat = _OutputFormat_Invalid;

    static struct option longopts[] = {
        { "output",         required_argument, NULL, 'o' },
        { "capture",        required_argument, NULL, 'c' },
        { "traffic_filter", required_argument, NULL, 't' },
        { "file",           required_argument, NULL, 'f' },
        { "help",           no_argument,       NULL, 'h' },
        { NULL,             0,                 NULL, 0   }
    };

    while ((value = getopt_long(argc, argv, "o:c:t:f:h", longopts, NULL)) != -1) {
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
                asprintf(&deviceString, "%s", optarg);
                liveMode = true;
                break;
            case 't':
                asprintf(&filterString, "%s", optarg);
                break;
            case 'f':
                asprintf(&fileName, "%s", optarg);
                fileMode = true;
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

    // Reporter *reporter = reporter_CreateRawFileReporter(stdout);
    Reporter *reporter = reporter_CreateJSONFileReporter(stdout);

    // The buffer to store a single packet at a time (64KB is the max packet size).
    if (liveMode) {
        captureFromDevice(reporter, deviceString, filterString);
    } else if (fileMode) {
        FILE *inputFile = fopen(fileName, "rb");
        if (inputFile != NULL) {
            captureFromFile(reporter, inputFile);
            fclose(inputFile);
        } else {
            fprintf(stderr, "Error: unable to open %s for reading\n", fileName);
        }
    } else {
        captureFromFile(reporter, stdin);
    }

    reporter_Destroy(&reporter);
}

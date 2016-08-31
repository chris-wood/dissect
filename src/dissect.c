//
// Created by cwood on 1/31/16.
//

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "packet.h"
#include "digester.h"
#include "capture.h"

#define DEBUG 1

// usage:
// - read from stdin and dump to stdout
// - specify filters (as SQL query or a list of fields to extract)
// - specify different output formats per packet (CSV, JSON, etc)

typedef enum {
    _OutputFormat_Raw,
    _OutputFormat_JSON,
    _OutputFormat_CSV,
    _OutputFormat_Invalid
} _OutputFormat;

static void
_showUsage(char *programName)
{
    printf("%s: CCNx packet dissector.\n", programName);
    printf("\n");
    printf("Usage: %s [-h] [-c <device>] [-f <pcap filter>] [-i <file name>] [-d <alg>] [-o (json | csv)]\n", programName);
    printf("\n");
    printf("  -c <device>:                the device from which to capture live packets \n");
    printf("  -f <traffic filter string>: filter traffic for the live capture with this filter string (see pcap_filter() for details).\n");
    printf("  -i <file name>:             name of the file from which to read packets.\n");
    printf("  -d <alg>:                   flag to output the message digest.\n");
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
    bool digestFlag = false;
    DigestAlgorithm digestAlg = DigestAlgorithm_Invalid;

    char **filters = NULL;
    int numFilters = 0;

    _OutputFormat outputFormat = _OutputFormat_Raw;

    static struct option longopts[] = {
        { "output_mode",    required_argument, NULL, 'm' },
        { "digest",         required_argument, NULL, 'd' },
        { "capture",        required_argument, NULL, 'c' },
        { "traffic_filter", required_argument, NULL, 't' },
        { "input_file",     required_argument, NULL, 'i' },
        { "filter",         required_argument, NULL, 'f' },
        { "help",           no_argument,       NULL, 'h' },
        { NULL,             0,                 NULL, 0   }
    };

    while ((value = getopt_long(argc, argv, "m:c:t:f:i:hd:", longopts, NULL)) != -1) {
        switch (value) {
            case 'm':
                cvalue = optarg;
                if (strcmp(cvalue, "json") == 0) {
                    outputFormat = _OutputFormat_JSON;
                } else if (strcmp(cvalue, "csv") == 0) {
                    outputFormat = _OutputFormat_CSV;
                } else {
                    outputFormat = _OutputFormat_Invalid;
                }
                break;
            case 'c':
                deviceString = optarg;
                liveMode = true;
                break;
            case 'f': {
                if (filters == NULL) {
                    filters = (char **) malloc((numFilters++) * sizeof(char *));
                } else {
                    filters = (char **) realloc(filters, (numFilters++) * sizeof(char*));
                }

                filters[numFilters - 1] = optarg;
                break;
            }
            case 'i':
                fileName = optarg;
                fileMode = true;
                break;
            case 'd':
                digestFlag = true;
                if (strcmp(optarg, "SHA256") == 0) {
                    digestAlg = DigestAlgorithm_SHA256;
                } else {
                    digestAlg = DigestAlgorithm_Invalid;
                    fprintf(stderr, "Unsupported algorithm :%d\n", digestAlg);
                    exit(-1);
                }
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

#if DEBUG
    for (int i = 0; i < numFilters; i++) {
        printf("Filter: %s\n", filters[i]);
    }
#endif

    Processor *packetProcessor = NULL;
    if (digestFlag) {
        Digester *digester = digester_Create(digestAlg);
        packetProcessor = digester_AsProcessor(digester);
    } else {
        Reporter *reporter = NULL;
        switch (outputFormat) {
            case _OutputFormat_Raw:
                reporter = reporter_CreateRawFileReporter(stdout);
                break;
            case _OutputFormat_JSON:
                reporter = reporter_CreateJSONFileReporter(stdout);
                break;
            case _OutputFormat_CSV:
                reporter = reporter_CreateCSVFileReporter(stdout);
                break;
            default:
                fprintf(stderr, "Report output format not implemented.\n");
                _showUsage(argv[0]);
                exit(-1);
        }
        
        for (int i = 0; i < numFilters; i++) {
            reporter_AddFilterByString(reporter, filters[i]);
        }

        packetProcessor = reporter_AsProcessor(reporter);
    }

    if (liveMode) {
        captureFromDevice(packetProcessor, deviceString, filterString);
    } else if (fileMode) {
        FILE *inputFile = fopen(fileName, "rb");
        if (inputFile != NULL) {
            captureFromFile(packetProcessor, inputFile);
            fclose(inputFile);
        } else {
            fprintf(stderr, "Error: unable to open %s for reading\n", fileName);
        }
    } else {
        captureFromFile(packetProcessor, stdin);
    }

    // XXX: free up memory
    //processor_Destroy(&reporter);
}


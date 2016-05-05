#include <stdbool.h>

#include <pcap/pcap.h>

#include "packet.h"
#include "capture.h"

#define BUFFER_SIZE 64000

int
captureFromDevice(Reporter *reporter, char *device, char *filter)
{
    // http://www.manpagez.com/man/7/pcap-filter/
    // http://www.tcpdump.org/pcap.html

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return -1;
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return -2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return -3;
    }

    struct pcap_pkthdr *header = NULL;
    const u_char *data = NULL;

    while (pcap_next_ex(handle, &header, &data)) {
        uint16_t length = ((uint16_t)(data[2]) << 8) | (uint16_t)(data[3]);

        // Create the packet
        Buffer *packetBuffer = buffer_CreateFromArray((uint8_t *) data, length);
        Packet *packet = packet_CreateFromBuffer(packetBuffer);

        // Display the packet
        packet_Report(packet, reporter);
    }

    return 0;
}

int
captureFromFile(Reporter *reporter, FILE *file)
{
    // The buffer to store a single packet at a time (64KB is the max packet size).
    char buffer[BUFFER_SIZE];
    size_t offset = 0;

    bool isMore = fgets(buffer, BUFFER_SIZE, file) != NULL;
    size_t bufferSize = BUFFER_SIZE;
    size_t tail = bufferSize;
    size_t packetNumber = 0;

    // Start reading from the command line
    while (isMore) {
        // Peek at length and fill in the tail of the buffer if necessary
        uint16_t length = ((uint16_t)(buffer[2]) << 8) | (uint16_t)(buffer[3]);
        if (length == 0) {
            break;
        } else if (length > tail) {
            fgets(buffer + tail, BUFFER_SIZE - tail, file);
        }

        // Create the packet
        Buffer *packetBuffer = buffer_CreateFromArray((uint8_t *) buffer, length);
        Packet *packet = packet_CreateFromBuffer(packetBuffer);

        // Display the packet
        packet_Report(packet, reporter);

        // Update the offset and shift down the rest of the buffer contents
        memcpy(buffer, buffer + length, bufferSize - length);
        memset(buffer + tail, 0, bufferSize - tail);
        tail = BUFFER_SIZE - length;
    }

    return 0;
}

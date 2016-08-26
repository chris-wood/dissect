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
    memset(buffer, 0, BUFFER_SIZE);

    // Start peeking into the file and read the packet if there's something there
    bool isMore = fgets(buffer, 5, file) != NULL && !feof(file);
    while (isMore) {
        // Peek at length and fill in the tail of the buffer if necessary
        uint16_t length = (((uint16_t)(buffer[2]) << 8) & 0xFF00) | ((uint16_t)(buffer[3]) & 0x00FF);
        if (length > 0) {
            isMore = fgets(((char *) buffer) + 4, length - 4 + 1, file) != NULL;
        }

        // Create the packet
        Buffer *packetBuffer = buffer_CreateFromArray((uint8_t *) buffer, length);
        Packet *packet = packet_CreateFromBuffer(packetBuffer);

        // Display the packet
        packet_Report(packet, reporter);
        packet_Destroy(&packet);
        buffer_Destroy(&packetBuffer);

        // Reset the buffer and try to read in the next packet
        memset(buffer, 0, BUFFER_SIZE);
        isMore = fgets(buffer, 5, file) != NULL && feof(file);
    }

    return 0;
}

#include <stdbool.h>

#include <pcap/pcap.h>

#include "packet.h"
#include "capture.h"

#define BUFFER_SIZE 64000

void
captureFromDevice(Reporter *reporter, char *device, char *filter)
{
    // TODO
    // http://www.manpagez.com/man/7/pcap-filter/
    // http://www.tcpdump.org/pcap.html

    // TODO: snippet from the above link
    // pcap_t *handle;		/* Session handle */
    // char dev[] = "rl0";		/* Device to sniff on */
    // char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    // struct bpf_program fp;		/* The compiled filter expression */
    // char filter_exp[] = "port 23";	/* The filter expression */
    // bpf_u_int32 mask;		/* The netmask of our sniffing device */
    // bpf_u_int32 net;		/* The IP of our sniffing device */
    //
    // if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    //     fprintf(stderr, "Can't get netmask for device %s\n", dev);
    //     net = 0;
    //     mask = 0;
    // }
    // handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // if (handle == NULL) {
    //     fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    //     return(2);
    // }
    // if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    //     fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //     return(2);
    // }
    // if (pcap_setfilter(handle, &fp) == -1) {
    //     fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    //     return(2);
    // }
}

void
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
}

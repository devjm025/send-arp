#include "sendarp.h"

#define MAX_MAC_ADDR_LEN 18
#define MAX_IP_ADDR_LEN 16

extern char sender_mac[MAX_MAC_ADDR_LEN];
extern char self_mac[MAX_MAC_ADDR_LEN];

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    GetSelfMac(argv[1]);
    //printf("%s\n", self_mac);

    char self_ip[MAX_IP_ADDR_LEN];
    strncpy(self_ip,"192.168.169.18", MAX_IP_ADDR_LEN);


    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    GetSenderMac(handle, self_ip, argv[2]);
    //printf("main: %s", sender_mac);

    SendARPReply(handle, argv[3], argv[2]);
    printf("Send ARP Reply to %s", argv[2]);

}

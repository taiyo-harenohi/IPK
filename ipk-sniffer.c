// Name: IPK 2. project - packet sniffer
// Author: Nikola Machalkova
// Login: xmacha80
// Date: 24/04/2022

#include<pcap/pcap.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>

// function for printing src and dst
void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]);
    printf("frame length: %d\n", header->len);
    
    // comparing for determing if it is IPV4 or IPV6
    if (memcmp(&bytes[12], "\x08\x00", 2) == 0) {
        printf("src IP: %d.%d.%d.%d\n", bytes[24+2], bytes[25+2], bytes[26+2], bytes[27+2]);
        printf("dst IP: %d.%d.%d.%d\n", bytes[28+2], bytes[29+2], bytes[30+2], bytes[31+2]);
        int lenIPV4 = 4 * (bytes[14]&15);
        if (bytes[23] == 6 || bytes[23] == 17) {
            printf("src port: %d\n", bytes[14+lenIPV4]*256 + bytes[15+lenIPV4]);
            printf("dst port: %d\n", bytes[16+lenIPV4]*256 + bytes[17+lenIPV4]);
        }
    }
    else if (memcmp(&bytes[12], "\x86\xdd", 2) == 0) {
        printf("src IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", bytes[20+2], bytes[21+2], bytes[22+2], bytes[23+2], bytes[24+2], bytes[25+2], bytes[26+2], bytes[27+2], bytes[28+2], bytes[29+2], bytes[30+2], bytes[31+2], bytes[32+2], bytes[33+2], bytes[34+2], bytes[35+2]);
        printf("dst IP: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", bytes[36+2], bytes[37+2], bytes[38+2], bytes[39+2], bytes[40+2], bytes[41+2], bytes[42+2], bytes[43+2], bytes[44+2], bytes[45+2], bytes[46+2], bytes[47+2], bytes[48+2], bytes[49+2], bytes[50+2], bytes[51+2]);
        if (bytes[23] == 6 || bytes[23] == 17) {
            printf("src port: %d\n", bytes[54]*256 + bytes[55]);
            printf("dst port: %d\n", bytes[56]*256 + bytes[57]);
        }
    }
    printf("\n");
    // for printing bytes in HEX and char
    for (int i = 0; i < (header->len + 15) / 16; i++) {
        printf("0x%04x:  ", i*16);
        for (int j = 0; j < 16; j++) {
            if (j == 8) {
                printf(" ");
            }            
            if (i*16 + j >= header->len) {
                printf("   ");
                continue;
            }
            printf("%02x ", bytes[i*16 + j]);
        }
        printf(" ");
        for (int j = 0; j < 16; j++) {
            if (j == 8) {
                printf(" ");
            }
            if (i*16 + j >= header->len) {
                break;          
            }
            if (isprint(bytes[i*16 + j])) {
                printf("%c", bytes[i*16 + j]);
            }
            else {
                printf(".");
            }
        }        
        printf("\n");
    }
}

// function for handlening offsets
void filter(pcap_t *handle, char *port, int tcp, int udp, int icmp, int arp) {
    char output[1000] = "";
    if (tcp == 1) {
        if (port == "") {
            strcat(output, "or tcp ");
        }
        else {
            strcat(output, "or tcp port ");
            strcat(output, port);
            strcat(output, " ");
        }
    }
    if (udp == 1) {
        if (port == "") {
            strcat(output, "or udp ");
        }
        else {
            strcat(output, "or udp port ");
            strcat(output, port);
            strcat(output, " ");
        }        
    }
    if (icmp == 1) {
        strcat(output, "or icmp ");
    }
    if (arp == 1) {
        strcat(output, "or arp ");
    }

    output[strlen(output) - 1] = '\0';

    struct bpf_program hehe_program;
    pcap_compile(handle, &hehe_program, output+3, 0, 0);
    pcap_setfilter(handle, &hehe_program);
    pcap_freecode(&hehe_program);
}

int main(int argc, char *argv[]) {
    // argument checking
    char *interface = "";
    int isInterface = 0;
    int packetCnt = 1;
    char *port = "";
    int tcp = 0;
    int udp = 0;
    int icmp = 0;
    int arp = 0;

    for (int i = 1; i < argc; i++) {
        // interface
        if (strcmp(argv[i],"-i") == 0 || strcmp(argv[i],"--interface") == 0) {
            interface = argv[i+1];
            isInterface = 1;
        }
        // port -- if none, writes nothing in filter()
        if (strcmp(argv[i],"-p") == 0) {
            if (atoi(argv[i+1]) < 0) {
                printf("ERROR Wrong number of port");
                return -1;
            }
            port = argv[i+1];
        }
        // packet count
        if (strcmp(argv[i],"-n") == 0) {
            packetCnt = atoi(argv[i+1]);
            if (packetCnt <= 0) {
                printf("ERROR negative number of packets");
                return -1;
            }
        }
        // packets
        if (strcmp(argv[i],"-t") == 0 || strcmp(argv[i],"--tcp") == 0) {
            tcp = 1;
        }        
        if (strcmp(argv[i],"-u") == 0 || strcmp(argv[i],"--udp") == 0) {
            udp = 1;
        }   
        if (strcmp(argv[i],"--icmp") == 0) {
            icmp = 1;
        }   
        if (strcmp(argv[i],"--arp") == 0) {
            arp = 1;
        }   
    }

    if (isInterface == 0) {
        printf("ERROR no interface is present\n");
        return -1;
    }

    if (tcp == 0 && udp == 0 && icmp == 0 && arp == 0) {
        tcp = 1;
        udp = 1;
        icmp = 1;
        arp = 1;
    }

    // error buffer for error codes
    char errbuf[PCAP_ERRBUF_SIZE];
    // all captured devices
    pcap_if_t *alldevsp;
    if (pcap_findalldevs(&alldevsp, errbuf)) {
        printf(errbuf);
        return -1;
    }

    if (strcmp(interface,"") == 0) {
        while (alldevsp != NULL) {
            printf(alldevsp->name);
            printf("\n");

            alldevsp = alldevsp->next;
        }
        return 0;
    }  

    pcap_t *handleDev = pcap_create(interface, errbuf);
    if (handleDev == NULL) {
        printf(errbuf);
        return -1;
    }

    pcap_set_timeout(handleDev, 500);
    if (pcap_activate(handleDev)) {
        printf("ERROR in pcap_activate\n");
        return -1;
    }

    filter(handleDev, port, tcp, udp, icmp, arp);

    if (pcap_loop(handleDev, packetCnt, callback, NULL)) {
        printf("ERROR in pcap_loop\n");
        return -1;
    }
    return 0; 
}

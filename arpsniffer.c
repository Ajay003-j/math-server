#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ether.h>

#define ARP_REQUEST 1
#define ARP_RESPONSE 2
#define LOG_FILE "/var/log/arp_spoof.log"
#define MAX_IPS 100
#define THRESHOLD 10
#define TIME_WINDOW 20  // seconds

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
    uint16_t htype;         // Hardware type
    uint16_t ptype;         // Protocol type
    uint8_t hlen;           // Hardware address length (MAC)
    uint8_t plen;           // Protocol address length
    uint16_t opcode;        // Operation code (request or response)
    uint8_t sender_mac[6];  // Sender hardware address
    uint8_t sender_ip[4];   // Sender IP address
    uint8_t target_mac[6];  // Target MAC address
    uint8_t target_ip[4];   // Target IP address
};

typedef struct {
    char ip[16];
    char mac[20];
    int count;
    time_t first_seen;
    int blocked;
} IPRecord;

IPRecord records[MAX_IPS];
int record_count = 0;

void log_event(const char* message) {
    FILE *logfile = fopen(LOG_FILE, "a");
    if (logfile == NULL) {
        printf("ERROR: Unable to write log file.\n");
        return;
    }
    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp)-1] = '\0';  // remove newline
    fprintf(logfile, "[%s] %s\n", timestamp, message);
    fclose(logfile);
}

void block_ip(const char* ip) {
    char cmd[100];
    sprintf(cmd, "sudo iptables -A INPUT -s %s -j DROP", ip);
    system(cmd);
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Blocked IP: %s via iptables", ip);
    log_event(log_msg);
}

void send_alert(const char* ip, const char* mac) {
    char cmd[500];
    const char *admin_email = "2022peccb247@gmail.com";
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Sending email alert for IP: %s (MAC: %s)", ip, mac);
    log_event(log_msg);

    sprintf(cmd, "echo \"[ALERT] ARP Spoofing Detected from IP: %s (MAC: %s). IP has been blocked. Log file attached.\" | "
            "mail -s \"ARP Spoofing Alert\" -A %s %s",
            ip, mac, LOG_FILE, admin_email);
    system(cmd);
}

void alert_spoof(const char* ip, const char* mac) {
    printf("\n[ALERT] Possible ARP Spoofing Detected. IP: %s and MAC: %s\n", ip, mac);
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "ALERT: Possible ARP Spoofing from IP: %s (MAC: %s)", ip, mac);
    log_event(log_msg);
}

int print_available_interfaces() {
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i = 0;

    if (pcap_findalldevs(&interfaces, error) == -1) {
        printf("Cannot acquire the devices...\n");
        return -1;
    }

    printf("The available interfaces are : \n");
    for (temp = interfaces; temp; temp = temp->next) {
        printf("$%d: %s\n", ++i, temp->name);
    }
    return 0;
}

void print_version() {
	printf("       ___    ____  ____     _____                   ____   ____       __            __            \n");
    printf("      /   |  / __ \\/ __ \\   / ___/____  ____  ____  / __/  / __ \\___  / /____  _____/ /_____  _____\n");
    printf("     / /| | / /_/ / /_/ /   \\__ \\/ __ \\/ __ \\/ __ \\/ /_   / / / / _ \\/ __/ _ \\/ ___/ __/ __ \\/ ___/\n");
    printf("    / ___ |/ _, _/ ____/   ___/ / /_/ / /_/ / /_/ / __/  / /_/ /  __/ /_/  __/ /__/ /_/ /_/ / /    \n");
    printf("   /_/  |_/_/ |_/_/       /____/ .___/\\____/\\____/_/    /_____/\\___/\\__/\\___/\\___/\\__/\\____/_/     \n");
    printf("                              /_/                                                              \n");
    printf("\nARP Spoof Detector v1.0\n");
    printf("This tool will sniff for ARP packets in the interface and detect ARP Spoofing attacks\n");
    printf("Features: Threshold-based detection (%d packets in %d seconds), IP blocking, logging, and email alerts\n", THRESHOLD, TIME_WINDOW);
}

void print_help(char *bin) {
    printf("\nAvailable arguments: \n");
    printf("--------------------------------------------------------------------------\n");
    printf("-h or --help:\t\t\tPrint this help text.\n");
    printf("-l or --lookup:\t\t\tPrint the available interfaces.\n");
    printf("-i or --interface:\t\tProvide the interface to sniff on.\n");
    printf("-v or --version:\t\tPrint the version information.\n");
    printf("--------------------------------------------------------------------------\n");
    printf("\nUsage: %s -i <interface> [You can look for the available interfaces using -l/--lookup]\n", bin);
    exit(1);
}

char *get_hardware_address(uint8_t mac[6]) {
    char *m = (char *)malloc(20 * sizeof(char));
    sprintf(m, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return m;
}

char *get_ip_address(uint8_t ip[4]) {
    char *m = (char *)malloc(20 * sizeof(char));
    sprintf(m, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return m;
}

void process_arp_packet(arp_hdr *arpheader) {
    char *s_mac = get_hardware_address(arpheader->sender_mac);
    char *s_ip = get_ip_address(arpheader->sender_ip);
    time_t now = time(NULL);
    int found = 0;

    printf("\n----------------------------------------------------------------\n");
    printf("Operation Type: %s\n", (ntohs(arpheader->opcode) == ARP_REQUEST) ? "ARP Request" : "ARP Response");
    printf("Sender MAC: %s\n", s_mac);
    printf("Sender IP: %s\n", s_ip);
    printf("Target MAC: %s\n", get_hardware_address(arpheader->target_mac));
    printf("Target IP: %s\n", get_ip_address(arpheader->target_ip));
    printf("-----------------------------------------------------------------\n");

    // Check if we already have this IP in our records
    for (int i = 0; i < record_count; i++) {
        if (strcmp(records[i].ip, s_ip) == 0) {
            found = 1;
            // Update MAC if it's different (possible spoofing)
            if (strcmp(records[i].mac, s_mac) != 0) {
                char log_msg[256];
                snprintf(log_msg, sizeof(log_msg), 
                    "MAC address changed for IP %s (was %s, now %s) - possible spoofing", 
                    s_ip, records[i].mac, s_mac);
                log_event(log_msg);
                strcpy(records[i].mac, s_mac);
            }

            if (difftime(now, records[i].first_seen) <= TIME_WINDOW) {
                records[i].count++;
            } else {
                // Reset counter if outside time window
                records[i].count = 1;
                records[i].first_seen = now;
            }

            if (records[i].count >= THRESHOLD && records[i].blocked == 0) {
                alert_spoof(s_ip, s_mac);
                block_ip(s_ip);
                send_alert(s_ip, s_mac);
                records[i].blocked = 1;
            }
            break;
        }
    }

    if (!found) {
        if (record_count < MAX_IPS) {
            strcpy(records[record_count].ip, s_ip);
            strcpy(records[record_count].mac, s_mac);
            records[record_count].count = 1;
            records[record_count].first_seen = now;
            records[record_count].blocked = 0;
            record_count++;
        }
    }

    free(s_mac);
    free(s_ip);
}

int sniff_arp(char *device_name) {
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *pack_desc;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *eptr;

    pack_desc = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
    if (pack_desc == NULL) {
        printf("%s\n", error);
        print_available_interfaces();
        return -1;
    }

    printf("Listening on %s...\n", device_name);
    log_event("ARP Sniffer started.");

    while (1) {
        packet = pcap_next(pack_desc, &header);
        if (packet == NULL) {
            printf("ERROR: Cannot capture packet...\n");
            continue;
        }

        eptr = (struct ether_header *)packet;
        if (ntohs(eptr->ether_type) == ETHERTYPE_ARP) {
            arp_hdr *arpheader = (arp_hdr *)(packet + sizeof(struct ether_header));
            process_arp_packet(arpheader);
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        printf("This program requires root privileges to run.\n");
        printf("Please run with sudo.\n");
        exit(-1);
    }

    if (argc < 2 || strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0) {
        print_version();
        print_help(argv[0]);
    }
    else if (strcmp("-v", argv[1]) == 0 || strcmp("--version", argv[1]) == 0) {
        print_version();
        exit(1);
    }
    else if (strcmp("-l", argv[1]) == 0 || strcmp("--lookup", argv[1]) == 0) {
        print_available_interfaces();
    }
    else if (strcmp("-i", argv[1]) == 0 || strcmp("--interface", argv[1]) == 0) {
        if (argc < 3) {
            printf("Please provide an interface to sniff on... Select from the following...\n");
            printf("-------------------------------------------------------------------------------\n");
            print_available_interfaces();
            printf("\nUsage: %s -i <interface> [You can look for the available interfaces using -l/--lookup]\n", argv[0]);
        }
        else {
            sniff_arp(argv[2]);
        }
    }
    else {
        printf("Invalid argument.\n");
        print_help(argv[0]);
    }
    return 0;
}
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<errno.h>
#include<netinet/in.h>

typedef unsigned char u_char;
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Packet captured: length %d\n", header->len);
}
int main(){
    char error[PCAP_BUF_SIZE];
    pcap_if_t *interface, *temp;
    int i = 0;
    if (pcap_findalldevs(&interface,error) == -1){
        printf("can't aquare any device \n");
        return -1;
    }
    printf("The avaliable devices are:\n");
    for (temp = interface;temp;temp=temp->next){
        printf("$%d, %s\n",++i,temp->name); 
        }
    int choice;
    printf("choice the interface:\n");
    scanf("%d",&choice);
    pcap_if_t *selected = interface;
    for(i = 1; i < choice && selected; i++) {
        selected = selected->next;
    }
    if (selected) {
        pcap_t *handle = pcap_open_live(selected->name, BUFSIZ, 1, 100, error);
        if (!handle) {
            fprintf(stderr, "Couldn't open device %s: %s\n", selected->name, error);
            return -1;
        }
    pcap_loop(handle, -1, packet_handler, NULL);
    }
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <osip2/osip.h>

#define MAX_FILTER_LEN 128

void sipdump(u_char *args, const struct pcap_pkthdr *header, const u_char *frame) {
  //header part
  //struct ether_header *ether_header = (struct ether_header *) frame;
  struct iphdr *ip_header = (struct iphdr *) (frame + sizeof(struct ether_header));
  int ip_header_length = ip_header->ihl * 4;   //ip header size may be variable
  struct udphdr *udp_header = (struct udphdr *) (frame + sizeof(struct ether_header) + ip_header_length);
  unsigned int header_length = (sizeof(struct ether_header) + ip_header_length + sizeof(struct udphdr));
  
  //payload part
  unsigned char *payload = (u_char *) (frame + header_length);
  unsigned int payload_length = header->len - header_length;
  printf("%s\n", payload);

  osip_event_t *oe = osip_parse(payload, payload_length);
  if(oe == NULL) {
    perror("Error parsing SIP");
    return;
  }
  //printf("transactionid %d", oe->transactionid);
}

int main(int argc, char *argv[]) {
  char *dev = argv[1], *port = argv[2];
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter[MAX_FILTER_LEN];
  sprintf(filter, "udp and port %s", port);

  printf("Device: %s, Filter: %s\n", dev, filter);
  
  //open sniffing session, non-promiscuous
  pcap_t *handle;
  handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
  if( handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s", dev, errbuf);
    exit(1);
  }
  //compile filter expression into a filter program
  struct bpf_program fp;
  //ignore ipv4 broadcast
  if(pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) { 
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
    exit(1);
  }

  if(pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
    exit(1);
  }

  if( pcap_loop(handle, -1, sipdump, NULL) == -1) {
    fprintf(stderr, "Error while processing of packets: %s\n", pcap_geterr(handle));
    exit(1);
  }

  return 0;
}

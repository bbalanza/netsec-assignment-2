#ifndef GLOBALS_H
#define GLOBALS_H
#include "globals.h"
#endif

#ifndef TYPEDEF_H
#define TYPEDEF_H
#include "typedef.h"
#endif // !TYPEDEF_H

uint32_t byteToUint32littleEndian(uint32_t serialized) {
  uint8_t *iter = (uint8_t *)(&serialized);
  uint8_t littleEndian[4] = {0};
  for (int i = 3; i >= 0; i--) {
    littleEndian[i] = *iter;
    iter += 1;
  }
  return *((uint32_t *)littleEndian);
}

Packet makePacket(const u_char *serialized) {
  uint16_t length = ETHERNET_HEADER_LENGTH;
  Packet packet;
  packet.ethernet = (struct ethhdr *)serialized;
  packet.ip = (struct iphdr *)(serialized + length);
  length += packet.ip->ihl * 4;
  packet.tcp = (struct tcphdr *)(serialized + length);
  return packet;
}

Pcap makePcap(char *uncompileFilter) {
  Pcap pcap;
  char *interface = "eth0";
  struct bpf_program filterExpression;
  pcap.errorBuffer = calloc(1, PCAP_ERRBUF_SIZE);

  if (pcap_lookupnet(interface, &(pcap.deviceIP), &(pcap.netMask),
                     pcap.errorBuffer) == -1) {
    fprintf(stderr, "Can't get netmask for interface %s\n", interface);
    exit(EXIT_FAILURE);
  }

  pcap.handle = pcap_open_live(interface, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS,
                               1000, pcap.errorBuffer);
  if (pcap.handle == NULL) {
    fprintf(stderr, "Cant open interface %s: %s\n", interface,
            pcap.errorBuffer);
    exit(EXIT_FAILURE);
  }

  if (pcap_compile(pcap.handle, &filterExpression, uncompileFilter, 0,
                   pcap.deviceIP) == -1) {
    fprintf(stderr, "Error: couldn't create filter %s: %s\n", uncompileFilter,
            pcap_geterr(pcap.handle));
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(pcap.handle, &filterExpression) == -1) {
    fprintf(stderr, "Couldn't add filter '%s' to pcap handle: %s\n",
            uncompileFilter, pcap_geterr(pcap.handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setnonblock(pcap.handle, 0, pcap.errorBuffer) == -1) {
    fprintf(stderr, "Couldn't set pcap in nonblocking mode: %s\n",
            pcap_geterr(pcap.handle));
  }
  return pcap;
}

void freePcap(Pcap pcap) {
  free(pcap.errorBuffer);
  pcap_close(pcap.handle);
}

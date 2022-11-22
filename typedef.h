#ifndef GLOBALS_H
#include "globals.h"
#endif // !GLOBALS_H
#define TYPEDEF_H

typedef struct {
  libnet_t *context;
  char *errorBuffer;
} Libnet;

typedef struct {
  uint16_t length;
  uint8_t tos;
  uint16_t id;
  uint16_t fragments;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t source;
  uint32_t destination;
  const uint8_t *payload;
  uint32_t payloadLength;
  Libnet libnet;
  libnet_ptag_t ptag;
} IPv4Options;

typedef struct {
  uint16_t sourcePort;
  uint16_t destinationPort;
  uint32_t sequence;
  uint32_t acknowledgement;
  uint8_t control;
  uint16_t windowSize;
  uint16_t checksum;
  uint16_t urgentPointer;
  uint16_t packetLength;
  const uint8_t *payload;
  uint32_t payloadLength;
  Libnet libnet;
  libnet_ptag_t ptag;
} TCPOptions;

typedef struct {
  uint32_t source;
  uint32_t destination;

} IPAddresses;

typedef struct {
  char *payload;
  uint32_t payloadLength;
  Libnet libnet;
  libnet_ptag_t ptag;
} PayloadOptions;

typedef struct {
  char *errorBuffer;
  pcap_t *handle;
  bpf_u_int32 netMask;
  bpf_u_int32 deviceIP;
} Pcap;

typedef struct {
  struct ethhdr *ethernet;
  struct iphdr *ip;
  struct tcphdr *tcp;
} Packet;

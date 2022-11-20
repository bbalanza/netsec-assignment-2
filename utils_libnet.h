#ifndef GLOBALS_H
#define GLOBALS_H
#include "globals.h"
#endif // !GLOBALS_H

#ifndef TYPEDEF_H
#define TYPEDEF_H
#include "typedef.h"
#endif // !TYPEDEF_H

Libnet makeLibnet() {
  Libnet libnet = {NULL, NULL};
  libnet.errorBuffer = calloc(STRING_BUFF_SIZE, sizeof(char));
  libnet.context = libnet_init(LIBNET_RAW4, "eth0", libnet.errorBuffer);
  if (libnet.context == NULL) {
    fprintf(stderr, "Failed to initialize libnet: %s", libnet.errorBuffer);
    exit(EXIT_FAILURE);
  }
  return libnet;
}

void freeLibnet(Libnet libnet) {
  libnet_destroy(libnet.context);
  free(libnet.errorBuffer);
}

libnet_ptag_t addIPv4ToContext(IPv4Options options) {
  libnet_ptag_t ptag = libnet_build_ipv4(
      options.length, options.tos, options.id, options.fragments, options.ttl,
      options.protocol, options.checksum, options.source, options.destination,
      options.payload, options.payloadLength, options.libnet.context,
      options.ptag);
  return ptag;
}

IPv4Options makeIPv4TCPOptions(uint32_t source, uint32_t destination,
                               uint16_t payloadLength, Libnet libnet,
                               libnet_ptag_t ptag) {
  IPv4Options options;
  options.length = LIBNET_IPV4_H + LIBNET_TCP_H + payloadLength;
  options.tos = 0;
  options.id = 0;
  options.fragments = 0;
  options.ttl = 64;
  options.protocol = IPPROTO_TCP;
  options.checksum = 0;
  options.source = source;
  options.destination = destination;
  options.payload = NULL;
  options.payloadLength = 0;
  options.libnet = libnet;
  options.ptag = ptag;

  return options;
}

TCPOptions makeTCPOptions(uint16_t sourcePort, uint16_t destinationPort,
                          uint32_t sequenceNumber,
                          uint32_t acknowledgementNumber, uint8_t control,
                          char *payload, uint32_t payloadLength, Libnet libnet,
                          libnet_ptag_t ptag) {
  TCPOptions options;
  options.sourcePort = sourcePort;
  options.destinationPort = destinationPort;
  options.sequence = sequenceNumber;
  options.acknowledgement = acknowledgementNumber;
  options.control = control;
  options.windowSize = 32767;
  options.checksum = 0;
  options.urgentPointer = 0;
  options.packetLength = LIBNET_TCP_H + payloadLength;
  options.payload = (uint8_t *)payload;
  options.payloadLength = payloadLength;
  options.libnet = libnet;
  options.ptag = ptag;
  return options;
}

libnet_ptag_t addTCPToContext(TCPOptions options) {
  libnet_ptag_t result = libnet_build_tcp(
      options.sourcePort, options.destinationPort, options.sequence,
      options.acknowledgement, options.control, options.windowSize,
      options.checksum, options.urgentPointer, options.packetLength,
      options.payload, options.payloadLength, options.libnet.context,
      options.ptag);

  if (result == -1) {
    fprintf(stderr, "Error adding a TCP header to context: %s\n",
            options.libnet.errorBuffer);
    exit(EXIT_FAILURE);
  }
  return result;
}

IPAddresses makeIPAddresses(char *source, char *destination) {
  Libnet libnet = makeLibnet();
  IPAddresses addresses;
  addresses.source =
      libnet_name2addr4(libnet.context, source, LIBNET_DONT_RESOLVE);
  addresses.destination =
      libnet_name2addr4(libnet.context, destination, LIBNET_DONT_RESOLVE);
  freeLibnet(libnet);
  return addresses;
}

PayloadOptions makePacketPayloadOptions(char *payload, uint32_t payloadLength,
                                        Libnet libnet, libnet_ptag_t ptag) {
  PayloadOptions options;
  options.payload = payload;
  options.payloadLength = payloadLength;
  options.libnet = libnet;
  options.ptag = ptag;
  return options;
}

libnet_ptag_t addPayloadToContext(PayloadOptions options) {
  return libnet_build_data((uint8_t *)options.payload, options.payloadLength,
                           options.libnet.context, options.ptag);
}

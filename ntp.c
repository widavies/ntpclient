#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 123

struct __attribute__((packed)) ntp {
  u_int32_t header;
  u_int32_t root_delay;
  u_int32_t root_dispersion;
  u_int32_t reference_id;
  u_int64_t reference_timestamp;
  u_int64_t origin_timestamp;
  u_int64_t receive_timestamp;
  u_int64_t transmit_timestamp;
};

int main() {
  char host[100] = {0};
  printf("Enter domain: ");
  scanf("%s", host);

  // get the ip address from DNS lookup
  struct addrinfo hints, *res, *result;
  char addrstr[100];
  void *ptr;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags |= AI_CANONNAME;

  int err = getaddrinfo(host, NULL, &hints, &result);
  res = result;
  while (res) {
    inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);

    switch (res->ai_family) {
      case AF_INET:
        ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
        break;
      case AF_INET6:
        ptr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
        break;
    }
    inet_ntop(res->ai_family, ptr, addrstr, 100);
    printf("IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4,
           addrstr, res->ai_canonname);
    if (strcmp(res->ai_canonname, host) == 0) {
      break;
    }
    res = res->ai_next;
  }

  freeaddrinfo(result);

  // IP address is addrstr

  // Set up socket
  int sockfd = socket(AF_INET, SOCK_DGRAM,
                      IPPROTO_UDP);  // create socket to establish connection
  if (sockfd == -1) {
    perror("socket error");
    exit(EXIT_FAILURE);
  }
  int socket_desc;
  struct sockaddr_in server_addr;
  char server_message[100];
  int server_struct_length = sizeof(server_addr);

  // Clean buffers:
  memset(server_message, '\0', sizeof(server_message));

  // Create socket:
  socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  server_addr.sin_family = AF_INET;  // IPv4
  server_addr.sin_addr.s_addr =
      inet_addr(addrstr);  // server IP, since the server is on same machine,
                           // use localhost IP
  server_addr.sin_port = htons(PORT);  // Port the server is listening on
  // Connect the socket
  int ret = connect(socket_desc, (struct sockaddr *)&server_addr,
                    sizeof(server_addr));
  if (ret == -1) {
    perror("Connect error");
    exit(1);
  }

  // Build the ntp packet
  struct ntp packet = {.header =
                           // LI
                       htonl((3 << 30) |
                             // VN
                             (4 << 27) |
                             // Mode
                             (3 << 24) |
                             // Stratum
                             (0 << 16) |
                             // Peer polling interval (seconds)
                             (10 << 8) |
                             // Precision in log2 seconds
                             (0)),
                       .root_delay = 0,
                       .root_dispersion = htonl(1),
                       .reference_id = 0,
                       .reference_timestamp = 0,
                       .origin_timestamp = 0,
                       .receive_timestamp = 0,
                       .transmit_timestamp = 0};

  // Send the message to server:
  if (sendto(socket_desc, (char *)&packet, sizeof(struct ntp), 0,
             (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0) {
    printf("Failed to send NTP packet!\n");
  }
  printf("Sent data\n");

  // Receive the server's response:
  if (recvfrom(socket_desc, &packet, sizeof(struct ntp), 0, NULL, NULL) < 0) {
    printf("Error while receiving server's msg\n");
    return -1;
  }

  // Close the socket:
  close(socket_desc);
}
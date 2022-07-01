#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// The structure of the program has been kept very simple as not many
// requirements were specified. The main() function calls setup_multicast_socket
// to configure the socket to receive the multicast datagram and then starts an
// infinite loop to receive data on that socket

// Use static constexpr instead of a macro as it is typed and safer
static constexpr unsigned int ARRAY_SIZE = 400;

uint8_t array[ARRAY_SIZE];  // Array where a single packet is stored
size_t array_len;           // Number of bytes currently stored in array

/**
 * @brief Adds membership to the provided multicast group
 *
 * @param sockfd Socket file descriptor
 * @param group_addr Multicast group address
 * @return int zero if successfull, -1 on error, also setting errno
 */
int add_multicast_membership(int sockfd, sockaddr_in* group_addr);

/**
 * @brief Setups a socket used to receive multicast messages
 * @warning User must close the socket once it is no longer used
 *
 * @param group_addr IP Address of the multicast group
 * @param port Port of the multicast message
 * @return int socket file descriptor or -1 on error
 */
int setup_multicast_socket(const char* group_addr, const char* port);

int main(int argc, char* argv[])
{
    int sockfd = setup_multicast_socket("239.154.117.1", "60050");
    if (sockfd < 0)
    {
        fprintf(stderr, "Error creating socket. Exiting.\n");
        return 1;
    }

    sockaddr sender;  // Address of the multicast sender
    unsigned int sender_addrlen = sizeof(sender);
    for (;;)
    {
        // After this call, the message is stored in the array. If we were using
        // TCP, we would need to split the packets we received from the incoming
        // stream, for example by detecting the sync byte and subseqently
        // reading the packet id field to obtain its length. Since we are using
        // UDP, this is not needed as one datagram should correspond to one
        // packet (assuming that packet are not fragmented or combined in a
        // single datagram at higher level)
        array_len =
            recvfrom(sockfd, array, ARRAY_SIZE, 0, &sender, &sender_addrlen);
        // Of course, receiving a new packet means that the previous one is
        // ovewritten.

        // Debug prints to confirm we received the correct messages. A printf
        // would be really bad in a real-time embedded system where printing to
        // a serial interface would take a really long time. Ideally, we could
        // have a consumer and a receiver thread to decouple the network code
        // with the one that uses the messages, making the two communicate via a
        // synchronized queue or circular buffer.
        uint32_t id;
        memcpy(&id, &array[1], 4);
        id = ntohl(id);  // Packet id appears to be big endian, so convert it to
                         // the proper host representation

        printf("SYNC: 0x%02X\tID: 0x%08X\tlen: %lu\n", array[0], id, array_len);
    }

    // Unreachable in this case, but always good to have
    close(sockfd);

    return 0;
}

int add_multicast_membership(int sockfd, sockaddr_in* group_addr)
{
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = group_addr->sin_addr.s_addr;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);  // Receive on any interface

    return setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq,
                      sizeof(mreq));
}

int setup_multicast_socket(const char* group_addr, const char* port)
{
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family   = AF_INET;     // IPv4, same as the provided multicast ip
    hints.ai_socktype = SOCK_DGRAM;  // UDP
    hints.ai_flags    = AI_NUMERICHOST;

    // Get addrinfo of the multicast group we want to bind to
    addrinfo* group_info;
    int res = getaddrinfo(group_addr, port, &hints, &group_info);
    if (res < 0)
    {
        fprintf(stderr, "getaddrinfo error %d (%s)\n", res, gai_strerror(res));
        return -1;
    }

    int sockfd = socket(group_info->ai_family, group_info->ai_socktype,
                        group_info->ai_protocol);
    if (sockfd == -1)
    {
        fprintf(stderr, "Error creating socket: %d (%s)\n", errno,
                strerror(errno));

        freeaddrinfo(group_info);
        return -1;
    }

    // Since we are receiving multicast datagrams, other programs on the same
    // host (or another instance of this program, too) may want to receive the
    // messages too, so set SO_REUSEADDR on the socket
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
    {
        fprintf(stderr,
                "Error setting socket options (SO_REUSEADDR): %d (%s)\n", errno,
                strerror(errno));

        // Here the cleanup code is unfortunately repeated multiple times every
        // time we check for an error. We could wrap things in a class and use
        // RAII (safe but time consuming) or we could use "goto cleanup" to jump
        // to some cleanup code at the end of the function. Some people like it,
        // some people really HATE it, so I decided not to use it here.
        close(sockfd);
        freeaddrinfo(group_info);
        return -1;
    }

    // Bind the socket to the group address. Here, we could have binded to
    // INADDR_ANY if, for example, we wanted to receive messages from multiple
    // multicast groups on the same socket
    if (bind(sockfd, group_info->ai_addr, group_info->ai_addrlen) < 0)
    {
        fprintf(stderr, "Error binding socket: %d (%s)\n", errno,
                strerror(errno));

        close(sockfd);
        freeaddrinfo(group_info);
        return -1;
    }

    // Finally signal that we want receive multicast messages on the specified
    // group. If we wanted to receive messages from multiple groups on the same
    // socket, we could call add_multicast_membership for every one of them
    if (add_multicast_membership(sockfd, (sockaddr_in*)group_info->ai_addr) < 0)
    {
        fprintf(stderr, "Error adding multicast membership: %d (%s)\n", errno,
                strerror(errno));

        close(sockfd);
        freeaddrinfo(group_info);
        return -1;
    }

    freeaddrinfo(group_info);
    return sockfd;
}
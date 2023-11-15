#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// prototypes
int              main(int argc, const char *argv[]);
static int       socket_create(int domain);
static void      parse_arguments(int argc, const char *argv[], const char **ip_address, const char **port);
static void      convert_address(const char *address, struct sockaddr_storage *addr);
static void      handle_arguments(const char *ip_address, const char *port_str, in_port_t *port);
static in_port_t parse_in_port_t(const char *str);
static void      socket_connect(int socket_file_desc, struct sockaddr_storage *addr, in_port_t port);
static void      socket_close(int socket_file_desc);
static void      send_data(const char *command, int client_sock_file_desc);
static void      receive_data(int client_sock_file_desc);

// variable declaration
#define BASE_TEN 10
#define MAX_LENGTH 256

// functions
int main(int argc, const char *argv[])
{
    struct sockaddr_storage addr;
    const char             *port_str;
    in_port_t               port;
    const char             *address;
    int                     client_socket_file_desc;
    char                    command[MAX_LENGTH];
    int                     command_flag = 0;
    parse_arguments(argc, argv, &address, &port_str);
    handle_arguments(address, port_str, &port);
    convert_address(address, &addr);
    client_socket_file_desc = socket_create(AF_INET);
    socket_connect(client_socket_file_desc, &addr, port);

    // get command
    while(command_flag == 0)
    {
        printf("Enter a command (no quotations) :");
        if(fgets(command, sizeof(command), stdin) != NULL)
        {
            printf("You entered: %s", command);
            command_flag = 1;
        }
        else
        {
            // error occurred while reading input (non-problematic)
            printf("Invalid input\n");
        }
    }

    // send command
    send_data(command, client_socket_file_desc);

    // receive result
    receive_data(client_socket_file_desc);
    // close client socket
    socket_close(client_socket_file_desc);

    return 1;
}

/**
 * Function creates a socket
 * @param domain as described in the socket() function
 * @return socket file descriptor
 */
static int socket_create(int domain)
{
    int socket_file_desc;
    // create a domain socket for the client
    socket_file_desc = socket(domain, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)

    // exits if an error occurs
    if(socket_file_desc == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // returns socket file descriptor
    return socket_file_desc;
}

/**
 * Function to convert a given ip address string into the correct type
 * @param address Ip address string
 * @param addr store of the IP type
 */
static void convert_address(const char *address, struct sockaddr_storage *addr)
{
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        addr->ss_family = AF_INET;
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        addr->ss_family = AF_INET6;
    }
    else
    {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
        exit(EXIT_FAILURE);
    }
}

/**
 * Function to set values from the command line input, exits if either are NULL
 * @param ip_address Input ip address
 * @param port_str Input port string
 * @param port Storage variable for the port
 */
static void handle_arguments(const char *ip_address, const char *port_str, in_port_t *port)
{
    if(ip_address == NULL)
    {
        perror("IP address is NULL");
        exit(EXIT_FAILURE);
    }

    if(port_str == NULL)
    {
        perror("Port string is null");
        exit(EXIT_FAILURE);
    }

    *port = parse_in_port_t(port_str);
}

/**
 * Function to parse the port into port_t type
 * @param str string to parse
 * @return parsed port type
 */
static in_port_t parse_in_port_t(const char *str)
{
    char     *endptr;
    uintmax_t parsed_value;

    errno        = 0;
    parsed_value = strtoumax(str, &endptr, BASE_TEN);

    if(errno != 0)
    {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        perror("Invalid characters in port input");
        exit(EXIT_FAILURE);
    }

    // Check if the parsed value is within the valid range for in_port_t
    if(parsed_value > UINT16_MAX)
    {
        perror("port value is out of range");
        exit(EXIT_FAILURE);
    }

    return (in_port_t)parsed_value;
}

/**
 * Function parses arguments and sets the ip address and port variables
 * @param argc
 * @param argv
 * @param ip_address
 * @param port
 */
static void parse_arguments(int argc, const char *argv[], const char **ip_address, const char **port)
{
    if(argc != 3)
    {
        perror("Invalid number of args");
        exit(EXIT_FAILURE);
    }
    *ip_address = argv[1];
    *port       = argv[2];
}

/**
 * Function to connect the socket to the domain using the stored IP address and port number USE IN CLIENT
 * @param sockfd
 * @param addr IP address
 * @param port port number
 */
static void socket_connect(int socket_file_desc, struct sockaddr_storage *addr, in_port_t port)
{
    char      addr_str[INET6_ADDRSTRLEN];
    in_port_t net_port;
    socklen_t addr_len;

    if(inet_ntop(addr->ss_family, addr->ss_family == AF_INET ? (void *)&(((struct sockaddr_in *)addr)->sin_addr) : (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr), addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Connecting to: %s:%u\n", addr_str, port);
    net_port = htons(port);

    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        ipv4_addr->sin_port = net_port;
        addr_len            = sizeof(struct sockaddr_in);
    }
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        ipv6_addr->sin6_port = net_port;
        addr_len             = sizeof(struct sockaddr_in6);
    }
    else
    {
        fprintf(stderr, "Invalid address family: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if(connect(socket_file_desc, (struct sockaddr *)addr, addr_len) == -1)
    {
        char *msg;

        msg = strerror(errno);
        fprintf(stderr, "Error: connect (%d): %s\n", errno, msg);
        exit(EXIT_FAILURE);
    }

    printf("Connected to: %s:%u\n", addr_str, port);
}

/**
 * Function to close the socket
 * @param socket_file_desc socket to close
 */
static void socket_close(int socket_file_desc)
{
    if(close(socket_file_desc) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Closed client.\n");
    }
}

/**
 * Function to send data to the server
 * @param command command to send to the server
 * @param client_sock_file_desc
 */
static void send_data(const char *command, int client_sock_file_desc)
{
    if(write(client_sock_file_desc, command, strlen(command)) == -1)
    {
        perror("Write failed");
        exit(EXIT_FAILURE);
    }
}

/**
 * Function to receive data from the server
 * @param client_sock_file_desc
 */
static void receive_data(int client_sock_file_desc)
{
    char buffer[UINT16_MAX];
    long bytes_received;
    bytes_received = recv(client_sock_file_desc, buffer, sizeof(buffer), 0);

    if(bytes_received == -1)
    {
        perror("Error receiving data");
        exit(EXIT_FAILURE);
    }

    // null-terminate the received data
    if((long unsigned int)bytes_received < sizeof(buffer))
    {
        buffer[bytes_received] = '\0';
    }

    // write the received data to STDOUT_FILENO
    write(STDOUT_FILENO, buffer, strlen(buffer));
}
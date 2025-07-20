package main

/*
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netdb.h>  // For struct addrinfo
#include <ifaddrs.h>  // For getifaddrs

typedef int (*bind_func_t)(int, const struct sockaddr *, socklen_t);
typedef int (*connect_func_t)(int, const struct sockaddr *, socklen_t);
typedef int (*getaddrinfo_func_t)(const char *, const char *, const struct addrinfo *, struct addrinfo **);

// Structure to store the original functions
static bind_func_t real_bind = NULL;
static connect_func_t real_connect = NULL;
static getaddrinfo_func_t real_getaddrinfo = NULL;

// Function to determine if an IP string is IPv4 or IPv6
int is_ipv6(const char *ip) {
    // If it contains a colon, it's IPv6
    return (strchr(ip, ':') != NULL);
}

// Load original functions if not already loaded
void load_original_functions() {
    if (!real_bind) {
        real_bind = (bind_func_t)dlsym(RTLD_NEXT, "bind");
        if (!real_bind) {
            fprintf(stderr, "[FBI-Go] Error: dlsym failed for bind: %s\n", dlerror());
            exit(1);
        }
    }

    if (!real_connect) {
        real_connect = (connect_func_t)dlsym(RTLD_NEXT, "connect");
        if (!real_connect) {
            fprintf(stderr, "[FBI-Go] Error: dlsym failed for connect: %s\n", dlerror());
            exit(1);
        }
    }

    if (!real_getaddrinfo) {
        real_getaddrinfo = (getaddrinfo_func_t)dlsym(RTLD_NEXT, "getaddrinfo");
        if (!real_getaddrinfo) {
            fprintf(stderr, "[FBI-Go] Error: dlsym failed for getaddrinfo: %s\n", dlerror());
            exit(1);
        }
    }
}

// Check if an IP is local (assigned to an interface)
int is_local_ip(const char *ip) {
    // Always allow loopback addresses
    if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0) {
        return 1;
    }

    // Get a list of all network interfaces
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, "[FBI-Go] Warning: Unable to check local interfaces: %s\n", strerror(errno));
        // Default to allowing the IP since we couldn't check
        return 1;
    }

    // Walk through linked list, maintaining head pointer so we can free list later
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        // Check IPv4 addresses
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in*)ifa->ifa_addr;
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr->sin_addr), addr_str, INET_ADDRSTRLEN);

            if (strcmp(ip, addr_str) == 0) {
                found = 1;
                break;
            }
        }
        // Check IPv6 addresses
        else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6*)ifa->ifa_addr;
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(addr->sin6_addr), addr_str, INET6_ADDRSTRLEN);

            // Remove scope id part if present (e.g., fe80::1%eth0 -> fe80::1)
            char *percent = strchr(addr_str, '%');
            if (percent) {
                *percent = '\0';
            }

            if (strcmp(ip, addr_str) == 0) {
                found = 1;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return found;
}

// Intercept the bind() call
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    load_original_functions();

    char *forced_ip = getenv("FORCE_BIND_IP");
    if (!forced_ip || strlen(forced_ip) == 0) {
        // No forced IP, call original bind
        return real_bind(sockfd, addr, addrlen);
    }

    // Check if this is a local IP we can actually bind to
    if (!is_local_ip(forced_ip)) {
        fprintf(stderr, "[FBI-Go] Warning: %s is not a local IP address. Only local IPs can be used for binding.\n", forced_ip);
        fprintf(stderr, "[FBI-Go] Try using one of your machine's actual IP addresses.\n");
        // Fall through to normal bind
    }

    // Handle IPv4
    if (addr->sa_family == AF_INET && !is_ipv6(forced_ip)) {
        struct sockaddr_in new_addr;
        memcpy(&new_addr, addr, sizeof(struct sockaddr_in));
        new_addr.sin_addr.s_addr = inet_addr(forced_ip);

        fprintf(stderr, "[FBI-Go] Intercepted IPv4 bind: Forcing IP to %s, port %d\n",
                forced_ip, ntohs(new_addr.sin_port));

        return real_bind(sockfd, (struct sockaddr *)&new_addr, addrlen);
    }
    // Handle IPv6
    else if (addr->sa_family == AF_INET6 && is_ipv6(forced_ip)) {
        struct sockaddr_in6 new_addr;
        memcpy(&new_addr, addr, sizeof(struct sockaddr_in6));

        // Convert string to IPv6 address
        if (inet_pton(AF_INET6, forced_ip, &(new_addr.sin6_addr)) != 1) {
            fprintf(stderr, "[FBI-Go] Error: Failed to convert %s to IPv6 address\n", forced_ip);
            return real_bind(sockfd, addr, addrlen);
        }

        fprintf(stderr, "[FBI-Go] Intercepted IPv6 bind: Forcing IP to %s, port %d\n",
                forced_ip, ntohs(new_addr.sin6_port));

        return real_bind(sockfd, (struct sockaddr *)&new_addr, addrlen);
    }
    // IP family mismatch (IPv4 socket with IPv6 address or vice versa)
    else if ((addr->sa_family == AF_INET && is_ipv6(forced_ip)) ||
             (addr->sa_family == AF_INET6 && !is_ipv6(forced_ip))) {
        fprintf(stderr, "[FBI-Go] Warning: IP family mismatch. Socket is %s but forced IP %s is %s\n",
                addr->sa_family == AF_INET ? "IPv4" : "IPv6",
                forced_ip,
                is_ipv6(forced_ip) ? "IPv6" : "IPv4");
        // Just call original bind
        return real_bind(sockfd, addr, addrlen);
    }
    else {
        // Unsupported address family, just call original
        return real_bind(sockfd, addr, addrlen);
    }
}

// For client applications that don't explicitly bind
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    load_original_functions();

    char *forced_ip = getenv("FORCE_BIND_IP");
    if (!forced_ip || strlen(forced_ip) == 0) {
        // No forced IP, call original connect
        return real_connect(sockfd, addr, addrlen);
    }

    // Print connection info
    char dst_str[INET6_ADDRSTRLEN];
    if (addr->sa_family == AF_INET) {
        inet_ntop(AF_INET, &(((struct sockaddr_in*)addr)->sin_addr), dst_str, INET_ADDRSTRLEN);
    } else if (addr->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &(((struct sockaddr_in6*)addr)->sin6_addr), dst_str, INET6_ADDRSTRLEN);
    } else {
        strcpy(dst_str, "unknown");
    }
    fprintf(stderr, "[FBI-Go] Intercepted connect to %s\n", dst_str);

    // Check if this is a local IP we can actually bind to
    if (!is_local_ip(forced_ip)) {
        fprintf(stderr, "[FBI-Go] Warning: %s is not a local IP address. Only local IPs can be used for binding.\n", forced_ip);
        fprintf(stderr, "[FBI-Go] Try using one of your machine's actual IP addresses.\n");
        // Continue with original connect without binding
        return real_connect(sockfd, addr, addrlen);
    }

    // Handle IPv4
    if (addr->sa_family == AF_INET && !is_ipv6(forced_ip)) {
        // First bind the socket to our forced IP
        struct sockaddr_in bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = inet_addr(forced_ip);
        bind_addr.sin_port = 0;  // Let the OS choose a port

        fprintf(stderr, "[FBI-Go] Binding to IPv4 %s before connecting\n", forced_ip);

        // Bind to our forced IP
        int bind_result = real_bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        if (bind_result != 0) {
            fprintf(stderr, "[FBI-Go] Warning: Failed to bind to %s: %s\n",
                    forced_ip, strerror(errno));
            // Continue anyway with original connect
        }
    }
    // Handle IPv6
    else if (addr->sa_family == AF_INET6 && is_ipv6(forced_ip)) {
        // First bind the socket to our forced IP
        struct sockaddr_in6 bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin6_family = AF_INET6;

        // Convert string to IPv6 address
        if (inet_pton(AF_INET6, forced_ip, &(bind_addr.sin6_addr)) != 1) {
            fprintf(stderr, "[FBI-Go] Error: Failed to convert %s to IPv6 address\n", forced_ip);
            return real_connect(sockfd, addr, addrlen);
        }

        bind_addr.sin6_port = 0;  // Let the OS choose a port

        fprintf(stderr, "[FBI-Go] Binding to IPv6 %s before connecting\n", forced_ip);

        // Bind to our forced IP
        int bind_result = real_bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        if (bind_result != 0) {
            fprintf(stderr, "[FBI-Go] Warning: Failed to bind to %s: %s\n",
                    forced_ip, strerror(errno));
            // Continue anyway with original connect
        }
    }
    // IP family mismatch (IPv4 socket with IPv6 address or vice versa)
    else if ((addr->sa_family == AF_INET && is_ipv6(forced_ip)) ||
             (addr->sa_family == AF_INET6 && !is_ipv6(forced_ip))) {
        fprintf(stderr, "[FBI-Go] Warning: IP family mismatch. Socket is %s but forced IP %s is %s\n",
                addr->sa_family == AF_INET ? "IPv4" : "IPv6",
                forced_ip,
                is_ipv6(forced_ip) ? "IPv6" : "IPv4");
        // Continue without binding - original address family will be used
    }

    // Call the original connect
    return real_connect(sockfd, addr, addrlen);
}
*/
import "C"

// Required for cgo to build a shared library
func main() {}

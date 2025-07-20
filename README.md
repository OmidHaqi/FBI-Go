# FBI-Go

FBI-Go is a utility that allows you to force applications to use a specific network interface/IP address for their outgoing connections, similar to the ForceBindIP utility for Windows. This is particularly useful for systems with multiple network interfaces where you need to control which interface is used for specific applications.

## How It Works

FBI-Go works by intercepting network-related system calls (bind, connect, getaddrinfo) using the `LD_PRELOAD` mechanism on Linux. When an application tries to make a network connection, FBI-Go forces it to bind to the specified IP address first.

## Features

- Force applications to use a specific IP address/network interface
- Supports both IPv4 and IPv6 addresses
- Works with any application that uses standard network system calls
- No modification of the target application required
- Transparent to the application being run

## Requirements

- Linux operating system
- Go 1.23.0 or later
- A C compiler (for CGO)

## Building

You can build FBI-Go using the included Makefile:

```bash
make all
```

This will build both the shared library (`binder.so`) and the loader binary (`fbi`).

To build components separately:

```bash
# Build just the shared library
make build-binder

# Build just the loader
make build-loader
```

## Installation

After building, you can install FBI-Go by copying the `fbi` binary and `binder.so` to a directory in your PATH:

```bash
sudo cp fbi binder.so /usr/local/bin/
```

## Usage

```bash
fbi <IP_ADDRESS> <COMMAND> [ARGS...]
```

### Examples

Force curl to use a specific IP address:
```bash
fbi 192.168.1.100 curl example.com
```

Force curl to use a specific IPv6 address:
```bash
fbi 2001:db8::1 curl example.com
```

Force a web browser to use a specific interface:
```bash
fbi 10.0.0.5 firefox
```

Run a server application binding to a specific IP:
```bash
fbi 172.16.1.5 python -m http.server 8080
```

### Notes

- You must use an IP address that actually exists on one of your network interfaces
- To see your available IP addresses, run: `ip addr`
- Both IPv4 and IPv6 addresses are supported
- The application being run must use standard system calls for networking

## How It Works

FBI-Go consists of two main components:

1. A shared library (`binder.so`) that intercepts network-related system calls
2. A loader program (`fbi`) that sets up the environment and executes the target application

When you run the `fbi` command, it:
1. Sets the `LD_PRELOAD` environment variable to point to the `binder.so` library
2. Sets the `FORCE_BIND_IP` environment variable to your specified IP
3. Executes your command with its arguments

The intercepted system calls then ensure that all network connections are bound to the specified IP address.

## Limitations

## Limitations

- Can only bind to IP addresses actually assigned to your interfaces
- Some applications with special privilege handling may not work correctly

## Troubleshooting

If you encounter issues:

1. Verify that the IP address you're trying to bind to exists on your system
2. Check that the `binder.so` file is accessible
3. Make sure the application you're running uses standard network system calls
4. Run with strace to see what's happening: `strace -f fbi <IP> <command>`

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

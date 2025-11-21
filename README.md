# Rust PCAP

Start by getting the Npcap and Ncap utils setup.

```md
Npcap allows for sending raw packets as well. Mac and Linux systems already include the 
Pcap API, so Npcap allows popular software such as Nmap and Wireshark to run on all
these platforms (and more) with a single codebase
```

See https://npcap.com/ for more.

## Linking

### On Windows, pcap requires special care when linking.

**Be sure to set LIBPCAP_LIBDIR & LIBPCAP_VER**

```toml
[env]
TEST_MODE = "1" // Use Win / Linux loopback
CAPTURE = "1" // Capture packets
LIBPCAP_LIBDIR = "C:/Users/.../npcap-sdk-1.15/Lib/x64"
LIBPCAP_VER = "1.15.0"
```

**Furthermore,**

```md
It is your responsibility, as the crate user, to configure linking with libpcap/wpcap
to suit your needs (e.g. library version, static vs. dynamic linking, etc.)
via your own build script.
```

**See https://crates.io/crates/pcap for more usage rules**

## Testing

### Find your IP
```bash
ipconfig

or

ip addr
```

### Local

```bash
# Default Server Mode
./tcp-server
./tcp-server server
./tcp-server server 0.0.0.0:9090 my_pool

# Client Mode
./tcp-server client 127.0.0.1:9090
./tcp-server client 127.0.0.1:9090 my_pool
```

### Remote
```bash
# Server listens on all network interfaces
./tcp-server server 0.0.0.0:9090

# Then connect from any machine using your actual IP
./tcp-server client 192.168.xx.xx:9090
```

**With custom pool:**
```bash
# Server
./tcp-server server 0.0.0.0:9090 production_pool

# Client (pool must match!)
./tcp-server client 192.168.1.100:9090 production_pool
```
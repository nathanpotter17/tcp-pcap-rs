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
LIBPCAP_LIBDIR = "C:/Users/nathan/npcap-sdk-1.15/Lib/x64"
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

## Find your IP
```bash
ipconfig
```

### Bind to your actual network IP
```bash
cargo run 192.168.xx.xx:9090
```

### Then connect from another machine or use the IP
```bash
echo "Hello Rust" | ncat 192.168.xx.xx 9090
```


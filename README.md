# PQ-TCP-RS

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

---

## Architecture

### PQ Mutual Authentication

The server implements a hardened authentication protocol using **Dilithium3** (NIST PQC standard) for digital signatures. Both client and server prove their identity to each other before any application data is exchanged.
```
┌────────────────────────────────────────────────────────┐
│                    AUTHENTICATION FLOW                 │
├────────────────────────────────────────────────────────┤
│                                                        │
│  Client                                        Server  │
│    │                                             │     │
│    │─── Connect(DID, PubKey, PoolCommitment) ───►│     │
│    │                                             │     │
│    │◄── Challenge(Nonce, ServerProof) ───────────│     │
│    │         [Server signs challenge]            │     │
│    │                                             │     │
│    │    [Client verifies server identity]        │     │
│    │                                             │     │
│    │─── Response(ClientSignature) ──────────────►│     │
│    │                                             │     │
│    │─── Elaborate(HumanReadableText) ───────────►│     |
│    │                                             │     │
│    │◄── Authenticated(SessionToken) ─────────────│     │
│    │                                             │     │
│    ╔═════════════════════════════════════════════╗     │
│    ║     SECURE BIDIRECTIONAL CHANNEL OPEN       ║     │
│    ╚═════════════════════════════════════════════╝     │
│                                                        │
└────────────────────────────────────────────────────────┘
```

### Decentralized Identity (DID)

Every participant (server and client) has a persistent cryptographic identity:
```
did:diagon:594b8670356d98c4aa0488d0122ec5a884bc5a270dde7b212f7aa64f29e5aa2b
           └──────────────────────────────────────────────────────────────────┘
                              SHA256(PublicKey)[0:32] in hex
```

- **Deterministic**: DID is derived directly from the public key
- **Self-certifying**: Anyone can verify DID-to-key binding
- **Persistent**: Stored locally in `db/` directory (CBOR format)
- **Portable**: Your identity is just a file—back it up, move it between machines

### Pool-Based Access Control

Clients must know the pool passphrase to connect. The server and client each compute a SHA256 commitment of the passphrase and compare them (constant-time) during authentication.
```
Pool: "production_pool"  →  Commitment: 7a3f2b1c...
```

Mismatched pools result in immediate rejection with no information leakage about the correct pool.

### Globally Unique Connection IDs

Every connection across all server lifetimes receives a unique, monotonically increasing ID:
```
Server Run 1:  conn #1, #2, #3
Server Run 2:  conn #4, #5       ← Counter persists!
Server Run 3:  conn #6, #7, #8
```

The counter is stored alongside the identity in `db/identity_*.cbor` and survives restarts.

---

## Security Features

| Feature | Implementation |
|---------|----------------|
| **Signatures** | Dilithium3 (NIST PQC Level 3) |
| **Hashing** | SHA256 |
| **Challenge** | 32-byte random nonce + timestamp + DID binding |
| **Domain Separation** | `DIAGON-TCP-AUTH-CHALLENGE-V1:` prefix |
| **Replay Protection** | Nonce cache with 60s expiry |
| **Timing Attack Mitigation** | Constant-time comparison for secrets |
| **Rate Limiting** | 5 auth attempts/minute per IP |
| **Session Binding** | Token bound to client DID + peer address |
| **Generic Errors** | No information leakage on failure |

### Startup Assertions

On every server start, security invariants are verified:
```
[STARTUP] Running security assertions...

✓ Identity persistence verified
✓ DID-pubkey binding verified
✓ Signature generation verified
✓ Challenge domain separation verified
✓ Constant-time comparison verified
✓ Message serialization verified

[✓✓✓] All security assertions passed
```

---

## Connection Lifecycle
```
┌─────────────────────────────────────────────────────────────────┐
│                    CONNECTION LIFECYCLE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. TCP Accept                                                  │
│       ↓                                                         │
│  2. Assign globally unique conn ID (persisted)                  │
│       ↓                                                         │
│  3. Register in ConnectionRegistry                              │
│       ↓                                                         │
│  4. Rate limit check                                            │
│       ↓                                                         │
│  5. Mutual authentication (30s timeout)                         │
│       ↓                                                         │
│  6. Create session token                                        │
│       ↓                                                         │
│  ╔═══════════════════════════════════════════════════════════╗  │
│  ║  AUTHENTICATED SESSION                                    ║  │
│  ║  - Echo server (current)                                  ║  │
│  ║  - Broadcast ready                                        ║  │
│  ║  - Direct messaging ready                                 ║  │
│  ╚═══════════════════════════════════════════════════════════╝  │
│       ↓                                                         │
│  7. Disconnect (graceful or error)                              │
│       ↓                                                         │
│  8. RAII cleanup (ConnectionGuard drops)                        │
│       ↓                                                         │
│  9. Unregister from registry                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### RAII Connection Management

Connections are tracked via `ConnectionGuard`—a Rust RAII pattern that guarantees cleanup on ANY exit path (success, error, panic):
```rust
// Pseudocode
let _guard = ConnectionGuard { id, registry };
// ... authentication and session logic ...
// Guard automatically unregisters on function return
```

---

## File Storage
```
db/
├── identity_<addr_hash>.cbor    # Server identity
│   ├── public_key               # Dilithium3 (1952 bytes)
│   ├── secret_key               # Dilithium3 (4016 bytes)
│   ├── did                      # "did:diagon:..."
│   └── connection_counter       # u64, persisted
│
└── client_identity.cbor         # Client identity
    ├── public_key
    ├── secret_key
    └── did
```

**Permissions (Unix):**
- `db/` directory: `0700` (owner only)
- Identity files: `0600` (owner read/write)

---

## Broadcast Infrastructure

The server maintains a `ConnectionRegistry` for message distribution:
```rust
// Send to all authenticated clients
broadcast_to_all(&registry, data);

// Send to specific connection
send_to_connection(&registry, conn_id, data);

// Graceful shutdown
shutdown_all(&registry);

// List active connections
let ids = get_active_connections(&registry);
```

Broadcast automatically cleans up disconnected clients during send.

---

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

### Automated Test Suite
```bash
./test.bash
```
```
═══════════════════════════════════════════════════════
  DGTCP Hardened Authentication Test Suite
═══════════════════════════════════════════════════════

► TEST 1: Successful mutual authentication
✓ Mutual authentication successful

► TEST 2: Pool mismatch rejection (security)
✓ Pool mismatch correctly rejected

► TEST 3: Identity persistence across restarts
✓ Server DID persisted correctly

► TEST 4: Multiple client connections
✓ All 3 connections succeeded

═══════════════════════════════════════════════════════
  Passed: 4  Failed: 0
═══════════════════════════════════════════════════════
All tests passed!
```

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `TEST_MODE=1` | Use loopback interface for packet capture |
| `CAPTURE=1` | Enable packet capture (requires pcap) |
| `LIBPCAP_LIBDIR` | Windows: Path to Npcap SDK lib directory |
| `LIBPCAP_VER` | Windows: Npcap version string |

---

## Protocol Constants
```rust
MAX_AUTH_MESSAGE_SIZE:    65,536 bytes   // 64KB for auth
MAX_DATA_MESSAGE_SIZE:    1,048,576      // 1MB for app data
CHALLENGE_TIMEOUT_SECS:   30             // Auth window
MIN_ELABORATION_LEN:      20             // Human text minimum
MAX_ELABORATION_LEN:      1,024          // Human text maximum
MAX_AUTH_ATTEMPTS:        5/minute/IP    // Rate limit
```

---

## Dependencies
```toml
pcap = "2.3.0"           # Packet capture
sha2 = "0.10"            # SHA256
pqcrypto-dilithium = "0.5"  # Post-quantum signatures
pqcrypto-traits = "0.3"
rand = "0.8"             # Cryptographic RNG
serde = "1.0"            # Serialization
serde_cbor = "0.11"      # CBOR format
bincode = "1.3"          # Binary protocol
hex = "0.4"              # Hex encoding
```
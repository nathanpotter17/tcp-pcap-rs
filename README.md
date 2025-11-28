# PQ-TCP-RS

Post-quantum authenticated TCP server/client with Dilithium3 signatures.

## Table of Contents

- [Setup](#setup)
  - [Windows](#windows)
  - [Linux](#linux)
- [Usage](#usage)
  - [Server Mode](#server-mode)
  - [Client Mode](#client-mode)
  - [Environment Variables](#environment-variables)
- [Architecture](#architecture)
  - [Authentication Flow](#authentication-flow)
  - [Decentralized Identity (DID)](#decentralized-identity-did)
  - [Pool Access Control](#pool-access-control)
  - [Connection IDs](#connection-ids)
  - [Connection Lifecycle](#connection-lifecycle)
- [Protocol](#protocol)
  - [Message Types](#message-types)
  - [Framing](#framing)
  - [Constants](#constants)
- [Security](#security)
  - [Features](#features)
  - [Startup Assertions](#startup-assertions)
- [API](#api)
  - [Broadcast Infrastructure](#broadcast-infrastructure)
  - [Core Types](#core-types)
- [Storage](#storage)
- [Dependencies](#dependencies)
- [Testing](#testing)

---

## Setup

### Windows

Requires Npcap SDK for packet capture.

1. Download from https://npcap.com/#download
2. Configure `.cargo/config.toml`:

```toml
[env]
TEST_MODE = "1"
CAPTURE = "1"
LIBPCAP_LIBDIR = "C:/Users/.../npcap-sdk-1.15/Lib/x64"
LIBPCAP_VER = "1.15.0"
```

### Linux

```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel

# Arch
sudo pacman -S libpcap
```

Post-build capability setup:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip target/release/tcp-server
```

---

## Usage

### Server Mode

```bash
# Default: 0.0.0.0:9090, pool="default_pool"
./tcp-server

# Explicit
./tcp-server server
./tcp-server server 0.0.0.0:9090 my_pool
```

### Client Mode

```bash
./tcp-server client 127.0.0.1:9090
./tcp-server client 192.168.1.100:9090 my_pool
```

Pool must match server's pool or connection rejected.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `TEST_MODE=1` | Use loopback for packet capture |
| `CAPTURE=1` | Enable packet capture (requires pcap) |
| `LIBPCAP_LIBDIR` | Windows: Npcap SDK lib path |
| `LIBPCAP_VER` | Windows: Npcap version |

---

## Architecture

### Authentication Flow

```
Client                                    Server
  │                                         │
  │─── Connect(DID, PubKey, PoolHash) ─────►│
  │                                         │
  │◄── Challenge(Nonce, ServerProof) ───────│
  │         [Server signs challenge]        │
  │                                         │
  │    [Client verifies server DID]         │
  │                                         │
  │─── Response(ClientSignature) ──────────►│
  │                                         │
  │─── Elaborate(HumanText) ───────────────►│
  │                                         │
  │◄── Authenticated(SessionToken) ─────────│
  │                                         │
  ╔═════════════════════════════════════════╗
  ║     SECURE CHANNEL ESTABLISHED          ║
  ╚═════════════════════════════════════════╝
```

Mutual authentication: both parties prove identity via Dilithium3 signatures.

### Decentralized Identity (DID)

Format: `did:diagon:<hex(SHA256(pubkey)[0:32])>`

```
did:diagon:594b8670356d98c4aa0488d0122ec5a884bc5a270dde7b212f7aa64f29e5aa2b
```

Properties:
- Deterministic: derived from public key
- Self-certifying: anyone verifies DID↔key binding
- Persistent: stored in `db/` (CBOR)
- Portable: backup/move identity file

### Pool Access Control

Both parties compute `SHA256(passphrase)` and compare (constant-time).

```
"production_pool" → 7a3f2b1c...
```

Mismatch → immediate rejection, no info leak.

### Connection IDs

Globally unique, monotonic, persisted across restarts:

```
Run 1: conn #1, #2, #3
Run 2: conn #4, #5       ← Counter persists
Run 3: conn #6, #7, #8
```

Stored in `db/identity_*.cbor`.

### Connection Lifecycle

```
1. TCP Accept
2. Assign unique conn ID (persisted)
3. Register in ConnectionRegistry
4. Rate limit check (5/min/IP)
5. Mutual authentication (30s timeout)
6. Create session token
7. ═══ AUTHENTICATED SESSION ═══
   - Echo server (current impl)
   - Broadcast ready
   - Direct messaging ready
8. Disconnect
9. RAII cleanup (ConnectionGuard drops)
10. Unregister from registry
```

`ConnectionGuard` guarantees cleanup on any exit (success/error/panic).

---

## Protocol

### Message Types

```rust
enum AuthMessage {
    // Client → Server
    Connect { client_did, client_pubkey, pool_commitment },
    Response { signature },
    Elaborate { text },
    
    // Server → Client
    Challenge { challenge, server_proof },
    Authenticated { session_token },
    Rejected,
}
```

### Framing

```
┌─────────┬──────────────────────┐
│ 4 bytes │ N bytes              │
│ length  │ bincode payload      │
└─────────┴──────────────────────┘
```

Length: big-endian u32.

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_AUTH_MESSAGE_SIZE` | 65,536 | 64KB auth phase limit |
| `MAX_DATA_MESSAGE_SIZE` | 1,048,576 | 1MB post-auth limit |
| `CHALLENGE_TIMEOUT_SECS` | 30 | Auth window |
| `MIN_ELABORATION_LEN` | 20 | Human text min |
| `MAX_ELABORATION_LEN` | 1,024 | Human text max |
| `MAX_AUTH_ATTEMPTS_PER_MINUTE` | 5 | Rate limit per IP |
| `CHALLENGE_DOMAIN` | `DIAGON-TCP-AUTH-CHALLENGE-V1:` | Domain separation |
| `SERVER_PROOF_DOMAIN` | `DIAGON-TCP-AUTH-SERVER-PROOF-V1:` | Server proof prefix |

---

## Security

### Features

| Feature | Implementation |
|---------|----------------|
| Signatures | Dilithium3 (NIST PQC Level 3) |
| Hashing | SHA256 |
| Challenge | 32B nonce + timestamp + DID binding |
| Domain Separation | Prefix bytes prevent cross-protocol attacks |
| Replay Protection | Nonce cache, 60s expiry |
| Timing Mitigation | Constant-time compare (`#[inline(never)]`) |
| Rate Limiting | 5 auth/min/IP, sliding window |
| Session Binding | Token bound to DID + peer address |
| Generic Errors | No info leak on failure |

### Startup Assertions

Run on every server start:

```
✓ Identity persistence verified
✓ DID-pubkey binding verified
✓ Signature generation verified
✓ Challenge domain separation verified
✓ Constant-time comparison verified
✓ Message serialization verified

[✓✓✓] All security assertions passed
```

---

## API

### Broadcast Infrastructure

```rust
// Send to all authenticated clients
broadcast_to_all(&registry, data);

// Send to specific connection
send_to_connection(&registry, conn_id, data);

// Graceful shutdown all
shutdown_all(&registry);

// List active connections
let ids = get_active_connections(&registry);
```

Auto-cleans disconnected clients during broadcast.

### Core Types

```rust
// Decentralized Identifier
struct Did(String);
impl Did {
    fn from_pubkey(pk: &PublicKey) -> Self;
    fn short(&self) -> String;  // Truncated display
}

// Content Identifier
struct Cid([u8; 32]);
impl Cid {
    fn new(data: &[u8], node_did: &Did, nonce: u64) -> Self;
    fn short(&self) -> String;
}

// Challenge structure
struct AuthChallenge {
    nonce: [u8; 32],
    timestamp: u64,
    server_did: Did,
    client_did: Did,
    pool_commitment: [u8; 32],
}

// Session token (address-bound)
struct SessionToken {
    token: [u8; 32],
    client_did: Did,
    created_at: Instant,
    peer_addr: SocketAddr,
}
```

---

## Storage

```
db/
├── identity_<addr_hash>.cbor   # Server identity
│   ├── public_key              # Dilithium3 (1952 bytes)
│   ├── secret_key              # Dilithium3 (4016 bytes)
│   ├── did                     # "did:diagon:..."
│   └── connection_counter      # u64, persisted
│
└── client_identity.cbor        # Client identity
    ├── public_key
    ├── secret_key
    └── did
```

Permissions (Unix):
- `db/`: `0700`
- Identity files: `0600`

---

## Dependencies

```toml
pcap = "2.3.0"              # Packet capture
sha2 = "0.10"               # SHA256
pqcrypto-dilithium = "0.5"  # PQ signatures
pqcrypto-traits = "0.3"     # Trait definitions
rand = "0.8"                # CSPRNG
serde = "1.0"               # Serialization
serde_cbor = "0.11"         # CBOR format (identity)
bincode = "1.3"             # Binary protocol (messages)
hex = "0.4"                 # Hex encoding
```

---

## Testing

### Automated Suite

```bash
./test.bash
```

Tests:
1. Successful mutual authentication
2. Pool mismatch rejection
3. Identity persistence across restarts
4. Multiple sequential connections

### Manual Testing

```bash
# Terminal 1
./tcp-server server 0.0.0.0:9090 test_pool

# Terminal 2
./tcp-server client 127.0.0.1:9090 test_pool
```

### Remote Testing

```bash
# Find IP
ip addr  # Linux
ipconfig # Windows

# Server (all interfaces)
./tcp-server server 0.0.0.0:9090

# Client (remote machine)
./tcp-server client 192.168.x.x:9090
```
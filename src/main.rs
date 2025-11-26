use std::{
    thread,
    sync::{
        mpsc::{self, Sender, Receiver, TryRecvError},
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    net::{TcpStream, TcpListener, SocketAddr},
    io::{self, Read, Write, ErrorKind, BufWriter},
    time::{SystemTime, UNIX_EPOCH, Duration, Instant},
    fs::{File, create_dir_all},
    path::Path,
    collections::HashMap,
};

use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium3::*;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
use serde::{Serialize, Deserialize};
use rand::RngCore;

use pcap::{Capture, Device};

// ============================================================================
// SECURITY CONSTANTS - Hardened values
// ============================================================================

/// Maximum auth message size (64KB - sufficient for Dilithium signatures)
const MAX_AUTH_MESSAGE_SIZE: usize = 65_536;

/// Maximum post-auth message size (1MB for application data)
const MAX_DATA_MESSAGE_SIZE: usize = 1_048_576;

/// Challenge validity window in seconds
const CHALLENGE_TIMEOUT_SECS: u64 = 30;

/// Minimum elaboration length
const MIN_ELABORATION_LEN: usize = 20;

/// Maximum elaboration length (prevent DoS)
const MAX_ELABORATION_LEN: usize = 1024;

/// Domain separation prefix for challenge signing
const CHALLENGE_DOMAIN: &[u8] = b"DIAGON-TCP-AUTH-CHALLENGE-V1:";

/// Domain separation prefix for server proof
const SERVER_PROOF_DOMAIN: &[u8] = b"DIAGON-TCP-AUTH-SERVER-PROOF-V1:";

/// Rate limit: max auth attempts per minute per IP
const MAX_AUTH_ATTEMPTS_PER_MINUTE: u32 = 5;

// ============================================================================
// CONSTANT-TIME COMPARISON
// ============================================================================

/// Constant-time byte array comparison to prevent timing attacks
/// Note: Length comparison is NOT constant-time by design (lengths are public)
#[inline(never)]
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Length mismatch - do dummy work to reduce timing leak
        // (Not perfect but reduces signal)
        let _ = std::hint::black_box(a.iter().fold(0u8, |acc, x| acc ^ x));
        return false;
    }
    
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    std::hint::black_box(result) == 0
}

// ============================================================================
// TCP INFO FOR PACKET CAPTURE
// ============================================================================

struct TcpInfo {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: String,
}

// ============================================================================
// RATE LIMITER
// ============================================================================

struct RateLimiter {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: u32,
    window: Duration,
}

impl RateLimiter {
    fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window: Duration::from_secs(window_secs),
        }
    }
    
    fn check_and_record(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let attempts = self.attempts.entry(key.to_string()).or_insert_with(Vec::new);
        
        // Remove old attempts outside window
        attempts.retain(|t| now.duration_since(*t) < self.window);
        
        if attempts.len() >= self.max_attempts as usize {
            false
        } else {
            attempts.push(now);
            true
        }
    }
    
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < self.window);
            !attempts.is_empty()
        });
    }
}

// ============================================================================
// CONNECTION REGISTRY
// ============================================================================

struct ConnectionRegistry {
    connections: HashMap<u64, Sender<AuthClientMessage>>,
    total_served: u64,
}

impl ConnectionRegistry {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
            total_served: 0,
        }
    }
    
    /// Register connection with pre-assigned ID
    fn register(&mut self, id: u64, sender: Sender<AuthClientMessage>) {
        self.connections.insert(id, sender);
        self.total_served += 1;
    }
    
    fn unregister(&mut self, id: u64) -> bool {
        self.connections.remove(&id).is_some()
    }
    
    fn active_count(&self) -> usize {
        self.connections.len()
    }
    
    fn total_served(&self) -> u64 {
        self.total_served
    }
    
    fn broadcast(&mut self, msg: AuthClientMessage) -> (usize, usize) 
    where 
        AuthClientMessage: Clone 
    {
        let mut success = 0;
        let mut failed = Vec::new();
        
        for (&id, sender) in self.connections.iter() {
            match sender.send(msg.clone()) {
                Ok(_) => success += 1,
                Err(_) => failed.push(id),
            }
        }
        
        let fail_count = failed.len();
        for id in failed {
            self.connections.remove(&id);
        }
        
        (success, fail_count)
    }
    
    fn send_to(&self, id: u64, msg: AuthClientMessage) -> Result<(), SendError> {
        match self.connections.get(&id) {
            Some(sender) => sender.send(msg).map_err(|_| SendError::Disconnected),
            None => Err(SendError::NotFound),
        }
    }
}

#[derive(Debug)]
enum SendError {
    NotFound,
    Disconnected,
}

/// RAII guard that unregisters connection when dropped
struct ConnectionGuard {
    id: u64,
    registry: Arc<Mutex<ConnectionRegistry>>,
    peer_addr: SocketAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().unwrap();
        if registry.unregister(self.id) {
            println!("[REGISTRY] Connection {} ({}) removed | Active: {}", 
                     self.id, self.peer_addr, registry.active_count());
        }
    }
}

// ============================================================================
// PACKET CAPTURE ACTOR
// ============================================================================

struct PacketCaptureActor {
    receiver: mpsc::Receiver<CaptureMessage>,
}

enum CaptureMessage {
    Start,
    Stop,
}

impl PacketCaptureActor {
    fn run(self) {
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                CaptureMessage::Start => {
                    println!("[CAPTURE] Starting packet capture");
                    self.capture_packets();
                }
                CaptureMessage::Stop => {
                    println!("[CAPTURE] Stopping packet capture");
                    break;
                }
            }
        }
    }
    
    fn capture_packets(&self) {
        let devices = Device::list().expect("Failed to list devices");
        let use_loopback = std::env::var("TEST_MODE").is_ok();
        
        let device = if use_loopback {
            devices.iter().find(|d| {
                d.name == "lo" || 
                d.desc.as_ref()
                    .map(|s| s.to_lowercase().contains("loopback"))
                    .unwrap_or(false)
            }).expect("Loopback interface not found")
        } else {
            devices.iter().find(|d| {
                let desc = d.desc.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();
                desc.contains("wi-fi") || desc.contains("ethernet")
            }).expect("Network adapter not found")
        }.clone();
        
        println!("[CAPTURE] Device: {} ({})", device.name, 
                 device.desc.as_ref().unwrap_or(&"N/A".to_string()));
        
        let mut cap = Capture::from_device(device)
            .expect("Failed to open device")
            .promisc(true).snaplen(65535).timeout(1000)
            .open().expect("Failed to activate capture");
        
        cap.filter("tcp port 9090", true).expect("Failed to set filter");
        
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some((tcp_info, payload)) = Self::parse_packet(&packet.data) {
                        println!("═══════════════════════════════════════");
                        println!("{}:{} → {}:{} [{}]", 
                                 tcp_info.src_ip, tcp_info.src_port,
                                 tcp_info.dst_ip, tcp_info.dst_port,
                                 tcp_info.flags.trim());
                        if !payload.is_empty() {
                            println!("Payload: {} bytes", payload.len());
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => eprintln!("[CAPTURE] Error: {:?}", e),
            }
        }
    }

    fn parse_packet(packet: &[u8]) -> Option<(TcpInfo, &[u8])> {
        if packet.len() < 4 { return None; }
        
        let mut offset = 4; // Loopback header
        
        if packet.len() < offset + 20 { return None; }
        let ip_header_len = ((packet[offset] & 0x0F) * 4) as usize;
        
        let src_ip = format!("{}.{}.{}.{}", 
            packet[offset + 12], packet[offset + 13], 
            packet[offset + 14], packet[offset + 15]);
        let dst_ip = format!("{}.{}.{}.{}", 
            packet[offset + 16], packet[offset + 17], 
            packet[offset + 18], packet[offset + 19]);
        
        offset += ip_header_len;
        
        if packet.len() < offset + 20 { return None; }
        
        let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let seq = u32::from_be_bytes([
            packet[offset + 4], packet[offset + 5], 
            packet[offset + 6], packet[offset + 7]
        ]);
        let ack = u32::from_be_bytes([
            packet[offset + 8], packet[offset + 9], 
            packet[offset + 10], packet[offset + 11]
        ]);
        
        let tcp_flags = packet[offset + 13];
        let mut flags = String::new();
        if tcp_flags & 0x02 != 0 { flags.push_str("SYN "); }
        if tcp_flags & 0x10 != 0 { flags.push_str("ACK "); }
        if tcp_flags & 0x01 != 0 { flags.push_str("FIN "); }
        if tcp_flags & 0x04 != 0 { flags.push_str("RST "); }
        if tcp_flags & 0x08 != 0 { flags.push_str("PSH "); }
        
        let tcp_header_len = ((packet[offset + 12] >> 4) * 4) as usize;
        offset += tcp_header_len;
        
        let payload = if offset >= packet.len() { &[] } else { &packet[offset..] };
        
        Some((TcpInfo { src_ip, dst_ip, src_port, dst_port, seq, ack, flags }, payload))
    }
}

#[derive(Clone)]
struct CaptureHandle {
    sender: mpsc::Sender<CaptureMessage>,
}

impl CaptureHandle {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        let actor = PacketCaptureActor { receiver };
        thread::spawn(move || actor.run());
        Self { sender }
    }
    
    fn start(&self) -> Result<(), mpsc::SendError<CaptureMessage>> {
        self.sender.send(CaptureMessage::Start)
    }
}

// ============================================================================
// CORE IDENTITY TYPES
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(pub String);

impl Did {
    pub fn from_pubkey(pk: &PublicKey) -> Self {
        Did(format!("did:diagon:{}", hex::encode(&pk.as_bytes()[..32])))
    }
    
    pub fn short(&self) -> String {
        if self.0.len() > 20 {
            format!("{}...{}", &self.0[..16], &self.0[self.0.len()-8..])
        } else {
            self.0.clone()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cid(pub [u8; 32]);

impl Cid {
    fn new(data: &[u8], node_did: &Did, nonce: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(node_did.0.as_bytes());
        Cid(hasher.finalize().into())
    }
    
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

// ============================================================================
// HARDENED PROTOCOL MESSAGES
// ============================================================================

/// Structured challenge with domain separation and binding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Random nonce (32 bytes)
    pub nonce: [u8; 32],
    /// Server timestamp (prevents replay across time)
    pub timestamp: u64,
    /// Server DID (binds challenge to specific server)
    pub server_did: Did,
    /// Client DID (binds challenge to specific client)
    pub client_did: Did,
    /// Pool commitment hash (binds to pool)
    pub pool_commitment: [u8; 32],
}

impl AuthChallenge {
    /// Create signable bytes with domain separation
    fn to_signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(256);
        data.extend_from_slice(CHALLENGE_DOMAIN);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(self.server_did.0.as_bytes());
        data.extend_from_slice(self.client_did.0.as_bytes());
        data.extend_from_slice(&self.pool_commitment);
        data
    }
}

/// Server proof for mutual authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerProof {
    /// Server's signature over the challenge
    pub signature: Vec<u8>,
    /// Server's public key for verification
    pub server_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMessage {
    /// Client → Server: Initial connection with identity
    Connect {
        client_did: Did,
        client_pubkey: Vec<u8>,
        pool_commitment: [u8; 32],
    },
    /// Server → Client: Challenge + server proof for mutual auth
    Challenge {
        challenge: AuthChallenge,
        server_proof: ServerProof,
    },
    /// Client → Server: Signed response to challenge
    Response {
        signature: Vec<u8>,
    },
    /// Client → Server: Human-readable elaboration
    Elaborate {
        text: String,
    },
    /// Server → Client: Authentication successful with session token
    Authenticated {
        session_token: [u8; 32],
    },
    /// Server → Client: Authentication failed (generic message)
    Rejected,
}

// ============================================================================
// SESSION TOKEN
// ============================================================================

#[derive(Debug, Clone)]
pub struct SessionToken {
    token: [u8; 32],
    client_did: Did,
    created_at: Instant,
    peer_addr: SocketAddr,
}

impl SessionToken {
    fn new(client_did: Did, peer_addr: SocketAddr) -> Self {
        let mut token = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);
        Self {
            token,
            client_did,
            created_at: Instant::now(),
            peer_addr,
        }
    }
    
    fn is_valid(&self, token: &[u8; 32], peer_addr: &SocketAddr) -> bool {
        // Constant-time token comparison + address binding
        constant_time_compare(&self.token, token) && self.peer_addr == *peer_addr
    }
}

// ============================================================================
// TCP FRAMING (Hardened)
// ============================================================================

fn write_auth_message(stream: &mut TcpStream, msg: &AuthMessage) -> io::Result<()> {
    let data = bincode::serialize(msg)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    
    if data.len() > MAX_AUTH_MESSAGE_SIZE {
        return Err(io::Error::new(ErrorKind::InvalidData, "Message too large"));
    }
    
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&data)?;
    stream.flush()?;
    Ok(())
}

fn read_auth_message(stream: &mut TcpStream) -> io::Result<AuthMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    if len > MAX_AUTH_MESSAGE_SIZE {
        return Err(io::Error::new(ErrorKind::InvalidData, "Message too large"));
    }
    
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    
    bincode::deserialize(&buf)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

// ============================================================================
// AUTHENTICATION ERROR (Generic to prevent information leakage)
// ============================================================================

#[derive(Debug)]
enum AuthError {
    /// Generic auth failure - don't leak specifics
    Failed,
    /// Timeout during auth
    Timeout,
    /// Protocol error (malformed messages)
    Protocol,
    /// Rate limited
    RateLimited,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Generic messages to prevent information leakage
        match self {
            AuthError::Failed => write!(f, "Authentication failed"),
            AuthError::Timeout => write!(f, "Authentication timeout"),
            AuthError::Protocol => write!(f, "Protocol error"),
            AuthError::RateLimited => write!(f, "Too many attempts"),
        }
    }
}

// ============================================================================
// AUTHENTICATED CLIENT ACTOR (Hardened)
// ============================================================================

struct AuthClientActor {
    receiver: Receiver<AuthClientMessage>,
    stream: TcpStream,
    peer_addr: SocketAddr,
    server_identity: Arc<ServerIdentity>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    conn_id: u64,
    registry: Arc<Mutex<ConnectionRegistry>>,
}

#[derive(Clone)]
enum AuthClientMessage {
    ProcessData(Vec<u8>),
    Broadcast(Vec<u8>),  // distinguish broadcast from direct send
    Shutdown,
}

impl AuthClientActor {
    fn run(mut self) {
        // RAII cleanup - will unregister on ANY exit path
        let _guard = ConnectionGuard {
            id: self.conn_id,
            registry: Arc::clone(&self.registry),
            peer_addr: self.peer_addr,
        };
        
        // Check rate limit before proceeding
        {
            let mut limiter = self.rate_limiter.lock().unwrap();
            if !limiter.check_and_record(&self.peer_addr.ip().to_string()) {
                println!("[AUTH] {} rate limited", self.peer_addr);
                let _ = write_auth_message(&mut self.stream, &AuthMessage::Rejected);
                return;  // _guard drops here, unregisters connection
            }
        }
        
        match self.handle_authentication() {
            Ok(session) => {
                println!("[AUTH] ✓ {} authenticated as {} (conn #{})", 
                    self.peer_addr, session.client_did.short(), self.conn_id);
                self.run_authenticated(session);
            }
            Err(e) => {
                println!("[AUTH] ✗ {} failed: {}", self.peer_addr, e);
                let _ = write_auth_message(&mut self.stream, &AuthMessage::Rejected);
            }
        }
        // _guard drops here, unregisters connection
    }
    
    fn handle_authentication(&mut self) -> Result<SessionToken, AuthError> {
        // Set strict timeout for auth phase
        self.stream.set_read_timeout(Some(Duration::from_secs(CHALLENGE_TIMEOUT_SECS)))
            .map_err(|_| AuthError::Protocol)?;
        
        let auth_start = Instant::now();
        
        // Step 1: Read Connect message
        let connect_msg = read_auth_message(&mut self.stream)
            .map_err(|_| AuthError::Protocol)?;
        
        let (client_did, client_pubkey_bytes, client_pool) = match connect_msg {
            AuthMessage::Connect { client_did, client_pubkey, pool_commitment } => {
                (client_did, client_pubkey, pool_commitment)
            }
            _ => return Err(AuthError::Protocol),
        };
        
        // Step 2: Validate DID-pubkey binding
        let client_pubkey = self.validate_identity(&client_did, &client_pubkey_bytes)?;
        
        // Step 3: Validate pool commitment (constant-time!)
        let server_pool = self.server_identity.get_pool_commitment();
        if !constant_time_compare(&client_pool, &server_pool) {
            return Err(AuthError::Failed);
        }
        
        // Step 4: Generate structured challenge
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        
        let challenge = AuthChallenge {
            nonce,
            timestamp: current_timestamp(),
            server_did: self.server_identity.did.clone(),
            client_did: client_did.clone(),
            pool_commitment: server_pool,
        };

        // Verify nonce not replayed
        if !self.server_identity.record_nonce(&challenge.nonce) {
            return Err(AuthError::Failed);
        }
        
        // Step 5: Create server proof (for mutual authentication)
        let challenge_bytes = challenge.to_signable_bytes();
        let server_sig = self.server_identity.sign(&challenge_bytes);
        
        let server_proof = ServerProof {
            signature: server_sig,
            server_pubkey: self.server_identity.public_key.as_bytes().to_vec(),
        };
        
        // Step 6: Send challenge with server proof
        write_auth_message(&mut self.stream, &AuthMessage::Challenge {
            challenge: challenge.clone(),
            server_proof,
        }).map_err(|_| AuthError::Protocol)?;
        
        // Step 7: Receive client signature
        let response_msg = read_auth_message(&mut self.stream)
            .map_err(|_| AuthError::Protocol)?;
        
        let client_sig = match response_msg {
            AuthMessage::Response { signature } => signature,
            _ => return Err(AuthError::Protocol),
        };
        
        // Step 8: Verify client signature (constant-time internally via pqcrypto)
        if !self.verify_signature(&challenge_bytes, &client_sig, &client_pubkey)? {
            return Err(AuthError::Failed);
        }
        
        // Step 9: Check timeout BEFORE accepting elaboration
        if auth_start.elapsed() > Duration::from_secs(CHALLENGE_TIMEOUT_SECS) {
            return Err(AuthError::Timeout);
        }
        
        // Step 10: Receive elaboration
        let elaborate_msg = read_auth_message(&mut self.stream)
            .map_err(|_| AuthError::Protocol)?;
        
        let elaborate_text = match elaborate_msg {
            AuthMessage::Elaborate { text } => text,
            _ => return Err(AuthError::Protocol),
        };
        
        // Step 11: Validate elaboration bounds
        if elaborate_text.len() < MIN_ELABORATION_LEN || elaborate_text.len() > MAX_ELABORATION_LEN {
            return Err(AuthError::Failed);
        }
        
        // Step 12: Final timeout check
        if auth_start.elapsed() > Duration::from_secs(CHALLENGE_TIMEOUT_SECS) {
            return Err(AuthError::Timeout);
        }
        
        // Step 13: Create session token bound to connection
        let session = SessionToken::new(client_did.clone(), self.peer_addr);
        
        // Step 14: Send success with session token
        write_auth_message(&mut self.stream, &AuthMessage::Authenticated {
            session_token: session.token,
        }).map_err(|_| AuthError::Protocol)?;
        
        println!("[AUTH] {} elaborated: {}...", 
            client_did.short(),
            sanitize_for_log(&elaborate_text[..elaborate_text.len().min(50)]));
        
        Ok(session)
    }
    
    fn validate_identity(&self, did: &Did, pubkey_bytes: &[u8]) -> Result<PublicKey, AuthError> {
        // Parse public key (validates structure)
        let pubkey = PublicKey::from_bytes(pubkey_bytes)
            .map_err(|_| AuthError::Failed)?;
        
        // Verify DID derivation
        let expected_did = Did::from_pubkey(&pubkey);
        
        // Constant-time DID comparison (compare the bytes, not string)
        if !constant_time_compare(did.0.as_bytes(), expected_did.0.as_bytes()) {
            return Err(AuthError::Failed);
        }
        
        Ok(pubkey)
    }
    
    fn verify_signature(&self, data: &[u8], sig_bytes: &[u8], pubkey: &PublicKey) -> Result<bool, AuthError> {
        let sig = DetachedSignature::from_bytes(sig_bytes)
            .map_err(|_| AuthError::Failed)?;
        
        // pqcrypto's verify is constant-time
        Ok(verify_detached_signature(&sig, data, pubkey).is_ok())
    }
    
    fn run_authenticated(mut self, session: SessionToken) {
        self.stream.set_nonblocking(true).ok();
        self.stream.set_read_timeout(None).ok();
        
        let mut buffer = [0u8; 4096];
        
        loop {
            // Check control messages (non-blocking)
            match self.receiver.try_recv() {
                Ok(AuthClientMessage::ProcessData(data)) => {
                    if let Err(e) = self.stream.write_all(&data) {
                        eprintln!("[DATA] Write error to conn #{}: {:?}", self.conn_id, e);
                        break;
                    }
                }
                Ok(AuthClientMessage::Broadcast(data)) => {
                    // Prefix broadcast messages for clarity (optional)
                    if let Err(e) = self.stream.write_all(&data) {
                        eprintln!("[BROADCAST] Write error to conn #{}: {:?}", self.conn_id, e);
                        break;
                    }
                }
                Ok(AuthClientMessage::Shutdown) => {
                    println!("[SESSION] Conn #{} received shutdown", self.conn_id);
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
            
            // Read application data
            match self.stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    // Echo back
                    if self.stream.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        
        println!("[SESSION] {} (conn #{}) disconnected", 
                 session.client_did.short(), self.conn_id);
    }
}

// ============================================================================
// AUTHENTICATED CLIENT HANDLE
// ============================================================================

#[derive(Clone)]
struct AuthClientHandle {
    conn_id: u64,
    sender: Sender<AuthClientMessage>,
}

impl AuthClientHandle {
    fn new(
        stream: TcpStream, 
        server_identity: Arc<ServerIdentity>,
        rate_limiter: Arc<Mutex<RateLimiter>>,
        registry: Arc<Mutex<ConnectionRegistry>>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        
        let peer_addr = stream.peer_addr()
            .expect("Failed to get peer address");
        
        // Get globally unique ID from ServerIdentity (persisted)
        let conn_id = server_identity.next_connection_id();
        
        // Register with pre-assigned ID
        {
            let mut reg = registry.lock().unwrap();
            reg.register(conn_id, sender.clone());
            println!("[CONNECT] {} assigned conn #{} | Active: {}", 
                     peer_addr, conn_id, reg.active_count());
        }
        
        let actor = AuthClientActor {
            receiver,
            stream,
            peer_addr,
            server_identity,
            rate_limiter,
            conn_id,
            registry,
        };
        
        thread::spawn(move || actor.run());
        
        Self { conn_id, sender }
    }
    
    #[allow(dead_code)]
    fn id(&self) -> u64 {
        self.conn_id
    }
    
    #[allow(dead_code)]
    fn send_data(&self, data: Vec<u8>) -> Result<(), mpsc::SendError<AuthClientMessage>> {
        self.sender.send(AuthClientMessage::ProcessData(data))
    }
    
    #[allow(dead_code)]
    fn shutdown(&self) -> Result<(), mpsc::SendError<AuthClientMessage>> {
        self.sender.send(AuthClientMessage::Shutdown)
    }
}

// ============================================================================
// SERVER IDENTITY MANAGEMENT
// ============================================================================

struct ServerIdentity {
    did: Did,
    public_key: PublicKey,
    secret_key: SecretKey,
    pool_commitment: RwLock<[u8; 32]>,
    nonce_counter: Mutex<u64>,
    used_nonces: Mutex<HashMap<[u8; 32], Instant>>,
    // NEW: Persistent connection counter
    connection_counter: Mutex<u64>,
    identity_path: String,  // Store path for persistence
}

impl ServerIdentity {
    fn load_or_create(addr: &str) -> io::Result<Arc<Self>> {
        create_dir_all("db").ok();
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata("db") {
                let mut perms = metadata.permissions();
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions("db", perms);
            }
        }
        
        let addr_hash = hex::encode(&sha256(addr.as_bytes())[..8]);
        let identity_path = format!("db/identity_{}.cbor", addr_hash);
        
        // NEW: Tuple now includes connection_counter as 4th element
        // Format: (pk_bytes, sk_bytes, did, connection_counter)
        let (pk, sk, did, conn_counter) = if Path::new(&identity_path).exists() {
            let data = std::fs::read(&identity_path)?;
            
            // Try new format first (with counter)
            match serde_cbor::from_slice::<(Vec<u8>, Vec<u8>, Did, u64)>(&data) {
                Ok((pk_bytes, sk_bytes, did, counter)) => {
                    match (PublicKey::from_bytes(&pk_bytes), SecretKey::from_bytes(&sk_bytes)) {
                        (Ok(pk), Ok(sk)) if Did::from_pubkey(&pk) == did => (pk, sk, did, counter),
                        _ => Self::generate_new_identity(),
                    }
                }
                Err(_) => {
                    // Try legacy format (without counter) for migration
                    match serde_cbor::from_slice::<(Vec<u8>, Vec<u8>, Did)>(&data) {
                        Ok((pk_bytes, sk_bytes, did)) => {
                            match (PublicKey::from_bytes(&pk_bytes), SecretKey::from_bytes(&sk_bytes)) {
                                (Ok(pk), Ok(sk)) if Did::from_pubkey(&pk) == did => {
                                    println!("[IDENTITY] Migrating legacy identity file...");
                                    (pk, sk, did, 0) // Start counter at 0 for legacy
                                }
                                _ => Self::generate_new_identity(),
                            }
                        }
                        Err(_) => Self::generate_new_identity(),
                    }
                }
            }
        } else {
            let (pk, sk, did) = Self::generate_new_keypair();
            
            // Create new identity file with counter = 0
            Self::persist_identity(&identity_path, &pk, &sk, &did, 0)?;
            
            (pk, sk, did, 0)
        };
        
        println!("[IDENTITY] DID: {}", did.0);
        println!("[IDENTITY] Connection counter starts at: {}", conn_counter);
        
        Ok(Arc::new(Self {
            did,
            public_key: pk,
            secret_key: sk,
            pool_commitment: RwLock::new([0; 32]),
            nonce_counter: Mutex::new(0),
            used_nonces: Mutex::new(HashMap::new()),
            connection_counter: Mutex::new(conn_counter),
            identity_path,
        }))
    }
    
    fn generate_new_identity() -> (PublicKey, SecretKey, Did, u64) {
        let (pk, sk) = keypair();
        let did = Did::from_pubkey(&pk);
        (pk, sk, did, 0)
    }
    
    fn generate_new_keypair() -> (PublicKey, SecretKey, Did) {
        let (pk, sk) = keypair();
        let did = Did::from_pubkey(&pk);
        (pk, sk, did)
    }
    
    /// Persist identity to disk
    fn persist_identity(
        path: &str,
        pk: &PublicKey,
        sk: &SecretKey,
        did: &Did,
        counter: u64,
    ) -> io::Result<()> {
        let file = File::create(path)?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        
        let identity = (
            pk.as_bytes().to_vec(),
            sk.as_bytes().to_vec(),
            did.clone(),
            counter,
        );
        
        serde_cbor::to_writer(BufWriter::new(file), &identity)
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        
        Ok(())
    }
    
    /// Save current state to disk
    fn persist(&self) -> io::Result<()> {
        let counter = *self.connection_counter.lock().unwrap();
        Self::persist_identity(
            &self.identity_path,
            &self.public_key,
            &self.secret_key,
            &self.did,
            counter,
        )
    }
    
    /// Get next connection ID and persist
    fn next_connection_id(&self) -> u64 {
        let mut counter = self.connection_counter.lock().unwrap();
        *counter += 1;
        let id = *counter;
        drop(counter); // Release lock before I/O
        
        // Persist every connection (or batch for performance)
        if let Err(e) = self.persist() {
            eprintln!("[IDENTITY] Warning: Failed to persist counter: {}", e);
        }
        
        id
    }
    
    fn set_pool(&self, passphrase: &str) {
        let commitment = sha256(passphrase.as_bytes());
        *self.pool_commitment.write().unwrap() = commitment;
        println!("[POOL] Commitment: {}", hex::encode(&commitment[..8]));
    }
    
    fn get_pool_commitment(&self) -> [u8; 32] {
        *self.pool_commitment.read().unwrap()
    }
    
    fn generate_cid(&self, data: &[u8]) -> Cid {
        let mut counter = self.nonce_counter.lock().unwrap();
        *counter += 1;
        Cid::new(data, &self.did, *counter)
    }
    
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        detached_sign(data, &self.secret_key).as_bytes().to_vec()
    }
    
    fn record_nonce(&self, nonce: &[u8; 32]) -> bool {
        let mut nonces = self.used_nonces.lock().unwrap();
        let now = Instant::now();
        
        nonces.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(CHALLENGE_TIMEOUT_SECS * 2));
        
        if nonces.contains_key(nonce) {
            false
        } else {
            nonces.insert(*nonce, now);
            true
        }
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(100)  // Truncate
        .collect()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ============================================================================
// CLI MODE SELECTION
// ============================================================================

enum Mode {
    Server { addr: String, pool: String },
    Client { server_addr: String, pool: String },
}

fn parse_args() -> Mode {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        return Mode::Server { 
            addr: "0.0.0.0:9090".to_string(), 
            pool: "default_pool".to_string() 
        };
    }
    
    match args[1].as_str() {
        "server" => {
            let addr = args.get(2).cloned().unwrap_or_else(|| "0.0.0.0:9090".to_string());
            let pool = args.get(3).cloned().unwrap_or_else(|| "default_pool".to_string());
            Mode::Server { addr, pool }
        }
        "client" => {
            if args.len() < 3 {
                eprintln!("Usage: {} client <server_addr> [pool]", args[0]);
                std::process::exit(1);
            }
            let server_addr = args[2].clone();
            let pool = args.get(3).cloned().unwrap_or_else(|| "default_pool".to_string());
            Mode::Client { server_addr, pool }
        }
        _ => {
            eprintln!("Usage: {} [server|client] ...", args[0]);
            std::process::exit(1);
        }
    }
}

// ============================================================================
// SERVER MODE
// ============================================================================

fn run_server(addr: String, pool: String) {
    let server_identity = ServerIdentity::load_or_create(&addr)
        .expect("Failed to load identity");
    
    run_startup_assertions(&server_identity, &addr, &pool);
    server_identity.set_pool(&pool);
    
    let rate_limiter = Arc::new(Mutex::new(
        RateLimiter::new(MAX_AUTH_ATTEMPTS_PER_MINUTE, 60)
    ));
    
    // NEW: Connection registry
    let registry = Arc::new(Mutex::new(ConnectionRegistry::new()));
    
    // Packet capture (unchanged)
    if std::env::var("CAPTURE").is_ok() {
        let capture_handle = CaptureHandle::new();
        capture_handle.start().expect("Failed to start capture");
    }
    
    // Periodic cleanup thread for rate limiter
    let rate_limiter_cleanup = Arc::clone(&rate_limiter);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(60));
            rate_limiter_cleanup.lock().unwrap().cleanup();
        }
    });
    
    // NEW: Periodic stats reporting
    let registry_stats = Arc::clone(&registry);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(300)); // Every 5 minutes
            let reg = registry_stats.lock().unwrap();
            println!("[STATS] Active: {} | Total served: {}", 
                     reg.active_count(), reg.total_served());
        }
    });
    
    let listener = TcpListener::bind(&addr).expect("Failed to bind");
    println!("\n[SERVER] Listening on {}", addr);
    println!("[SERVER] Pool: {}", pool);
    println!("[SERVER] DID: {}", server_identity.did.0);
    println!("[SERVER] Rate limit: {} attempts/minute per IP\n", MAX_AUTH_ATTEMPTS_PER_MINUTE);
    
    for stream_result in listener.incoming() {
        if let Ok(stream) = stream_result {
            // Handle created, thread spawned, handle can be dropped
            // Registry tracks the connection, guard handles cleanup
            let _ = AuthClientHandle::new(
                stream, 
                Arc::clone(&server_identity),
                Arc::clone(&rate_limiter),
                Arc::clone(&registry),
            );
        }
    }
}

/// Broadcast raw bytes to all connected clients
#[allow(dead_code)]
fn broadcast_to_all(registry: &Arc<Mutex<ConnectionRegistry>>, data: Vec<u8>) {
    let mut reg = registry.lock().unwrap();
    let (success, failed) = reg.broadcast(AuthClientMessage::Broadcast(data));
    if failed > 0 {
        println!("[BROADCAST] Sent to {} clients, {} disconnected", success, failed);
    }
}

/// Send to specific connection by ID
#[allow(dead_code)]
fn send_to_connection(
    registry: &Arc<Mutex<ConnectionRegistry>>, 
    conn_id: u64, 
    data: Vec<u8>
) -> Result<(), SendError> {
    let reg = registry.lock().unwrap();
    reg.send_to(conn_id, AuthClientMessage::ProcessData(data))
}

/// Shutdown all connections gracefully
#[allow(dead_code)]
fn shutdown_all(registry: &Arc<Mutex<ConnectionRegistry>>) {
    let mut reg = registry.lock().unwrap();
    let (success, _) = reg.broadcast(AuthClientMessage::Shutdown);
    println!("[SHUTDOWN] Sent shutdown to {} clients", success);
}

/// Get list of active connection IDs
#[allow(dead_code)]
fn get_active_connections(registry: &Arc<Mutex<ConnectionRegistry>>) -> Vec<u64> {
    let reg = registry.lock().unwrap();
    reg.connections.keys().copied().collect()
}

fn run_startup_assertions(server_identity: &Arc<ServerIdentity>, addr: &str, pool: &str) {
    println!("\n[STARTUP] Running security assertions...\n");
    
    // Assert 1: Identity persistence
    let addr_hash = hex::encode(&sha256(addr.as_bytes())[..8]);
    let identity_path = format!("db/identity_{}.cbor", addr_hash);
    assert!(Path::new(&identity_path).exists(), "Identity file not persisted");
    println!("✓ Identity persistence verified");
    
    // Assert 2: DID-pubkey binding
    let derived_did = Did::from_pubkey(&server_identity.public_key);
    assert!(constant_time_compare(derived_did.0.as_bytes(), server_identity.did.0.as_bytes()),
        "DID-pubkey binding invalid");
    println!("✓ DID-pubkey binding verified");
    
    // Assert 3: Signature roundtrip
    let test_msg = b"security_assertion_test";
    let sig = server_identity.sign(test_msg);
    let sig_obj = DetachedSignature::from_bytes(&sig).expect("Signature parse failed");
    assert!(verify_detached_signature(&sig_obj, test_msg, &server_identity.public_key).is_ok(),
        "Signature verification failed");
    println!("✓ Signature generation verified");
    
    // Assert 4: Challenge structure
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let challenge = AuthChallenge {
        nonce,
        timestamp: current_timestamp(),
        server_did: server_identity.did.clone(),
        client_did: Did("did:diagon:test".to_string()),
        pool_commitment: sha256(pool.as_bytes()),
    };
    let challenge_bytes = challenge.to_signable_bytes();
    assert!(challenge_bytes.starts_with(CHALLENGE_DOMAIN), "Challenge domain separation failed");
    println!("✓ Challenge domain separation verified");
    
    // Assert 5: Constant-time comparison
    let a = [1u8; 32];
    let b = [1u8; 32];
    let c = [2u8; 32];
    assert!(constant_time_compare(&a, &b), "Constant-time equal failed");
    assert!(!constant_time_compare(&a, &c), "Constant-time unequal failed");
    println!("✓ Constant-time comparison verified");
    
    // Assert 6: Message serialization
    let test_connect = AuthMessage::Connect {
        client_did: server_identity.did.clone(),
        client_pubkey: server_identity.public_key.as_bytes().to_vec(),
        pool_commitment: [0u8; 32],
    };
    let serialized = bincode::serialize(&test_connect).expect("Serialization failed");
    assert!(serialized.len() <= MAX_AUTH_MESSAGE_SIZE, "Test message exceeds limit");
    let _: AuthMessage = bincode::deserialize(&serialized).expect("Deserialization failed");
    println!("✓ Message serialization verified");
    
    println!("\n[✓✓✓] All security assertions passed\n");
}

// ============================================================================
// CLIENT MODE
// ============================================================================

struct ClientIdentity {
    did: Did,
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl ClientIdentity {
    fn load_or_create() -> io::Result<Self> {
        create_dir_all("db").ok();
        
        let identity_path = "db/client_identity.cbor";
        
        let (pk, sk, did) = if Path::new(identity_path).exists() {
            let data = std::fs::read(identity_path)?;
            match serde_cbor::from_slice::<(Vec<u8>, Vec<u8>, Did)>(&data) {
                Ok((pk_bytes, sk_bytes, did)) => {
                    match (PublicKey::from_bytes(&pk_bytes), SecretKey::from_bytes(&sk_bytes)) {
                        (Ok(pk), Ok(sk)) if Did::from_pubkey(&pk) == did => (pk, sk, did),
                        _ => {
                            let (pk, sk) = keypair();
                            let did = Did::from_pubkey(&pk);
                            (pk, sk, did)
                        }
                    }
                }
                Err(_) => {
                    let (pk, sk) = keypair();
                    let did = Did::from_pubkey(&pk);
                    (pk, sk, did)
                }
            }
        } else {
            let (pk, sk) = keypair();
            let did = Did::from_pubkey(&pk);
            
            let file = File::create(identity_path)?;
            let identity = (pk.as_bytes().to_vec(), sk.as_bytes().to_vec(), did.clone());
            let _ = serde_cbor::to_writer(BufWriter::new(file), &identity);
            
            (pk, sk, did)
        };
        
        Ok(Self { did, public_key: pk, secret_key: sk })
    }
    
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        detached_sign(data, &self.secret_key).as_bytes().to_vec()
    }
}

fn run_client(server_addr: String, pool: String) {
    println!("\n[CLIENT] Initializing...\n");
    
    let client_identity = ClientIdentity::load_or_create()
        .expect("Failed to load client identity");
    
    println!("[CLIENT] DID: {}", client_identity.did.short());
    
    let pool_commitment = sha256(pool.as_bytes());
    println!("[CLIENT] Pool: {} ({})", pool, hex::encode(&pool_commitment[..8]));
    
    println!("[CLIENT] Connecting to {}...", server_addr);
    let mut stream = TcpStream::connect(&server_addr)
        .expect("Failed to connect");
    
    stream.set_read_timeout(Some(Duration::from_secs(CHALLENGE_TIMEOUT_SECS)))
        .expect("Failed to set timeout");
    
    println!("[CLIENT] Connected!\n");
    println!("[CLIENT] === MUTUAL AUTHENTICATION ===\n");
    
    // Step 1: Send Connect
    println!("[CLIENT] 1. Sending Connect...");
    let connect_msg = AuthMessage::Connect {
        client_did: client_identity.did.clone(),
        client_pubkey: client_identity.public_key.as_bytes().to_vec(),
        pool_commitment,
    };
    write_auth_message(&mut stream, &connect_msg).expect("Failed to send Connect");
    
    // Step 2: Receive Challenge + Server Proof
    println!("[CLIENT] 2. Receiving Challenge...");
    let challenge_msg = read_auth_message(&mut stream).expect("Failed to read Challenge");
    
    let (challenge, server_proof) = match challenge_msg {
        AuthMessage::Challenge { challenge, server_proof } => (challenge, server_proof),
        AuthMessage::Rejected => {
            eprintln!("[CLIENT] ✗ Rejected by server");
            std::process::exit(1);
        }
        _ => {
            eprintln!("[CLIENT] ✗ Unexpected message");
            std::process::exit(1);
        }
    };
    
    println!("[CLIENT]    Challenge nonce: {}", hex::encode(&challenge.nonce[..8]));
    println!("[CLIENT]    Server DID: {}", challenge.server_did.short());
    
    // Step 3: Verify server proof (MUTUAL AUTHENTICATION)
    println!("[CLIENT] 3. Verifying server identity...");
    let server_pubkey = PublicKey::from_bytes(&server_proof.server_pubkey)
        .expect("Invalid server pubkey");
    
    // Verify server DID matches pubkey
    let expected_server_did = Did::from_pubkey(&server_pubkey);
    if !constant_time_compare(expected_server_did.0.as_bytes(), challenge.server_did.0.as_bytes()) {
        eprintln!("[CLIENT] ✗ Server DID mismatch!");
        std::process::exit(1);
    }
    
    // Verify server signature
    let challenge_bytes = challenge.to_signable_bytes();
    let server_sig = DetachedSignature::from_bytes(&server_proof.signature)
        .expect("Invalid server signature format");
    
    if verify_detached_signature(&server_sig, &challenge_bytes, &server_pubkey).is_err() {
        eprintln!("[CLIENT] ✗ Server signature invalid!");
        std::process::exit(1);
    }
    println!("[CLIENT]    ✓ Server identity verified");
    
    // Step 4: Sign challenge
    println!("[CLIENT] 4. Signing challenge...");
    let client_sig = client_identity.sign(&challenge_bytes);
    
    let response_msg = AuthMessage::Response { signature: client_sig };
    write_auth_message(&mut stream, &response_msg).expect("Failed to send Response");
    
    // Step 5: Send elaboration
    println!("[CLIENT] 5. Sending elaboration...");
    let elaborate_text = format!(
        "Client {} connecting to {} at timestamp {} for pool {}",
        client_identity.did.short(),
        server_addr,
        current_timestamp(),
        pool
    );
    
    let elaborate_msg = AuthMessage::Elaborate { text: elaborate_text };
    write_auth_message(&mut stream, &elaborate_msg).expect("Failed to send Elaborate");
    
    // Step 6: Receive result
    println!("[CLIENT] 6. Awaiting authentication result...");
    let result_msg = read_auth_message(&mut stream).expect("Failed to read result");
    
    match result_msg {
        AuthMessage::Authenticated { session_token } => {
            println!("[CLIENT]    ✓ AUTHENTICATED");
            println!("[CLIENT]    Session: {}", hex::encode(&session_token[..8]));
        }
        AuthMessage::Rejected => {
            eprintln!("[CLIENT] ✗ Authentication rejected");
            std::process::exit(1);
        }
        _ => {
            eprintln!("[CLIENT] ✗ Unexpected response");
            std::process::exit(1);
        }
    }
    
    println!("\n[CLIENT] === DATA EXCHANGE TEST ===\n");
    
    stream.set_nonblocking(true).ok();
    
    let test_messages = vec![
        b"Hello from authenticated client!".to_vec(),
        b"Testing secure channel".to_vec(),
    ];
    
    for (i, msg) in test_messages.iter().enumerate() {
        println!("[CLIENT] Sending message {}: {} bytes", i + 1, msg.len());
        stream.write_all(msg).expect("Write failed");
        
        thread::sleep(Duration::from_millis(100));
        
        let mut buf = [0u8; 1024];
        match stream.read(&mut buf) {
            Ok(n) if &buf[..n] == msg.as_slice() => {
                println!("[CLIENT]    ✓ Echo verified");
            }
            Ok(_) => println!("[CLIENT]    ✗ Echo mismatch"),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                println!("[CLIENT]    (awaiting response)");
            }
            Err(e) => eprintln!("[CLIENT]    Error: {:?}", e),
        }
    }
    
    println!("\n[CLIENT] === TEST COMPLETE ===\n");
}

// ============================================================================
// MAIN
// ============================================================================

fn main() {
    match parse_args() {
        Mode::Server { addr, pool } => run_server(addr, pool),
        Mode::Client { server_addr, pool } => run_client(server_addr, pool),
    }
}
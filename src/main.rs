use std::{
    thread,
    sync::{mpsc::{self, Sender, Receiver}, Arc, Mutex},
    net::{TcpStream, TcpListener},
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

struct TcpInfo {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: String,
}

// Client Actor
struct ClientActor {
    receiver: mpsc::Receiver<ClientMessage>,
    stream: TcpStream,
    peer_addr: String,
}

enum ClientMessage {
    ProcessData(Vec<u8>),
    Shutdown,
}

impl ClientActor {
    fn run(mut self) {
        let mut buffer = [0; 1024];
        
        // Set non-blocking mode for stream to allow checking messages
        self.stream.set_nonblocking(true).expect("Failed to set non-blocking");
        
        loop {
            // Check for messages
            if let Ok(msg) = self.receiver.try_recv() {
                match msg {
                    ClientMessage::ProcessData(data) => {
                        println!("Processing {} bytes: {:02x?}", data.len(), &data);
                        if let Err(e) = self.stream.write_all(&data) {
                            eprintln!("Write error: {:?}", e);
                            break;
                        }
                    }
                    ClientMessage::Shutdown => {
                        println!("Shutting down client {}", self.peer_addr);
                        break;
                    }
                }
            }
            
            // Try to read from socket
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    println!("Client closed: {}", self.peer_addr);
                    break;
                }
                Ok(n) => {
                    let data = buffer[0..n].to_vec();
                    println!("Received {} bytes", n);
                    
                    // Echo back immediately
                    if let Err(e) = self.stream.write_all(&data) {
                        eprintln!("Write error: {:?}", e);
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // No data available, sleep briefly
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => {
                    eprintln!("Read error: {:?}", e);
                    break;
                }
            }
        }
        
        println!("Connection finished: {}", self.peer_addr);
    }
}

#[derive(Clone)]
struct ClientHandle {
    sender: mpsc::Sender<ClientMessage>,
}

impl ClientHandle {
    fn new(stream: TcpStream) -> Self {
        let (sender, receiver) = mpsc::channel();
        
        let peer_addr = stream.peer_addr()
            .map_or_else(|_| "unknown".to_string(), |addr| addr.to_string());
        
        println!("New client actor for: {}", peer_addr);
        
        let actor = ClientActor {
            receiver,
            stream,
            peer_addr,
        };
        
        thread::spawn(move || actor.run());
        
        Self { sender }
    }
    
    fn send_data(&self, data: Vec<u8>) -> Result<(), mpsc::SendError<ClientMessage>> {
        self.sender.send(ClientMessage::ProcessData(data))
    }
    
    fn shutdown(&self) -> Result<(), mpsc::SendError<ClientMessage>> {
        self.sender.send(ClientMessage::Shutdown)
    }
}

// Packet Capture Actor
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
                    println!("Starting packet capture");
                    self.capture_packets();
                }
                CaptureMessage::Stop => {
                    println!("Stopping packet capture");
                    break;
                }
            }
        }
    }
    
    fn capture_packets(&self) {
        // Your existing capture logic
        let devices = Device::list().expect("Failed to list devices");
        let use_loopback = std::env::var("TEST_MODE").is_ok();
        
        let device = if use_loopback {
            devices.iter().find(|d| 
                d.desc.as_ref()
                    .map(|s| s.to_lowercase().contains("loopback"))
                    .unwrap_or(false)
            ).expect("Loopback not found")
        } else {
            devices.iter().find(|d| {
                let desc = d.desc.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();
                desc.contains("wi-fi") || desc.contains("ethernet")
            }).expect("Network adapter not found")
        }.clone();
        
        println!("Capturing on: {} ({})", device.name, 
                 device.desc.as_ref().unwrap_or(&"N/A".to_string()));
        
        let mut cap = Capture::from_device(device)
            .expect("Failed to open device")
            .promisc(true).snaplen(65535).timeout(1000)
            .open().expect("Failed to activate capture");
        
        cap.filter("tcp port 9090", true).expect("Failed to set filter");
        
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    println!("═══════════════════════════════════════");
                    println!("Packet: {} bytes", packet.len());
                    
                    if let Some((tcp_info, payload)) = Self::parse_packet(&packet.data) {
                        println!("{}:{} -> {}:{}", 
                                 tcp_info.src_ip, tcp_info.src_port,
                                 tcp_info.dst_ip, tcp_info.dst_port);
                        println!("Flags: {}", tcp_info.flags);
                        
                        if !payload.is_empty() {
                            println!("Payload: {} bytes", payload.len());
                        }
                    }
                    println!("═══════════════════════════════════════\n");
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => eprintln!("Error capturing: {:?}", e),
            }
        }
    }

    fn parse_packet(packet: &[u8]) -> Option<(TcpInfo, &[u8])> {
        if packet.len() < 4 { return None; }
        
        let mut offset = 4; // Windows loopback header
        
        // IP header
        if packet.len() < offset + 20 { return None; }
        let ip_header_len = ((packet[offset] & 0x0F) * 4) as usize;
        
        // Extract IP addresses
        let src_ip = format!("{}.{}.{}.{}", 
            packet[offset + 12], packet[offset + 13], 
            packet[offset + 14], packet[offset + 15]);
        let dst_ip = format!("{}.{}.{}.{}", 
            packet[offset + 16], packet[offset + 17], 
            packet[offset + 18], packet[offset + 19]);
        
        offset += ip_header_len;
        
        // TCP header
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
// CORE IDENTITY TYPES (from DIAGON)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(pub String);

impl Did {
    pub fn from_pubkey(pk: &PublicKey) -> Self {
        Did(format!("did:diagon:{}", hex::encode(&pk.as_bytes()[..32])))
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
// PROTOCOL MESSAGES (from DIAGON, simplified)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMessage {
    Connect(Did, Vec<u8>, [u8; 32]),  // DID, pubkey, pool_commitment
    Challenge([u8; 32]),                // 32-byte nonce
    Response(Vec<u8>),                  // signature of challenge
    Elaborate(String),                  // elaboration text for auth
    Authenticated,                      // auth successful
    Rejected(String),                   // auth failed with reason
}

// ============================================================================
// TCP FRAMING (from DIAGON)
// ============================================================================

const MAX_MESSAGE_SIZE: usize = 10_000_000;

fn write_auth_message(stream: &mut TcpStream, msg: &AuthMessage) -> io::Result<()> {
    let data = bincode::serialize(msg)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    
    if data.len() > MAX_MESSAGE_SIZE {
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
    
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(ErrorKind::InvalidData, "Message too large"));
    }
    
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    
    bincode::deserialize(&buf)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

// ============================================================================
// AUTHENTICATED CLIENT ACTOR
// ============================================================================

struct AuthClientActor {
    receiver: Receiver<AuthClientMessage>,
    stream: TcpStream,
    peer_addr: String,
    auth_state: AuthState,
    server_identity: Arc<ServerIdentity>,
}

struct AuthState {
    peer_did: Option<Did>,
    peer_pubkey: Option<Vec<u8>>,
    authenticated: bool,
    challenge: Option<[u8; 32]>,
    challenge_time: Option<Instant>,
}

enum AuthClientMessage {
    HandleAuth,
    ProcessData(Vec<u8>),
    Shutdown,
}

impl AuthClientActor {
    fn run(mut self) {
        // First, handle authentication
        match self.handle_authentication() {
            Ok(true) => {
                println!("[AUTH] {} authenticated successfully", self.peer_addr);
                // Transition to regular client actor behavior
                self.run_authenticated();
            }
            Ok(false) => {
                println!("[AUTH] {} authentication incomplete", self.peer_addr);
            }
            Err(e) => {
                println!("[AUTH] {} authentication failed: {}", self.peer_addr, e);
                let _ = write_auth_message(&mut self.stream, &AuthMessage::Rejected(e.to_string()));
            }
        }
    }
    
    fn handle_authentication(&mut self) -> io::Result<bool> {
        // Set timeout for auth phase
        self.stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        
        // Read initial Connect message
        let connect_msg = read_auth_message(&mut self.stream)?;
        
        match connect_msg {
            AuthMessage::Connect(peer_did, peer_pubkey, peer_pool) => {
                // Validate DID-pubkey binding
                if let Err(e) = self.validate_did_pubkey_binding(&peer_did, &peer_pubkey) {
                    return Err(io::Error::new(ErrorKind::InvalidData, e));
                }
                
                // Validate pool commitment
                if peer_pool != self.server_identity.pool_commitment {
                    return Err(io::Error::new(ErrorKind::PermissionDenied, "Pool mismatch"));
                }
                
                // Generate challenge
                let mut challenge = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut challenge);
                
                self.auth_state.peer_did = Some(peer_did);
                self.auth_state.peer_pubkey = Some(peer_pubkey);
                self.auth_state.challenge = Some(challenge);
                self.auth_state.challenge_time = Some(Instant::now());
                
                // Send challenge
                write_auth_message(&mut self.stream, &AuthMessage::Challenge(challenge))?;
                
                // Wait for response (signature)
                let response_msg = read_auth_message(&mut self.stream)?;
                
                match response_msg {
                    AuthMessage::Response(signature) => {
                        // Verify signature
                        if !self.verify_challenge_response(&signature)? {
                            return Err(io::Error::new(ErrorKind::PermissionDenied, "Invalid signature"));
                        }
                        
                        // Request elaboration
                        let elaborate_msg = read_auth_message(&mut self.stream)?;
                        
                        match elaborate_msg {
                            AuthMessage::Elaborate(text) => {
                                // Validate elaboration
                                if text.len() < 20 {
                                    return Err(io::Error::new(ErrorKind::InvalidData, 
                                        "Elaboration too short (min 20 chars)"));
                                }
                                
                                // Check challenge timeout (30 seconds for elaboration)
                                if let Some(challenge_time) = self.auth_state.challenge_time {
                                    if challenge_time.elapsed() > Duration::from_secs(30) {
                                        return Err(io::Error::new(ErrorKind::TimedOut, 
                                            "Challenge expired"));
                                    }
                                }
                                
                                // Authentication successful
                                self.auth_state.authenticated = true;
                                write_auth_message(&mut self.stream, &AuthMessage::Authenticated)?;
                                
                                println!("[AUTH] {} elaborated: {}", 
                                    self.auth_state.peer_did.as_ref().unwrap().0, 
                                    &text[..50.min(text.len())]);
                                
                                Ok(true)
                            }
                            _ => Err(io::Error::new(ErrorKind::InvalidData, "Expected elaboration"))
                        }
                    }
                    _ => Err(io::Error::new(ErrorKind::InvalidData, "Expected response"))
                }
            }
            _ => Err(io::Error::new(ErrorKind::InvalidData, "Expected connect"))
        }
    }
    
    fn run_authenticated(mut self) {
        // Switch to non-blocking for main operation
        self.stream.set_nonblocking(true).expect("Failed to set non-blocking");
        self.stream.set_read_timeout(None).ok();
        
        let mut buffer = [0; 1024];
        
        println!("[AUTHENTICATED] {} entering main loop", 
            self.auth_state.peer_did.as_ref().unwrap().0);
        
        loop {
            // Check for control messages
            if let Ok(msg) = self.receiver.try_recv() {
                match msg {
                    AuthClientMessage::ProcessData(data) => {
                        println!("[DATA] Sending {} bytes to {}", 
                            data.len(), self.peer_addr);
                        if let Err(e) = self.stream.write_all(&data) {
                            eprintln!("[ERROR] Write failed: {:?}", e);
                            break;
                        }
                    }
                    AuthClientMessage::Shutdown => {
                        println!("[SHUTDOWN] {}", self.peer_addr);
                        break;
                    }
                    _ => {}
                }
            }
            
            // Try to read application data
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    println!("[CLOSED] {}", self.peer_addr);
                    break;
                }
                Ok(n) => {
                    let data = buffer[0..n].to_vec();
                    println!("[RECV] {} bytes from {}", n, self.peer_addr);
                    
                    // Echo back
                    if let Err(e) = self.stream.write_all(&data) {
                        eprintln!("[ERROR] Echo write failed: {:?}", e);
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    eprintln!("[ERROR] Read failed: {:?}", e);
                    break;
                }
            }
        }
        
        println!("[DISCONNECTED] {}", self.peer_addr);
    }
    
    fn validate_did_pubkey_binding(&self, did: &Did, pubkey_bytes: &[u8]) -> Result<(), String> {
        let pubkey = PublicKey::from_bytes(pubkey_bytes)
            .map_err(|_| "Invalid public key bytes")?;
        
        if Did::from_pubkey(&pubkey) != *did {
            return Err("DID does not match public key".into());
        }
        
        Ok(())
    }
    
    fn verify_challenge_response(&self, signature: &[u8]) -> io::Result<bool> {
        let challenge = self.auth_state.challenge
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "No active challenge"))?;
        
        let pubkey_bytes = self.auth_state.peer_pubkey.as_ref()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "No peer pubkey"))?;
        
        let pubkey = PublicKey::from_bytes(pubkey_bytes)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        
        let sig = DetachedSignature::from_bytes(signature)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        
        Ok(verify_detached_signature(&sig, &challenge, &pubkey).is_ok())
    }
}

// ============================================================================
// AUTHENTICATED CLIENT HANDLE
// ============================================================================

#[derive(Clone)]
struct AuthClientHandle {
    sender: Sender<AuthClientMessage>,
}

impl AuthClientHandle {
    fn new(stream: TcpStream, server_identity: Arc<ServerIdentity>) -> Self {
        let (sender, receiver) = mpsc::channel();
        
        let peer_addr = stream.peer_addr()
            .map_or_else(|_| "unknown".to_string(), |addr| addr.to_string());
        
        println!("[NEW CONNECTION] {}", peer_addr);
        
        let actor = AuthClientActor {
            receiver,
            stream,
            peer_addr,
            auth_state: AuthState {
                peer_did: None,
                peer_pubkey: None,
                authenticated: false,
                challenge: None,
                challenge_time: None,
            },
            server_identity,
        };
        
        thread::spawn(move || actor.run());
        
        Self { sender }
    }
    
    fn send_data(&self, data: Vec<u8>) -> Result<(), mpsc::SendError<AuthClientMessage>> {
        self.sender.send(AuthClientMessage::ProcessData(data))
    }
    
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
    pool_commitment: [u8; 32],
    nonce_counter: Mutex<u64>,
}

impl ServerIdentity {
    fn load_or_create(addr: &str) -> io::Result<Arc<Self>> {
        create_dir_all("db").ok();
        
        let addr_hash = hex::encode(&sha256(addr.as_bytes())[..8]);
        let identity_path = format!("db/identity_{}.cbor", addr_hash);
        
        let (pk, sk, did) = if Path::new(&identity_path).exists() {
            // Load existing identity
            let data = std::fs::read(&identity_path)?;
            if let Ok((pk_bytes, sk_bytes, did)) = 
                serde_cbor::from_slice::<(Vec<u8>, Vec<u8>, Did)>(&data) {
                if let (Ok(pk), Ok(sk)) = (
                    PublicKey::from_bytes(&pk_bytes),
                    SecretKey::from_bytes(&sk_bytes)
                ) {
                    if Did::from_pubkey(&pk) == did {
                        (pk, sk, did)
                    } else {
                        let (pk, sk) = keypair();
                        let did = Did::from_pubkey(&pk);
                        (pk, sk, did)
                    }
                } else {
                    let (pk, sk) = keypair();
                    let did = Did::from_pubkey(&pk);
                    (pk, sk, did)
                }
            } else {
                let (pk, sk) = keypair();
                let did = Did::from_pubkey(&pk);
                (pk, sk, did)
            }
        } else {
            // Create new identity
            let (pk, sk) = keypair();
            let did = Did::from_pubkey(&pk);
            
            // Save identity
            let identity = (pk.as_bytes().to_vec(), sk.as_bytes().to_vec(), did.clone());
            if let Ok(file) = File::create(&identity_path) {
                let _ = serde_cbor::to_writer(BufWriter::new(file), &identity);
            }
            
            (pk, sk, did)
        };
        
        println!("[IDENTITY] Server DID: {}", did.0);
        
        Ok(Arc::new(Self {
            did,
            public_key: pk,
            secret_key: sk,
            pool_commitment: [0; 32],  // Will be set with set_pool()
            nonce_counter: Mutex::new(0),
        }))
    }
    
    fn set_pool(&mut self, passphrase: &str) {
        self.pool_commitment = sha256(passphrase.as_bytes());
        println!("[POOL] Set to: {}", hex::encode(&self.pool_commitment[..8]));
    }
    
    fn generate_cid(&self, data: &[u8]) -> Cid {
        let mut counter = self.nonce_counter.lock().unwrap();
        *counter += 1;
        Cid::new(data, &self.did, *counter)
    }
    
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        detached_sign(data, &self.secret_key).as_bytes().to_vec()
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

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Replace entire fn main() starting at line 713

// ============================================================================
// AUTHENTICATED SERVER MAIN
// ============================================================================

// Replace entire main() function (starting at line 713) with the following:

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
        // Default: server mode
        let addr = "0.0.0.0:9090".to_string();
        let pool = "default_pool".to_string();
        return Mode::Server { addr, pool };
    }
    
    match args[1].as_str() {
        "server" => {
            let addr = args.get(2).cloned()
                .unwrap_or_else(|| "0.0.0.0:9090".to_string());
            let pool = args.get(3).cloned()
                .unwrap_or_else(|| "default_pool".to_string());
            Mode::Server { addr, pool }
        }
        "client" => {
            if args.len() < 3 {
                eprintln!("Usage: {} client <server_addr> [pool]", args[0]);
                std::process::exit(1);
            }
            let server_addr = args[2].clone();
            let pool = args.get(3).cloned()
                .unwrap_or_else(|| "default_pool".to_string());
            Mode::Client { server_addr, pool }
        }
        _ => {
            eprintln!("Unknown mode: {}", args[1]);
            eprintln!("Usage: {} [server|client] ...", args[0]);
            std::process::exit(1);
        }
    }
}

// ============================================================================
// SERVER MODE
// ============================================================================

fn run_server(addr: String, pool: String) {
    // Initialize server identity
    let mut server_identity = ServerIdentity::load_or_create(&addr)
        .expect("Failed to load identity");
    
    // ========================================================================
    // STARTUP ASSERTIONS - Verify service operational state
    // ========================================================================
    
    println!("\n[STARTUP] Running operational checks...\n");
    
    // Assert 1: Identity file persistence
    let addr_hash = hex::encode(&sha256(addr.as_bytes())[..8]);
    let identity_path = format!("db/identity_{}.cbor", addr_hash);
    assert!(Path::new(&identity_path).exists(), 
        "[ASSERT FAILED] Identity file not persisted: {}", identity_path);
    println!("✓ Identity persistence verified: {}", identity_path);
    
    // Assert 2: Identity file can be reloaded and matches current identity
    let reloaded = ServerIdentity::load_or_create(&addr)
        .expect("Failed to reload identity");
    assert_eq!(server_identity.did, reloaded.did,
        "[ASSERT FAILED] Reloaded DID doesn't match original");
    assert_eq!(server_identity.public_key.as_bytes(), reloaded.public_key.as_bytes(),
        "[ASSERT FAILED] Reloaded public key doesn't match original");
    println!("✓ Identity reload consistency verified");
    
    // Assert 3: DID-Pubkey binding is valid
    let derived_did = Did::from_pubkey(&server_identity.public_key);
    assert_eq!(derived_did, server_identity.did,
        "[ASSERT FAILED] DID doesn't match public key derivation");
    println!("✓ DID-Pubkey binding verified: {}", server_identity.did.0);
    
    // Set pool commitment from passphrase
    Arc::get_mut(&mut server_identity)
        .expect("Failed to get mutable reference")
        .set_pool(&pool);
    
    // Assert 4: Pool commitment is set correctly
    let expected_pool = sha256(pool.as_bytes());
    assert_eq!(server_identity.pool_commitment, expected_pool,
        "[ASSERT FAILED] Pool commitment mismatch");
    assert_ne!(server_identity.pool_commitment, [0u8; 32],
        "[ASSERT FAILED] Pool commitment still default zeros after set_pool");
    println!("✓ Pool commitment set: {}", hex::encode(&server_identity.pool_commitment[..8]));
    
    // Assert 5: Nonce counter initialized correctly
    {
        let nonce = server_identity.nonce_counter.lock().unwrap();
        assert_eq!(*nonce, 0, "[ASSERT FAILED] Nonce counter not initialized to 0");
    }
    println!("✓ Nonce counter initialized to 0");
    
    // Assert 6: CID generation works and produces unique values
    let test_data = b"test_content_for_cid_generation";
    let cid1 = server_identity.generate_cid(test_data);
    let cid2 = server_identity.generate_cid(test_data);
    assert_ne!(cid1, cid2, "[ASSERT FAILED] CIDs should be unique (nonce increments)");
    {
        let nonce = server_identity.nonce_counter.lock().unwrap();
        assert_eq!(*nonce, 2, "[ASSERT FAILED] Nonce counter should be 2 after 2 generations");
    }
    println!("✓ CID generation functional: {} != {} (nonce-based uniqueness)", 
        cid1.short(), cid2.short());
    
    // Assert 7: Signature generation works
    let test_message = b"test_message_for_signing_verification";
    let signature = server_identity.sign(test_message);
    assert!(!signature.is_empty(), "[ASSERT FAILED] Signature is empty");
    
    // Validate signature can be parsed
    let sig_parsed = DetachedSignature::from_bytes(&signature)
        .expect("[ASSERT FAILED] Cannot parse generated signature");
    assert_eq!(signature.len(), sig_parsed.as_bytes().len(),
        "[ASSERT FAILED] Signature length mismatch after parse");
    println!("✓ Signature generation functional: {} bytes", signature.len());
    
    // Assert 8: Signature verification works (core auth pattern)
    assert!(verify_detached_signature(&sig_parsed, test_message, &server_identity.public_key).is_ok(),
        "[ASSERT FAILED] Self-signature verification failed - crypto broken");
    println!("✓ Signature verification functional");
    
    // Assert 9: Challenge-response pattern components work correctly
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    let challenge_sig = server_identity.sign(&challenge);
    let challenge_sig_obj = DetachedSignature::from_bytes(&challenge_sig)
        .expect("[ASSERT FAILED] Cannot parse challenge signature");
    assert!(verify_detached_signature(&challenge_sig_obj, &challenge, &server_identity.public_key).is_ok(),
        "[ASSERT FAILED] Challenge-response verification failed");
    
    // Verify wrong challenge fails
    let mut wrong_challenge = challenge;
    wrong_challenge[0] ^= 0xFF;
    assert!(verify_detached_signature(&challenge_sig_obj, &wrong_challenge, &server_identity.public_key).is_err(),
        "[ASSERT FAILED] Signature verified with wrong challenge - crypto insecure");
    println!("✓ Challenge-response pattern verified (correct passes, wrong fails)");
    
    // Assert 10: AuthMessage serialization works (protocol correctness)
    let test_connect = AuthMessage::Connect(
        server_identity.did.clone(),
        server_identity.public_key.as_bytes().to_vec(),
        server_identity.pool_commitment
    );
    let serialized = bincode::serialize(&test_connect)
        .expect("[ASSERT FAILED] Cannot serialize AuthMessage::Connect");
    assert!(serialized.len() > 0, "[ASSERT FAILED] Serialized message is empty");
    
    let deserialized: AuthMessage = bincode::deserialize(&serialized)
        .expect("[ASSERT FAILED] Cannot deserialize AuthMessage::Connect");
    match deserialized {
        AuthMessage::Connect(did, pk, pool) => {
            assert_eq!(did, server_identity.did, 
                "[ASSERT FAILED] Deserialized DID mismatch");
            assert_eq!(pk, server_identity.public_key.as_bytes(), 
                "[ASSERT FAILED] Deserialized pubkey mismatch");
            assert_eq!(pool, server_identity.pool_commitment, 
                "[ASSERT FAILED] Deserialized pool commitment mismatch");
        }
        _ => panic!("[ASSERT FAILED] Deserialized wrong AuthMessage variant"),
    }
    println!("✓ AuthMessage serialization verified ({} bytes)", serialized.len());
    
    // Assert 11: Other AuthMessage variants serialize correctly
    let challenge_msg = AuthMessage::Challenge(challenge);
    let response_msg = AuthMessage::Response(signature.clone());
    let elaborate_msg = AuthMessage::Elaborate("Test elaboration text".to_string());
    
    for msg in [challenge_msg, response_msg, elaborate_msg, 
                AuthMessage::Authenticated, 
                AuthMessage::Rejected("test".to_string())] {
        let ser = bincode::serialize(&msg)
            .expect("[ASSERT FAILED] Cannot serialize AuthMessage variant");
        let _deser: AuthMessage = bincode::deserialize(&ser)
            .expect("[ASSERT FAILED] Cannot deserialize AuthMessage variant");
    }
    println!("✓ All AuthMessage variants serializable");
    
    println!("\n[✓✓✓] All {} startup assertions passed - service operational\n", 11);
    
    // ========================================================================
    
    // Start packet capture if desired
    if std::env::var("CAPTURE").is_ok() {
        let capture_handle = CaptureHandle::new();
        capture_handle.start().expect("Failed to start capture");
        println!("[CAPTURE] Packet capture started");
    }
    
    // Start TCP listener
    let listener = TcpListener::bind(&addr).expect("Failed to bind");
    println!("[SERVER] Listening on {} (pool: {})", addr, &pool);
    println!("[SERVER] Server DID: {}", server_identity.did.0);
    println!("[SERVER] Pool commitment: {}", hex::encode(&server_identity.pool_commitment[..16]));
    
    // Store authenticated client handles
    let clients = Arc::new(Mutex::new(Vec::<AuthClientHandle>::new()));
    
    // Accept loop
    for stream_result in listener.incoming() {
        if let Ok(stream) = stream_result {
            let handle = AuthClientHandle::new(stream, Arc::clone(&server_identity));
            clients.lock().unwrap().push(handle);
        }
    }
}

// ============================================================================
// CLIENT MODE - Test Client
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
            // Load existing identity
            let data = std::fs::read(identity_path)?;
            if let Ok((pk_bytes, sk_bytes, did)) = 
                serde_cbor::from_slice::<(Vec<u8>, Vec<u8>, Did)>(&data) {
                if let (Ok(pk), Ok(sk)) = (
                    PublicKey::from_bytes(&pk_bytes),
                    SecretKey::from_bytes(&sk_bytes)
                ) {
                    if Did::from_pubkey(&pk) == did {
                        (pk, sk, did)
                    } else {
                        let (pk, sk) = keypair();
                        let did = Did::from_pubkey(&pk);
                        (pk, sk, did)
                    }
                } else {
                    let (pk, sk) = keypair();
                    let did = Did::from_pubkey(&pk);
                    (pk, sk, did)
                }
            } else {
                let (pk, sk) = keypair();
                let did = Did::from_pubkey(&pk);
                (pk, sk, did)
            }
        } else {
            // Create new identity
            let (pk, sk) = keypair();
            let did = Did::from_pubkey(&pk);
            
            // Save identity
            let identity = (pk.as_bytes().to_vec(), sk.as_bytes().to_vec(), did.clone());
            if let Ok(file) = File::create(identity_path) {
                let _ = serde_cbor::to_writer(BufWriter::new(file), &identity);
            }
            
            (pk, sk, did)
        };
        
        Ok(Self {
            did,
            public_key: pk,
            secret_key: sk,
        })
    }
    
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        detached_sign(data, &self.secret_key).as_bytes().to_vec()
    }
}

fn run_client(server_addr: String, pool: String) {
    println!("\n[CLIENT] Initializing test client...\n");
    
    // Load/create client identity
    let client_identity = ClientIdentity::load_or_create()
        .expect("Failed to load client identity");
    
    println!("[CLIENT] Client DID: {}", client_identity.did.0);
    
    // Compute pool commitment
    let pool_commitment = sha256(pool.as_bytes());
    println!("[CLIENT] Pool: {} (commitment: {})", pool, hex::encode(&pool_commitment[..8]));
    
    // Connect to server
    println!("[CLIENT] Connecting to {}...", server_addr);
    let mut stream = TcpStream::connect(&server_addr)
        .expect("Failed to connect to server");
    
    println!("[CLIENT] Connected!\n");
    
    // Set timeout for auth phase
    stream.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("Failed to set read timeout");
    
    // ========================================================================
    // AUTHENTICATION HANDSHAKE
    // ========================================================================
    
    println!("[CLIENT] === AUTHENTICATION HANDSHAKE ===\n");
    
    // Step 1: Send Connect message
    println!("[CLIENT] Step 1: Sending Connect message...");
    let connect_msg = AuthMessage::Connect(
        client_identity.did.clone(),
        client_identity.public_key.as_bytes().to_vec(),
        pool_commitment,
    );
    write_auth_message(&mut stream, &connect_msg)
        .expect("Failed to send Connect");
    println!("[CLIENT]   → Sent DID and pool commitment");
    
    // Step 2: Receive Challenge
    println!("\n[CLIENT] Step 2: Waiting for Challenge...");
    let challenge_msg = read_auth_message(&mut stream)
        .expect("Failed to read Challenge");
    
    let challenge = match challenge_msg {
        AuthMessage::Challenge(c) => {
            println!("[CLIENT]   ← Received challenge: {}", hex::encode(&c[..8]));
            c
        }
        AuthMessage::Rejected(reason) => {
            eprintln!("[CLIENT] ✗ Authentication rejected: {}", reason);
            std::process::exit(1);
        }
        _ => {
            eprintln!("[CLIENT] ✗ Unexpected message, expected Challenge");
            std::process::exit(1);
        }
    };
    
    // Step 3: Sign challenge and send Response
    println!("\n[CLIENT] Step 3: Signing challenge...");
    let signature = client_identity.sign(&challenge);
    println!("[CLIENT]   Signature: {} bytes", signature.len());
    
    let response_msg = AuthMessage::Response(signature);
    write_auth_message(&mut stream, &response_msg)
        .expect("Failed to send Response");
    println!("[CLIENT]   → Sent signature");
    
    // Step 4: Send Elaborate message
    println!("\n[CLIENT] Step 4: Sending elaboration...");
    let elaborate_text = format!(
        "Test client connection at {} - DID: {} - Pool: {} - Testing authentication flow with post-quantum signatures",
        current_timestamp(),
        &client_identity.did.0[..40],
        &pool
    );
    let elaborate_msg = AuthMessage::Elaborate(elaborate_text.clone());
    write_auth_message(&mut stream, &elaborate_msg)
        .expect("Failed to send Elaborate");
    println!("[CLIENT]   → Sent elaboration ({} chars)", elaborate_text.len());
    
    // Step 5: Receive final authentication result
    println!("\n[CLIENT] Step 5: Waiting for authentication result...");
    let auth_result = read_auth_message(&mut stream)
        .expect("Failed to read auth result");
    
    match auth_result {
        AuthMessage::Authenticated => {
            println!("[CLIENT]   ✓ AUTHENTICATED!\n");
        }
        AuthMessage::Rejected(reason) => {
            eprintln!("[CLIENT]   ✗ REJECTED: {}", reason);
            std::process::exit(1);
        }
        _ => {
            eprintln!("[CLIENT]   ✗ Unexpected response");
            std::process::exit(1);
        }
    }
    
    println!("[CLIENT] === AUTHENTICATION COMPLETE ===\n");
    
    // ========================================================================
    // POST-AUTH DATA EXCHANGE
    // ========================================================================
    
    // Switch to non-blocking for data exchange
    stream.set_nonblocking(true).expect("Failed to set non-blocking");
    stream.set_read_timeout(None).ok();
    
    println!("[CLIENT] === TESTING DATA EXCHANGE ===\n");
    
    // Send test messages
    let test_messages = vec![
        b"Hello from test client!".to_vec(),
        b"Message 2: Testing echo".to_vec(),
        b"Message 3: Final test".to_vec(),
    ];
    
    for (i, msg) in test_messages.iter().enumerate() {
        println!("[CLIENT] Sending message {}: {} bytes", i + 1, msg.len());
        stream.write_all(msg).expect("Failed to write message");
        
        // Wait for echo response
        thread::sleep(Duration::from_millis(100));
        
        let mut buf = [0u8; 1024];
        match stream.read(&mut buf) {
            Ok(n) => {
                println!("[CLIENT] Received echo: {} bytes", n);
                if &buf[..n] == msg.as_slice() {
                    println!("[CLIENT]   ✓ Echo matches sent data");
                } else {
                    println!("[CLIENT]   ✗ Echo mismatch!");
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                println!("[CLIENT]   (No immediate response)");
            }
            Err(e) => {
                eprintln!("[CLIENT]   Read error: {:?}", e);
            }
        }
        
        println!();
        thread::sleep(Duration::from_millis(500));
    }
    
    println!("[CLIENT] === TEST COMPLETE ===\n");
    println!("[CLIENT] Closing connection...");
    drop(stream);
    println!("[CLIENT] Done.");
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

fn main() {
    let mode = parse_args();
    
    match mode {
        Mode::Server { addr, pool } => {
            run_server(addr, pool);
        }
        Mode::Client { server_addr, pool } => {
            run_client(server_addr, pool);
        }
    }
}
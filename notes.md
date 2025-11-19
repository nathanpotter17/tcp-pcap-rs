# TCP PCAP & STM

```
"Civilization advances by extending the number of important
operations which we can perform without thinking about them."

- Alfred North Whitehead
```

# The Actor Model

```rust
// The actor recipe by Alice Ryhl
struct MyActor {
    receiver: mpsc::Receiver<ActorMessage>,
    connection: TcpStream,
}

impl MyActor {
    async fn handle_message() -> io::Result<()> {
        match msg {
            ActorMessage::SendMessage { message, respond_to } => {
                self.connection.write_all(message.as_bytes()).await?;
                let response = self.connection.read_u32().await?;
                let _ = respond_to.send(response);
                Ok(())
            }
        }
    }
}

async fn run_my_actor(mut Actor: MyActor) {
    while let Some(msg) = actor.receiver.recv.await {
        actor.handle_message(msg).await.unwrap();
    }
}

enum ActorMessage {
    SendMessage {
        message: String,
        respond_to: oneshot::Sender<u32>,
    }
}

#[derive(Clone)]
pub struct MyActorHandle {
    sender: mpsc::Sender<ActorMessage>,
}

impl MyActorHandle {
    pub fn new(conn: TcpStream) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = MyActor::new(receiver, conn);
        tokio::spawn(run_my_actor(actor));

        Self { sender }
    }

    pub async fn send_message(&self, msg: String) -> u32 {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::SendMessage {
            respond_to: send,
            message: msg,
        };

        // Ignore send failurs. If the send fails, so does the recv.await
        // below. No need to check fail twice.
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed");
    }
}
```

# Databases as Values - Rich Hickey

```
"Time is atomic, epochal succession of process events"
```

```
"There is a becoming of continuity, but no continuity of becoming"
```

People call filesystems, key:value stores, and etc 'databases', however, they are
quite the opposite. Databases are about leveraging data - if there is no leverage,
it simply is a 'data store'.

Firstly, State:
- Must be organized to support queries
- Sorted set of facts
    - Maintaining sorted sets has been proven to be wasted space and ptime
- Key idea is to accumulate change and novelty in memory, and periodically
merge that state onto disk. Use persistent trees.
- Collect, sort, flatten, diff, merge.

Secondly, Memory Index:
- Persistent sorted set
- Large internal nodes
- Pluggable comparators
- 2 sorts always maintained
    - EAVT, AEVT
        - plus AVET, VAET

Thirdly, Storage:
- Log of tx asserts/retracts (in tree)
- Various covering indexes (trees)
- Storage requirements
    - Data segment values (K -> V)
    - Atoms (consistent read)
    - Pods (conditional put)

Finally, Process:
- Assert/retract can't express transformation
- transaction function:
    - (f db & args) -> tx-data
- tx-data: assert|retract|(tx-fn args...)
- Expand/splice until all asserts/retracts

With this functional rep. we can represent any process transformation:
- Assert, Retract, or composite operation, which are all F(DB) + arguments -> tx-data

Additionally, Transactor is an independent process:
- Accepts transactions
    - expands, applies, logs, broadcasts (reader loop)
- Cannot be root based if using epochal time model for new state mapping
- Periodic indexing, background thread
- Indexing creates garbage
    - Storage GC

Additionally, Peers:
- Peers directly access storage service directly
- Have own query engine
- have live mem index and merging
- two-tier cache
    - segments (on/off heap)
    - Datoms w/ object values (on heap)

DB Simplicity
- Epochal state
    - coordination only for process
- Same query, same results: stable bases
- Tx's well defined
    - functional accretion

# STMs - Rich Hickey

Uniform State Transistion Model
- 'change-state' reference function [args*]
- function will be passed current state of the reference (plus any args)
- return value of function will be the next state of the reference
- snapshot of 'current' state always available with de-ref
- No user locking, and no deadlocks

This means we are afforded a 'Persistent Edit', where
- New value is function of the old
- shares immutable structure
- doesnt impede any readers
- Edit is not impeded by any readers

Next, our new version is just an Atomic State transistion.
- Always coordinated: Anytime someone dereferences this AFTER the atomic state transistion, readers will see the new value.
    - Multiple semantics
- Next dereference sees the new value
- Consumers of values are unaffected

As of Refs and Transactions
- Refs can only be changed within a transaction.
- All changes are Atomic and Isolated
    - All - or - None change model (atomicity)
    whereby every change to a ref made within a tx
    occurs or none do at all
    - No tx sees the effects of any other tx's while
    it is running
- Transactions are speculative (You May Not Win, Retry Limit, and thus, no side effects)

Gotchas
- Read tracking is a faulty was of trying to solve the problem of well synced STMs
- HashMaps DO NOT preserve ordering!

Implementation - STM
- Not a lock-free spinning optimistic design...
- Uses locks, wait/notify to avoid churn
- Deadlock detection + barging
- One timestamp CAS is only global resource
- No read tracking
- Course grained orientation
    - Refs + persistent data structures
- Readers don't impede writers/readers, writers

References to Immutable Values is Key!

Another STM: Agentic State
- Each agent manages independent state
- state changes through actions, which are ordinary functions (state=>new-state)
- actions are dispatched using send or send off which return immediately.
- actions occur **async** on thread-pool threads
- only one action per agent happens at a time, mailbox queue - serial processing.

Agents State
- Agent state always accessible, via deref/A,
but may not reflect all actions.
- Any dispatches made during an action are held until **after** the state
- Agents coordinate with tx's - any dispatches made during a transaction are held until
it commits
- Agents are not Actors (Erlang/Scala)

# Actor Governance

```rust
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{File, OpenOptions},
    io::{self, Write, Read, BufWriter, ErrorKind},
    net::{TcpListener, TcpStream, SocketAddr, ToSocketAddrs},
    sync::{Arc, RwLock, atomic::{AtomicU64, AtomicBool, Ordering}, mpsc::{self, Sender, Receiver}},
    thread,
    time::{SystemTime, UNIX_EPOCH, Duration, Instant},
    path::Path,
};

use sha2::{Sha256, Digest};
use pqcrypto_dilithium::dilithium3::*;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
use serde::{Serialize, Deserialize};
use rand::RngCore;
use pcap::{Device, Capture};

// ============================================================================
// CONFIGURATION (unchanged)
// ============================================================================

const MAX_MESSAGE_SIZE: usize = 10_000_000;
pub const PUBLIC_GENESIS: [u8; 32] = [
    0xa9, 0xb5, 0x42, 0x31, 0x6b, 0xf2, 0xbe, 0x58,
    0xa9, 0x0f, 0xa8, 0x68, 0xc9, 0xb1, 0x17, 0xa5,
    0x04, 0x82, 0x11, 0x0a, 0xac, 0xa2, 0x70, 0xe9,
    0x87, 0x0a, 0x8b, 0xb6, 0x5f, 0x51, 0x50, 0x7f,
];
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct Config {
    pub buffer_size: usize,
    pub heartbeat_interval: Duration,
    pub gossip_interval: Duration,
    pub peer_timeout_heartbeats: u32,
    pub connection_timeout: Duration,
    pub trust_decay_rate: f64,
    pub trust_decay_days: u64,
    pub min_trust_for_proposals: f64,
    pub min_trust_for_recommendations: f64,
    pub privacy_threshold_supermajority: f64,
    pub stake_lock_period_secs: u64,
    pub min_elaboration_length: usize,
    pub max_entry_data_size: usize,
    pub max_elaboration_size: usize,
    pub max_timestamp_drift_secs: u64,
    pub max_messages_per_minute: u32,
    pub max_proposals_per_hour: u32,
    pub max_elaborations_per_hour: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            buffer_size: 65536,
            heartbeat_interval: Duration::from_secs(30),
            gossip_interval: Duration::from_secs(60),
            peer_timeout_heartbeats: 5,
            connection_timeout: Duration::from_secs(10),
            trust_decay_rate: 0.95,
            trust_decay_days: 7,
            min_trust_for_proposals: 0.4,
            min_trust_for_recommendations: 0.7,
            privacy_threshold_supermajority: 0.75,
            stake_lock_period_secs: 30 * 24 * 3600,
            min_elaboration_length: 20,
            max_entry_data_size: 60_000,
            max_elaboration_size: 10_000,
            max_timestamp_drift_secs: 300,
            max_messages_per_minute: 60,
            max_proposals_per_hour: 10,
            max_elaborations_per_hour: 20,
        }
    }
}

// ============================================================================
// CORE TYPES (unchanged from DIAGON)
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
    fn new(data: &[u8], node_did: &Did) -> Self {
        let nonce = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        Cid(sha256(&[data, &nonce.to_le_bytes(), node_did.0.as_bytes()].concat()))
    }
    
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub cid: Cid,
    pub entry_type: EntryType,
    pub data: Vec<u8>,
    pub creator: Did,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntryType {
    Knowledge { category: String, concept: String, content: String },
    Proposal { text: String },
    Pool { commitment: [u8; 32], name: String },
    Vote { target: Cid, support: bool },
    Prune { target: Cid, reason: String },
    Stake { amount: u64, duration_secs: u64 },
    PrivacyThreshold { plaintext_required: f64, anon_min_trust: f64, anon_min_stake: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub did: Did,
    pub overall_score: f64,
    pub interaction_count: u32,
    pub vote_alignment: f64,
    pub last_updated: u64,
}

impl TrustScore {
    fn new(did: Did) -> Self {
        Self {
            did,
            overall_score: 0.5,
            interaction_count: 0,
            vote_alignment: 0.5,
            last_updated: current_timestamp(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub cid: Cid,
    pub entry_type: EntryType,
    pub proposer: Did,
    pub elaboration: String,
    pub votes_for: HashMap<Did, String>,
    pub votes_against: HashMap<Did, String>,
    pub threshold: i32,
    pub executed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeRecord {
    pub amount: u64,
    pub locked_until: u64,
    pub slashed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyThreshold {
    pub plaintext_required: f64,
    pub anon_min_trust: f64,
    pub anon_min_stake: u64,
}

impl Default for PrivacyThreshold {
    fn default() -> Self {
        Self {
            plaintext_required: 0.5,
            anon_min_trust: 0.6,
            anon_min_stake: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Connect(Did, Vec<u8>, [u8; 32]),
    Challenge([u8; 32]),
    Response(Vec<u8>),
    Elaborate(String),
    Approve(bool, Vec<u8>, u64),
    Propose(Did, Entry, String),
    Vote(Did, Cid, bool, String, Vec<u8>),
    SyncRequest(Did),
    SyncReply(Vec<Entry>),
    Heartbeat(Did),
    RequestCreatorKey(Did),
    CreatorKeyReply(Did, Vec<u8>),
    PoolMembershipAnnouncement { member: Did, pool: [u8; 32], timestamp: u64, signature: Vec<u8> },
    TrustRecommendations { recommender: Did, recommendations: Vec<(Did, f64)>, signature: Vec<u8> },
    StakeAnnouncement { staker: Did, amount: u64, locked_until: u64, signature: Vec<u8> },
    PruneNotification { target: Cid, reason: String, executor: Did, executed_proposal_cid: Cid, signature: Vec<u8> },
}

// ============================================================================
// ACTOR MESSAGES
// ============================================================================

pub enum MainActorMsg {
    // User API commands
    Auth(String),
    Connect(String, Sender<io::Result<()>>),
    Elaborate(String),
    Approve(String),
    Propose(EntryType, String),
    Vote(String, bool, String),
    Stake(u64, u64),
    Status(Sender<NodeStatus>),
    Shutdown,
    
    // Internal coordination
    PeerConnected(Did, Sender<PeerActorMsg>),
    PeerDisconnected(Did),
}

pub enum NetworkActorMsg {
    StartListening(SocketAddr),
    ConnectTo(SocketAddr, Sender<io::Result<()>>),
    Broadcast(Message),
    SendTo(Did, Message),
    Heartbeat,
    Shutdown,
}

pub enum PeerActorMsg {
    HandleMessage(Message),
    SendMessage(Message),
    Disconnect,
}

pub enum GovernanceActorMsg {
    CreateProposal(Did, EntryType, String, Sender<Result<Cid, String>>),
    CastVote(Did, Cid, bool, String),
    CheckThresholds,
    GetProposal(Cid, Sender<Option<Proposal>>),
    GetAllProposals(Sender<Vec<Proposal>>),
}

pub enum TrustActorMsg {
    UpdateTrust(Did, String),
    GetTrust(Did, Sender<f64>),
    DecayTrust,
    GetAllScores(Sender<HashMap<Did, TrustScore>>),
}

pub enum StorageActorMsg {
    SaveEntry(Entry),
    SaveProposal(Proposal),
    SaveTrustScore(TrustScore),
    SaveStake(Did, StakeRecord),
    SavePrivacyThreshold(PrivacyThreshold),
    LoadState(Sender<Option<SavedState>>),
    Persist,
}

pub enum CaptureActorMsg {
    Start(String),
    Stop,
}

// ============================================================================
// VALIDATION MODULE
// ============================================================================

pub struct Validator {
    config: Config,
}

impl Validator {
    fn new(config: Config) -> Self {
        Self { config }
    }
    
    fn validate_entry(&self, entry: &Entry) -> Result<(), String> {
        self.validate_timestamp(entry.timestamp, "Entry")?;
        
        if entry.data.len() > self.config.max_entry_data_size {
            return Err(format!("Entry exceeds {} bytes", self.config.max_entry_data_size));
        }
        
        match &entry.entry_type {
            EntryType::Knowledge { content, .. } if content.len() > 40_000 => 
                Err("Knowledge content too large".into()),
            EntryType::Pool { name, .. } if name.is_empty() || name.len() > 256 => 
                Err("Invalid pool name size".into()),
            _ => Ok(())
        }
    }
    
    fn validate_timestamp(&self, timestamp: u64, context: &str) -> Result<(), String> {
        let now = current_timestamp();
        
        if timestamp < 1704067200 {
            return Err(format!("{}: Timestamp too old", context));
        }
        
        let drift = self.config.max_timestamp_drift_secs;
        if timestamp < now.saturating_sub(drift) || timestamp > now + drift {
            return Err(format!("{}: Timestamp outside acceptable range", context));
        }
        
        Ok(())
    }
    
    fn validate_elaboration(&self, text: &str) -> Result<(), String> {
        if text.len() < self.config.min_elaboration_length {
            return Err(format!("Too short (min {} chars)", self.config.min_elaboration_length));
        }
        if text.len() > self.config.max_elaboration_size {
            return Err(format!("Too long (max {} chars)", self.config.max_elaboration_size));
        }
        Ok(())
    }
    
    fn validate_did_pubkey_binding(&self, did: &Did, pubkey_bytes: &[u8]) -> Result<PublicKey, String> {
        let pubkey = PublicKey::from_bytes(pubkey_bytes)
            .map_err(|_| "Invalid public key bytes")?;
        
        if Did::from_pubkey(&pubkey) != *did {
            return Err("DID does not match public key".into());
        }
        
        Ok(pubkey)
    }
}

// ============================================================================
// RATE LIMITER
// ============================================================================

#[derive(Debug, Clone)]
pub struct RateLimiter {
    message_count: u32,
    proposal_count: u32,
    elaboration_count: u32,
    last_minute_reset: Instant,
    last_hour_reset: Instant,
    config: Config,
}

impl RateLimiter {
    fn new(config: Config) -> Self {
        let now = Instant::now();
        Self {
            message_count: 0,
            proposal_count: 0,
            elaboration_count: 0,
            last_minute_reset: now,
            last_hour_reset: now,
            config,
        }
    }
    
    fn check_and_increment(&mut self, msg_type: MessageType) -> bool {
        let now = Instant::now();
        
        if now.duration_since(self.last_minute_reset) >= Duration::from_secs(60) {
            self.message_count = 0;
            self.last_minute_reset = now;
        }
        
        if now.duration_since(self.last_hour_reset) >= Duration::from_secs(3600) {
            self.proposal_count = 0;
            self.elaboration_count = 0;
            self.last_hour_reset = now;
        }
        
        match msg_type {
            MessageType::Any => {
                if self.message_count >= self.config.max_messages_per_minute {
                    return false;
                }
                self.message_count += 1;
            },
            MessageType::Proposal => {
                if self.proposal_count >= self.config.max_proposals_per_hour {
                    return false;
                }
                self.proposal_count += 1;
            },
            MessageType::Elaboration => {
                if self.elaboration_count >= self.config.max_elaborations_per_hour {
                    return false;
                }
                self.elaboration_count += 1;
            },
        }
        true
    }
}

enum MessageType {
    Any,
    Proposal,
    Elaboration,
}

// ============================================================================
// PEER ACTOR
// ============================================================================

struct PeerActor {
    did: Did,
    pubkey: Option<Vec<u8>>,
    authenticated: bool,
    stream: TcpStream,
    receiver: Receiver<PeerActorMsg>,
    main_tx: Sender<MainActorMsg>,
    rate_limiter: RateLimiter,
    config: Config,
}

impl PeerActor {
    fn new(
        did: Did,
        pubkey: Option<Vec<u8>>,
        authenticated: bool,
        stream: TcpStream,
        receiver: Receiver<PeerActorMsg>,
        main_tx: Sender<MainActorMsg>,
        config: Config,
    ) -> Self {
        Self {
            did,
            pubkey,
            authenticated,
            stream,
            receiver,
            main_tx,
            rate_limiter: RateLimiter::new(config.clone()),
            config,
        }
    }
    
    fn run(mut self) {
        let _ = self.stream.set_nonblocking(true);
        let _ = self.stream.set_read_timeout(Some(Duration::from_secs(1)));
        
        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut read_buffer = Vec::new();
        
        loop {
            // Check for actor messages
            if let Ok(msg) = self.receiver.try_recv() {
                match msg {
                    PeerActorMsg::HandleMessage(message) => {
                        self.handle_protocol_message(message);
                    }
                    PeerActorMsg::SendMessage(message) => {
                        let _ = write_message(&mut self.stream, &message);
                    }
                    PeerActorMsg::Disconnect => {
                        println!("[PEER] {} disconnecting", self.did.0);
                        break;
                    }
                }
            }
            
            // Try to read from socket
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    println!("[PEER] {} connection closed", self.did.0);
                    break;
                }
                Ok(n) => {
                    read_buffer.extend_from_slice(&buffer[..n]);
                    
                    // Try to parse messages from buffer
                    while read_buffer.len() >= 4 {
                        let len = u32::from_be_bytes([
                            read_buffer[0], read_buffer[1], 
                            read_buffer[2], read_buffer[3]
                        ]) as usize;
                        
                        if len > MAX_MESSAGE_SIZE {
                            println!("[PEER] Message too large from {}", self.did.0);
                            break;
                        }
                        
                        if read_buffer.len() >= 4 + len {
                            let msg_bytes = read_buffer[4..4+len].to_vec();
                            read_buffer.drain(..4+len);
                            
                            if let Ok(message) = bincode::deserialize::<Message>(&msg_bytes) {
                                self.handle_protocol_message(message);
                            }
                        } else {
                            break; // Need more data
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    println!("[PEER] Read error from {}: {}", self.did.0, e);
                    break;
                }
            }
        }
        
        // Notify main actor of disconnection
        let _ = self.main_tx.send(MainActorMsg::PeerDisconnected(self.did.clone()));
    }
    
    fn handle_protocol_message(&mut self, message: Message) {
        if !self.rate_limiter.check_and_increment(MessageType::Any) {
            println!("[RATE] Limiting {}", self.did.0);
            return;
        }
        
        // Forward message to appropriate actor via main actor
        // This is simplified - in full impl would route to governance/trust actors
        match message {
            Message::Elaborate(text) => {
                println!("[ELABORATE] From {}: {}", self.did.0, text);
                // Would forward to TrustActor
            }
            Message::Propose(did, entry, elaboration) => {
                println!("[PROPOSE] From {}: {}", did.0, entry.cid.short());
                // Would forward to GovernanceActor
            }
            Message::Vote(did, cid, support, elaboration, signature) => {
                println!("[VOTE] From {} on {}: {}", did.0, cid.short(), support);
                // Would forward to GovernanceActor
            }
            Message::Heartbeat(_) => {
                // Update last_seen in NetworkActor
            }
            _ => {}
        }
    }
}

// ============================================================================
// NETWORK ACTOR
// ============================================================================

struct NetworkActor {
    listener: Option<TcpListener>,
    peers: HashMap<Did, Sender<PeerActorMsg>>,
    receiver: Receiver<NetworkActorMsg>,
    main_tx: Sender<MainActorMsg>,
    config: Config,
    identity: (Did, PublicKey, SecretKey),
    pool_commitment: [u8; 32],
}

impl NetworkActor {
    fn new(
        receiver: Receiver<NetworkActorMsg>,
        main_tx: Sender<MainActorMsg>,
        config: Config,
        identity: (Did, PublicKey, SecretKey),
        pool_commitment: [u8; 32],
    ) -> Self {
        Self {
            listener: None,
            peers: HashMap::new(),
            receiver,
            main_tx,
            config,
            identity,
            pool_commitment,
        }
    }
    
    fn run(mut self) {
        loop {
            // Check for actor messages
            if let Ok(msg) = self.receiver.recv_timeout(Duration::from_millis(100)) {
                match msg {
                    NetworkActorMsg::StartListening(addr) => {
                        match TcpListener::bind(addr) {
                            Ok(listener) => {
                                listener.set_nonblocking(true).ok();
                                self.listener = Some(listener);
                                println!("[NETWORK] Listening on {}", addr);
                            }
                            Err(e) => {
                                println!("[NETWORK] Failed to bind: {}", e);
                            }
                        }
                    }
                    NetworkActorMsg::ConnectTo(addr, reply_tx) => {
                        let result = self.connect_to_peer(addr);
                        let _ = reply_tx.send(result);
                    }
                    NetworkActorMsg::Broadcast(message) => {
                        for (_, peer_tx) in &self.peers {
                            let _ = peer_tx.send(PeerActorMsg::SendMessage(message.clone()));
                        }
                    }
                    NetworkActorMsg::SendTo(did, message) => {
                        if let Some(peer_tx) = self.peers.get(&did) {
                            let _ = peer_tx.send(PeerActorMsg::SendMessage(message));
                        }
                    }
                    NetworkActorMsg::Heartbeat => {
                        let hb = Message::Heartbeat(self.identity.0.clone());
                        for (_, peer_tx) in &self.peers {
                            let _ = peer_tx.send(PeerActorMsg::SendMessage(hb.clone()));
                        }
                    }
                    NetworkActorMsg::Shutdown => {
                        for (_, peer_tx) in &self.peers {
                            let _ = peer_tx.send(PeerActorMsg::Disconnect);
                        }
                        break;
                    }
                }
            }
            
            // Accept new connections
            if let Some(listener) = &self.listener {
                match listener.accept() {
                    Ok((stream, _)) => {
                        self.handle_incoming_connection(stream);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        // No connections ready
                    }
                    Err(e) => {
                        println!("[NETWORK] Accept error: {}", e);
                    }
                }
            }
        }
        
        println!("[NETWORK] Actor shutting down");
    }
    
    fn connect_to_peer(&mut self, addr: SocketAddr) -> io::Result<()> {
        let mut stream = TcpStream::connect_timeout(&addr, self.config.connection_timeout)?;
        stream.set_nodelay(true)?;
        
        // Send Connect message
        let connect_msg = Message::Connect(
            self.identity.0.clone(),
            self.identity.1.as_bytes().to_vec(),
            self.pool_commitment
        );
        write_message(&mut stream, &connect_msg)?;
        
        // Handle challenge-response auth
        let response = read_message(&mut stream)?;
        match response {
            Message::Challenge(challenge) => {
                let signature = detached_sign(&challenge, &self.identity.2);
                write_message(&mut stream, &Message::Response(signature.as_bytes().to_vec()))?;
                
                let auth_result = read_message(&mut stream)?;
                if let Message::Connect(peer_did, peer_pubkey, _) = auth_result {
                    // Spawn peer actor
                    let (peer_tx, peer_rx) = mpsc::channel();
                    self.peers.insert(peer_did.clone(), peer_tx.clone());
                    
                    let peer_actor = PeerActor::new(
                        peer_did.clone(),
                        Some(peer_pubkey),
                        true,
                        stream,
                        peer_rx,
                        self.main_tx.clone(),
                        self.config.clone(),
                    );
                    
                    thread::spawn(move || peer_actor.run());
                    
                    // Notify main actor
                    let _ = self.main_tx.send(MainActorMsg::PeerConnected(peer_did, peer_tx));
                    
                    Ok(())
                } else {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "Auth failed"))
                }
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Expected Challenge"))
        }
    }
    
    fn handle_incoming_connection(&mut self, mut stream: TcpStream) {
        // Read Connect message
        match read_message(&mut stream) {
            Ok(Message::Connect(peer_did, peer_pubkey, peer_commitment)) => {
                if peer_commitment != self.pool_commitment {
                    println!("[NETWORK] Pool mismatch from {}", peer_did.0);
                    return;
                }
                
                // Send challenge
                let mut challenge = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut challenge);
                
                if write_message(&mut stream, &Message::Challenge(challenge)).is_err() {
                    return;
                }
                
                // Verify response
                match read_message(&mut stream) {
                    Ok(Message::Response(signature)) => {
                        if verify_signature(&challenge, &signature, &peer_pubkey) {
                            // Send our identity
                            let _ = write_message(&mut stream, &Message::Connect(
                                self.identity.0.clone(),
                                self.identity.1.as_bytes().to_vec(),
                                self.pool_commitment
                            ));
                            
                            // Spawn peer actor
                            let (peer_tx, peer_rx) = mpsc::channel();
                            self.peers.insert(peer_did.clone(), peer_tx.clone());
                            
                            let peer_actor = PeerActor::new(
                                peer_did.clone(),
                                Some(peer_pubkey),
                                true,
                                stream,
                                peer_rx,
                                self.main_tx.clone(),
                                self.config.clone(),
                            );
                            
                            thread::spawn(move || peer_actor.run());
                            
                            // Notify main actor
                            let _ = self.main_tx.send(MainActorMsg::PeerConnected(peer_did, peer_tx));
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

// ============================================================================
// GOVERNANCE ACTOR
// ============================================================================

struct GovernanceActor {
    entries: Vec<Entry>,
    proposals: HashMap<Cid, Proposal>,
    receiver: Receiver<GovernanceActorMsg>,
    network_tx: Sender<NetworkActorMsg>,
    trust_tx: Sender<TrustActorMsg>,
    storage_tx: Sender<StorageActorMsg>,
    config: Config,
    validator: Validator,
    authenticated_peers: usize,
}

impl GovernanceActor {
    fn run(mut self) {
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                GovernanceActorMsg::CreateProposal(did, entry_type, elaboration, reply_tx) => {
                    let result = self.create_proposal(did, entry_type, elaboration);
                    let _ = reply_tx.send(result);
                }
                GovernanceActorMsg::CastVote(did, cid, support, elaboration) => {
                    self.cast_vote(did, cid, support, elaboration);
                }
                GovernanceActorMsg::CheckThresholds => {
                    self.check_execution_thresholds();
                }
                GovernanceActorMsg::GetProposal(cid, reply_tx) => {
                    let _ = reply_tx.send(self.proposals.get(&cid).cloned());
                }
                GovernanceActorMsg::GetAllProposals(reply_tx) => {
                    let _ = reply_tx.send(self.proposals.values().cloned().collect());
                }
            }
        }
    }
    
    fn create_proposal(&mut self, did: Did, entry_type: EntryType, elaboration: String) -> Result<Cid, String> {
        self.validator.validate_elaboration(&elaboration)?;
        
        let data = bincode::serialize(&entry_type).unwrap();
        let cid = Cid::new(&data, &did);
        
        let entry = Entry {
            cid,
            entry_type: entry_type.clone(),
            data,
            creator: did.clone(),
            timestamp: current_timestamp(),
            signature: vec![], // Would be signed in real impl
        };
        
        self.validator.validate_entry(&entry)?;
        
        self.entries.push(entry.clone());
        self.proposals.insert(cid, Proposal {
            cid,
            entry_type,
            proposer: did,
            elaboration,
            votes_for: HashMap::new(),
            votes_against: HashMap::new(),
            threshold: self.calculate_threshold(),
            executed: false,
        });
        
        // Persist
        let _ = self.storage_tx.send(StorageActorMsg::SaveEntry(entry));
        
        Ok(cid)
    }
    
    fn cast_vote(&mut self, did: Did, cid: Cid, support: bool, elaboration: String) {
        if let Some(proposal) = self.proposals.get_mut(&cid) {
            if support {
                proposal.votes_for.insert(did, elaboration);
            } else {
                proposal.votes_against.insert(did, elaboration);
            }
            
            if !proposal.executed && self.check_execution_threshold(proposal) {
                proposal.executed = true;
                self.execute_proposal(cid, proposal.entry_type.clone());
            }
        }
    }
    
    fn check_execution_thresholds(&mut self) {
        let mut to_execute = Vec::new();
        
        for (cid, proposal) in &mut self.proposals {
            if !proposal.executed && self.check_execution_threshold(proposal) {
                proposal.executed = true;
                to_execute.push((*cid, proposal.entry_type.clone()));
            }
        }
        
        for (cid, entry_type) in to_execute {
            self.execute_proposal(cid, entry_type);
        }
    }
    
    fn calculate_threshold(&self) -> i32 {
        ((self.authenticated_peers + 1) as f64 * 0.67).ceil() as i32
    }
    
    fn check_execution_threshold(&self, proposal: &Proposal) -> bool {
        let votes_for = proposal.votes_for.len() as i32;
        
        if matches!(proposal.entry_type, EntryType::PrivacyThreshold { .. }) {
            let required = (proposal.threshold as f64 * self.config.privacy_threshold_supermajority).ceil() as i32;
            return votes_for >= required;
        }
        
        votes_for >= proposal.threshold
    }
    
    fn execute_proposal(&mut self, cid: Cid, entry_type: EntryType) {
        match entry_type {
            EntryType::Knowledge { category, concept, .. } => {
                println!("[EXECUTE] Knowledge: {} > {}", category, concept);
            }
            EntryType::Prune { target, reason } => {
                println!("[EXECUTE] Prune {} - {}", target.short(), reason);
                self.entries.retain(|e| e.cid != target);
            }
            _ => {}
        }
    }
}

// ============================================================================
// TRUST ACTOR
// ============================================================================

struct TrustActor {
    scores: HashMap<Did, TrustScore>,
    receiver: Receiver<TrustActorMsg>,
    config: Config,
}

impl TrustActor {
    fn run(mut self) {
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                TrustActorMsg::UpdateTrust(did, elaboration) => {
                    let score = self.score_elaboration(&elaboration);
                    let ts = self.scores.entry(did.clone())
                        .or_insert_with(|| TrustScore::new(did));
                    ts.overall_score = (ts.overall_score * 0.7) + (score * 0.3);
                    ts.interaction_count += 1;
                    ts.last_updated = current_timestamp();
                }
                TrustActorMsg::GetTrust(did, reply_tx) => {
                    let trust = self.scores.get(&did)
                        .map(|ts| ts.overall_score)
                        .unwrap_or(0.5);
                    let _ = reply_tx.send(trust);
                }
                TrustActorMsg::DecayTrust => {
                    let now = current_timestamp();
                    for score in self.scores.values_mut() {
                        let days_inactive = (now - score.last_updated) / 86400;
                        if days_inactive > self.config.trust_decay_days {
                            let decay_periods = days_inactive / self.config.trust_decay_days;
                            score.overall_score *= self.config.trust_decay_rate.powi(decay_periods as i32);
                        }
                    }
                }
                TrustActorMsg::GetAllScores(reply_tx) => {
                    let _ = reply_tx.send(self.scores.clone());
                }
            }
        }
    }
    
    fn score_elaboration(&self, text: &str) -> f64 {
        let words: Vec<_> = text.split_whitespace().collect();
        let unique: HashSet<_> = words.iter().collect();
        let uniqueness = unique.len() as f64 / words.len().max(1) as f64;
        let length_score = (text.len() as f64 / 100.0).min(1.0);
        (uniqueness * 0.5 + length_score * 0.5).min(1.0)
    }
}

// ============================================================================
// CAPTURE ACTOR (PCAP)
// ============================================================================

struct CaptureActor {
    receiver: Receiver<CaptureActorMsg>,
}

impl CaptureActor {
    fn run(self) {
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                CaptureActorMsg::Start(interface) => {
                    self.capture_packets(&interface);
                }
                CaptureActorMsg::Stop => break,
            }
        }
    }
    
    fn capture_packets(&self, interface: &str) {
        let devices = match Device::list() {
            Ok(devs) => devs,
            Err(e) => {
                println!("[PCAP] Failed to list devices: {}", e);
                return;
            }
        };
        
        let device = devices.iter()
            .find(|d| d.name == interface || 
                      d.desc.as_ref().map(|s| s.contains(interface)).unwrap_or(false))
            .cloned();
        
        let device = match device {
            Some(d) => d,
            None => {
                println!("[PCAP] Device not found: {}", interface);
                return;
            }
        };
        
        let mut cap = match Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open() 
        {
            Ok(c) => c,
            Err(e) => {
                println!("[PCAP] Failed to open capture: {}", e);
                return;
            }
        };
        
        if let Err(e) = cap.filter("tcp", true) {
            println!("[PCAP] Failed to set filter: {}", e);
        }
        
        println!("[PCAP] Capturing packets...");
        
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    self.parse_packet(&packet.data);
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    println!("[PCAP] Capture error: {}", e);
                    break;
                }
            }
        }
    }
    
    fn parse_packet(&self, packet: &[u8]) {
        // Skip if too small for headers
        if packet.len() < 54 { return; } // 14 (eth) + 20 (ip) + 20 (tcp)
        
        // Parse Ethernet header (14 bytes)
        let eth_offset = 14;
        
        // Parse IP header
        let ip_version = (packet[eth_offset] >> 4) & 0x0F;
        if ip_version != 4 { return; } // Only IPv4 for now
        
        let ip_header_len = ((packet[eth_offset] & 0x0F) * 4) as usize;
        let ip_total_len = u16::from_be_bytes([packet[eth_offset + 2], packet[eth_offset + 3]]) as usize;
        
        let src_ip = format!("{}.{}.{}.{}", 
            packet[eth_offset + 12], packet[eth_offset + 13], 
            packet[eth_offset + 14], packet[eth_offset + 15]);
        let dst_ip = format!("{}.{}.{}.{}", 
            packet[eth_offset + 16], packet[eth_offset + 17], 
            packet[eth_offset + 18], packet[eth_offset + 19]);
        
        // Parse TCP header
        let tcp_offset = eth_offset + ip_header_len;
        if packet.len() < tcp_offset + 20 { return; }
        
        let src_port = u16::from_be_bytes([packet[tcp_offset], packet[tcp_offset + 1]]);
        let dst_port = u16::from_be_bytes([packet[tcp_offset + 2], packet[tcp_offset + 3]]);
        
        let tcp_flags = packet[tcp_offset + 13];
        let mut flags = String::new();
        if tcp_flags & 0x02 != 0 { flags.push_str("SYN "); }
        if tcp_flags & 0x10 != 0 { flags.push_str("ACK "); }
        if tcp_flags & 0x01 != 0 { flags.push_str("FIN "); }
        if tcp_flags & 0x04 != 0 { flags.push_str("RST "); }
        if tcp_flags & 0x08 != 0 { flags.push_str("PSH "); }
        
        let tcp_header_len = ((packet[tcp_offset + 12] >> 4) * 4) as usize;
        let payload_offset = tcp_offset + tcp_header_len;
        
        if payload_offset < packet.len() {
            let payload_len = packet.len() - payload_offset;
            
            // Try to parse DIAGON messages
            if payload_len >= 4 {
                let msg_len = u32::from_be_bytes([
                    packet[payload_offset], packet[payload_offset + 1],
                    packet[payload_offset + 2], packet[payload_offset + 3]
                ]) as usize;
                
                if payload_len >= 4 + msg_len {
                    let msg_bytes = &packet[payload_offset + 4..payload_offset + 4 + msg_len];
                    
                    if let Ok(message) = bincode::deserialize::<Message>(msg_bytes) {
                        println!("[PCAP] {}:{} -> {}:{} [{}] DIAGON: {:?}", 
                                 src_ip, src_port, dst_ip, dst_port, flags.trim(), 
                                 self.message_summary(&message));
                        return;
                    }
                }
            }
            
            println!("[PCAP] {}:{} -> {}:{} [{}] {} bytes", 
                     src_ip, src_port, dst_ip, dst_port, flags.trim(), payload_len);
        }
    }
    
    fn message_summary(&self, msg: &Message) -> String {
        match msg {
            Message::Connect(did, _, _) => format!("Connect({})", &did.0[..20]),
            Message::Challenge(_) => "Challenge".to_string(),
            Message::Response(_) => "Response".to_string(),
            Message::Elaborate(text) => format!("Elaborate({})", &text[..20.min(text.len())]),
            Message::Propose(did, entry, _) => format!("Propose({}, {})", &did.0[..20], entry.cid.short()),
            Message::Vote(did, cid, support, _, _) => format!("Vote({}, {}, {})", &did.0[..20], cid.short(), support),
            Message::Heartbeat(did) => format!("Heartbeat({})", &did.0[..20]),
            _ => format!("{:?}", msg).split('(').next().unwrap_or("Unknown").to_string(),
        }
    }
}

// ============================================================================
// STORAGE ACTOR
// ============================================================================

struct StorageActor {
    db_path: String,
    receiver: Receiver<StorageActorMsg>,
    state: SavedState,
}

impl StorageActor {
    fn new(db_path: String, receiver: Receiver<StorageActorMsg>) -> Self {
        let state = Self::load_from_disk(&db_path).unwrap_or_default();
        Self {
            db_path,
            receiver,
            state,
        }
    }
    
    fn run(mut self) {
        while let Ok(msg) = self.receiver.recv() {
            match msg {
                StorageActorMsg::SaveEntry(entry) => {
                    self.state.entries.push(entry);
                }
                StorageActorMsg::SaveProposal(proposal) => {
                    self.state.proposals.insert(proposal.cid, proposal);
                }
                StorageActorMsg::SaveTrustScore(score) => {
                    self.state.trust_scores.insert(score.did.clone(), score);
                }
                StorageActorMsg::SaveStake(did, stake) => {
                    self.state.stakes.insert(did, stake);
                }
                StorageActorMsg::SavePrivacyThreshold(threshold) => {
                    self.state.privacy_threshold = threshold;
                }
                StorageActorMsg::LoadState(reply_tx) => {
                    let _ = reply_tx.send(Some(self.state.clone()));
                }
                StorageActorMsg::Persist => {
                    let _ = self.save_to_disk();
                }
            }
        }
    }
    
    fn load_from_disk(path: &str) -> Option<SavedState> {
        std::fs::read(path).ok()
            .and_then(|data| serde_cbor::from_slice(&data).ok())
    }
    
    fn save_to_disk(&self) -> io::Result<()> {
        let temp_path = format!("{}.tmp", self.db_path);
        let file = File::create(&temp_path)?;
        serde_cbor::to_writer(BufWriter::new(file), &self.state)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        std::fs::rename(temp_path, &self.db_path)?;
        Ok(())
    }
}

// ============================================================================
// MAINTENANCE ACTOR
// ============================================================================

struct MaintenanceActor {
    receiver: Receiver<()>,
    network_tx: Sender<NetworkActorMsg>,
    trust_tx: Sender<TrustActorMsg>,
    storage_tx: Sender<StorageActorMsg>,
    config: Config,
}

impl MaintenanceActor {
    fn run(self) {
        let mut last_heartbeat = Instant::now();
        let mut last_trust_decay = Instant::now();
        let mut last_persist = Instant::now();
        
        loop {
            // Use timeout to periodically check tasks
            match self.receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(_) => break, // Shutdown signal
                Err(_) => {} // Timeout - continue with maintenance
            }
            
            let now = Instant::now();
            
            // Send heartbeats
            if now.duration_since(last_heartbeat) >= self.config.heartbeat_interval {
                let _ = self.network_tx.send(NetworkActorMsg::Heartbeat);
                last_heartbeat = now;
            }
            
            // Decay trust scores
            if now.duration_since(last_trust_decay) >= Duration::from_secs(86400) {
                let _ = self.trust_tx.send(TrustActorMsg::DecayTrust);
                last_trust_decay = now;
            }
            
            // Persist state
            if now.duration_since(last_persist) >= Duration::from_secs(300) {
                let _ = self.storage_tx.send(StorageActorMsg::Persist);
                last_persist = now;
            }
        }
    }
}

// ============================================================================
// MAIN ACTOR & NODE API
// ============================================================================

pub struct Node {
    main_tx: Sender<MainActorMsg>,
    network_tx: Sender<NetworkActorMsg>,
    governance_tx: Sender<GovernanceActorMsg>,
    trust_tx: Sender<TrustActorMsg>,
    capture_tx: Option<Sender<CaptureActorMsg>>,
    maintenance_shutdown: Sender<()>,
    pub did: Did,
}

impl Node {
    pub fn new(addr: &str) -> io::Result<Arc<Self>> {
        let (main_tx, main_rx) = mpsc::channel();
        let (network_tx, network_rx) = mpsc::channel();
        let (governance_tx, governance_rx) = mpsc::channel();
        let (trust_tx, trust_rx) = mpsc::channel();
        let (storage_tx, storage_rx) = mpsc::channel();
        let (maintenance_tx, maintenance_rx) = mpsc::channel();
        let (capture_tx, capture_rx) = mpsc::channel();
        
        // Create identity
        let addr_hash = hex::encode(&sha256(addr.as_bytes())[..8]);
        let (public_key, secret_key, did) = Self::load_or_create_identity(&addr_hash)?;
        
        let config = Config::default();
        
        // Spawn storage actor
        let db_path = format!("db/diagon_{}.cbor", addr_hash);
        thread::spawn(move || {
            StorageActor::new(db_path, storage_rx).run();
        });
        
        // Spawn network actor
        let network_actor = NetworkActor::new(
            network_rx,
            main_tx.clone(),
            config.clone(),
            (did.clone(), public_key, secret_key),
            PUBLIC_GENESIS,
        );
        thread::spawn(move || network_actor.run());
        
        // Spawn governance actor
        let governance_actor = GovernanceActor {
            entries: Vec::new(),
            proposals: HashMap::new(),
            receiver: governance_rx,
            network_tx: network_tx.clone(),
            trust_tx: trust_tx.clone(),
            storage_tx: storage_tx.clone(),
            config: config.clone(),
            validator: Validator::new(config.clone()),
            authenticated_peers: 0,
        };
        thread::spawn(move || governance_actor.run());
        
        // Spawn trust actor
        let trust_actor = TrustActor {
            scores: HashMap::new(),
            receiver: trust_rx,
            config: config.clone(),
        };
        thread::spawn(move || trust_actor.run());
        
        // Spawn maintenance actor
        let maint_network_tx = network_tx.clone();
        let maint_trust_tx = trust_tx.clone();
        thread::spawn(move || {
            MaintenanceActor {
                receiver: maintenance_rx,
                network_tx: maint_network_tx,
                trust_tx: maint_trust_tx,
                storage_tx,
                config,
            }.run();
        });
        
        // Optionally spawn capture actor
        if std::env::var("ENABLE_PCAP").is_ok() {
            thread::spawn(move || {
                CaptureActor { receiver: capture_rx }.run();
            });
        } else {
            // Drain capture channel
            thread::spawn(move || {
                while capture_rx.recv().is_ok() {}
            });
        }
        
        // Start listening
        let socket_addr: SocketAddr = addr.parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address"))?;
        network_tx.send(NetworkActorMsg::StartListening(socket_addr))
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to start network"))?;
        
        // Start capture if requested
        let capture_tx = if std::env::var("ENABLE_PCAP").is_ok() {
            let tx = capture_tx.clone();
            let interface = std::env::var("PCAP_INTERFACE").unwrap_or_else(|_| "lo".to_string());
            tx.send(CaptureActorMsg::Start(interface)).ok();
            Some(capture_tx)
        } else {
            None
        };
        
        println!("[NODE] Started: {}", did.0);
        
        Ok(Arc::new(Self {
            main_tx,
            network_tx,
            governance_tx,
            trust_tx,
            capture_tx,
            maintenance_shutdown: maintenance_tx,
            did,
        }))
    }
    
    fn load_or_create_identity(addr_hash: &str) -> io::Result<(PublicKey, SecretKey, Did)> {
        std::fs::create_dir_all("db").ok();
        let identity_path = format!("db/identity_{}.cbor", addr_hash);
        
        if Path::new(&identity_path).exists() {
            if let Ok(data) = std::fs::read(&identity_path) {
                if let Ok((pk_bytes, sk_bytes, did)) = serde_cbor::from_slice::<(Vec<u8>, Vec<u8>, Did)>(&data) {
                    if let (Ok(pk), Ok(sk)) = (PublicKey::from_bytes(&pk_bytes), SecretKey::from_bytes(&sk_bytes)) {
                        if Did::from_pubkey(&pk) == did {
                            return Ok((pk, sk, did));
                        }
                    }
                }
            }
        }
        
        let (pk, sk) = keypair();
        let did = Did::from_pubkey(&pk);
        let identity = (pk.as_bytes().to_vec(), sk.as_bytes().to_vec(), did.clone());
        
        if let Ok(file) = File::create(&identity_path) {
            let _ = serde_cbor::to_writer(BufWriter::new(file), &identity);
        }
        
        Ok((pk, sk, did))
    }
    
    // Public API methods
    pub fn auth(&self, passphrase: &str) {
        let _ = self.main_tx.send(MainActorMsg::Auth(passphrase.to_string()));
    }
    
    pub fn connect(&self, addr: &str) -> io::Result<()> {
        let socket_addr: SocketAddr = addr.parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address"))?;
        
        let (reply_tx, reply_rx) = mpsc::channel();
        self.network_tx.send(NetworkActorMsg::ConnectTo(socket_addr, reply_tx))
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to send"))?;
        
        reply_rx.recv_timeout(Duration::from_secs(10))
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Connect timeout"))?
    }
    
    pub fn elaborate(&self, text: &str) {
        let _ = self.main_tx.send(MainActorMsg::Elaborate(text.to_string()));
        let msg = Message::Elaborate(text.to_string());
        let _ = self.network_tx.send(NetworkActorMsg::Broadcast(msg));
    }
    
    pub fn approve(&self, did_str: &str) {
        let _ = self.main_tx.send(MainActorMsg::Approve(did_str.to_string()));
    }
    
    pub fn propose(&self, entry_type: EntryType, elaboration: &str) {
        let _ = self.main_tx.send(MainActorMsg::Propose(entry_type, elaboration.to_string()));
    }
    
    pub fn vote(&self, cid_str: &str, support: bool, elaboration: &str) {
        let _ = self.main_tx.send(MainActorMsg::Vote(cid_str.to_string(), support, elaboration.to_string()));
    }
    
    pub fn stake(&self, amount: u64, duration_secs: u64) {
        let _ = self.main_tx.send(MainActorMsg::Stake(amount, duration_secs));
    }
    
    pub fn status(&self) {
        let (reply_tx, reply_rx) = mpsc::channel();
        if self.main_tx.send(MainActorMsg::Status(reply_tx)).is_ok() {
            if let Ok(status) = reply_rx.recv_timeout(Duration::from_secs(5)) {
                println!("\n=== NODE STATUS ===");
                println!("DID: {}", self.did.0);
                println!("Entries: {}", status.entries);
                println!("Proposals: {}", status.proposals);
                println!("Peers: {}", status.peers);
            }
        }
    }
    
    pub fn shutdown(&self) {
        println!("[SHUTDOWN] Initiating shutdown");
        
        // Stop capture if running
        if let Some(capture_tx) = &self.capture_tx {
            let _ = capture_tx.send(CaptureActorMsg::Stop);
        }
        
        // Shutdown maintenance
        let _ = self.maintenance_shutdown.send(());
        
        // Shutdown network
        let _ = self.network_tx.send(NetworkActorMsg::Shutdown);
        
        // Shutdown main
        let _ = self.main_tx.send(MainActorMsg::Shutdown);
        
        thread::sleep(Duration::from_millis(500));
        println!("[SHUTDOWN] Complete");
    }
}

// ============================================================================
// HELPERS
// ============================================================================

#[derive(Clone, Default)]
pub struct NodeStatus {
    pub entries: usize,
    pub proposals: usize,
    pub peers: usize,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct SavedState {
    entries: Vec<Entry>,
    proposals: HashMap<Cid, Proposal>,
    trust_scores: HashMap<Did, TrustScore>,
    stakes: HashMap<Did, StakeRecord>,
    privacy_threshold: PrivacyThreshold,
    nonce_counter: u64,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn write_message(stream: &mut TcpStream, msg: &Message) -> io::Result<()> {
    let data = bincode::serialize(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large"));
    }
    
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&data)?;
    stream.flush()?;
    Ok(())
}

fn read_message(stream: &mut TcpStream) -> io::Result<Message> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large"));
    }
    
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    
    bincode::deserialize(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn verify_signature(data: &[u8], signature: &[u8], pubkey_bytes: &[u8]) -> bool {
    if let (Ok(pk), Ok(sig)) = (PublicKey::from_bytes(pubkey_bytes), DetachedSignature::from_bytes(signature)) {
        verify_detached_signature(&sig, data, &pk).is_ok()
    } else {
        false
    }
}
```
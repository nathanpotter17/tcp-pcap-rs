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
// main.rs - Enhanced DIAGON Actor-Based P2P System
// Replace entire main.rs content

use std::{
    thread,
    sync::{mpsc, Arc, Mutex, atomic::{AtomicBool, Ordering}},
    net::{TcpStream, TcpListener, SocketAddr},
    io::{Read, Write, ErrorKind},
    collections::{HashMap, HashSet},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use pcap::{Device, Capture};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

// ============================================================================
// CORE TYPES (from DIAGON)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cid(pub [u8; 32]);

impl Cid {
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
    Vote { target: Cid, support: bool },
    Prune { target: Cid, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Connect(Did, Vec<u8>, [u8; 32]),
    Challenge([u8; 32]),
    Response(Vec<u8>),
    Elaborate(String),
    Propose(Did, Entry, String),
    Vote(Did, Cid, bool, String, Vec<u8>),
    Heartbeat(Did),
    Shutdown,
}

// ============================================================================
// QUERY ENGINE - Datalog-style queries
// ============================================================================

#[derive(Debug, Clone)]
pub struct Pattern {
    pub entity: Option<EntityId>,
    pub attribute: Option<AttributeId>,
    pub value: Option<Value>,
    pub tx: Option<TxId>,
}

impl TemporalDatabase {
    pub fn query(&self, patterns: Vec<Pattern>) -> Vec<Datom> {
        let mut results = Vec::new();
        
        for pattern in patterns {
            let matches = self.query_pattern(&pattern);
            results.extend(matches);
        }
        
        results
    }
    
    fn query_pattern(&self, pattern: &Pattern) -> Vec<Datom> {
        match (&pattern.entity, &pattern.attribute, &pattern.value) {
            // Most specific: E-A-V
            (Some(e), Some(a), Some(v)) => {
                let start = (*e, *a, v.clone(), TxId(0));
                let end = (*e, *a, v.clone(), TxId(u64::MAX));
                
                self.eavt
                    .range(start..=end)
                    .filter(|(key, _)| {
                        pattern.tx.map_or(true, |tx| key.3 == tx)
                    })
                    .map(|(_, datom)| datom.clone())
                    .collect()
            }
            
            // E-A
            (Some(e), Some(a), None) => {
                let start = (*e, *a, Value::Boolean(false), TxId(0));
                let end = (*e, *a, Value::Bytes(vec![255; 32]), TxId(u64::MAX));
                
                self.eavt
                    .range(start..end)
                    .filter(|(key, _)| key.0 == *e && key.1 == *a)
                    .filter(|(key, _)| {
                        pattern.tx.map_or(true, |tx| key.3 == tx)
                    })
                    .map(|(_, datom)| datom.clone())
                    .collect()
            }
            
            // A-V (use AVET index for efficiency)
            (None, Some(a), Some(v)) => {
                let start = (*a, v.clone(), EntityId(0), TxId(0));
                let end = (*a, v.clone(), EntityId(u64::MAX), TxId(u64::MAX));
                
                self.avet
                    .range(start..=end)
                    .filter(|(key, _)| {
                        pattern.tx.map_or(true, |tx| key.3 == tx)
                    })
                    .map(|(_, datom)| datom.clone())
                    .collect()
            }
            
            // Just entity
            (Some(e), None, None) => {
                let start = (*e, AttributeId(0), Value::Boolean(false), TxId(0));
                let end = (*e, AttributeId(u64::MAX), Value::Bytes(vec![255; 32]), TxId(u64::MAX));
                
                self.eavt
                    .range(start..end)
                    .filter(|(key, _)| key.0 == *e)
                    .filter(|(key, _)| {
                        pattern.tx.map_or(true, |tx| key.3 == tx)
                    })
                    .map(|(_, datom)| datom.clone())
                    .collect()
            }
            
            _ => Vec::new(),
        }
    }
    
    // Get all entities that reference a given entity
    pub fn reverse_refs(&self, entity: EntityId) -> Vec<(EntityId, AttributeId)> {
        let start = (entity, AttributeId(0), EntityId(0), TxId(0));
        let end = (entity, AttributeId(u64::MAX), EntityId(u64::MAX), TxId(u64::MAX));
        
        self.vaet
            .range(start..=end)
            .filter(|(key, _)| key.0 == entity)
            .map(|(key, _)| (key.2, key.1))
            .collect()
    }
    
    // Time travel - get database as of a specific transaction
    pub fn as_of(&self, tx: TxId) -> DatabaseSnapshot {
        let mut snapshot = DatabaseSnapshot::new();
        
        // Replay all transactions up to tx
        for (txid, transaction) in &self.tx_log {
            if *txid > tx {
                break;
            }
            
            for datom in &transaction.datoms {
                match datom.op {
                    Op::Assert => snapshot.assert_datom(datom.clone()),
                    Op::Retract => snapshot.retract_datom(datom.clone()),
                }
            }
        }
        
        snapshot
    }
}

// ============================================================================
// DATABASE SNAPSHOT - Point-in-time view
// ============================================================================

pub struct DatabaseSnapshot {
    eavt: BTreeMap<(EntityId, AttributeId, Value, TxId), Datom>,
}

impl DatabaseSnapshot {
    fn new() -> Self {
        Self {
            eavt: BTreeMap::new(),
        }
    }
    
    fn assert_datom(&mut self, datom: Datom) {
        self.eavt.insert(
            (datom.entity, datom.attribute, datom.value.clone(), datom.tx),
            datom
        );
    }
    
    fn retract_datom(&mut self, datom: Datom) {
        // Remove any existing assertions for this E-A-V
        self.eavt.retain(|key, _| {
            !(key.0 == datom.entity && 
              key.1 == datom.attribute && 
              key.2 == datom.value)
        });
    }
    
    pub fn get_entity(&self, entity: EntityId) -> Vec<Datom> {
        let start = (entity, AttributeId(0), Value::Boolean(false), TxId(0));
        let end = (entity, AttributeId(u64::MAX), Value::Bytes(vec![255; 32]), TxId(u64::MAX));
        
        self.eavt
            .range(start..end)
            .filter(|(key, _)| key.0 == entity)
            .map(|(_, datom)| datom.clone())
            .collect()
    }
}

// ============================================================================
// TRANSACTION - Unit of change
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TxId,
    pub pool: [u8; 32],
    pub datoms: Vec<Datom>,
    pub proposer: Did,
    pub timestamp: u64,
    pub parent_tx: Option<TxId>,
    pub consensus_proof: ConsensusProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProof {
    pub votes: HashMap<Did, Vote>,
    pub ordering_hash: [u8; 32],
    pub achieved_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub support: bool,
    pub signature: Vec<u8>,
    pub elaboration: String,
}

// ============================================================================
// POOL DATABASE - Segregated temporal databases
// ============================================================================

pub struct PoolDatabase {
    pub pool_id: [u8; 32],
    pub db: TemporalDatabase,
    pub pending_transactions: BTreeMap<TxId, Transaction>,
    pub consensus_participants: HashSet<Did>,
}

impl PoolDatabase {
    pub fn new(pool_id: [u8; 32]) -> Self {
        Self {
            pool_id,
            db: TemporalDatabase::new(),
            pending_transactions: BTreeMap::new(),
            consensus_participants: HashSet::new(),
        }
    }
    
    pub fn propose_transaction(&mut self, tx: Transaction) -> Result<TxId, String> {
        // Validate transaction
        if tx.pool != self.pool_id {
            return Err("Transaction pool mismatch".to_string());
        }
        
        // Check parent exists if specified
        if let Some(parent) = tx.parent_tx {
            if !self.db.tx_log.contains_key(&parent) {
                return Err("Parent transaction not found".to_string());
            }
        }
        
        // Add to pending
        self.pending_transactions.insert(tx.id, tx.clone());
        
        Ok(tx.id)
    }
    
    pub fn commit_transaction(&mut self, tx_id: TxId) -> Result<(), String> {
        let tx = self.pending_transactions.remove(&tx_id)
            .ok_or("Transaction not found in pending")?;
        
        // Verify consensus achieved
        let support_count = tx.consensus_proof.votes
            .values()
            .filter(|v| v.support)
            .count();
        
        let required = (self.consensus_participants.len() as f64 * 0.67).ceil() as usize;
        
        if support_count < required {
            return Err(format!("Insufficient consensus: {} < {}", support_count, required));
        }
        
        // Apply to database
        self.db.apply_transaction(tx)?;
        
        Ok(())
    }
}

// ============================================================================
// INTEGRATION WITH YOUR AUTH SERVER
// ============================================================================

impl AuthClientActor {
    // Add this method to handle data operations after authentication
    fn handle_data_operation(&mut self, entity_id: EntityId, operation: DataOperation) {
        match operation {
            DataOperation::Assert { attribute, value } => {
                // Create datom for assertion
                let datom = Datom {
                    entity: entity_id,
                    attribute,
                    value,
                    tx: TxId(0), // Will be set by transaction processor
                    op: Op::Assert,
                };
                
                // Would send to pool database for consensus
                println!("[DATA] Assert: {:?}", datom);
            }
            DataOperation::Query { patterns } => {
                // Would query pool database
                println!("[QUERY] Patterns: {:?}", patterns);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum DataOperation {
    Assert { attribute: AttributeId, value: Value },
    Query { patterns: Vec<Pattern> },
}

// ============================================================================
// USAGE EXAMPLE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_temporal_database() {
        let mut db = TemporalDatabase::new();
        
        // Create a transaction
        let mut tx = Transaction {
            id: db.allocate_tx_id(),
            pool: [0; 32],
            datoms: vec![],
            proposer: Did("did:test:123".to_string()),
            timestamp: current_timestamp(),
            parent_tx: None,
            consensus_proof: ConsensusProof {
                votes: HashMap::new(),
                ordering_hash: [0; 32],
                achieved_at: current_timestamp(),
            },
        };
        
        // Add some datoms
        let entity = db.allocate_entity_id();
        
        tx.datoms.push(Datom {
            entity,
            attribute: AttributeId(100), // user/did
            value: Value::String("did:test:alice".to_string()),
            tx: tx.id,
            op: Op::Assert,
        });
        
        tx.datoms.push(Datom {
            entity,
            attribute: AttributeId(102), // user/trust
            value: Value::double(0.75),
            tx: tx.id,
            op: Op::Assert,
        });
        
        // Apply transaction
        db.apply_transaction(tx).unwrap();
        
        // Query by attribute and value
        let results = db.query(vec![
            Pattern {
                entity: None,
                attribute: Some(AttributeId(100)),
                value: Some(Value::String("did:test:alice".to_string())),
                tx: None,
            }
        ]);
        
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity, entity);
        
        // Time travel query
        let snapshot = db.as_of(TxId(999)); // Before our transaction
        assert_eq!(snapshot.get_entity(entity).len(), 0);
        
        let snapshot = db.as_of(TxId(1001)); // After our transaction
        assert_eq!(snapshot.get_entity(entity).len(), 2);
    }
}
```
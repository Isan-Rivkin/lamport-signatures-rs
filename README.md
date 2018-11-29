# lamport-signatures-rs
In cryptography, a Lamport signature or Lamport one-time signature scheme is a method for constructing a digital signature. Lamport signatures can be built from any cryptographically secure one-way function; usually a cryptographic hash function is used.  Although the potential development of quantum computers threatens the security of many common forms of cryptography such as RSA, it is believed that Lamport signatures with large hash functions would still be secure in that event. Unfortunately, each Lamport key can only be used to sign a single message. However, combined with hash trees, a single key could be used for many messages, making this a fairly efficient digital signature scheme.

# Never tested in production, use at your own risk

# How to Use 

```rust
extern crate lamport_signatures;
use lamport_signatures::lamport_utils;

// generate private key 
let priv_key = lamport_utils::gen_secret_key().unwrap();
// derive public key 
let pub_key = lamport_utils::derive_pub_key(&priv_key);
// create some message 
let msg = "hi elichai2, some secret msg";
// digest the msg 
let msg_digest = lamport_utils::hash(msg.as_bytes());
// sign the digest 
let signature : Vec<[u8;32]> = priv_key.sign(&msg_digest);
// verify signature against public key 
let is_valid = pub_key.verify(&msg_digest, &signature);
```


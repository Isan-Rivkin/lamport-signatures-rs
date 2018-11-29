# lamport-signatures-rs
In cryptography, a Lamport signature or Lamport one-time signature scheme is a method for constructing a digital signature. Lamport signatures can be built from any cryptographically secure one-way function; usually a cryptographic hash function is used.  Although the potential development of quantum computers threatens the security of many common forms of cryptography such as RSA, it is believed that Lamport signatures with large hash functions would still be secure in that event. Unfortunately, each Lamport key can only be used to sign a single message. However, combined with hash trees, a single key could be used for many messages, making this a fairly efficient digital signature scheme.

# How to Use 
Visit the test in lib.rs or the documentation on crates.io.
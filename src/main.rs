extern crate ring;
extern crate bit;
mod lamport_utils;

fn main() {
    let priv_key = lamport_utils::gen_secret_key().unwrap();
    let pub_key = lamport_utils::derive_pub_key(&priv_key);
    let hashes = pub_key.flat_hashes();
    let msg = "hi elichai";
    let msg_digest = lamport_utils::hash(msg.as_bytes());
    let signature : Vec<[u8;32]> = priv_key.sign(&msg_digest);
    let is_valid = pub_key.verify(&msg_digest, &signature);
    println!("is valid signature? {} ",is_valid );
}

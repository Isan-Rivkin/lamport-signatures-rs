extern crate ring;
extern crate bit;
pub mod lamport_utils;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sig() {
        // generate private key 
        let priv_key = lamport_utils::gen_secret_key().unwrap();
        // derive public key 
        let pub_key = lamport_utils::derive_pub_key(&priv_key);
        // create some message 
        let msg = "hi elichai2";
        // digest the msg 
        let msg_digest = lamport_utils::hash(msg.as_bytes());
        // sign the digest 
        let signature : Vec<[u8;32]> = priv_key.sign(&msg_digest);
        // verify signature against public key 
        let is_valid = pub_key.verify(&msg_digest, &signature);
        assert_eq!(true,is_valid );
    }
}
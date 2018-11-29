use ring::rand::{SecureRandom, SystemRandom};
use ring::error::Unspecified;
use ring::digest;
use bit::BitIndex;

pub struct PrivKey {
    tuples : Vec<([u8;32],[u8;32])>
}
impl PrivKey{
    pub fn get_tuple(&self,i : usize )->([u8;32],[u8;32]){
        return self.tuples[i]
    }
    pub fn tuples_amount(&self)->usize{
        256
    }
    pub fn sign(&self, h : &[u8;32])->Vec<[u8;32]>{
        let mut counter = 0;
        let mut signature : Vec<[u8;32]> = Vec::with_capacity(256);
        for (index,b) in h.iter().enumerate(){
            let val = b;
            for i in 0..u8::bit_length(){
                let is_on = val.bit(i);
                let t = self.get_tuple(counter);
                let secret_num = match is_on {
                    true => t.1,
                    false => t.0
                };
                signature.push(secret_num);
                counter += 1;
            }
        }
        signature
    }
}
pub struct PubKey {
    hashes : Vec<([u8; 32], [u8; 32])>,
}
impl PubKey{
    pub fn get_tuple(&self, i : usize)->([u8; 32], [u8; 32]){
        return self.hashes[i];
    }
    pub fn flat_hashes(&self)->Vec<[u8;32]>{
        let mut flat = Vec::new();
        for i in 0..256{
            let (a,b) = self.get_tuple(i);
            flat.push(a);
            flat.push(b);
        }
        flat
    }
    /*
    for each bit in digest:
    -  if bit==1 : 
        get hash from bit index, tuple 1 
    -  if bit ==0 : 
        get hash from bit index, tuple 0
    
    hash the value in signature[bit index] 
    and compare the hashes. 
    */ 
    pub fn verify(&self,digest : &[u8;32],  signature : &Vec<[u8;32]>)->bool{
        let mut counter = 0;
        let mut verified = true;
        for (index,b) in digest.iter().enumerate(){
            let val = b;
            for i in 0..u8::bit_length(){
                let is_on = val.bit(i);
                let t = self.get_tuple(counter);
                let secret_num_hash = match is_on {
                    true => t.1,
                    false => t.0
                };
                //
                let test_hash = hash(&signature[counter]);
                if test_hash != secret_num_hash{
                    verified = false;
                    break;
                } 
                counter += 1;
            }
        }
        return verified;
    }
}

fn generate_pair(sr : &SystemRandom)->Result<([u8;32],[u8;32]),Box<Unspecified>>{
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    sr.fill(&mut a[..])?;
    sr.fill(&mut b[..])?;
    Ok((a,b))
}

pub fn gen_secret_key_with_input(entrophy : [u8;256])->Result<(PrivKey),Box<Unspecified>>{
    let sr = SystemRandom::new();

    // entrophy.into_iter().map(|s| s % 255);
    let mut pairs = Vec::with_capacity(256);
    for i in 0..256{
        let (a,b) = generate_pair(&sr)?;
        //TODO:: add entrophy here .... to a and b 
        pairs.push((a,b));
    }   
    Ok((PrivKey{tuples : pairs}))
}
pub fn gen_secret_key()->Result<(PrivKey),Box<Unspecified>>{
    let sr = SystemRandom::new();
    let mut pairs = Vec::with_capacity(256);
    for i in 0..256{
        let (a,b) = generate_pair(&sr)?;
        pairs.push((a,b));
    }   
    Ok((PrivKey{tuples : pairs}))
}
pub fn derive_pub_key(privKey : & PrivKey)-> PubKey{
    let mut hashes: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(privKey.tuples_amount());
    for i in 0..privKey.tuples_amount(){
        let (secA,secB) = privKey.get_tuple(i);         
        let hashA = digest::digest(&digest::SHA256, &secA);
        let hashB = digest::digest(&digest::SHA256, &secB);
        let mut array_hashA = [0u8; 32];
        let mut array_hashB = [0u8; 32];
        array_hashA.copy_from_slice(hashA.as_ref());
        array_hashB.copy_from_slice(hashB.as_ref());
        hashes.push((array_hashA,array_hashB));
    }
    PubKey{hashes: hashes}
}
pub fn hash(data : &[u8])->[u8;32]{
    let digest = digest::digest(&digest::SHA256,&data);
    let mut byte_result = [0u8;32];
    byte_result.copy_from_slice(digest.as_ref());
    byte_result
}







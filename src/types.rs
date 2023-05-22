
struct Message{
    reciever: PublicRSAKey,
    encrypted_part: Vec<BigUint>
}

// Max size 1024bit
struct EncryptAbleMessage {
    sender: PublicRSAKey,
    text: String
}

impl EncryptAbleMessage {
    fn encrypt(self, key : PublicRSAKey) -> Vec<BigUint> {
        let text = self.text + &self.sender.to_string();
        let text_as_bytes = text.bytes();
        // 128 bytes per chunk
        let mut chunks : Vec<BigUint> = Vec::new();

        let mut vec_b = Vec::new();
        for c in text_as_bytes.enumerate(){
            vec_b.push(c.1);
            
            if c.0 % 128 == 0 && c.0 > 0 {
                let bi = BigUint::from_bytes_le(&vec_b);
                chunks.push(bi);
                vec_b = Vec::new();
            }
        }

        let mut encrypted_chunks = Vec::new();
        for c in chunks{
            encrypted_chunks.push(rsa_encrypt())
        }

        return encrypted_chunks;
    }
}

pub fn rsa_encrypt_simple(plaintext: BigUint, public_key: PublicRSAKey) -> BigUint {
    return plaintext.modpow(public_key.public_e, public_key.public_n);
}

pub fn test(){
    let k = generate_rsa_key(2048);
    let e = EncryptAbleMessage{
        sender:k.public.clone(),
        text: "ABCDEF abcdef".to_owned(),
    };
    let a = e.encrypt(k.public);
    println!("{:?}",a);

}


#[derive(Debug, Clone)]
pub struct RsaKey {
    pub public: PublicRSAKey,
    pub private: PrivateRSAKey
}

#[derive(Debug, Clone)]
pub struct PublicRSAKey{
    pub public_n: BigUint,
    pub public_e: BigUint,
}
impl PublicRSAKey {
    fn to_string(self) -> String{
        let n = self.public_n.to_string();
        let e = self.public_e.to_string();
        return n + &e;
    }
}

#[derive(Debug, Clone)]
pub struct PrivateRSAKey{
    pub private_phi_n: BigUint,
    pub private_d: BigUint
}
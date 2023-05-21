// src/rsa.rs

use crate::key_gen::*;
use num_bigint::BigUint;
use std::fs::File;
use std::io;
use std::io::prelude::*;

pub fn rsa_encrypt(pub_key: &PublicKey, plaintext: &str) -> Vec<BigUint> {
    let plaintext_bytes = plaintext.as_bytes();
    let plaintext_as_int = BigUint::from_bytes_be(plaintext_bytes);
    vec![mod_exp(
        plaintext_as_int,
        pub_key.e().clone(),
        pub_key.n().clone(),
    )]
}

pub fn rsa_decrypt(
    priv_key: &PrivateKey,
    ciphertext: &Vec<BigUint>,
) -> Result<String, std::string::FromUtf8Error> {
    let mut plaintext_bytes = Vec::new();
    for block in ciphertext {
        let plaintext_block = mod_exp(block.clone(), priv_key.d().clone(), priv_key.n().clone());
        plaintext_bytes.extend_from_slice(&plaintext_block.to_bytes_be());
    }
    String::from_utf8(plaintext_bytes)
}

pub fn read_plaintext_message() -> io::Result<String> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer)
}

pub fn read_public_key_from_file(filename: &str) -> io::Result<PublicKey> {
    let mut file = std::fs::File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let lines: Vec<&str> = contents.lines().collect();
    let e = lines[0].parse::<BigUint>().unwrap();
    let n = lines[1].parse::<BigUint>().unwrap();
    Ok(PublicKey::new(e, n))
}

pub fn read_private_key_from_file(filename: &str) -> io::Result<PrivateKey> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let lines: Vec<&str> = contents.lines().collect();
    let d = lines[0].parse::<BigUint>().unwrap();
    let n = lines[1].parse::<BigUint>().unwrap();
    Ok(PrivateKey::new(d, n))
}

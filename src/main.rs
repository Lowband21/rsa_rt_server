mod key_gen;
use crate::key_gen::{PrivateKey, PublicKey};
mod rsa;
use crate::rsa::*;
use num_bigint::BigUint;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tokio::sync::Mutex;
use tokio::sync::broadcast::error::RecvError;
use std::collections::HashMap;
use std::error::Error;
use std::hash::Hash;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket,TcpStream};

use rand::Rng; // Add this for generating random nonces

async fn start_server(
    local_addr: &str,
    pub_key: PublicKey,
    priv_key: PrivateKey,
) -> Result<(), Box<dyn Error>> {
    println!("Starting server...");
    let listener = TcpListener::bind(local_addr).await?;
    let priv_key = Arc::new(priv_key);

    loop {
        let (mut socket, _) = listener.accept().await?;
        println!("Accepted a connection...");

        let priv_key = Arc::clone(&priv_key);

        // Serialize and send the server's public key
        socket.write_all(&pub_key.to_bytes().unwrap()).await?;

        println!("Wrote server public key");

        // Wait for and read the client's public key
        let mut buf = [0; 1024];
        socket.read(&mut buf).await?;
        println!("Read from client");
        let client_pub_key = PublicKey::from_bytes(&buf)?;
        println!("Got client public key");

        tokio::spawn(async move {
            let mut buf = [0; 1024];
            let mut rng = StdRng::from_entropy();
            let nonce: u64 = rng.gen(); // Generate a random nonce

            // Send the nonce to the client
            match socket.write_all(&nonce.to_be_bytes()).await {
                Ok(_) => println!("Sent nonce..."),
                Err(e) => println!("Failed to send nonce: {}", e),
            };

            // Wait for the client's response
            let n = match socket.read(&mut buf).await {
                Ok(n) if n == 0 => {
                    println!("Client closed connection...");
                    return;
                }
                Ok(n) => {
                    println!("Read {} bytes from client...", n);
                    n
                }
                Err(e) => {
                    println!("Failed to read from socket: {}", e);
                    return;
                }
            };

            // Decrypt the client's response
            let response_as_big_uint = BigUint::from_bytes_be(&buf[..n]);
            let decrypted_response = rsa_decrypt(&*priv_key, &vec![response_as_big_uint]);

            // Check if the decrypted response matches the original nonce
            if let Ok(response) = decrypted_response {
                let response_bytes = response.as_bytes();
                if response_bytes.len() != 8 {
                    println!("Incorrect byte length");
                }
                let response_array =
                    <[u8; 8]>::try_from(response_bytes).expect("Length checked above");
                let response_nonce = u64::from_be_bytes(response_array);
                if response_nonce == nonce {
                    // The client is authenticated, process the request
                    println!("Client connected!");
                } else {
                    // The client is not authenticated, return error
                    println!("Authentication failed");
                }
            } else {
                println!("Failed to decrypt client's response");
                return;
            }
        });
    }
}

#[tokio::main]
async fn main() {
    let pub_key = read_public_key_from_file("public_key.txt").unwrap();
    let priv_key = read_private_key_from_file("private_key.txt").unwrap();
    let result = start_server("localhost:8000", pub_key, priv_key).await;


    result.unwrap();
}
async fn start_other_server() ->  Result<(), Box<dyn Error>>{
    let socket = TcpListener::bind("127.0.0.1:9000").await?;
    let user_map : Arc<Mutex<HashMap<PublicKey, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let stream = socket.accept().await?.0;
        let Ok(data) = verify_user(stream).await else {
            println!("User un verifiable");
            break;
        };

        let mut m = user_map.lock().await;
        m.insert(data.0, data.1);
        todo!("Fix");
        // Note does not work Due to need of a duplicate stream, to add the user to teh connected_users_map to write
        // But to handle to connection to read from it
        handle_connection(user_map.clone(), data.1);
    }

    Ok(())
}

async fn verify_user(mut socket: TcpStream) -> Result<(PublicKey,tokio::net::TcpStream), Box<dyn Error>> {
    let mut buf = [0; 1024];
    socket.read(&mut buf).await?;
    let client_pub_key = PublicKey::from_bytes(&buf)?;

    let mut rng = StdRng::from_entropy();
    let random_secret: u128 = rng.gen();


    let encrypted_secret = rsa_encrypt(&client_pub_key, &random_secret.to_string());
    socket.write_all(&encrypted_secret[0].to_bytes_le() ).await;
    
    buf.fill(0);
    socket.read(&mut buf).await?;
    let test_num = BigUint::from_bytes_le(&buf);

    if test_num == random_secret.into() {
        return Ok((client_pub_key,socket));
    } else {
        socket.shutdown();
        return Err(Box::new(RecvError::Closed));
    }
}

async fn handle_connection(user_map : Arc<Mutex<HashMap<PublicKey, TcpStream>>>, stream:TcpStream) {

}
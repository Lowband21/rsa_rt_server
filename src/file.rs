use std::convert::Infallible;
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::Neg;
use std::str::FromStr;
use std::string::ParseError;
use std::sync::Arc;
use std::time::{Instant, Duration};
use std::{thread, cell};

use std::{ops::Sub, hint::black_box};

use num::bigint::{BigUint, RandBigInt, BigInt,ToBigInt};
use rand::{SeedableRng, Rng, RngCore};

use rand::rngs::StdRng;
use tokio::macros::support::poll_fn;
use std::collections::HashMap;
use std::error::Error;
use tokio::sync::{Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpSocket,TcpStream};
use tokio::macros::support::Poll;
// use tokio

pub async fn start_other_server() ->  Result<(), Box<dyn Error>>{
    let socket = TcpListener::bind("127.0.0.1:9000").await?;
    let user_map : Arc<Mutex<HashMap<PublicRSAKey, Arc<Mutex<TcpStream>>>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let stream = socket.accept().await?;
        println!("Accepted socket {}", stream.1);

        let Ok(data) = verify_user(stream.0).await else {
            println!("User un verifiable");
            break;
        };

        println!("User Verified!");
        let mut m = user_map.lock().await;

        let wrapped_socket = Arc::new(Mutex::new(data.1));
        (*m).insert(data.0, wrapped_socket.clone());

        let ucp = user_map.clone();

        let t = tokio::spawn(async move {
            handle_connection(ucp, wrapped_socket.clone(), stream.1).await;
        });
    }

    Ok(())
}

async fn verify_user(mut socket: TcpStream) -> Result<(PublicRSAKey,tokio::net::TcpStream), Box<dyn Error>> {
    // let mut buf = String::with_capacity(4096);
    let mut buf = [0;4096];
    // let mut buf = Vec::new();
    let num_bytes = socket.read(&mut buf).await?;
    let trimmed_buffer = buf.to_vec().iter().enumerate().filter(|x| x.0 < num_bytes).map(|x| *x.1 as u8).collect();
    let response = String::from_utf8(trimmed_buffer).unwrap();
    let client_pub_key = PublicRSAKey::from_string(response)?;

    println!("CBK\n{:?}",client_pub_key);

    let mut rng = StdRng::from_entropy();
    let random_secret: u128 = rng.gen();

    println!("Challenge\n{:?}",random_secret);

    let encrypted_secret = rsa_encrypt_simple(random_secret.into(), &client_pub_key);
    socket.write(&encrypted_secret.to_bytes_le()).await?;
    

    let num_bytes = socket.read(&mut buf).await?;
    let trimmed_buffer = buf.to_vec().iter().enumerate().filter(|x| x.0 < num_bytes).map(|x| *x.1 as u8).collect();
    let response = String::from_utf8(trimmed_buffer).unwrap();

    let test_num = BigUint::from_str(&response)?;

    if test_num == random_secret.into() {
        return Ok((client_pub_key,socket));
    } else {
        socket.shutdown().await?;
        return Err(Box::new(RsaError::new()));
    }
}

async fn handle_connection(user_map : Arc<Mutex<HashMap<PublicRSAKey, Arc<Mutex<TcpStream>>>>>, stream: Arc<Mutex<TcpStream>>, id:std::net::SocketAddr) {
    let mut buf: [u8; 4096] = [0;4096];
    // let mut buf = ReadBuf::new(&mut buf);

    let mut socket_open = true;
    while socket_open == true {

        let mut s = stream.lock().await;
        println!("Aquired lock for {}\n\tpeeking for data", id);

        let in_socket = s.try_read(&mut buf);
        match in_socket {
            Err(e) => {
                println!("\tNo data in buffer\n\tDropping Lock for {}", id);
                drop(s);
                tokio::time::sleep(Duration::from_millis(1500)).await;
                continue;
            }
            Ok(num_bytes) => {
                if num_bytes == 0 {
                    s.shutdown();
                    drop(s);
                    println!("Stream Closed");
                    socket_open = false;
                    break;
       
                } else {
                    // NOTE NEED TO ADD message end character to end of message, or a message length header
                    // How do we know when the message has finsihed transmitting? what if we read at tcp packet one
                    // but we dont wait for packets 2-5, maybe continuely loop inside here 
                    println!("Data in buffer!"); 

                    let trimmed_buffer = buf.iter().enumerate().filter(|x| x.0 < num_bytes).map(|x| *x.1 as u8).collect();
                    let response = String::from_utf8(trimmed_buffer).unwrap();
            
                    let mut i : Vec<&str> = response.split("-").collect();
                    println!("Key + message: {:?}", i);
                    let key_as_string = i[0];
                    // println!("\tkey:{}",key_as_string);
                    let message = i[1];
                    // println!("\tmessage:{}",message);
            
                    let recv = PublicRSAKey::from_string(key_as_string.to_owned()).unwrap();
                    println!("Public key obj {:?}", recv);
                    let mut u =  user_map.lock().await;
                    println!("User map lock acuired");
                    let mut recv_stream = (*u).get(&recv).unwrap();
                    println!("Reciever Stream found");
                    let mut recv_stream = recv_stream.lock().await;
                    println!("Reciever stream lock aquired");
                    recv_stream.write(message.as_bytes()).await;
                    println!("Data written");
                }
            }
        }
      
    }
}


#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RsaKey {
    pub public: PublicRSAKey,
    pub private: PrivateRSAKey
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PublicRSAKey{
    pub public_n: BigUint,
    pub public_e: BigUint,
}
impl PublicRSAKey {
    fn to_string(self) -> String{
        let n = self.public_n.to_string();
        let e = self.public_e.to_string();
        return n + "," + &e;
    }
    fn from_string(s : String) -> Result<PublicRSAKey,RsaError> {
        let mut p = s.split(",");
        let Some(n) = p.next() else {
            return Err(RsaError::new());
        };
        let Some(e) = p.next() else {
            return Err(RsaError::new());
        };


        let Ok(n) = BigUint::from_str(n) else {
            return Err(RsaError::new());
        };
        let Ok(e) =  BigUint::from_str(e) else {
            return Err(RsaError::new());
        };

        return Ok(PublicRSAKey{
            public_e:e,
            public_n:n
        })
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PrivateRSAKey{
    pub private_phi_n: BigUint,
    pub private_d: BigUint
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RsaError;

impl RsaError{
    fn new() -> RsaError{
        return RsaError;
    }
}

impl Error for RsaError{}
impl std::fmt::Display for RsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Oh no, something bad went down")
    }
}

pub fn rsa_encrypt_simple(plaintext: BigUint, public_key: &PublicRSAKey) -> BigUint {
    return plaintext.modpow(&public_key.public_e, &public_key.public_n);
}

pub fn rsa_decrypt_simple(ciphertext:BigUint, private_key: &PrivateRSAKey, public_key: &PublicRSAKey) -> BigUint {
    return ciphertext.modpow(&private_key.private_d, &public_key.public_n);
}
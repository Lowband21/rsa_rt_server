use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::Neg;
use std::str::FromStr;
use std::time::Instant;
use std::{thread, cell};
use std::sync::{mpsc::channel, Arc, Mutex};
use std::{ops::Sub, hint::black_box};
use std::mem::swap;

use num::bigint::{BigUint, RandBigInt, BigInt,ToBigInt};
use rand::{SeedableRng, Rng, RngCore};
use rayon::prelude::*;





#[derive(Debug)]
pub struct RsaKey {
    pub public: PublicRSAKey,
    pub private: PrivateRSAKey
}

#[derive(Debug)]
pub struct PublicRSAKey{
    pub public_n: BigUint,
    pub public_e: BigUint,
}

#[derive(Debug)]
pub struct PrivateRSAKey{
    pub private_phi_n: BigUint,
    pub private_d: BigUint
}


pub fn rsa_encrypt(plaintext_blocks: Vec<BigUint>, public_key: PublicRSAKey) -> Vec<u8> {


    todo!()
}

pub fn rsa_decrypt(ciphertext:Vec<BigUint>, private_key: PrivateRSAKey) -> Vec<u8> {
    todo!();
}



pub fn generate_rsa_key(bit_size : u64) -> RsaKey{
    let t1 = Instant::now();
    let one = BigUint::from(1_u32);
    let two_primes = generate_big_primes(bit_size / 2, 2);
    let t2 = Instant::now();

    let n : BigUint = &two_primes[0] * &two_primes[1];
    let t3 = Instant::now();

    // Everyone uses 65537 as the exponenet (I dont know why)
    let e : BigUint = BigUint::from(65537_u32);
    let phi_n : BigUint =  (&two_primes[0] - &one) * (&two_primes[1] - &one);
    let t4 = Instant::now();
    let phi_n_bi : BigInt = phi_n.clone().into();
    
    let mut d = inverse_mod_n_biguint(e.clone(), phi_n.clone()).1;
    let t5 = Instant::now();
    while d < BigInt::from(0_i32){
        d += &phi_n_bi;
    }

    assert!((&e.to_bigint().expect("Weird") * &d) % phi_n_bi == one.to_bigint().expect("What"), "E and D wernt modular inverse");
    let t6 = Instant::now();

    // println!("TwoPrimes: {:?}, Generate N: {:?}, Generate Phi_n: {:?}, Inverse E phi_n: {:?}, Assert: {:?}", t2-t1, t3-t2, t4-t3, t5-t4, t6-t5);

    RsaKey { 
        public : PublicRSAKey{
            public_n: n, 
            public_e: e
        }, 
        private: PrivateRSAKey {
            private_phi_n: phi_n, 
            private_d: d.to_biguint().expect("error")
        }
    }
}



/// Generate 100 random numbers and then paralize them into threads to run tests on all the numbers, 
/// then filter out the numbers that are not prime and finally return the first element in our primes list
/// with a batch size of 100 the largest number of primes found was 5
pub fn generate_big_primes(bit_size: u64, number_of_primes:usize) -> Vec<BigUint> {
    let mut generator = rand::rngs::StdRng::from_entropy();

    let one = BigUint::from(1 as usize);
    let three = BigUint::from(3_u32);

    let batch_size = 250;
    let av_th : usize=  std::thread::available_parallelism().unwrap().into();
    let num_threads = av_th - 2;

    let mut threads = Vec::new();
    let (tx, rx) = channel();
    for i in 0..num_threads{
        let send_chanel = tx.clone();
        let start = Instant::now();
        let t = thread::spawn(move|| -> _{
            let end1: Instant = Instant::now();
            // println!("Thread {} Started at {:?}",i, end1-start);
            let mut odd_check_counter:usize  = 0;


            let mut counter = 0;
            let mut test_nums : Vec<BigUint >= (0..batch_size).map(|_| -> BigUint{generate_random_odd_number(bit_size)}).collect();

            loop {
                if solovay_strassen_primality_test(&test_nums[counter], 55) == true {

                    let end2: Instant = Instant::now();
                    // println!("Thread {} of {num_threads} found Prime in {:?}, tried {} nums",i, end2-start, odd_check_counter);

                    let res = send_chanel.send(test_nums[counter].clone());
                    match res {
                        Err(_) => {
                            return ();
                        }
                        Ok(_) => {}
                    }
                }

                counter += 1;
                odd_check_counter += 1;

                if counter == batch_size {
                    test_nums = (0..batch_size).map(|_| -> BigUint{generate_random_odd_number(bit_size)}).collect();
                    counter = 0;
                } 
            }
        });
        threads.push(t);
    }
    let mut final_primes = Vec::with_capacity(number_of_primes);
    for _ in 0..number_of_primes{
        let prime: BigUint = rx.recv().unwrap();
        final_primes.push(prime);
    }
// // This is the single threaded version
        // if solovay_strassen_primality_test(&test_nums[counter], 55) == true {
        //     // println!("{} numbers tested before prime", counter);
        //     return test_nums[counter].clone()
        // } else {
        //     counter += 1;
        //     if counter == batch_size {
        //         // println!("New Batch");
        //         test_nums = (0..batch_size).map(|_| -> BigUint{generate_random_odd_number(bit_size)}).collect();
        //         counter = 0
        //     } 
        // }
    // }
    return final_primes;
}

pub fn solovay_strassen_primality_test(n : &BigUint, iterations: usize) -> bool{
    let zero = BigUint::from(0_u32);
    let zero_bi = BigInt::from(0_u32);

    let one = BigUint::from(1_u32);
    let two = &one + &one;
    let three = &two + &one;
    let four = &two + &two;
    let five = &four + &one;
    let eight = &four + &four;

    let one_less = n - &two;
    // iterations should be near 55 for 1 in 100 trillion chance we are wrong
    let random_witnesses : Vec<BigUint>= (0..iterations).map(|_| -> BigUint{generate_random_odd_number_range(&three, &one_less)}).collect();

    for whiteness in random_witnesses {
        let power = (n - &one) / &two;

        let jac = BigInt::from(jacobi_symbol(&whiteness, n));

        if &jac == &zero_bi{
            return false
        }

        // Takes over a 1ms and im doing it 55 times per prime so 55ms atleast per prime
        let euloer = whiteness.modpow(&power, &n);
        let neg_euloer:BigInt = &(BigInt::from(euloer.clone())) - BigInt::from(n.clone());

        if jac != euloer.into() && jac != neg_euloer.into() {
            return false;
        }
    }

    return true;
}

pub fn generate_random_odd_number(bit_size: u64) -> BigUint{
    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);

    let mut generator = rand::rngs::StdRng::from_entropy();
    let mut test_num : BigUint = generator.gen_biguint(bit_size);

    while &test_num & &one == zero{
        test_num = generator.gen_biguint(bit_size);
    }
    return test_num
}
pub fn generate_random_odd_number_range(lbound: &BigUint, ubound: &BigUint) -> BigUint{
    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);

    let mut generator = rand::rngs::StdRng::from_entropy();
    let mut test_num : BigUint = generator.gen_biguint_range(lbound,ubound);

    while &test_num & &one == zero{
        test_num = generator.gen_biguint_range(lbound, ubound);
    }
    return test_num
}
// Implementing the Jacobi symbol computation in Rust

pub fn bi(n:i32) -> BigInt{
    num::BigInt::from(n)
}
pub fn bu(n:u32) -> BigUint{
    num::BigUint::from(n)
}


pub fn jacobi_symbol(top: &BigUint, bottom: &BigUint) -> i32 {

    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);
    let two = &one + &one;
    let three = &two + &one;
    let four = &two + &two;
    let five = &four + &one;
    let eight = &four + &four;
    
    if &(bottom & &one) != &one {
        panic!("bottom must be an odd integer");
    }

    let mut done = false;
    let mut result = 1;

    let mut top = (top % bottom).clone();
    let mut bottom = bottom.clone();

    while &top != &zero {
        // Rule 1
        // println!("|---|");
        // print!("\\{bottom}/");

        let tmp = &top % &bottom;
        top = tmp;
        // println!("{} / {}", top, bottom);

        // Rule 4, pull out the twos and see how it effects the rest of the vibe
        while &top > &zero && &top & BigUint::from(1_u32) == zero {
            top = (&top / &two);
            if n_is_a_mod_p(&bottom, &three, &eight) || n_is_a_mod_p(&bottom, &five, &eight) {
                result = -result;
            }
        }

        // Rule 5
        if is_odd(&top) {
            // Inverse and invert potentally
            swap(&mut top, &mut bottom);;
            if n_is_a_mod_p(&top, &three, &four) && n_is_a_mod_p(&bottom, &three, &four) {
                result = -result;
            }
        } 
    }
    if &bottom == &one {
        result
    } else {
        0
    }
}

pub fn n_is_a_mod_p(n : &BigUint,a: &BigUint,p: &BigUint) -> bool{
    return &(n % p) == a;
}
pub fn is_odd(n:&BigUint) -> bool{
    return (n & BigUint::from(1_u32)) == BigUint::from(1_u32);
}



// struct user{
//     alias: &str,
//     id_public_key:
//     url_user_aviableat
// }
 
// sender: hi! give me your my public key!
// [public key]
// sender: sends message 


fn gcd(num : BigUint, mod_n : BigUint) -> BigUint{
    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);
    let two = &one + &one;
    let three = &two + &one;
    let four = &two + &two;
    let five = &four + &one;
    let eight = &four + &four;

    let mut a = mod_n;
    let mut b = num;

    let mut done = false;
    let mut gcd = zero.clone();

    // From remainter to tuple of scales of mod_n and num

    while !done {
        if &(&a % &b) == &zero || &b == &one{
            gcd = b.clone();
            done = true;
        }
        
        if (&b < &zero){
            return one;
        }

        let mut counter = BigUint::from(1_u32);
        let mut dup_a = a.clone();

        while dup_a >= &two * &b {
            dup_a = dup_a - &b;
            let tmp = counter + &one;
            counter = (tmp);
        }
        let remainder = &a - (&b * &counter);
        
        let a_scale = 1;
        let b_scale = counter;
        
        a = b;
        b = remainder;
    }

    return gcd;
}


fn inverse_mod_n_biguint(num : BigUint, mod_n : BigUint) -> (BigInt,BigInt){
    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);
    let two = &one + &one;
    let three = &two + &one;
    let four = &two + &two;
    let five = &four + &one;
    let eight = &four + &four;

    let mut a = mod_n;
    let mut b = num;

    let mut done = false;
    let mut gcd = zero.clone();

    // From remainter to tuple of scales of mod_n and num
    let mut rem_map : std::collections::HashMap<BigInt,(BigInt,BigInt)>= std::collections::HashMap::new();

    rem_map.insert(a.clone().into(), (one.clone().into(),zero.clone().into()));
    rem_map.insert(b.clone().into(), (zero.clone().into(),one.clone().into()));

    while !done {
        if &(&a % &b) == &zero || &b == &one{
            gcd = b.clone();
            done = true;
        }

        if (&b < &zero){
            return (one.clone().into(),one.clone().into());
        }

        let mut dup_a = a.clone();
        let mut counter = &dup_a / &b; 

        let remainder = &a - (&b * &counter);
        
        let a_scale = &one;
        let b_scale = &counter;

        let known_remainder_a = rem_map.get(&a.into()).expect("Value of A should be in map");
        let known_remainder_b = rem_map.get(&(b.clone()).into()).expect("Value of B should be in map");

        let tmp1 : BigInt = counter.clone().into();
        let tmp2 : BigInt = counter.into();

        let first: BigInt = known_remainder_a.0.clone() -  (known_remainder_b.0.clone() * tmp1);
        let second: BigInt = known_remainder_a.1.clone() - (known_remainder_b.1.clone() * tmp2);

        let new_tuple = (first,second);
        rem_map.insert(remainder.clone().into(), new_tuple);

        a = b.clone();
        b = remainder.clone();
    }

    if &gcd != &one {
        println!("Not co-prime/no inverse");
        return (zero.clone().into(),zero.clone().into());
    }

    // for k in rem_map.iter() {
    //     println!("{}, {}x{} {}x{}", k.0, mod_n, k.1.0,num,k.1.1);
    // }

    let val = rem_map.get(&one.into()).unwrap();
    return (val.0.clone().into(), val.1.clone().into());
}
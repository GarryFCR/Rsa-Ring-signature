extern crate aes;
extern crate block_modes;
extern crate hex;
extern crate hex_literal;
extern crate rand;
extern crate rsa;
extern crate sha2;

use std::vec;

use aes::Aes256;
use aes::cipher::generic_array::typenum::Len;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hex_literal::hex;
use rand::rngs::OsRng;
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
pub struct Rsasign {
    set: Vec<RsaPublicKey>,
    signer: RsaPrivateKey,
}

impl Rsasign {
    //initialising the struct tha stores the members public keys and the signers private key
    pub fn init(list: Vec<RsaPublicKey>, e: RsaPrivateKey) -> Rsasign {
        Rsasign {
            set: list,
            signer: e,
        }
    }

    pub fn sign(&self, m: String) -> Vec<BigUint> {
        //Choose a key
        let key = hash(m);
        //Pick a random glue value
        let glue = generate_rand(1)[0].clone();

        //Pick random xi ’s and calculate yi's
        let mut xi_list: Vec<BigUint> = vec![];
        let mut yi_list: Vec<BigUint> = vec![];
        let mut index: u8 = 0;
        let mut pos: u8 = 0;
        for i in self.set.iter() {
            if *i != RsaPublicKey::from(self.signer.clone()) {
                let x = generate_rand(1);
                xi_list.push(x[0].clone());
                let y = g(x[0].clone(), i.clone());
                yi_list.push(y);
            } else {
                pos = index;
            }
            index += 1;
        }

        //Solve C_k,v (y1,y2 , . . . , yr)
        let mut c = BigUint::from_bytes_be(b"");
        let mut xor = glue.clone();
        for j in 0..pos {
            xor ^= yi_list[j as usize].clone();
            c = encrypt(key.clone(), xor.to_str_radix(16));
        }

        let mut v = glue.clone();
        for j in ((pos + 1)..index + 1).rev() {
            v = decrypt(key.clone(), v);
            v = v ^ yi_list[j as usize].clone();
        }

        //Solve C_k,v (y1,y2 , . . . , yr) = v for ys
        let mut y_s = decrypt(key.clone(), v);
        y_s = y_s ^ c;
        //g^(-1)
        let pub_key = RsaPublicKey::from(self.signer.clone());
        let d = self.signer.d();
        let n = pub_key.n();
        // let f_r = y_s.clone()%n;
        let q = y_s.clone() / n;
        let r = y_s;
        r.modpow(d, n);

        let x_s = q * n + r;
        xi_list[pos as usize] = x_s;
        return xi_list;
    }
}

//trapdoor function
pub fn g(x: BigUint, pub_key: RsaPublicKey) -> BigUint {
    //let pub_key = RsaPublicKey::from(self.signer.clone());
    let n = pub_key.n();
    let e = pub_key.e();
    let q = x.clone() / n;
    let r = x % n;
    let fr = r.modpow(e, n);
    let gx = q * n + fr;
    return gx;
}
//Generates a list of rsa key pairs
pub fn generate_keys(bit: usize, no: u8) -> Vec<RsaPrivateKey> {
    let mut priv_list: Vec<RsaPrivateKey> = vec![];

    let mut rng = OsRng;
    let mut i: u8 = 0;
    while i < no {
        priv_list.push(RsaPrivateKey::new(&mut rng, bit).expect("failed to generate a key"));
        i += 1;
    }

    return priv_list;
}

pub fn hash(m: String) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(m);
    let result = hasher.finalize();

    let num = BigUint::from_radix_be(&result, 256).unwrap();
    return num;
}

pub fn generate_rand(n: u8) -> Vec<BigUint> {
    let mut list: Vec<BigUint> = vec![];
    let mut i: u8 = 0;
    while i < n {
        let temp = rand::random::<u128>();
        list.push(BigUint::from(temp));
        i += 1;
    }
    return list;
}

pub fn encrypt(key: BigUint, m: String) -> BigUint {
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let key_new = key.to_str_radix(16);
    let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let cipher = Aes256Cbc::new_from_slices(&key_new.into_bytes(), &iv).unwrap();

    // buffer must have enough space for message+padding
    let mut buffer = [0u8; 32];
    // copy message to the buffer
    let pos = m.len();
    buffer[..pos].copy_from_slice(&m.into_bytes());

    let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
    let cipher = BigUint::from_radix_be(ciphertext, 256).unwrap();

    println!("cipher:{:?}", cipher);
    return cipher;
}

pub fn decrypt(key: BigUint, m: BigUint) -> BigUint {
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let key_new = key.to_str_radix(16);
    let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let cipher = Aes256Cbc::new_from_slices(&key_new.into_bytes(), &iv).unwrap();

    let mut buf = m.to_bytes_be();
    let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();
    let num = BigUint::from_radix_be(decrypted_ciphertext, 256).unwrap();
    println!("Decipher{:?}", num);
    return num;
}

pub fn verify(pub_key_list :Vec<RsaPublicKey>, xi_list: Vec<BigUint>, glue: BigUint, m:String) -> bool {

    let mut yi_list = vec![];
    for i in 0..xi_list.len() {
        yi_list.push(g(xi_list[i].clone(), pub_key_list[i].clone() ));
    }
    let key = hash(m);
    let mut c = BigUint::from_bytes_be(b"");
        let mut xor = glue.clone();
        for j in 0..xi_list.len() {
            xor ^= yi_list[j as usize].clone();
            c = encrypt(key.clone(), xor.to_str_radix(16));
        }

    if c == glue {
        return true;
    }

    return false;
    
}

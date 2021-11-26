extern crate aes;
extern crate rand;
extern crate rsa;
extern crate sha2;
extern crate sp_core;

#[path = "symmetric.rs"]
mod symmetric;
use rand::{rngs::OsRng, RngCore};
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use sp_core::hashing::blake2_128;
use std::vec;
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
    //sign a message
    pub fn sign(&self, m: String) -> (Vec<BigUint>, BigUint) {
        //Choose a key
        let key = hash256(m);
        //Pick a random glue value
        let glue = generate_rand256bytes();
        //Pick random xi ’s and calculate yi's
        let mut xi_list: Vec<BigUint> = vec![];
        let mut yi_list: Vec<BigUint> = vec![];
        let mut index: u8 = 0;
        let mut pos: u8 = 0;
        for i in self.set.iter() {
            if *i != RsaPublicKey::from(self.signer.clone()) {
                let x = generate_rand256bytes();
                xi_list.push(x.clone());
                let y = g(x.clone(), i.clone());
                yi_list.push(y);
            } else {
                yi_list.push(BigUint::from_bytes_be(b""));
                xi_list.push(BigUint::from_bytes_be(b""));
                pos = index;
            }
            index += 1;
        }

        //Solve C_k,v (y1,y2 , . . . , yr)
        let mut enc = glue.clone();
        for j in 0..pos {
            let c = enc ^ yi_list[j as usize].clone();
            enc = symmetric::encrypt(key.clone(), c.clone());
        }

        let mut v = glue.clone();
        for j in ((pos + 1)..index).rev() {
            let dec = symmetric::decrypt(key.clone(), v);
            v = dec ^ yi_list[j as usize].clone();
        }

        //Solve C_k,v (y1,y2 , . . . , yr) = v for ys
        let mut y_s = symmetric::decrypt(key.clone(), v);
        y_s = y_s ^ enc;
        //g^(-1)
        let pub_key = RsaPublicKey::from(self.signer.clone());
        let d = self.signer.d();
        let n = pub_key.n();
        let f_r = y_s.clone() % n;
        let q = y_s.clone() / n;
        let r = f_r.modpow(d, n);

        let x_s = q * n + r.clone();
        xi_list[pos as usize] = x_s;
        return (xi_list, glue);
    }
}

//trapdoor function
fn g(x: BigUint, pub_key: RsaPublicKey) -> BigUint {
    let n = pub_key.n();
    let e = pub_key.e();
    let q = x.clone() / n;
    let r = x % n;
    let fr = r.modpow(e, n);
    let gx = q * n + fr;
    return gx;
}

//generate a random 128 bit
/*pub fn generate_rand() -> BigUint {
    let temp = rand::random::<u128>();
    let rand_x = temp >> 1; //so that x is less than 128bits and y is atmost 16 bytes
    return BigUint::from(rand_x);
}*/

//verify the ring signature
pub fn verify(
    pub_key_list: Vec<RsaPublicKey>,
    xi_list: Vec<BigUint>,
    glue: BigUint,
    m: String,
) -> bool {
    let mut yi_list = vec![];
    for i in 0..xi_list.len() {
        yi_list.push(g(xi_list[i].clone(), pub_key_list[i].clone()));
    }
    let key = hash256(m);

    let mut enc = glue.clone();
    for j in 0..xi_list.len() {
        let c = enc ^ yi_list[j as usize].clone();
        enc = symmetric::encrypt(key.clone(), c.clone());
    }
    if enc == glue {
        return true;
    }

    return false;
}

//using sha256 hash on a message and then using a non-cryptographic hash to get the 128 bit hash
pub fn hash256(m: String) -> BigUint {
    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(m.into_bytes());
    // read hash digest and consume hasher
    let result = hasher.finalize();
    let x = result.as_slice();

    let hash128 = blake2_128(x);
    return BigUint::from_bytes_be(&hash128);
}
//generate a random 256 bytes
pub fn generate_rand256bytes() -> BigUint {
    let mut key = [0u8; 256];
    OsRng.fill_bytes(&mut key);
    let rand_num = BigUint::from_bytes_be(&key);
    return rand_num;
}

extern crate aes;
extern crate rand;
extern crate rsa;
extern crate sp_core;

#[path = "symmetric.rs"]
mod symmetric;
use rand::rngs::OsRng;
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
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

    pub fn sign(&self, m: String) -> (Vec<BigUint>, BigUint) {
        //Choose a key
        let key = hash(m);
        //Pick a random glue value
        let temp = BigUint::from(rand::random::<u128>()).to_str_radix(16);
        let glue = hash(temp);

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
                yi_list.push(BigUint::from(rand::random::<u64>()));
                pos = index;
            }
            index += 1;
        }

        //Solve C_k,v (y1,y2 , . . . , yr)
        let mut c = BigUint::from_bytes_be(b"");
        let mut xor = glue.clone();
        for j in 0..pos {
            xor ^= yi_list[j as usize].clone();
            c = symmetric::encrypt(key.clone(), xor.clone());
        }

        let mut v = glue.clone();
        for j in ((pos + 1)..index).rev() {
            v = symmetric::decrypt(key.clone(), v);
            v ^= yi_list[j as usize].clone();
        }

        //Solve C_k,v (y1,y2 , . . . , yr) = v for ys
        let mut y_s = symmetric::decrypt(key.clone(), v);
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
        return (xi_list, glue);
    }
}

//trapdoor function
fn g(x: BigUint, pub_key: RsaPublicKey) -> BigUint {
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
    let num = blake2_128(&m.into_bytes());
    return BigUint::from_bytes_be(&num);
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
    let key = hash(m);
    let mut c = BigUint::from_bytes_be(b"");
    let mut xor = glue.clone();
    for j in 0..xi_list.len() {
        xor ^= yi_list[j as usize].clone();
        c = symmetric::encrypt(key.clone(), xor.clone());
    }

    if c == glue {
        return true;
    }

    return false;
}

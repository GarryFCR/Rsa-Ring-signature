extern crate hex;
extern crate rand;
extern crate rsa;
extern crate sha2;

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

pub struct Rsasign {
    set: Vec<RsaPublicKey>,
    signer: RsaPrivateKey,
}

impl Rsasign {
    //trapdoor function
    pub fn g(&self /*, x: BigUint*/) {
        let pub_key = RsaPublicKey::from(self.signer.clone());
        let n = pub_key.n();
        println!("N:::::{:?}", n);
    }

    //initialising the struct tha stores the members public keys and the signers private key
    pub fn init(list: Vec<RsaPublicKey>, e: RsaPrivateKey) -> Rsasign {
        Rsasign {
            set: list,
            signer: e,
        }
    }

    /* pub fn sign(&self, m: String) {
        let key = hash(m);
        let glue = generate_rand(1);
        let mut xi_list: Vec<BigUint> = vec![];
        let mut yi_list: Vec<BigUint> = vec![];

        for i in self.set.iter() {
            if *i != RsaPublicKey::from(self.signer.clone()) {
                let x = generate_rand(1);
                xi_list.push(x[0].clone());
                let y = self.g();
            }
        }
    }*/
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

pub fn encrypt(key: String, m: String) -> BigUint {
    let mut text = String::from("");
    text.push_str(&key);
    text.push_str(&m);
    let hash_text = hash(text);
    return hash_text;
}

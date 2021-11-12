extern crate hex;
extern crate rand;
extern crate rsa;

use rand::rngs::OsRng;
use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};

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

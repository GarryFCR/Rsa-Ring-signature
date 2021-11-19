extern crate rand;
extern crate rsa;

mod rsa_ring;
mod symmetric;
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};

fn main() {
    //key generation
    println!("\nGenerating 5 random rsa key pairs...");
    let list = generate_keys(128, 5);
    //init
    println!("\nInitialising Rsasign struct...");
    let e = list[2].clone(); //signer
    let mut pub_list: Vec<RsaPublicKey> = vec![];
    for i in list.iter() {
        pub_list.push(RsaPublicKey::from(i));
    }
    let test = pub_list.clone();
    let r = rsa_ring::Rsasign::init(pub_list, e);

    //sign
    println!("\nSigning the message (\"Hello, world!\").");
    let hello = String::from("Hello, world!");
    let (xi_list, glue) = r.sign(hello.clone());
    println!("\nGenerated x_i's :\n{:?}\n", xi_list);
    println!("Generated random glue : {:?}\n", glue);

    //verify
    println!(
        "Verification : {:?}",
        rsa_ring::verify(test, xi_list, glue, hello.clone())
    );
    /*
    //symmetric
    let key = rsa_ring::hash(String::from("Helld"));
    let text = rsa_ring::hash(String::from("Hello"));
    let enc = symmetric::encrypt(key.clone(), text.clone());
    let dec = symmetric::decrypt(key.clone(), enc);

    println!("{:?}\n{:?}", text.to_bytes_be(), dec.to_bytes_be());
    */
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

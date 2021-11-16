extern crate block_modes;
extern crate hex;
extern crate rand;
extern crate rsa;

mod rsa_ring;
mod symmetric;

use rsa::{BigUint, RsaPublicKey};

fn main() {
    //key generation
    let list = rsa_ring::generate_keys(128, 5);
    //init
    let e = list[1].clone(); //signer
    let mut pub_list: Vec<RsaPublicKey> = vec![];
    for i in list.iter() {
        pub_list.push(RsaPublicKey::from(i));
    }
    let test = pub_list.clone();
    let r = rsa_ring::Rsasign::init(pub_list, e);

    //sign
    let hello = String::from("Hello, world!");
    let (xi_list, glue) = r.sign(hello.clone());
    println!("{:?}", xi_list);
    println!("{:?}", glue);
    //verify
    println!("{:?}", rsa_ring::verify(test, xi_list, glue, hello.clone()));
    /*
    //symmetric
    let key = rsa_ring::hash(String::from("Helld"));
    let text = rsa_ring::hash(String::from("Hello"));
    let enc = symmetric::encrypt(key.clone(), text.clone());
    let dec = symmetric::decrypt(key.clone(), enc);

    println!("{:?}\n{:?}", text.to_bytes_be(), dec.to_bytes_be());
    */
}

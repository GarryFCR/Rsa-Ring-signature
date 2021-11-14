extern crate hex;
extern crate rand;
extern crate rsa;
mod rsa_ring;

use rsa::{BigUint, RsaPublicKey};

fn main() {
    //key generate
    let list = rsa_ring::generate_keys(512, 2);

    let e = list[0].clone();
    let temp = list[0].clone();

    let mut pub_list: Vec<RsaPublicKey> = vec![];

    for i in list.iter() {
        pub_list.push(RsaPublicKey::from(i));
    }

    //init
    let r = rsa_ring::Rsasign::init(pub_list, e);

    //g()
    //let xy = BigUint::from_bytes_be(b"A");
    //println!("\n{:?}", G);

    //r.g();
    println!("\n{:?}\n", temp);
    let hello = String::from("Hello, world!");

    //hash
    rsa_ring::hash(hello);

    //encrypt
    let random_list = rsa_ring::generate_rand(1);
    println!("{:?}", random_list);

    let key = rsa_ring::generate_rand(1);
    println!("{:?}", key);
    let text = String::from("Hello world");
    let m = rsa_ring::encrypt(key[0].clone(), text);

    //decrypt
    rsa_ring::decrypt(key[0].clone(), m);

    let byte = String::from("Hello world");

    println!("{:?}", BigUint::from_bytes_be(byte.as_bytes()));
}

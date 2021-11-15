extern crate hex;
extern crate rand;
extern crate rsa;
mod rsa_ring;

use rsa::{BigUint, RsaPublicKey};

fn main() {
    //key generation
    let list = rsa_ring::generate_keys(512, 5);
    //init
    let e = list[0].clone(); //signer
    let mut pub_list: Vec<RsaPublicKey> = vec![];
    for i in list.iter() {
        pub_list.push(RsaPublicKey::from(i));
    }
    let r = rsa_ring::Rsasign::init(pub_list, e);

    //sign
    let hello = String::from("Hello, world!");
    let (xi_list, glue) = r.sign(hello);
    println!("{:?}", xi_list);
    println!("{:?}", glue);

    /*
        //g()
        //let xy = BigUint::from_bytes_be(b"A");
        //println!("\n{:?}", G);
        let temp = list[0].clone();
        //r.g();
        println!("\n{:?}\n", temp);
        let hello = String::from("Hello, world!");

        //hash
        rsa_ring::hash(hello);
    */
    /*
    //encrypt
    let key = rsa_ring::hash(String::from("Helld"));
    let text = String::from("Hello world");
    let m = rsa_ring::encrypt(key.clone(), text);

    //decrypt
    let de = rsa_ring::decrypt(key.clone(), m);

    let byte = String::from("Hello world");

    println!("{:?} {:?}", de, BigUint::from_bytes_be(&byte.into_bytes()));*/
}

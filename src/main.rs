extern crate hex;
extern crate rand;
extern crate rsa;
mod rsa_ring;

//use std::str;

//mod rsa_ring;
//use rand::rngs::OsRng;
use rsa::{BigUint, RsaPublicKey};

fn main() {
    /*
        //Trying--------------------------------------------------------------------------
        let mut rng = OsRng;
        let bits = 512;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&priv_key);

        // Encrypt
        let data = b"hello world";
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let enc_data = public_key
            .encrypt(&mut rng, padding, &data[..])
            .expect("failed to encrypt");
        assert_ne!(&data[..], &enc_data[..]);

        // Decrypt
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let dec_data = priv_key
            .decrypt(padding, &enc_data)
            .expect("failed to decrypt");
        assert_eq!(&data[..], &dec_data[..]);

        let hex_string = hex::encode(enc_data.clone());
        let num = BigUint::from_radix_be(&enc_data, 256).unwrap();
        let mystr = str::from_utf8(&dec_data).unwrap();
        println!("\nDecrypted :\t{}", mystr);
        println!("\nDecrypted :\t{} \n{}", hex_string, num);
        //-----------------------------------------------------------------------------------

    */

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
    r.g();
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

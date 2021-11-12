extern crate hex;
extern crate rand;
extern crate rsa;
mod rsa_ring;

use std::str;

//mod rsa_ring;
use rand::rngs::OsRng;
use rsa::{BigUint, PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

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
    let list = rsa_ring::generate_keys(512, 2);
    // println!("{:?}", list);

    let e = list[0].clone();
    let temp = list[0].clone();

    let mut pub_list: Vec<RsaPublicKey> = vec![];

    for i in list.iter() {
        pub_list.push(RsaPublicKey::from(i));
    }
    let r = rsa_ring::Rsasign::init(pub_list, e);
    r.g();
    println!("\n{:?}\n", temp);
}

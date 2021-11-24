use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, NewBlockCipher};
use aes::{Aes128, Block};
use rsa::BigUint;

#[allow(dead_code)]
//encrypt multiple 128 bit blocks using a 128 bit key
pub fn encrypt(key: BigUint, m: BigUint) -> BigUint {
    let slices = key.to_bytes_be();
    let text = m.to_bytes_be();
    let no_of_blocks = text.len() / 16;
    assert_eq!(slices.len(), 16);
    let key = GenericArray::from_slice(&slices);

    let mut cipher_array: Vec<u8> = vec![];

    for i in 0..no_of_blocks {
        let mut part: Vec<u8> = vec![];
        for j in 0..16 {
            part.push(text[(i * 16) + j]);
        }
        let block = Block::from_slice(&part);
        let mut block_test = block.clone();

        // Initialize cipher
        let cipher = Aes128::new(&key);
        // Encrypt block in-place
        cipher.encrypt_block(&mut block_test);
        cipher_array.extend_from_slice(block_test.as_slice());
    }

    return BigUint::from_bytes_be(&cipher_array);
}

#[allow(dead_code)]
//decrypt multiple 128 bit blocks using a 128 bit key
pub fn decrypt(key: BigUint, m: BigUint) -> BigUint {
    let slices = key.to_bytes_be();
    let text = m.to_bytes_be();
    let no_of_blocks = text.len() / 16;
    assert_eq!(slices.len(), 16);

    let key = GenericArray::from_slice(&slices);

    let mut cipher_array: Vec<u8> = vec![];

    for i in 0..no_of_blocks {
        let mut part: Vec<u8> = vec![];
        for j in 0..16 {
            part.push(text[(i * 16) + j]);
        }
        let block = Block::from_slice(&part);
        let mut block_test = block.clone();

        // Initialize cipher
        let cipher = Aes128::new(&key);
        // Encrypt block in-place
        cipher.decrypt_block(&mut block_test);
        cipher_array.extend_from_slice(block_test.as_slice());
    }

    return BigUint::from_bytes_be(&cipher_array);
}

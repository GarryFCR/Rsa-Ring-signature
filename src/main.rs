mod base_58;

fn main() {
    let mut numbers: [u8; 4] = [1, 2, 3, 4];
    let code = base_58::base_58(&mut numbers);
    println!("{}", code);

    let set = base_58::base_58_decode(code);
    for i in set.iter() {
        println!("{}", i);
    }
}

mod base_58;

fn main() {
    let mut numbers: [u8; 4] = [1, 2, 3, 4];
    println!("Hello, world!");
    base_58::base_58(&mut numbers);
}

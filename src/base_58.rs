// Encode a bytes as an array into a base-58 encoded string

pub fn base_58(buf: &mut [u8]) -> String {
    let table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let base_table: Vec<char> = table.chars().collect();

    let mut num_be = as_u32_be(buf);

    let base: u32 = 58;
    let mut index: usize;
    let mut code = String::from("");

    while num_be != 0 {
        index = (num_be % base) as usize;
        num_be = num_be / base;
        let temp = base_table[index].to_string();
        code = temp + &code;
    }
    return code;
}

fn as_u32_be(array: &mut [u8]) -> u32 {
    let mut num: u32 = 0;

    let mut arr_len = array.len() - 1;

    for i in 0..array.len() {
        num = num + ((array[i] as u32) << (arr_len * 8));
        if arr_len != 0 {
            arr_len = arr_len - 1;
        }
    }
    return num;
}

// String to bytes array

pub fn base_58_decode(s: String) -> Vec<u8> {
    let table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let base_table: Vec<char> = table.chars().collect();
    let s_array: Vec<char> = s.chars().collect();

    let mut x: u32 = 0;
    let mut index: usize = 0;

    for i in s_array.iter() {
        println!("{}", i);
        for j in 0..base_table.len() {
            if i.eq(&base_table[j]) {
                index = j;
                break;
            }
        }
        x = x * 58;
        x = x + (index as u32);
    }

    println!("{}", x);
    let mut numbers: Vec<u8> = vec![];
    while x > 0 {
        numbers.push((x & 15) as u8);
        x = x >> 8;
    }
    numbers.reverse();
    return numbers;
}

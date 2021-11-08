// Encode a byte array into a base-58 encoded string

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

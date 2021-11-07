pub fn base_58(buf: &mut [u8]) {
    //const BASE58_TABLE: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let num = as_u32_be(buf);

    println!("{}", num);
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

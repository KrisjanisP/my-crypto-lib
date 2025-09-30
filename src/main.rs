use std::io;

// checks length and parity bits
fn valid_des_key(key: &[u8]) -> bool {
    return key.len() == 8 && key.iter().all(|&b| b.count_ones() % 2 == 0);
}

fn feistel_function(right: &[u8], key: &[u8]) -> [u8; 4] {

}

const DES_ROUNDS: usize = 16;
fn des(block: &[u8], key: &[u8]) -> [u8; 8] {
    assert!(valid_des_key(key));
    assert!(block.len() == 8);

    let mut left: [u8; 4] = block[..4].try_into().unwrap();
    let mut right: [u8; 4] = block[4..].try_into().unwrap();
    for _ in 0..DES_ROUNDS {
        let f = feistel_function(&right, &key);
        (left, right) = (right, std::array::from_fn(|i| left[i] ^ f[i]));
    }

    [left, right].concat().try_into().unwrap()
}

fn main() {
    println!("Hello, world!");
}

//! triple des(3des) ecb pkcs5 padding encrypt/decrypt function for rust, use openssl crypto
//! library.
//! refer to <http://blog.csdn.net/lyjinger/article/details/1722570>
//! coded by vinoca.
//! 2017.11.24

#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

extern crate libc;

use libc::c_uchar;
use base64::{Engine as _, engine::general_purpose};

pub type DES_cblock = [c_uchar; 8];
pub type const_DES_cblock = [c_uchar; 8];
pub type DES_LONG = libc::c_ulong;

#[repr(C)]
#[derive(Default, Debug)]
pub struct DES_key_schedule {
    ks: [DES_cblock; 16],
}


#[link(name = "crypto")]
extern {
    fn DES_set_key_unchecked(block_key: *const c_uchar, ks: *mut DES_key_schedule);
    fn DES_ecb3_encrypt(input: *const c_uchar, output: *mut c_uchar,
                            ks1: *const DES_key_schedule,
                            ks2: *const DES_key_schedule,
                            ks3: *const DES_key_schedule,
                            enc: libc::c_int,
    );
}

pub const Encrypt: i32 = 1;
pub const Decrypt: i32 = 0;

pub fn des_ecb3(data: &[u8], key: &str, mode:i32) -> Vec<u8> {

    // pad data
    let mut data = data.to_vec();
    let mut pad = 8 - data.len() % 8;
    if pad == 8 {
        pad = 0;
    }
    for _ in 0..pad {
        data.push(pad as u8);
    }

    // pad key
    let mut key = key.as_bytes().to_vec();
    key.truncate(24);
    for _ in 0..24 - key.len() {
        key.push(0);
    }

    let mut ks = Vec::new();
    for _ in 0..3 {
        ks.push(DES_key_schedule::default());
    }
    let mut out_block = vec![0u8; 8];
    let mut output = Box::new(Vec::with_capacity(data.len()));
    unsafe {
        for (i, item) in key.chunks(8).enumerate() {
            DES_set_key_unchecked(item.as_ptr(), &mut ks[i]);
        }

        for i in data.chunks(8) {
            DES_ecb3_encrypt(i.as_ptr(), out_block.as_mut_ptr(), &ks[0], &ks[1], &ks[2], mode);
            output.extend_from_slice(out_block.as_slice());
        }
    }
    if mode == Decrypt {
        let pad = *output.last().unwrap();
        (*output).truncate(data.len() - pad as usize);
        *output
    } else {
        *output
    }
}

#[cfg(test)]
mod tests {
    use super::{Encrypt, Decrypt, des_ecb3};
    #[test]
    fn test_des_ecb3() {
        println!("Que merda eh essa?");
        let data = "hello world!";
        let key = "01234567899876543210";
        let e = des_ecb3(&data.as_bytes(), &key, Encrypt);
        let d = des_ecb3(&e, &key, Decrypt);
        println!("I have no idea this is: {:?}", d);
        println!("{:?}", std::str::from_utf8(&d).unwrap());

    }
}

fn main(){
        println!("Que merda eh essa?");
        let data = "ABCDEFGGIHKLMNOPQRSTUVWXYZ";
        let key = "01234567899876543210";
        let e = des_ecb3(&data.as_bytes(), &key, Encrypt);
        let encrypted_data = general_purpose::STANDARD
        .encode(&e);
        //.unwrap();
        let d = des_ecb3(&e, &key, Decrypt);
        println!("Encrypted in numeric: {:?}", encrypted_data);
        println!("Decrypted in numeric: {:?}", d);
        println!("Decrypted in string : {:?}", std::str::from_utf8(&d).unwrap());
}

// extern crate libc;
// #[macro_use]
// extern crate lazy_static;
// use libc::c_ulonglong;
use libsodium_sys::*;
use ssh_agent::proto::public_key::PublicKey;

use std::ffi;

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

pub fn initialize_library() -> bool {
    let sodium_ret: i32 = unsafe { sodium_init() };
    sodium_ret >= 0
}

pub fn verify_signature(
    content: &[u8],
    pubkey: &PublicKey,
    signature: &[u8],
) -> Result<bool, ErrType> {

        


    Err(RsshErr::PARSE_PUBKEY_ERR.into_ptr())
}

pub fn gen_challenge() -> Result<Vec<u8>, ErrType> {
    let mut buffer: Vec<u8> = vec![0; 32];
    let buf_ref = buffer.as_mut_slice();
    unsafe {
        randombytes_buf(buf_ref.as_mut_ptr() as *mut ffi::c_void, buf_ref.len());
    }
    Ok(buffer)
}

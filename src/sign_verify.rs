use ssh_agent::proto::public_key::PublicKey;

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

pub fn verify_signature(
    content: &[u8],
    pubkey: &PublicKey,
    signature: &[u8],
) -> Result<(), ErrType> {
    Err(RsshErr::PARSE_PUBKEY_ERR.into_ptr())
}
pub fn gen_challenge() -> Result<Vec<u8>,ErrType> {
    Ok(vec![4,5,2])
}

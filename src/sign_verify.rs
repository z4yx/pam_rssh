// extern crate libc;
// #[macro_use]
// extern crate lazy_static;
// use libc::c_ulonglong;
use openssl::pkey::{PKey, Public};
use openssl::nid::Nid;
use openssl::ec::{EcGroup,EcPoint,EcKey};
use ssh_agent::proto::public_key::PublicKey;

use std::ffi;

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

trait ToOpensslKey {
    fn to_pkey(&self) -> Result<PKey<Public>, ErrType>;
}
impl ToOpensslKey for PublicKey {
    fn to_pkey(&self) -> Result<PKey<Public>,ErrType> {
        let toEcKey = |nid, q:&Vec<u8>| -> Result<PKey<Public>,ErrType> {
            let group = EcGroup::from_curve_name(nid)?;
            let mut ctx = openssl::bn::BigNumContext::new()?;
            let pt = EcPoint::from_bytes(&group, q, &mut ctx)?;
            Ok(PKey::from_ec_key(EcKey::from_public_key(&group, &pt)?)?)
        };
        match self {
            PublicKey::EcDsa(input) => {
                println!("input.identifier={}", input.identifier);
                let nid = match input.identifier.as_str() {
                    "nistp256" => Nid::X9_62_PRIME256V1,
                    "nistp384" => Nid::SECP384R1,
                    "nistp521" => Nid::SECP521R1,
                    _ => return Err(RsshErr::PARSE_PUBKEY_ERR.into_ptr())
                };
                toEcKey(nid, &input.q)
            },
            // PublicKey::Ed25519(input) => {
            //     println!("input ed25519");
            //     toEcKey(Nid::SECP112R1, &input.enc_a)
            // },
            PublicKey::Rsa(input) => {
                use openssl::bn::BigNum;
                use openssl::rsa::Rsa;
                let e = BigNum::from_slice(&input.e)?;
                let n = BigNum::from_slice(&input.n)?;
                Ok(PKey::from_rsa(Rsa::from_public_components(n,e)?)?)
            },
            _ => Err(RsshErr::PARSE_PUBKEY_ERR.into_ptr())
        }
    }
}

pub fn initialize_library() -> bool {
    true
}

pub fn verify_signature(
    content: &[u8],
    pubkey: &PublicKey,
    signature: &[u8],
) -> Result<bool, ErrType> {
    use openssl::sign::Verifier;
    use openssl::hash::{hash, MessageDigest};

    let pkey = pubkey.to_pkey()?;
    let digest = hash(MessageDigest::sha256(), content)?;
    let mut verifier = Verifier::new_without_digest(&pkey)?;
    let ret = verifier.verify_oneshot(signature, &digest)?;

    Ok(ret)
}

pub fn gen_challenge() -> Result<Vec<u8>, ErrType> {
    let mut buffer: Vec<u8> = vec![0; 32];
    let buf_ref = buffer.as_mut_slice();
    openssl::rand::rand_bytes(buf_ref)?;
    Ok(buffer)
}

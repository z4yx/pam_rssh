use log::*;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use ssh_agent::proto::public_key::PublicKey;

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

trait ToOpensslKey {
    fn to_pkey(&self) -> Result<(PKey<Public>, Option<MessageDigest>), ErrType>;
}
impl ToOpensslKey for PublicKey {
    fn to_pkey(&self) -> Result<(PKey<Public>, Option<MessageDigest>), ErrType> {
        debug!("SSH public key to OpenSSL format:");
        match self {
            PublicKey::EcDsa(input) => {
                debug!("    ECDSA key identifier={}", input.identifier);
                let (nid, digest) = match input.identifier.as_str() {
                    "nistp256" => (Nid::X9_62_PRIME256V1, Some(MessageDigest::sha256())),
                    "nistp384" => (Nid::SECP384R1, Some(MessageDigest::sha384())),
                    "nistp521" => (Nid::SECP521R1, Some(MessageDigest::sha512())),
                    _ => return Err(RsshErr::ParsePubkeyErr.into_ptr()),
                };
                let group = EcGroup::from_curve_name(nid)?;
                debug!("    Curve group: {}", nid.long_name()?);
                let mut ctx = openssl::bn::BigNumContext::new()?;
                let pt = EcPoint::from_bytes(&group, &input.q, &mut ctx)?;
                let eckey = EcKey::from_public_key(&group, &pt)?;
                eckey.check_key()?;
                Ok((PKey::from_ec_key(eckey)?, digest))
            }
            PublicKey::Ed25519(input) => {
                debug!("    ED25519 key");
                Ok((
                    PKey::public_key_from_raw_bytes(&input.enc_a, openssl::pkey::Id::ED25519)?,
                    None,
                ))
            }
            PublicKey::Rsa(input) => {
                debug!("    RSA key");
                use openssl::bn::BigNum;
                use openssl::rsa::Rsa;
                let e = BigNum::from_slice(&input.e)?;
                let n = BigNum::from_slice(&input.n)?;
                let rsa = Rsa::from_public_components(n, e)?;
                Ok((PKey::from_rsa(rsa)?, Some(MessageDigest::sha256())))
            }
            _ => Err(RsshErr::ParsePubkeyErr.into_ptr()),
        }
    }
}

pub fn verify_signature(
    content: &[u8],
    pubkey: &PublicKey,
    signature: &[u8],
) -> Result<bool, ErrType> {
    use openssl::sign::Verifier;

    let (pkey, digest) = pubkey.to_pkey()?;
    let mut verifier = digest.map_or(Verifier::new_without_digest(&pkey), |d| {
        Verifier::new(d, &pkey)
    })?;
    let ret = verifier.verify_oneshot(signature, &content)?;

    Ok(ret)
}

pub fn gen_challenge() -> Result<Vec<u8>, ErrType> {
    let mut buffer: Vec<u8> = vec![0; 32];
    let buf_ref = buffer.as_mut_slice();
    openssl::rand::rand_bytes(buf_ref)?;
    Ok(buffer)
}

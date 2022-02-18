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
            PublicKey::Dss(input) => {
                debug!("    DSA key");
                use openssl::bn::BigNum;
                use openssl::dsa::Dsa;
                let p = BigNum::from_slice(&input.p)?;
                let q = BigNum::from_slice(&input.q)?;
                let g = BigNum::from_slice(&input.g)?;
                let y = BigNum::from_slice(&input.y)?;
                let dsa = Dsa::from_public_components(p, q, g, y)?;
                Ok((PKey::from_dsa(dsa)?, Some(MessageDigest::sha1())))
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

#[test]
fn test_dsa_sign_verify() {
    use openssl::sign::{Signer, Verifier};
    use openssl::dsa::Dsa;  
    use openssl::pkey::PKey;
    use openssl::hash::MessageDigest;

    // Generate a keypair
    let keypair = Dsa::generate(1024).unwrap();
    let keypair = PKey::from_dsa(keypair).unwrap();

    let data = b"hello, world!";
    let data2 = b"hola, mundo!";

    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha1(), &keypair).unwrap();
    signer.update(data).unwrap();
    signer.update(data2).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    println!("signature={} len={}", base64::encode(&signature), signature.len());

    // Verify the data
    let mut verifier = Verifier::new(MessageDigest::sha1(), &keypair).unwrap();
    verifier.update(data).unwrap();
    verifier.update(data2).unwrap();
    assert!(verifier.verify(&signature).unwrap());
}
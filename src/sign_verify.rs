use log::*;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use ssh_agent::proto;
use ssh_agent::proto::public_key::PublicKey;
use ssh_agent::proto::from_bytes;

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

trait ToOpensslKey {
    type OpensslKeyResult;
    fn to_pkey(&self) -> Self::OpensslKeyResult;
}
impl ToOpensslKey for PublicKey {
    type OpensslKeyResult = Result<(PKey<Public>, Option<MessageDigest>), ErrType>;

    fn to_pkey(&self) -> Self::OpensslKeyResult {
        let parse_ecdsa = |identifier: &String, q: &Vec<u8>| -> Self::OpensslKeyResult {
            let (nid, digest) = match identifier.as_str() {
                "nistp256" => (Nid::X9_62_PRIME256V1, Some(MessageDigest::sha256())),
                "nistp384" => (Nid::SECP384R1, Some(MessageDigest::sha384())),
                "nistp521" => (Nid::SECP521R1, Some(MessageDigest::sha512())),
                _ => return Err(RsshErr::ParsePubkeyErr.into_ptr()),
            };
            let group = EcGroup::from_curve_name(nid)?;
            debug!("    Curve group: {}", nid.long_name()?);
            let mut ctx = openssl::bn::BigNumContext::new()?;
            let pt = EcPoint::from_bytes(&group, &q, &mut ctx)?;
            let eckey = EcKey::from_public_key(&group, &pt)?;
            eckey.check_key()?;
            Ok((PKey::from_ec_key(eckey)?, digest))
        };
        debug!("SSH public key to OpenSSL format:");
        match self {
            PublicKey::EcDsa(input) => {
                debug!("    ECDSA key identifier={}", input.identifier);
                parse_ecdsa(&input.identifier, &input.q)
            }
            PublicKey::SkEcDsa(input) => {
                debug!("    ECDSA security key identifier={}", input.identifier);
                parse_ecdsa(&input.identifier, &input.q)
            }
            PublicKey::Ed25519(input) => {
                debug!("    ED25519 key");
                Ok((
                    PKey::public_key_from_raw_bytes(&input.enc_a, openssl::pkey::Id::ED25519)?,
                    None,
                ))
            }
            PublicKey::SkEd25519(input) => {
                debug!("    ED25519 security key");
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
        }
    }
}

fn build_asn1_integer(input: &[u8]) -> Vec<u8> {
    let mut bn = input;
    while bn.len() > 1 && bn[0] == 0 {
        bn = &bn[1..];
    }
    let mut header = if bn[0] & 0x80 == 0 {
        vec![0x02, bn.len() as u8]
    } else {
        vec![0x02, (bn.len() + 1) as u8, 0]
    };
    header.extend_from_slice(bn);
    header
}

fn decode_signature_blob(blob: &[u8], pubkey: &PublicKey) -> Result<Vec<u8>, ErrType> {
    match pubkey {
        PublicKey::SkEcDsa(_) | PublicKey::EcDsa(_) => {
            use openssl::bn::BigNum;
            use openssl::ecdsa::EcdsaSig;

            let data: proto::EcDsaSignatureData = from_bytes(&blob)?;
            trace!("ECDSA signature: r={:02X?} s={:02X?}", data.r, data.s);
            let r = BigNum::from_slice(&data.r)?;
            let s = BigNum::from_slice(&data.s)?;

            Ok(EcdsaSig::from_private_components(r, s)?.to_der()?)
        }
        PublicKey::Dss(_) => {
            if blob.len() != 40 {
                return Err(RsshErr::InvalidSigErr.into_ptr());
            }
            trace!(
                "DSA signature: r={:02X?} s={:02X?}",
                &blob[..20],
                &blob[20..]
            );
            // Blob to ASN.1 SEQUENCE(INTEGER,INTEGER)
            let mut r = build_asn1_integer(&blob[..20]);
            let mut s = build_asn1_integer(&blob[20..]);
            let mut seq = vec![0x30, (r.len() + s.len()) as u8];
            seq.append(&mut r);
            seq.append(&mut s);
            Ok(seq)
        }
        _ => {
            trace!("signature: blob={:02X?}", blob);
            Ok(blob.to_vec())
        }
    }
}

fn preprocess_content_and_sig(
    msg: &[u8],
    ssh_sig: &[u8],
    pubkey: &PublicKey,
) -> Result<(Vec<u8>, Vec<u8>), ErrType> {
    use byteorder::{BigEndian, WriteBytesExt};
    use openssl::sha::sha256;
    match pubkey {
        // regenerate the message as per U2F spec
        PublicKey::SkEcDsa(_) | PublicKey::SkEd25519(_) => {
            let sig: proto::SkSignature = from_bytes(ssh_sig)?;
            let app = match pubkey {
                PublicKey::SkEcDsa(k) => &k.application,
                PublicKey::SkEd25519(k) => &k.application,
                _ => panic!()
            };
            // Bit 0 of the flags byte is the U2F "user presence" bit. Without
            // it the key signed without a touch, so refuse the signature.
            if sig.flags & 0x01 == 0 {
                error!("user presence missing in security-key signature");
                return Err(RsshErr::InvalidSigErr.into_ptr());
            }
            let mut new_msg = Vec::with_capacity(32 + 1 + 4 + 32);
            new_msg.extend_from_slice(&sha256(app.as_bytes()));
            new_msg.push(sig.flags);
            new_msg.write_u32::<BigEndian>(sig.counter)?;
            new_msg.extend_from_slice(&sha256(msg));
            Ok((new_msg, decode_signature_blob(&sig.blob, pubkey)?))
        }
        // "msg" is untouched otherwise
        _ => {
            let sig: proto::Signature = from_bytes(ssh_sig)?;
            Ok((msg.to_vec(), decode_signature_blob(&sig.blob, pubkey)?))
        }
    }
}

pub fn verify_signature(
    raw_content: &[u8],
    pubkey: &PublicKey,
    ssh_signature: &[u8],
) -> Result<bool, ErrType> {
    use openssl::sign::Verifier;

    let (content, signature) = preprocess_content_and_sig(raw_content, ssh_signature, pubkey)?;
    let (pkey, digest) = pubkey.to_pkey()?;
    let mut verifier = digest.map_or(Verifier::new_without_digest(&pkey), |d| {
        Verifier::new(d, &pkey)
    })?;
    let ret = verifier.verify_oneshot(&signature, &content)?;

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
    use openssl::dsa::Dsa;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::{Signer, Verifier};

    // Generate a keypair
    let keypair = Dsa::generate(1024).unwrap();
    let keypair = PKey::from_dsa(keypair).unwrap();

    let data = b"hello, world!";
    let data2 = b"hola, mundo!";

    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(data).unwrap();
    signer.update(data2).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    println!(
        "signature={} len={}",
        base64::encode(&signature),
        signature.len()
    );

    // Verify the data
    let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair).unwrap();
    verifier.update(data).unwrap();
    verifier.update(data2).unwrap();
    assert!(verifier.verify(&signature).unwrap());
}

#[test]
fn rejects_missing_user_presence() {
    use ssh_agent::proto::public_key::{Ed25519PublicKey, SkEd25519PublicKey};
    use ssh_agent::proto::to_bytes;

    let sk_key = PublicKey::SkEd25519(SkEd25519PublicKey {
        enc_a: vec![0; 32],
        application: "ssh:".to_string(),
    });
    let sk_sig = |flags: u8| {
        to_bytes(&proto::SkSignature {
            algorithm: "sk-ssh-ed25519@openssh.com".to_string(),
            blob: vec![0; 64],
            flags,
            counter: 1,
        })
        .unwrap()
    };

    // User presence bit clear: rejected, even with the verified bit set.
    assert!(preprocess_content_and_sig(b"msg", &sk_sig(0x00), &sk_key).is_err());
    assert!(preprocess_content_and_sig(b"msg", &sk_sig(0x04), &sk_key).is_err());
    // User presence bit set: accepted.
    assert!(preprocess_content_and_sig(b"msg", &sk_sig(0x01), &sk_key).is_ok());
    assert!(preprocess_content_and_sig(b"msg", &sk_sig(0x05), &sk_key).is_ok());

    // A non-security-key signature has no flags byte and is unchanged.
    let plain_key = PublicKey::Ed25519(Ed25519PublicKey { enc_a: vec![0; 32] });
    let plain_sig = to_bytes(&proto::Signature {
        algorithm: "ssh-ed25519".to_string(),
        blob: vec![0; 64],
    })
    .unwrap();
    let (msg, sig) = preprocess_content_and_sig(b"msg", &plain_sig, &plain_key).unwrap();
    assert_eq!(msg, b"msg".to_vec());
    assert_eq!(sig, vec![0; 64]);
}

#[test]
fn rejects_missing_user_presence_ecdsa() {
    use ssh_agent::proto::public_key::SkEcDsaPublicKey;
    use ssh_agent::proto::signature::EcDsaSignatureData;
    use ssh_agent::proto::to_bytes;

    let sk_key = PublicKey::SkEcDsa(SkEcDsaPublicKey {
        identifier: "nistp256".to_string(),
        q: vec![0; 65],
        application: "ssh:".to_string(),
    });
    // Accepted signatures have their blob decoded as r||s, so build a minimal
    // valid one.
    let blob = to_bytes(&EcDsaSignatureData {
        r: vec![1; 32],
        s: vec![1; 32],
    })
    .unwrap();
    let sk_sig = |flags: u8| {
        to_bytes(&proto::SkSignature {
            algorithm: "sk-ecdsa-sha2-nistp256@openssh.com".to_string(),
            blob: blob.clone(),
            flags,
            counter: 1,
        })
        .unwrap()
    };

    // User presence bit clear: rejected, even with the verified bit set.
    assert!(preprocess_content_and_sig(b"msg", &sk_sig(0x00), &sk_key).is_err());
    assert!(preprocess_content_and_sig(b"msg", &sk_sig(0x04), &sk_key).is_err());
    // User presence bit set: accepted.
    assert!(preprocess_content_and_sig(b"msg", &sk_sig(0x01), &sk_key).is_ok());
    assert!(preprocess_content_and_sig(b"msg", &sk_sig(0x05), &sk_key).is_ok());
}

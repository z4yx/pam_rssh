use log::*;
use ssh_agent::proto::from_bytes;
use ssh_agent::proto::public_key::PublicKey;

use std::fs;
use std::path::PathBuf;

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

fn parse_pubkey_fields(line: &str) -> Result<PublicKey, ErrType> {
    let mut fields = line.split_whitespace();
    if let Some(algo) = fields.next() {
        if let Some(b64key) = fields.next() {
            debug!("parse_authorized_keys: {} {}", algo, b64key);
            let key = base64::decode(b64key)
                .map_err(|_| RsshErr::ParsePubkeyErr)
                .and_then(|blob| from_bytes(&blob).map_err(|_| RsshErr::ParsePubkeyErr))?;
            return Ok(key);
        }
    }
    return Err(RsshErr::ParsePubkeyErr.into_ptr());
}

// Based on sshkey_advance_past_options() in https://github.com/openssh/openssh-portable/blob/master/authfile.c
fn skip_options(line: &str) -> Result<String, ErrType> {
    let mut it = line.chars();
    let mut quote = false;
    while let Some(ch) = it.next() {
        if (ch == ' ' || ch == '\t') && !quote {
            break;
        }
        if ch == '\\' {
            // skip one character after escape symbol
            it.next();
        } else if ch == '"' {
            quote = !quote;
        }
    }
    if quote {
        Err(RsshErr::ParsePubkeyErr.into_ptr())
    } else {
        Ok(it.collect::<String>())
    }
}

pub fn parse_authorized_keys(filename: &str) -> Result<Vec<PublicKey>, ErrType> {
    let content =
        fs::read_to_string(filename).map_err(|_| RsshErr::FileReadErr(filename.to_string()))?;
    let mut lines = content.lines();
    let mut res: Vec<PublicKey> = vec![];
    while let Some(line) = lines.next() {
        let trimed = line.trim_start();
        if trimed.starts_with("#") {
            continue;
        }
        if let Ok(pubkey) = parse_pubkey_fields(trimed) {
            res.push(pubkey);
            continue;
        }
        // If there are options before public key, skip them
        let skipped = skip_options(trimed);
        res.push(skipped.and_then(|s| parse_pubkey_fields(s.trim_start()))?);
    }
    Ok(res)
}

pub fn parse_user_authorized_keys(username: &str) -> Result<Vec<PublicKey>, ErrType> {
    let path: PathBuf = ["/home", username, ".ssh", "authorized_keys"]
        .iter()
        .collect();
    parse_authorized_keys(path.to_str().ok_or(RsshErr::GetHomeErr)?)
}

#[test]
fn test_skip_options() {
    assert_eq!(skip_options("opt key comment").unwrap(), "key comment");
    assert_eq!(skip_options("a=b,c=d key comment").unwrap(), "key comment");
    assert_eq!(
        skip_options("a=b,x=\"\t\",c=\"d key\"\t key2 comment").unwrap(),
        " key2 comment"
    );
    assert_eq!(skip_options("ee").unwrap(), "");
    assert_eq!(skip_options("").unwrap(), "");
    assert_eq!(skip_options("a=\"").is_err(), true);
    assert_eq!(skip_options("a=\" k").is_err(), true);
    assert_eq!(skip_options("a=\\\"").unwrap(), "");
    assert_eq!(skip_options("a=\"\\\"\" k").unwrap(), "k");
    assert_eq!(skip_options("a=\"\\\\\" k").unwrap(), "k");
}

#[test]
fn test_parse_authorized_keys() {
    let content = concat!(
        "  some_opt   ssh-ed25519  AAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV my key\n",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV\tmy key\n",
        " ssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV\tmy key\n",
        "  #ssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV\tmy key",
    );
    let path = "/tmp/pam_rssh.test";
    fs::write(path, content).unwrap();
    assert_eq!(parse_authorized_keys(path).unwrap().len(), 3);
}

use ssh_agent::proto::public_key::PublicKey;
use ssh_agent::proto::{from_bytes, to_bytes};
use log::*;

use std::fs;
use std::path::PathBuf;

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

pub fn parse_authorized_keys(filename: &str) -> Result<Vec<PublicKey>, ErrType> {
    let content = fs::read_to_string(filename)
        .map_err(|_| RsshErr::FILE_READ_ERR(filename.to_string()))?;
    let mut lines = content.lines();
    let mut res: Vec<PublicKey> = vec![];
    while let Some(line) = lines.next() {
        let mut fields = line.split_whitespace();
        if let Some(algo) = fields.next() {
            if let Some(b64key) = fields.next() {
                debug!("parse_authorized_keys: {} {}", algo, b64key);
                let key = base64::decode(b64key)
                    .map_err(|_| RsshErr::PARSE_PUBKEY_ERR)
                    .and_then(|blob| from_bytes(&blob).map_err(|_| RsshErr::PARSE_PUBKEY_ERR))?;
                res.push(key);
            }
        }
    }
    Ok(res)
}

pub fn parse_user_authorized_keys(username: &str) -> Result<Vec<PublicKey>, ErrType> {
    let path: PathBuf = ["/home", username, ".ssh", "authorized_keys"]
        .iter()
        .collect();
    parse_authorized_keys(path.to_str().ok_or(RsshErr::GET_HOME_ERR)?)
}

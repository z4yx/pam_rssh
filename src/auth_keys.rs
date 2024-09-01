use log::*;
#[link(name = "c")]
extern "C" {
    fn geteuid() -> u32;
    fn getegid() -> u32;
}
use pwd::Passwd;
use ssh_agent::proto::from_bytes;
use ssh_agent::proto::public_key::PublicKey;

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

fn parse_pubkey_fields(line: &str) -> Result<PublicKey, ErrType> {
    let mut fields = line.split_whitespace();
    if let Some(algo) = fields.next() {
        if let Some(b64key) = fields.next() {
            let b64trimmed = b64key.trim_end();
            debug!("parse_pubkey_fields: {} {}", algo, b64trimmed);
            let key = base64::decode(b64trimmed)
                .map_err(|_| RsshErr::ParsePubkeyErr)
                .and_then(|blob| from_bytes(&blob).map_err(|_| RsshErr::ParsePubkeyErr))?;
            return Ok(key);
        }
    }
    warn!("At least two fields are required: `{}`", line);
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

pub fn parse_content_of_authorized_keys(content: &String) -> Result<Vec<PublicKey>, ErrType> {
    let mut lines = content.lines();
    let mut res: Vec<PublicKey> = vec![];
    while let Some(line) = lines.next() {
        let trimed = line.trim_start();
        if trimed.is_empty() || trimed.starts_with("#") {
            continue;
        }
        if let Ok(pubkey) = parse_pubkey_fields(trimed) {
            res.push(pubkey);
            continue;
        }
        // If there are options before public key, skip them
        let skipped = skip_options(trimed);
        if let Err(e) = skipped {
            debug!("skip_options() returns: {}", e.as_ref());
            continue;
        }
        debug!("pubkey line after options skipped: {:?}", skipped);
        match skipped.and_then(|s| parse_pubkey_fields(s.trim_start())) {
            Ok(pubkey) => res.push(pubkey),
            Err(e) => debug!("parse_pubkey_fields() returns: {}", e.as_ref())
        }
    }
    Ok(res)
}

pub fn parse_authorized_keys(filename: &str) -> Result<Vec<PublicKey>, ErrType> {
    let content =
        fs::read_to_string(filename).map_err(|_| RsshErr::FileReadErr(filename.to_string()))?;
    parse_content_of_authorized_keys(&content)
}

pub fn parse_user_authorized_keys(username: &str) -> Result<Vec<PublicKey>, ErrType> {
    let mut prefix = format!("/home/{}",username);
    // Gets user's $HOME to search for authorized_keys
    let _ = Passwd::from_name(username).map(|opt_passwd| {
        opt_passwd.map(|passwd| {
            prefix = passwd.dir;
        })
    });
    let path: PathBuf = [prefix.as_str(), ".ssh", "authorized_keys"]
        .iter()
        .collect();
    parse_authorized_keys(path.to_str().ok_or(RsshErr::GetHomeErr)?)
}

pub fn run_authorized_keys_cmd(auth_key_cmd: &str, auth_user: &str, run_user: &str) -> Result<String, ErrType> {
    let uid;
    let opt_p = Passwd::from_name(run_user)?;
    if let Some(p) = opt_p {
        uid = p.uid;
    } else {
        warn!("Failed to get the uid of `{}`", run_user);
        return Err(RsshErr::GetUidErr.into_ptr());
    };
    let euid: u32;
    unsafe {
        euid = geteuid();
    }
    let mut cmd = Command::new(auth_key_cmd);
    let cmd_with_arg;
    if euid == 0 { // current user is root, setuid() is allowed
        debug!("Current user is root, set uid to {}", uid);
        cmd_with_arg = cmd.arg(auth_user).uid(uid);
    } else {
        cmd_with_arg = cmd.arg(auth_user);
    }
    let result = cmd_with_arg.output()?;
    let status = result.status;
    if !status.success() {
        return Err(RsshErr::CmdExitErr(status.code()).into_ptr())
    }
    if let Ok(t) = String::from_utf8(result.stdout) {
        debug!("Got authorized keys from command output, len={}", t.len());
        Ok(t)
    } else {
        Err(RsshErr::CmdOutputDecodeErr.into_ptr())
    }
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
    let _ = log::set_boxed_logger(Box::new(super::logger::ConsoleLogger))
        .map(|()| log::set_max_level(log::LevelFilter::Debug));
    let mut content = concat!(
        "ssh-ed25519  InvalidBase64\n",
        "ssh-ed25519  AAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV   \n",
        "  some_opt   ssh-ed25519  AAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV my key\n",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV\tmy key\n",
        " ssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV\tmy key\n",
        "  #ssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV\tmy key\n",
        "#comment\n",
    );
    let path = "/tmp/pam_rssh.test";
    fs::write(path, content).unwrap();
    assert_eq!(parse_authorized_keys(path).unwrap().len(), 4);

    content = concat!(
        "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBOs1kRdss9EmY9MPMA/e5HC10mtxnkXbU6wSdlIMugAweQc7ckFPvY+y1F86Z2eR4X42Qo/85bMDjlM/2BAJqbYAAAAEc3NoOg== test@n\n",
        "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIBRogHNAvK4P9f8EKulnxrF8SfKIdqNrIleHdj0wvAU5AAAADXNzaDpUb3VjaE9ubHk=    \n",
        "ssh-rsa              AAAAB3NzaC1yc2EAAAADAQABAAABgQCx3nZIDXpjn68tl0McPq8WCoTio1iVaAlAE7NnQRn9js8+T/dhiE1s4T7qMqf3iSNDzfq/qY8paAWips5z8t/Soy2x5xTcSWBX2zoCcM1H4R/jYcnfUTvfsTfjCVkUiQxX3wkyThe5biU/NjrB92NbQH6ZFf53SjXL6ax/9Q1e5938uKQnE+bBBHDBPBixRQzGT6NbTiegjDf6tyQaKNzPhATTlAqDaQzUIVHvoVPuJ2hT7OiDr72wwdrnIkobKtykbrGITobd4XujhIMje024gqlTucWUzA91m2LgBx4pfOzYlVUZcXorVAL0wpTPN4ursiEEtU/kYZN5xUDX1anp0GeNK74SBvUfq8mm9nx7evPMEH9Cdl3SFa9oQsqOSOHJNICW6svfaDweGTsI51KJptSuF1jq/V9VlLZmIOFezPEXiM13Q6ZqAigzPBggzNI4KgtSzztFnEKwvV1RO/GfaMn5xp2Cdovpfb0FhIsZ7i6wTXCk4ZqfvUDuKRoDE+k=\n",
        "ecdsa-sha2-nistp256  AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF279yp1qnjADnYs+muktz26HuNwznkDf6vQT6WKJ42GwD4GHhFLCj2CIL26qkroEynLAqt19XUMBnb/JGPCThw=    test\n",
        "ssh-dss AAAAB3NzaC1kc3MAAACBAOPA1udikQuPhCemarDkDj5ZIinN3quZty5Y0/APTdhOVQ8Ad5aJ7Bz0cCNzjeaTYrZh92nT8PJzIFnn/bT0sPcao8ApLu3OgeYdXx9tofw53o5bcUEkcVaKiSgVTYXIYTJmDFTTgTaQWNAjag+zcfZGRXVyuHfhOLYzIUuJEZmjAAAAFQDq6w2ThuInZSY3FEAynryDfNjAuwAAAIALvNCORC5qigYfNpqJ68P21GDQ3II9FeOa3zo4vV2h0htJb9OY8MpUEAMFyOuhtJ97OvbjjTBQY6WLycOwoJnsf8wZcVJFR5/R0DrVzil9sPLduAVkzrHGbH0ESAxWsymlLDWYywycCtCEFEGouyBNgsgzMgRycDPH2akQeX+vGAAAAIEAurSBK5tyWFvdGQUlhPQwmGnT4iGaYsElDLjRSFe4qNFJ1vJ+m8FEaoNudR0JLx/AtlyP2GNdDddnsxNvusr2x+uXzyc5PRKhZ82xSlGDSkrPPxDl4s24KE3c6jY8Lu5JZ/dEjjW2SsydY3nrlY12toLCtFAMMojcf0pNQMqnh6s= \n",
    );
    fs::write(path, content).unwrap();
    assert_eq!(parse_authorized_keys(path).unwrap().len(), 5);
}

#[test]
fn test_run_authorized_keys_cmd() {
    let _ = log::set_boxed_logger(Box::new(super::logger::ConsoleLogger))
        .map(|()| log::set_max_level(log::LevelFilter::Debug));
    // let whoami = Passwd::current_user().unwrap().name;
    let test_user = String::from("nobody");

    let mut ret = run_authorized_keys_cmd("/bin/non-exist", "root", "root");
    assert!(ret.is_err());
    info!("err message: {}", ret.unwrap_err());

    ret = run_authorized_keys_cmd("/bin/echo", "sb", "root");
    assert!(ret.is_ok());
    assert_eq!(ret.unwrap(), "sb\n");

    ret = run_authorized_keys_cmd("/bin/echo", test_user.as_str(), test_user.as_str());
    assert!(ret.is_ok());
    assert_eq!(ret.unwrap(), test_user.clone() + "\n");

    ret = run_authorized_keys_cmd("/bin/echo", "sb", "no_such_user");
    assert!(ret.is_err());
    let mut err = ret.unwrap_err();
    info!("err message: {}", err);
    assert!(matches!(err.downcast::<RsshErr>().unwrap().as_ref(), RsshErr::GetUidErr));

    ret = run_authorized_keys_cmd("/bin/false", "sb", test_user.as_str());
    assert!(ret.is_err());
    err = ret.unwrap_err();
    info!("err message: {}", err);
    assert!(matches!(err.downcast::<RsshErr>().unwrap().as_ref(), RsshErr::CmdExitErr(Some(n)) if *n==1));

}

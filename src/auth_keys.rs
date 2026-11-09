use log::*;
#[link(name = "c")]
extern "C" {
    fn geteuid() -> u32;
}
use base64::{Engine as _, engine::general_purpose};
use pwd::Passwd;
use ssh_agent::proto::from_bytes;
use ssh_agent::proto::public_key::PublicKey;

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

/// One entry of an `authorized_keys` file: the public key together with the
/// options that precede it on the same line.
#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub pubkey: PublicKey,
    /// The entry carries the OpenSSH `no-touch-required` option, meaning a
    /// security-key (FIDO2/U2F) signature may be accepted even when its
    /// user-presence bit is clear, i.e. the key was created with
    /// `ssh-keygen -O no-touch-required` and signed without a touch.
    pub no_touch_required: bool,
}

impl AuthorizedKey {
    /// Whether the signature of this key must carry the FIDO user-presence
    /// bit. This mirrors sshd, which requires it unless the matching
    /// `authorized_keys` entry says `no-touch-required`.
    pub fn requires_user_presence(&self) -> bool {
        !self.no_touch_required
    }
}

fn parse_pubkey_fields(line: &str) -> Result<PublicKey, ErrType> {
    let mut fields = line.split_whitespace();
    if let Some(algo) = fields.next() {
        if let Some(b64key) = fields.next() {
            let b64trimmed = b64key.trim_end();
            debug!("parse_pubkey_fields: {} {}", algo, b64trimmed);
            let key = general_purpose::STANDARD.decode(b64trimmed)
                .map_err(|_| RsshErr::ParsePubkeyErr)
                .and_then(|blob| from_bytes(&blob).map_err(|_| RsshErr::ParsePubkeyErr))?;
            return Ok(key);
        }
    }
    warn!("At least two fields are required: `{}`", line);
    return Err(RsshErr::ParsePubkeyErr.into_ptr());
}

// Based on sshkey_advance_past_options() in https://github.com/openssh/openssh-portable/blob/master/authfile.c
// Returns the options part of the line and the rest that starts with the key.
fn split_options(line: &str) -> Result<(&str, &str), ErrType> {
    let mut it = line.char_indices();
    let mut quote = false;
    while let Some((idx, ch)) = it.next() {
        if (ch == ' ' || ch == '\t') && !quote {
            return Ok((&line[..idx], &line[idx + ch.len_utf8()..]));
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
        Ok((line, ""))
    }
}

// Split the comma separated options of an authorized_keys entry, honoring
// quotes and backslash escapes the same way sshd's opt_dequote() does. Values
// are kept with their `name=value` form; only names are interpreted here.
fn parse_key_options(options: &str) -> Result<Vec<String>, ErrType> {
    let mut tokens: Vec<String> = vec![];
    let mut current = String::new();
    let mut quote = false;
    let mut it = options.chars();
    while let Some(ch) = it.next() {
        match ch {
            '\\' => match it.next() {
                Some(escaped) => current.push(escaped),
                None => return Err(RsshErr::ParsePubkeyErr.into_ptr()),
            },
            '"' => quote = !quote,
            ',' if !quote => tokens.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    if quote {
        return Err(RsshErr::ParsePubkeyErr.into_ptr());
    }
    tokens.push(current);
    Ok(tokens)
}

fn has_key_option(options: &[String], name: &str) -> bool {
    options.iter().any(|option| option.trim() == name)
}

fn parse_line(line: &str) -> Result<AuthorizedKey, ErrType> {
    let (options, rest) = split_options(line)?;
    // A line without options starts with the key type itself.
    if let Ok(pubkey) = parse_pubkey_fields(line) {
        return Ok(AuthorizedKey {
            pubkey,
            no_touch_required: false,
        });
    }
    if rest.trim_start().is_empty() {
        // Options without a key, or a malformed line: skip it.
        return Err(RsshErr::ParsePubkeyErr.into_ptr());
    }
    let pubkey = parse_pubkey_fields(rest.trim_start())?;
    let options = parse_key_options(options)?;
    Ok(AuthorizedKey {
        pubkey,
        no_touch_required: has_key_option(&options, "no-touch-required"),
    })
}

pub fn parse_content_of_authorized_keys(content: &String) -> Result<Vec<AuthorizedKey>, ErrType> {
    let mut res: Vec<AuthorizedKey> = vec![];
    for line in content.lines() {
        let trimed = line.trim_start();
        if trimed.is_empty() || trimed.starts_with("#") {
            continue;
        }
        match parse_line(trimed) {
            Ok(entry) => res.push(entry),
            Err(e) => debug!("Failed to parse authorized_keys line: {}", e.as_ref()),
        }
    }
    Ok(res)
}

pub fn parse_authorized_keys(filename: &str) -> Result<Vec<AuthorizedKey>, ErrType> {
    let content =
        fs::read_to_string(filename).map_err(|_| RsshErr::FileReadErr(filename.to_string()))?;
    parse_content_of_authorized_keys(&content)
}

pub fn parse_user_authorized_keys(username: &str) -> Result<Vec<AuthorizedKey>, ErrType> {
    let mut prefix = format!("/home/{}",username);
    // Gets user's $HOME to search for authorized_keys
    let _ = Passwd::from_name(username).map(|opt_passwd| {
        opt_passwd.map(|passwd| {
            prefix = passwd.dir;
            debug!("Got home dir of user {}: {}", username, prefix);
        })
    });
    debug!("Searching for authorized_keys in {}", prefix);
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
fn test_split_options() {
    let skip = |line: &str| split_options(line).map(|(_, rest)| rest.to_string());
    assert_eq!(split_options("opt key comment").unwrap(), ("opt", "key comment"));
    assert_eq!(skip("opt key comment").unwrap(), "key comment");
    assert_eq!(skip("a=b,c=d key comment").unwrap(), "key comment");
    assert_eq!(
        skip("a=b,x=\"\t\",c=\"d key\"\t key2 comment").unwrap(),
        " key2 comment"
    );
    assert_eq!(skip("ee").unwrap(), "");
    assert_eq!(skip("").unwrap(), "");
    assert_eq!(skip("a=\"").is_err(), true);
    assert_eq!(skip("a=\" k").is_err(), true);
    assert_eq!(skip("a=\\\"").unwrap(), "");
    assert_eq!(skip("a=\"\\\"\" k").unwrap(), "k");
    assert_eq!(skip("a=\"\\\\\" k").unwrap(), "k");
}

#[test]
fn test_parse_key_options() {
    assert_eq!(
        parse_key_options("no-touch-required").unwrap(),
        vec!["no-touch-required".to_string()]
    );
    assert_eq!(
        parse_key_options("a=b,c=\"d,e\",no-touch-required").unwrap(),
        vec![
            "a=b".to_string(),
            "c=d,e".to_string(),
            "no-touch-required".to_string()
        ]
    );
    // The option name inside a value must not enable it.
    assert_eq!(
        parse_key_options("command=\"no-touch-required\"").unwrap(),
        vec!["command=no-touch-required".to_string()]
    );
    assert!(parse_key_options("a=\"unterminated").is_err());
    assert!(parse_key_options("a=c\\").is_err());
}

#[test]
fn test_no_touch_required_option() {
    let sk = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIBRogHNAvK4P9f8EKulnxrF8SfKIdqNrIleHdj0wvAU5AAAADXNzaDpUb3VjaE9ubHk=";
    let plain = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILNwZPJqdxsO6ahniFpVqNbT9ACXHSDpF5XLkrRU9dUV";
    let content = format!(
        "{sk}\n\
         no-touch-required {sk}\n\
         command=\"echo no-touch-required\",no-touch-required {sk}\n\
         command=\"no-touch-required\" {plain}\n\
         ,,no-touch-required,, {plain}\n"
    );
    let entries = parse_content_of_authorized_keys(&content).unwrap();
    assert_eq!(entries.len(), 5);
    let no_touch: Vec<bool> = entries.iter().map(|e| e.no_touch_required).collect();
    assert_eq!(no_touch, vec![false, true, true, false, true]);
    // Only the entries without the option require the presence bit.
    assert!(entries[0].requires_user_presence());
    assert!(!entries[1].requires_user_presence());
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

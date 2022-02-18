#[macro_use]
extern crate pam;

mod auth_keys;
mod error;
mod logger;
mod sign_verify;
mod ssh_agent_auth;

use log::*;
use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use ssh_agent::proto::public_key::PublicKey;
use syslog::{BasicLogger, Facility, Formatter3164};

use std::ffi::CStr;
use std::str::FromStr;

use self::error::RsshErr;
use self::logger::ConsoleLogger;

type ErrType = Box<dyn std::error::Error>;

struct PamRssh;
pam_hooks!(PamRssh);

fn is_key_authorized(key: &PublicKey, authorized_keys: &Vec<PublicKey>) -> bool {
    for item in authorized_keys {
        if item == key {
            return true;
        }
    }
    false
}

fn read_authorized_keys(pamh: &PamHandle, auth_key_file: &str) -> Result<Vec<PublicKey>, ErrType> {
    if auth_key_file.len() == 0 {
        let user = pamh.get_user(None).map_err(|_| RsshErr::GetUserErr)?;
        info!("Reading authorized_keys of user {}", user);
        auth_keys::parse_user_authorized_keys(&user)
    } else {
        info!("Reading configured authorized_keys file: {}", auth_key_file);
        auth_keys::parse_authorized_keys(auth_key_file)
    }
}

fn authenticate_via_agent(
    agent: &mut ssh_agent_auth::AgentClient,
    pubkey: &PublicKey,
) -> Result<(), ErrType> {
    let challenge = sign_verify::gen_challenge()?;
    let sig = agent.sign_data(&challenge, pubkey)?;
    let verified = sign_verify::verify_signature(&challenge, pubkey, &sig)?;
    if verified {
        Ok(())
    } else {
        Err(RsshErr::SignVerifyErr.into_ptr())
    }
}

fn setup_logger() {
    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTH,
        hostname: None,
        process: "pam_rssh".into(),
        pid: std::process::id() as i32,
    };
    syslog::unix(formatter)
        .ok()
        .and_then(|logger| log::set_boxed_logger(Box::new(BasicLogger::new(logger))).ok())
        .or_else(|| log::set_boxed_logger(Box::new(ConsoleLogger)).ok())
        .map(|()| log::set_max_level(log::LevelFilter::Warn));
}

impl PamHooks for PamRssh {
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        /* if (flags & pam::constants::PAM_SILENT) == 0 */
        {
            setup_logger();
        }

        let mut ssh_agent_addr = "";
        let mut auth_key_file = "";
        for carg in args {
            let kv: Vec<&str> = carg.to_str().unwrap_or("").splitn(2, '=').collect();
            if kv.len() == 0 {
                continue;
            }
            trace!("Parsing option {:?}", kv);
            match kv[0] {
                "loglevel" => {
                    if kv.len() > 1 {
                        let _ = log::Level::from_str(kv[1])
                            .and_then(|level| Ok(log::set_max_level(level.to_level_filter())));
                    }
                }
                "debug" => log::set_max_level(log::LevelFilter::Debug),
                "ssh_agent_addr" => {
                    if kv.len() > 1 {
                        ssh_agent_addr = kv[1];
                    }
                }
                "auth_key_file" => {
                    if kv.len() > 1 {
                        auth_key_file = kv[1];
                    }
                }
                _ => {
                    error!("Unknown option `{}`", kv[0]);
                    return PamResultCode::PAM_SYSTEM_ERR;
                }
            }
        }

        let addr_from_env;
        if ssh_agent_addr.is_empty() {
            let agent_addr_os = std::env::var_os("SSH_AUTH_SOCK");
            if let Some(a) = agent_addr_os {
                addr_from_env = a;
                ssh_agent_addr = addr_from_env.to_str().unwrap_or("");
            }
            debug!("SSH-Agent address: {}", ssh_agent_addr);
            if ssh_agent_addr.is_empty() {
                error!("SSH agent socket address not configured");
                return PamResultCode::PAM_AUTHINFO_UNAVAIL;
            }
        }

        let authorized_keys = match read_authorized_keys(pamh, &auth_key_file) {
            Ok(u) => {
                info!("Got {} entries from authorized_keys", u.len());
                u
            },
            Err(e) => {
                error!("read_authorized_keys: {}", e);
                return PamResultCode::PAM_CRED_INSUFFICIENT;
            }
        };

        let mut agent = ssh_agent_auth::AgentClient::new(ssh_agent_addr);
        let result = agent.list_identities().and_then(|client_keys| {
            debug!("SSH-Agent reports {} keys", client_keys.len());
            for (i, key) in client_keys.iter().enumerate() {
                if !is_key_authorized(&key, &authorized_keys) {
                    debug!("Key {} is not authorized", i);
                    continue;
                }
                debug!("Key {} is authorized", i);
                match authenticate_via_agent(&mut agent, &key) {
                    Ok(_) => {
                        info!("Successful authentication");
                        return Ok(true);
                    }
                    Err(e) => {
                        warn!("Failed to authenticate key {}: {}", i, e);
                        continue; // try next key
                    }
                }
            }
            warn!("None of these keys passed authentication");
            Ok(false)
        });
        match result {
            Ok(true) => PamResultCode::PAM_SUCCESS,
            Ok(false) => PamResultCode::PAM_AUTH_ERR,
            Err(e) => {
                error!("{}", e);
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }

    // Always return PAM_SUCCESS for sm_setcred, just like pam-u2f
    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        info!("set-credentials is not implemented");
        PamResultCode::PAM_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::ssh_agent_auth::AgentClient;
    use log::debug;

    fn init_log() {
        let _ = log::set_boxed_logger(Box::new(super::logger::ConsoleLogger))
            .map(|()| log::set_max_level(log::LevelFilter::Info));
    }

    fn enable_debug_log() {
        log::set_max_level(log::LevelFilter::Debug)
    }

    #[test]
    fn sshagent_list_identities() {
        init_log();
        enable_debug_log();
        let mut agent = AgentClient::new(env!("SSH_AUTH_SOCK"));
        let result = agent.list_identities();
        debug!("result={:?}", result);
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert!(keys.len() > 0);
        for item in keys {
            debug!("key: {:?}", item);
        }
    }

    #[test]
    fn sshagent_auth() {
        init_log();
        enable_debug_log();
        let mut agent = AgentClient::new(env!("SSH_AUTH_SOCK"));
        let result = agent.list_identities();
        debug!("result={:?}", result);
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert!(keys.len() > 0);
        for item in keys {
            let data: &[u8] = &[3, 5, 6, 7];
            let sig_ret = agent.sign_data(data, &item);
            debug!("sig_ret={:?}", sig_ret);
            assert!(sig_ret.is_ok());
            let sig = sig_ret.unwrap();
            let verify_ret = super::sign_verify::verify_signature(&data, &item, &sig);
            debug!("verify_ret={:?}", verify_ret);
            assert!(verify_ret.is_ok());
            assert!(verify_ret.unwrap());
        }
    }

    #[test]
    fn sshagent_more_auth() {
        init_log();
        let mut agent = AgentClient::new(env!("SSH_AUTH_SOCK"));
        let result = agent.list_identities();
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert!(keys.len() > 0);
        for _ in 0..1000 {
            for item in &keys {
                let auth_ret = super::authenticate_via_agent(&mut agent, &item);
                assert!(auth_ret.is_ok());
            }
        }
    }

    #[test]
    fn parse_user_authorized_keys() {
        init_log();
        enable_debug_log();
        let username = env!("USER");
        let result = super::auth_keys::parse_user_authorized_keys(&username);
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert!(keys.len() > 0);
        for item in keys {
            debug!("key: {:?}", item);
        }
    }
}

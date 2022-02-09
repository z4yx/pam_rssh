#[macro_use]
extern crate pam;

mod auth_keys;
mod error;
mod logger;
mod sign_verify;
mod ssh_agent_auth;

use log::*;
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_ON};
use pam::conv::PamConv;
use pam::module::{PamHandle, PamHooks};
use ssh_agent::proto::public_key::PublicKey;

use std::ffi::CStr;
use std::str::FromStr;

use self::error::RsshErr;

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
        Err(RsshErr::SIGN_VERIFY_ERR.into_ptr())
    }
}

fn enable_debug_log() {
    log::set_max_level(log::LevelFilter::Debug)
}

impl PamHooks for PamRssh {
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        let mut ssh_agent_addr = "";
        let mut global_auth_keys = "";
        let mut debug = 0u8;
        for carg in args {
            let kv: Vec<&str> = carg.to_str().unwrap_or("").splitn(2, '=').collect();
            if kv.len() == 0 {
                continue;
            }
            trace!("Parsing option {:?}", kv);
            match kv[0] {
                "debug" => {
                    debug = if kv.len() > 1 {
                        u8::from_str(kv[1]).unwrap_or(0)
                    } else {
                        1
                    };
                }
                "ssh_agent_addr" => {
                    if kv.len() > 1 {
                        ssh_agent_addr = kv[1];
                    }
                }
                "global_auth_keys" => {
                    if kv.len() > 1 {
                        global_auth_keys = kv[1];
                    }
                }
                default => {
                    error!("Unknown option {}", kv[0]);
                    return PamResultCode::PAM_SYSTEM_ERR;
                }
            }
        }

        if debug > 0 {
            enable_debug_log()
        }

        if (ssh_agent_addr.is_empty()) {
            error!("SSH agent socket address not configured");
            return PamResultCode::PAM_SYSTEM_ERR;
        }

        let authorized_keys = if global_auth_keys.len() == 0 {
            let user = match pamh.get_user(None) {
                Ok(u) => u,
                Err(e) => {
                    error!("Failed to get user name");
                    return e;
                }
            };
            match auth_keys::parse_user_authorized_keys(&user) {
                Ok(val) => val,
                Err(err) => {
                    error!("{}", err);
                    return PamResultCode::PAM_AUTHINFO_UNAVAIL;
                }
            }
        } else {
            match auth_keys::parse_authorized_keys(global_auth_keys) {
                Ok(val) => val,
                Err(err) => {
                    error!("{}", err);
                    return PamResultCode::PAM_AUTHINFO_UNAVAIL;
                }
            }
        };

        let mut agent = ssh_agent_auth::AgentClient::new(ssh_agent_addr);
        let result = agent.list_identities().and_then(|client_keys| {
            debug!("SSH-agent reports {} keys", client_keys.len());
            for (i, key) in client_keys.iter().enumerate() {
                if !is_key_authorized(&key, &authorized_keys) {
                    debug!("Key {} is not authorized", i);
                    continue;
                }
                debug!("Key {} is authorized", i);
                match authenticate_via_agent(&mut agent, &key) {
                    Ok(_) => {
                        info!("Authenticated successfully");
                        return Ok(true);
                    }
                    Err(e) => {
                        warn!("Failed to authenticate key {}: {}", i, e);
                        continue; // try next key
                    }
                }
            }
            warn!("None of the keys passed authentication");
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

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        info!("set-credentials is not implemented");
        PamResultCode::PAM_IGNORE
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        info!("account-management is not implemented");
        PamResultCode::PAM_IGNORE
    }
}

#[cfg(test)]
mod tests {
    use super::logger::ConsoleLogger;
    use super::sign_verify;
    use super::ssh_agent_auth::AgentClient;
    use log::debug;

    fn init_log() {
        log::set_boxed_logger(Box::new(ConsoleLogger))
            .map(|()| log::set_max_level(log::LevelFilter::Info));
    }

    #[test]
    fn sshagent_list_identities() {
        init_log();
        super::enable_debug_log();
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
        super::enable_debug_log();
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
        for times in 0..1000 {
            for item in &keys {
                let auth_ret = super::authenticate_via_agent(&mut agent, &item);
                assert!(auth_ret.is_ok());
            }
        }
    }
}

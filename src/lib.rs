#[macro_use]
extern crate pam;

mod auth_keys;
mod error;
mod sign_verify;
mod ssh_agent_auth;

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
    let _ = sign_verify::verify_signature(&challenge, pubkey, &sig)?;
    Ok(())
}

impl PamHooks for PamRssh {
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        println!("Let's make sure you're sober enough to perform basic addition");

        let mut ssh_agent_addr = "";
        let mut global_auth_keys = "";
        let mut debug = 0u8;
        for carg in args {
            let kv: Vec<&str> = carg.to_str().unwrap_or("").splitn(2, '=').collect();
            if kv.len() == 0 {
                continue;
            }
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
                    println!("Unknown option {}", kv[0]);
                    return PamResultCode::PAM_SYSTEM_ERR;
                }
            }
        }

        if (ssh_agent_addr.is_empty()) {
            println!("Error: SSH agent socket address not configured");
            return PamResultCode::PAM_SYSTEM_ERR;
        }

        let authorized_keys = if global_auth_keys.len() == 0 {
            let user = match pamh.get_user(None) {
                Ok(u) => u,
                Err(e) => {
                    println!("Error: Failed to get user name");
                    return e;
                }
            };
            match auth_keys::parse_user_authorized_keys(&user) {
                Ok(val) => val,
                Err(err) => {
                    println!("Error: {}", err);
                    return PamResultCode::PAM_AUTHINFO_UNAVAIL;
                }
            }
        } else {
            match auth_keys::parse_authorized_keys(global_auth_keys) {
                Ok(val) => val,
                Err(err) => {
                    println!("Error: {}", err);
                    return PamResultCode::PAM_AUTHINFO_UNAVAIL;
                }
            }
        };

        if !sign_verify::initialize_library() {
            println!("Error: {}", RsshErr::LIBSODIUM_INIT_ERR);
            return PamResultCode::PAM_SYSTEM_ERR;
        }

        let mut agent = ssh_agent_auth::AgentClient::new(ssh_agent_addr);
        let result = agent.list_identities().and_then(|client_keys| {
            for key in client_keys {
                if !is_key_authorized(&key, &authorized_keys) {
                    continue;
                }
                match authenticate_via_agent(&mut agent, &key) {
                    Ok(_) => {
                        println!("Authenticated");
                        return Ok(());
                    }
                    Err(e) => {
                        println!("Error: {}", e);
                        continue; // try next key
                    }
                }
            }
            Err(RsshErr::NO_KEY_PASSED_ERR.into_ptr())
        });
        match result {
            Ok(_) => PamResultCode::PAM_SUCCESS,
            Err(e) => {
                println!("Error: {}", e);
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("set credentials");
        PamResultCode::PAM_IGNORE
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("account management");
        PamResultCode::PAM_IGNORE
    }
}

#[cfg(test)]
mod tests {
    use super::ssh_agent_auth::AgentClient;
    use super::sign_verify;

    #[test]
    fn sshagent_list_identities() {
        let mut agent = AgentClient::new(&"unix:/run/user/1000/piv-ssh-jc.socket");
        let result = agent.list_identities();
        println!("result={:?}", result);
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert!(keys.len() > 0);
        for item in keys {
            println!("key: {:?}", item);
        }
    }

    #[test]
    fn libsodium_sys_test() {
        assert!(sign_verify::initialize_library());
    }
}
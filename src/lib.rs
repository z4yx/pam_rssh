#[macro_use] extern crate pam;

mod auth_keys;

use pam::module::{PamHandle, PamHooks};
use pam::constants::{PamResultCode, PamFlag, PAM_PROMPT_ECHO_ON};
use pam::conv::PamConv;
use std::str::FromStr;
use std::ffi::CStr;

struct PamRssh;
pam_hooks!(PamRssh);

impl PamHooks for PamRssh{
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        println!("Let's make sure you're sober enough to perform basic addition");

        let mut ssh_agent_addr = "";
        let mut global_auth_keys = "";
        let mut debug = 0u8;
        for carg in args {
            let kv: Vec<&str> = carg.to_str().unwrap_or("").splitn(2, '=').collect();
            if kv.len() == 0 {
                continue
            }
            match kv[0] {
                "debug" => {
                    debug = u8::from_str(kv[1]).unwrap_or(0);
                },
                "ssh_agent_addr" => {
                    ssh_agent_addr = kv[1];
                },
                "global_auth_keys" => {
                    global_auth_keys = kv[1];
                },
                default => {
                    println!("Unknown option {}", kv[0]);
                    return PamResultCode::PAM_SYSTEM_ERR;
                }
            }
        }

        let auth_keys = if global_auth_keys.len() == 0 {
            let user = match pamh.get_user(None) {
                Ok(u) => u,
                Err(e) => {
                    println!("Failed to get user name");
                    return e
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

        
        PamResultCode::PAM_SUCCESS
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
//! The data signed when `challenge=pam_ssh_agent_auth` is set: the authentication request
//! in the format pam_ssh_agent_auth uses, which tells the ssh-agent who is authenticating,
//! to which service, and the command being run. An agent can show these to its user before
//! signing, and log them afterwards.
//!
//! The layout follows pam_ssh_agent_auth 0.10 (`iterate_ssh_agent_keys.c` and
//! `userauth_pubkey_from_id.c`), so agents which already understand its requests understand
//! these too. Integers are big-endian, and strings are prefixed with their length as a u32.
//!
//! ```text
//! string    session_id2:
//!               uint32  101 (PAM_SSH_AGENT_AUTH_REQUESTv1)
//!               string  random cookie
//!               string  user (PAM_USER)
//!               string  ruser (PAM_RUSER, or the user running the program)
//!               string  service (PAM_SERVICE)
//!               string  working directory
//!               string  action: empty if unavailable, otherwise
//!                           uint32  argument count
//!                           string  each argument of the program's command line
//!               string  hostname
//!               uint64  time, in seconds since the epoch
//! byte      54 (SSH2_MSG_USERAUTH_TRUST_REQUEST)
//! string    ruser
//! string    "pam_ssh_agent_auth"
//! string    "publickey"
//! byte      1
//! string    public key algorithm
//! string    public key blob
//! ```

use byteorder::{BigEndian, WriteBytesExt};
use log::*;
use pwd::Passwd;
use ssh_agent::proto::public_key::PublicKey;
use ssh_agent::proto::to_bytes;
use ssh_agent::proto::KeyTypeEnum;

use std::os::unix::ffi::OsStrExt;
use std::time::{SystemTime, UNIX_EPOCH};

use super::error::RsshErr;

type ErrType = Box<dyn std::error::Error>;

const PAM_SSH_AGENT_AUTH_REQUESTV1: u32 = 101;
const SSH2_MSG_USERAUTH_TRUST_REQUEST: u8 = 54;

/// The most command line the request will carry. Agents show it to decide whether to sign,
/// so a longer one is refused rather than cut short.
const MAX_ACTION_LEN: usize = 64 * 1024;

/// What is being authenticated, as reported to the agent.
#[derive(Debug, Default)]
pub struct Request {
    pub user: String,
    pub ruser: String,
    pub service: String,
    pub cwd: Vec<u8>,
    /// The program's command line, or None where it can't be read.
    pub argv: Option<Vec<Vec<u8>>>,
    pub hostname: String,
    pub timestamp: u64,
}

impl Request {
    /// Collects the request from PAM's items and the current process. `ruser` falls back to
    /// the user running the program, which for sudo is the user invoking it.
    pub fn collect(user: &str, ruser: Option<String>, service: Option<String>) -> Result<Request, ErrType> {
        let ruser = match ruser.filter(|r| !r.is_empty()) {
            Some(r) => r,
            None => Passwd::current_user().ok_or(RsshErr::GetUidErr)?.name,
        };
        let argv = match current_argv() {
            Some(argv) => Some(argv),
            None => {
                warn!("Cannot determine the command line of the current process");
                None
            }
        };
        let request = Request {
            user: user.to_string(),
            ruser,
            service: service.unwrap_or_default(),
            cwd: std::env::current_dir()
                .map(|p| p.as_os_str().as_bytes().to_vec())
                .unwrap_or_default(),
            argv,
            hostname: system_hostname(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        debug!("Request: user={} ruser={} service={}", request.user, request.ruser, request.service);
        Ok(request)
    }

    /// The session identifier: this request, with `cookie` making it unique.
    pub fn session_id(&self, cookie: &[u8]) -> Result<Vec<u8>, ErrType> {
        let mut action = vec![];
        if let Some(argv) = &self.argv {
            action.write_u32::<BigEndian>(argv.len() as u32)?;
            for arg in argv {
                put_string(&mut action, arg)?;
            }
        }
        if action.len() > MAX_ACTION_LEN {
            return Err(RsshErr::CmdlineTooLongErr(action.len()).into_ptr());
        }
        let mut buf = vec![];
        buf.write_u32::<BigEndian>(PAM_SSH_AGENT_AUTH_REQUESTV1)?;
        put_string(&mut buf, cookie)?;
        put_string(&mut buf, self.user.as_bytes())?;
        put_string(&mut buf, self.ruser.as_bytes())?;
        put_string(&mut buf, self.service.as_bytes())?;
        put_string(&mut buf, &self.cwd)?;
        put_string(&mut buf, &action)?;
        put_string(&mut buf, self.hostname.as_bytes())?;
        buf.write_u64::<BigEndian>(self.timestamp)?;
        Ok(buf)
    }

    /// The data the agent signs with `pubkey` for the session `session_id`.
    pub fn signed_data(&self, session_id: &[u8], pubkey: &PublicKey) -> Result<Vec<u8>, ErrType> {
        let mut buf = vec![];
        put_string(&mut buf, session_id)?;
        buf.push(SSH2_MSG_USERAUTH_TRUST_REQUEST);
        put_string(&mut buf, self.ruser.as_bytes())?;
        put_string(&mut buf, b"pam_ssh_agent_auth")?;
        put_string(&mut buf, b"publickey")?;
        buf.push(1);
        put_string(&mut buf, pubkey.key_type().as_bytes())?;
        put_string(&mut buf, &to_bytes(pubkey)?)?;
        Ok(buf)
    }
}

fn put_string(buf: &mut Vec<u8>, s: &[u8]) -> Result<(), ErrType> {
    buf.write_u32::<BigEndian>(s.len() as u32)?;
    buf.extend_from_slice(s);
    Ok(())
}

/// The command line of the current process.
///
/// This is the same data as `/proc/self/cmdline` on Linux, but it also works where there is
/// no `/proc`, such as macOS. Empty arguments are kept, as they were when the file was read.
fn current_argv() -> Option<Vec<Vec<u8>>> {
    let argv: Vec<Vec<u8>> = std::env::args_os()
        .map(|arg| arg.as_os_str().as_bytes().to_vec())
        .collect();
    if argv.is_empty() {
        None
    } else {
        Some(argv)
    }
}

/// The host name of the machine, the same value the `hostname` command reports.
///
/// `gethostname()` is used instead of `/proc/sys/kernel/hostname`, which does not exist on
/// macOS.
fn system_hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname() writes at most buf.len() bytes into buf and keeps no pointer.
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret != 0 {
        warn!("gethostname() failed");
        return String::new();
    }
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_agent::proto::from_bytes;

    fn get_u32(b: &mut &[u8]) -> u32 {
        let (n, rest) = b.split_at(4);
        *b = rest;
        <BigEndian as byteorder::ByteOrder>::read_u32(n)
    }

    fn get_string<'a>(b: &mut &'a [u8]) -> &'a [u8] {
        let n = get_u32(b) as usize;
        let (s, rest) = b.split_at(n);
        *b = rest;
        s
    }

    fn sample() -> Request {
        Request {
            user: "root".to_string(),
            ruser: "alice".to_string(),
            service: "sudo".to_string(),
            cwd: b"/home/alice".to_vec(),
            argv: Some(vec![b"sudo".to_vec(), b"apt".to_vec(), b"".to_vec(), b"install".to_vec()]),
            hostname: "host1".to_string(),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn test_current_argv() {
        let argv = current_argv().unwrap();
        assert!(!argv.is_empty());
        assert_eq!(argv.len(), std::env::args_os().count());
    }

    // On Linux the argv we send must be exactly what /proc/self/cmdline held, so switching
    // from the file to std::env::args_os() does not change the request.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_current_argv_matches_proc_cmdline() {
        let raw = std::fs::read("/proc/self/cmdline").unwrap();
        let mut expected: Vec<Vec<u8>> = raw.split(|byte| *byte == 0).map(|arg| arg.to_vec()).collect();
        if expected.last().map(|arg| arg.is_empty()).unwrap_or(false) {
            expected.pop();
        }
        assert_eq!(current_argv().unwrap(), expected);
    }

    #[test]
    fn test_system_hostname() {
        assert!(!system_hostname().is_empty());
    }

    #[test]
    fn test_action_too_long() {
        let req = Request {
            argv: Some(vec![vec![b'a'; MAX_ACTION_LEN]]),
            ..sample()
        };
        let err = req.session_id(b"cookie").unwrap_err();
        assert!(matches!(
            err.downcast::<RsshErr>().unwrap().as_ref(),
            RsshErr::CmdlineTooLongErr(_)
        ));
    }

    #[test]
    fn test_session_id_layout() {
        let req = sample();
        let id = req.session_id(b"0123456789abcdef").unwrap();
        let mut b = id.as_slice();
        assert_eq!(get_u32(&mut b), 101);
        assert_eq!(get_string(&mut b), b"0123456789abcdef");
        assert_eq!(get_string(&mut b), b"root");
        assert_eq!(get_string(&mut b), b"alice");
        assert_eq!(get_string(&mut b), b"sudo");
        assert_eq!(get_string(&mut b), b"/home/alice");
        let mut action = get_string(&mut b);
        assert_eq!(get_u32(&mut action), 4);
        for arg in [&b"sudo"[..], b"apt", b"", b"install"] {
            assert_eq!(get_string(&mut action), arg);
        }
        assert!(action.is_empty());
        assert_eq!(get_string(&mut b), b"host1");
        assert_eq!(b, &1_700_000_000u64.to_be_bytes()[..]);
    }

    #[test]
    fn test_session_id_without_action() {
        let req = Request { argv: None, ..sample() };
        let id = req.session_id(b"cookie").unwrap();
        let mut b = id.as_slice();
        get_u32(&mut b);
        for _ in 0..5 {
            get_string(&mut b);
        }
        assert_eq!(get_string(&mut b), b"");
        assert_eq!(get_string(&mut b), b"host1");
    }

    #[test]
    fn test_signed_data_layout() {
        // An ed25519 key: string "ssh-ed25519", string <32 bytes>.
        let mut blob = vec![];
        put_string(&mut blob, b"ssh-ed25519").unwrap();
        put_string(&mut blob, &[7u8; 32]).unwrap();
        let key: PublicKey = from_bytes(&blob).unwrap();

        let req = sample();
        let data = req.signed_data(b"session", &key).unwrap();
        let mut b = data.as_slice();
        assert_eq!(get_string(&mut b), b"session");
        assert_eq!(b[0], 54);
        b = &b[1..];
        assert_eq!(get_string(&mut b), b"alice");
        assert_eq!(get_string(&mut b), b"pam_ssh_agent_auth");
        assert_eq!(get_string(&mut b), b"publickey");
        assert_eq!(b[0], 1);
        b = &b[1..];
        assert_eq!(get_string(&mut b), b"ssh-ed25519");
        assert_eq!(get_string(&mut b), blob.as_slice());
        assert!(b.is_empty());
    }
}

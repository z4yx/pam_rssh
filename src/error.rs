use std::error::Error;
use std::fmt::Formatter;
use std::fmt::{Display, Result};

#[derive(Debug)]
pub enum RsshErr {
    FileReadErr(String),
    ParsePubkeyErr,
    AgentFailureErr,
    SignVerifyErr,
    InvalidSigErr,
    RetryLT1Err,
    InvalidRspErr,
    GetUserErr,
    GetHomeErr,
    GetUidErr,
    CmdExitErr(Option<i32>),
    CmdOutputDecodeErr,
}

impl RsshErr {
    pub fn into_ptr(self) -> Box<Self> {
        Box::new(self)
    }
}

macro_rules! S {
    ($s:expr) => {
        String::from($s)
    };
}

impl Display for RsshErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self {
            RsshErr::FileReadErr(name) => format!("Failed to read `{}`", name),
            RsshErr::ParsePubkeyErr => S!("Failed to parse the public key"),
            RsshErr::AgentFailureErr => S!("SSH-Agent reports failure"),
            RsshErr::SignVerifyErr => S!("Signature verification failed"),
            RsshErr::InvalidSigErr => S!("Invalid signature format"),
            RsshErr::RetryLT1Err => S!("Number of retry is less than one"),
            RsshErr::InvalidRspErr => S!("Invalid type of response"),
            RsshErr::GetUserErr => S!("Failed to get user name"),
            RsshErr::GetHomeErr => S!("Cannot get user's home directory"),
            RsshErr::GetUidErr => S!("Cannot get uid of specified user"),
            RsshErr::CmdExitErr(code) => format!("Command exit code is {}", code.unwrap_or(-1)),
            RsshErr::CmdOutputDecodeErr => S!("Failed to decode the output of command"),
        };
        f.write_str(&msg)
    }
}

impl Error for RsshErr {}

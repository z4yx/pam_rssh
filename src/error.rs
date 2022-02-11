use std::error::Error;
use std::fmt::Formatter;
use std::fmt::{Display, Result};

#[derive(Debug)]
pub enum RsshErr {
    FileReadErr(String),
    ParsePubkeyErr,
    AgentFailureErr,
    SignVerifyErr,
    RetryLT1Err,
    InvalidRspErr,
    GetUserErr,
    GetHomeErr,
}

impl RsshErr {
    pub fn new(val: RsshErr) -> Box<Self> {
        Box::new(val)
    }
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
            RsshErr::RetryLT1Err => S!("Number of retry is less than one"),
            RsshErr::InvalidRspErr => S!("Invalid type of response"),
            RsshErr::GetUserErr => S!("Failed to get user name"),
            RsshErr::GetHomeErr => S!("Cannot get user's home directory"),
        };
        f.write_str(&msg)
    }
}

impl Error for RsshErr {}

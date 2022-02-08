use std::error::Error;
use std::fmt::Formatter;
use std::fmt::{Display, Result};

#[derive(Debug)]
pub enum RsshErr {
    FILE_READ_ERR(String),
    PARSE_PUBKEY_ERR,
    RETRY_LT_1_ERR,
    INVALID_RSP_ERR,
    NO_KEY_PASSED_ERR,
}

impl RsshErr {
    pub fn new(val: RsshErr) -> Box<Self> {
        Box::new(val)
    }
    pub fn into_ptr(self) -> Box<Self> {
        Box::new(self)
    }
}

impl Display for RsshErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        // write!(f, )
        let msg = match self {
            RsshErr::FILE_READ_ERR(name) => format!("Failed to read: {}", name),
            RsshErr::PARSE_PUBKEY_ERR => "Failed to parse the public key".to_string(),
            RsshErr::RETRY_LT_1_ERR => "Number of retry is less than one".to_string(),
            RsshErr::INVALID_RSP_ERR => "Invalid type of response".to_string(),
            RsshErr::NO_KEY_PASSED_ERR => "None of keys passed authentication".to_string(),
        };
        f.write_str(&msg);
        Ok(())
    }
}

impl Error for RsshErr {}

// use bytes::{BytesMut, BufMut};
use byteorder::{BigEndian, ReadBytesExt};
use multisock::{SocketAddr, Stream};
use ssh_agent::proto;
use ssh_agent::proto::{from_bytes, to_bytes, Message};
// use tokio::codec::{Framed, Encoder, Decoder};
use std::io::{Read, Write};
// use std::mem::size_of;
use std::net::Shutdown;

use super::auth_keys::Pubkey;

// struct MessageCodec;

pub struct AgentClient<'a> {
    addr: &'a str,
    stream: Option<Stream>,
}

#[derive(Debug)]
pub enum CommError {
    NoDef,
    Proto(proto::error::ProtoError),
    IO(std::io::Error),
    Addr(std::net::AddrParseError),
}

impl From<proto::error::ProtoError> for CommError {
    fn from(e: proto::error::ProtoError) -> CommError {
        CommError::Proto(e)
    }
}

impl From<std::io::Error> for CommError {
    fn from(e: std::io::Error) -> CommError {
        CommError::IO(e)
    }
}

impl From<std::net::AddrParseError> for CommError {
    fn from(e: std::net::AddrParseError) -> CommError {
        CommError::Addr(e)
    }
}

impl std::string::ToString for CommError {
    fn to_string(&self) -> String {
        match self {
            CommError::Proto(e) => e.to_string(),
            CommError::IO(e) => e.to_string(),
            CommError::Addr(e) => e.to_string(),
            default => String::from("Unknown Error"),
        }
    }
}

// impl Decoder for MessageCodec {
//     type Item = Message;
//     type Error = CommError;
//     fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
//         let mut bytes = &src[..];
//         if bytes.len() < size_of::<u32>() {
//             return Ok(None);
//         }
//         let length = bytes.read_u32::<BigEndian>()? as usize;
//         if bytes.len() < length {
//             return Ok(None);
//         }
//         let message: Message = from_bytes(bytes)?;
//         src.advance(size_of::<u32>() + length);
//         Ok(Some(message))
//     }
// }

// impl Encoder for MessageCodec {
//     type Item = Message;
//     type Error = CommError;
//     fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
//         let bytes = to_bytes(&to_bytes(&item)?)?;
//         dst.put(bytes);
//         Ok(())
//     }
// }

// impl From<std::net::AddrParseError> for String {

// }

static NET_RETRY_CNT: u32 = 3;

enum SSH_AGENT_SIGN_FLAG {
    NONE = 0,
    RESERVED = 1,
    SSH_AGENT_RSA_SHA2_256 = 2,
    SSH_AGENT_RSA_SHA2_512 = 4,
}

impl<'a> AgentClient<'a> {
    pub fn new(addr: &str) -> AgentClient {
        AgentClient { addr, stream: None }
    }

    fn read_message(stream: &mut Stream) -> Result<Message, CommError> {
        // let mut preamble = [0; 4];
        // stream.read_exact(&preamble)?;
        let length = stream.read_u32::<BigEndian>()? as usize;
        let mut buffer: Vec<u8> = Vec::with_capacity(length);
        stream.read_exact(buffer.as_mut_slice())?;
        let msg: Message = from_bytes(buffer.as_slice())?;
        Ok(msg)
    }

    fn write_message(stream: &mut Stream, msg: &Message) -> Result<(), CommError> {
        let mut bytes = to_bytes(&to_bytes(msg)?)?;
        stream.write_all(&mut bytes)?;
        Ok(())
    }

    fn connect(&mut self) -> Result<(), CommError> {
        let sockaddr: SocketAddr = self.addr.parse()?;
        // match self.addr.parse() {
        //     Ok(_addr) => sockaddr = _addr,
        //     Err(e) => return Err(e.to_string()),
        // }
        if let Some(ref mut s) = self.stream {
            let _ = s.shutdown(Shutdown::Both);
            self.stream = None;
        }
        self.stream = Some(Stream::connect(&sockaddr)?);
        // match Stream::connect(&sockaddr) {
        //     Ok(s) => self.stream = Some(s),
        //     Err(e) => return Err(e.to_string()),
        // }
        Ok(())
    }

    fn call_agent_once(&mut self, cmd: &Message) -> Result<Message, CommError> {
        if self.stream.is_none() {
            self.connect()?;
        }
        let sock = self.stream.as_mut().unwrap();
        Self::write_message(sock, cmd)?;
        Self::read_message(sock)
        // match Self::read_message(sock) {
        //     Ok(msg) => return Ok(msg),
        //     Err(e) => ret = Err(e.to_string())
        // }
    }

    fn call_agent(&mut self, cmd: &Message, retry: u32) -> Result<Message, String> {
        let mut ret: Result<Message, CommError> = Err(CommError::NoDef);
        for _i in 0..retry {
            ret = self.call_agent_once(cmd);
            if let Ok(val) = ret {
                return Ok(val);
            }
        }
        Err(ret.unwrap_err().to_string())
    }

    pub fn list_identities(&mut self) -> Result<Vec<Pubkey>, String> {
        let msg = self.call_agent(&Message::RequestIdentities, NET_RETRY_CNT)?;
        if let Message::IdentitiesAnswer(keys) = msg {
            for item in keys {
                println!("key: {:?} ({})", item.pubkey_blob, item.comment);
            }
            Ok(vec![])
        } else {
            Err("Invalid type of response".to_string())
        }
    }

    pub fn sign_data<'b>(&mut self, data: &'b str, pubkey: &'b Pubkey) -> Result<String, String> {
        let args = proto::SignRequest {
            pubkey_blob: Vec::from(pubkey.b64key.as_bytes()),
            data: Vec::from(data.as_bytes()),
            flags: (SSH_AGENT_SIGN_FLAG::NONE) as u32,
        };
        let msg = self.call_agent(&Message::SignRequest(args), NET_RETRY_CNT)?;
        if let Message::SignResponse(val) = msg {
            println!("signature: {:?}", val);
            match String::from_utf8(val) {
                Ok(s) => Ok(s),
                Err(e) => Err(e.to_string())
            }
        } else {
            Err("Invalid type of response".to_string())
        }
    }
}

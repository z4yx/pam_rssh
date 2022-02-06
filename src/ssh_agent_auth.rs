use super::auth_keys::Pubkey;

pub struct AgentClient<'a>  {
    addr: &'a str,
    connected: bool
}

impl<'a> AgentClient<'a>{
    pub fn new(addr: &str) -> AgentClient {
        AgentClient{addr, connected: false}
    }

    pub fn list_identities(&mut self) -> Result<Vec<Pubkey>, String> {
        Err("".to_string())
    }

    pub fn sign_data<'b>(&mut self, data: &'b str, pubkey: &'b Pubkey) -> Result<String, String> {
        Err("".to_string())
    }
}

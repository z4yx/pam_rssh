use super::auth_keys::Pubkey;

pub struct AgentClient<'a>  {
    addr: &'a str,
    connected: bool
}

impl<'a,'b,'e> AgentClient<'a> where 'a:'b, 'a:'e{
    pub fn new(addr: &str) -> AgentClient {
        AgentClient{addr, connected: false}
    }

    pub fn list_identities(self: &mut AgentClient<'a>) -> Result<Vec<Pubkey>,  &'e str> {
        Err(&"")
    }

    pub fn sign_data(self: &mut AgentClient<'a>, data: &'b str, pubkey: &'b Pubkey) -> Result<&'e str, &'e str> {
        Err(&"")
    }
}

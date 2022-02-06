use std::fs;
use std::path::PathBuf;

pub struct Pubkey {
    pub b64key: String,
    pub algo: String,
}

pub fn parse_authorized_keys(filename: &str) -> Result<Vec<Pubkey>, String> {
    let content = match fs::read_to_string(filename) {
        Err(e) => return Err("Failed to read ".to_string() + filename),
        Ok(v) => v,
    };
    let mut lines = content.lines();
    let mut res: Vec<Pubkey> = vec![];
    while let Some(line) = lines.next() {
        let mut fields = line.split_whitespace();
        if let Some(algo) = fields.next() {
            if let Some(b64key) = fields.next() {
                let key = Pubkey {
                    algo: algo.to_string(),
                    b64key: b64key.to_string()
                };
                res.push(key);
            }
        }
    }
    Ok(res)
}

pub fn parse_user_authorized_keys(username: &str) -> Result<Vec<Pubkey>, String> {
    let path: PathBuf = ["/home", username, ".ssh", "authorized_keys"]
        .iter()
        .collect();
    parse_authorized_keys(path.to_str().unwrap_or(""))
}

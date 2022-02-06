use super::auth_keys::Pubkey;
pub fn verify_signature(
    content: &str,
    pubkey: &Pubkey,
    signature: &str,
) -> Result<(), String> {
    Err("bak".to_string())
}
pub fn gen_challenge() -> String {
    String::from("2312")
}

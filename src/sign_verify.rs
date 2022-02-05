use super::auth_keys::Pubkey;
pub fn verify_signature<'a>(
    content: &str,
    pubkey: &Pubkey,
    signature: &str,
) -> Result<(), &'a str> {
    Err(&"bak")
}
pub fn gen_challenge<'a>() -> &'a str {
    &"2312"
}

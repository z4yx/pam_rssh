
use pam::constants::PamResultCode;
use pam::module::{PamHandle, PamResult};
use pam::items;
use subst::VariableMap;

pub struct PamItemsMap<'a> {
    pam: &'a PamHandle,
}

impl<'a> VariableMap<'a> for PamItemsMap<'a> {
    type Value = String;
    fn get(&'a self, key: &str) -> Option<Self::Value> {
        self.get_str_val(key).ok()
    }
}

impl<'a> PamItemsMap<'a> {
    pub fn new(pam_handle: &PamHandle) ->PamItemsMap {
        PamItemsMap { pam: pam_handle }
    }
    fn get_str_val(&'a self, key: &str) -> PamResult<String> {
        let str_val = match key {
            "service" => {
                let v = self.pam.get_item::<items::Service>()?.ok_or(PamResultCode::PAM_BUF_ERR)?;
                v.to_str().or(Err(PamResultCode::PAM_BUF_ERR))?
            }
            "user" => {
                let v = self.pam.get_item::<items::User>()?.ok_or(PamResultCode::PAM_BUF_ERR)?;
                v.to_str().or(Err(PamResultCode::PAM_BUF_ERR))?
            }
            "tty" => {
                let v = self.pam.get_item::<items::Tty>()?.ok_or(PamResultCode::PAM_BUF_ERR)?;
                v.to_str().or(Err(PamResultCode::PAM_BUF_ERR))?
            }
            "rhost" => {
                let v = self.pam.get_item::<items::RHost>()?.ok_or(PamResultCode::PAM_BUF_ERR)?;
                v.to_str().or(Err(PamResultCode::PAM_BUF_ERR))?
            }
            "ruser" => {
                let v = self.pam.get_item::<items::RUser>()?.ok_or(PamResultCode::PAM_BUF_ERR)?;
                v.to_str().or(Err(PamResultCode::PAM_BUF_ERR))?
            }
            _ => {
                return Err(PamResultCode::PAM_BAD_ITEM)
            }
        };
        Ok(str_val.to_string())
    }
}

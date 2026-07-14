use log::{Level, Metadata, Record};

pub struct ConsoleLogger;

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

use std::ffi::CStr;

const FMT: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"%s\0") };

pub struct SyslogLogger;

impl log::Log for SyslogLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let priority = match record.level() {
            Level::Error => libc::LOG_ERR,
            Level::Warn => libc::LOG_WARNING,
            Level::Info => libc::LOG_INFO,
            Level::Debug => libc::LOG_DEBUG,
            Level::Trace => libc::LOG_DEBUG,
        };

        let msg = std::ffi::CString::new(record.args().to_string()).unwrap();

        unsafe {
            libc::syslog(priority | libc::LOG_AUTH, FMT.as_ptr(), msg.as_ptr());
        }
    }

    fn flush(&self) {}
}

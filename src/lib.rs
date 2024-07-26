mod err;

use cfg_if::*;
use err::*;

#[cfg(feature = "Win32")]
mod win;

pub struct ProcessId(pub u32);

#[allow(dead_code)]
pub struct Payload<'a> {
    shellcode: &'a [u8],
    len: usize,
}

impl<'a> From<&'a [u8]> for Payload<'a> {
    fn from(shellcode: &'a [u8]) -> Self {
        Self {
            shellcode,
            len: shellcode.len(),
        }
    }
}

pub fn find_process(name: &str) -> Result<ProcessId, FindProcessError> {
    cfg_if! {
        if #[cfg(feature = "Win32")] {
            win::find_process(name)
        }else {
            let _ = name;
            unimplemented!("Win32 not present during building")
        }
    }
}

pub fn inject(pid: ProcessId, payload: Payload) -> Result<(), InjectionError> {
    cfg_if! {
        if #[cfg(feature = "Win32")] {
            win::inject(pid, payload)
        }else {
            let (_, _) = (pid, payload);
            unimplemented!("Win32 not present during building")
        }
    }
}

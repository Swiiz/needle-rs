#[cfg(feature = "windows")]
mod win;

#[cfg(feature = "cyphers")]
pub use cyphres as cypher;
pub mod err;

use cyphres::{Payload, RawPayload};
use err::*;

pub struct ProcessId(pub u32);

pub struct Shellcode(pub RawPayload);
impl Shellcode {
    pub fn raw(&self) -> &RawPayload {
        &self.0
    }

    pub fn into_raw(self) -> RawPayload {
        self.0
    }
}
impl From<RawPayload> for Shellcode {
    fn from(value: RawPayload) -> Self {
        Self(value)
    }
}
impl From<&[u8]> for Shellcode {
    fn from(value: &[u8]) -> Self {
        Self(value.into())
    }
}
impl Payload for Shellcode {}

platform_impl! {
    fn find_process(name: &str) -> Result<ProcessId, FindProcessError>;
    fn inject(pid: ProcessId, shellcode: Shellcode) -> Result<(), InjectionError>;
}

#[macro_export(local_inner_macros)]
macro_rules! platform_impl {
    ( $(fn $fn:ident $(< $($ name:ident $(: $type:ident)? ),*>)? ($($argname:ident : $argtype:ty),* ) $( -> $ret:ty )? ; )*) => {
        use cfg_if::*;
        $(
            pub fn $fn$(<$($name$(: $type)?),*>)?($($argname: $argtype),*) $( -> $ret )? {
                cfg_if! {
                    if #[cfg(feature = "windows")] {
                        win::$fn($($argname),*)
                    }else {
                        no_platform_impl()
                    }
                }
            }
        )*
    };
}

#[allow(dead_code)]
fn no_platform_impl() -> ! {
    panic!("You need to enable a platform feature to use this function: cargo run ... -features `windows`")
}

pub mod cypher;
pub mod err;
use err::*;

#[cfg(feature = "windows")]
mod win;

pub struct ProcessId(pub u32);

pub trait Payload {
    fn shellcode(&self) -> Vec<u8>;
}
pub type Shellcode = Vec<u8>;
impl Payload for &[u8] {
    fn shellcode(&self) -> Vec<u8> {
        self.to_vec()
    }
}
impl Payload for Vec<u8> {
    fn shellcode(&self) -> Vec<u8> {
        self.to_vec()
    }
}

platform_impl! {
    fn find_process(name: &str) -> Result<ProcessId, FindProcessError>;
    fn inject(pid: ProcessId, payload: impl Payload) -> Result<(), InjectionError>;
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
    panic!("You need to enable a platform feature to use this function")
}

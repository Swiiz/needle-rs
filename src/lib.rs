pub mod err;
use err::*;

#[cfg(feature = "windows")]
mod win;

pub struct ProcessId(pub u32);

#[allow(dead_code)]
pub struct Payload<'a> {
    shellcode: &'a [u8],
    len: usize,
}

platform_impl! {
    fn find_process(name: &str) -> Result<ProcessId, FindProcessError>;
    fn inject(pid: ProcessId, payload: Payload) -> Result<(), InjectionError>;
}

impl<'a> From<&'a [u8]> for Payload<'a> {
    fn from(shellcode: &'a [u8]) -> Self {
        Self {
            shellcode,
            len: shellcode.len(),
        }
    }
}

#[macro_export(local_inner_macros)]
macro_rules! platform_impl {
    ( $(fn $fn:ident ($($name:ident : $type:ty),* ) $( -> $ret:ty )? ; )*) => {
        use cfg_if::*;
        $(
            pub fn $fn($($name: $type),*) $( -> $ret )? {
                cfg_if! {
                    if #[cfg(feature = "windows")] {
                        win::$fn($($name),*)
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

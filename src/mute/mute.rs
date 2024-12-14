use pkgcrypto::crypto as crypto;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MuteRole { Client, Server }

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MuteVersion { // -> u64
    MuteVersion1 = 0x0000000000000001,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm { // -> u32
    AES_128_CCM       = 0x00000001,
    AES_192_CCM       = 0x00000002,
    AES_256_CCM       = 0x00000003,
    AES_128_GCM       = 0x00000004,
    AES_192_GCM       = 0x00000005,
    AES_256_GCM       = 0x00000006,
    CHACHA20_POLY1305 = 0x00000007,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm { // -> u32
    SHA256   = 0x00000001,
    SHA384   = 0x00000002,
    SHA512   = 0x00000003,
    SHA3_256 = 0x00000004,
    SHA3_384 = 0x00000005,
    SHA3_512 = 0x00000006,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyShareAlgorithm { // -> u32
    X25519 = 0x00000001,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm { // -> u32
    ED25519 = 0x00000001,
}

/*

struct MuteMessage


*/
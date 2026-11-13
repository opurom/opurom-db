//! Pure-std hashes and the bounded RSA-OAEP helper used by MySQL full auth.
//!
//! shortcut: textbook modular exponentiation is not constant-time/blinded, upgrade before production use.
//! Only SPKI `PUBLIC KEY` PEM, RSA 512..2048 bits, odd public exponents and
//! SHA-1/MGF1 OAEP are accepted. Random seeds come from `/dev/urandom` on Unix;
//! other targets return a typed UNSUPPORTED error instead of faking encryption.
#![allow(dead_code)]

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::Read;

pub const SHA1_LEN: usize = 20;
pub const SHA256_LEN: usize = 32;
const MIN_RSA_MODULUS_BYTES: usize = 64;
const MAX_RSA_MODULUS_BYTES: usize = 256;
const MAX_RSA_PEM_BYTES: usize = 8 * 1024;
const MAX_RSA_DER_BYTES: usize = 4 * 1024;
const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[cfg(test)]
pub const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL6sREozs1JhXPiWgwCiwosKWmjbcnZM
bf8/PcH6T4JQDxpP2DZR9ngNW37rEhC1EPQJMvBdawrzKbq/0tX5vi0CAwEAAQ==
-----END PUBLIC KEY-----
";
#[cfg(test)]
pub const TEST_MODULUS_HEX: &str =
    "beac444a33b352615cf8968300a2c28b0a5a68db72764c6dff3f3dc1fa4f82500f1a4fd83651f6780d5b7eeb1210b510f40932f05d6b0af329babfd2d5f9be2d";
#[cfg(test)]
pub const TEST_PRIVATE_EXPONENT_HEX: &str =
    "4cf415b3a4de10b77ee04d4e9de9127f2f3481f15f66e33dd9b05a6a796db1778fd3809375a4aef1113abd205bc7d2d5367f054f77e5dc15d44b38f90a642f39";
#[cfg(test)]
pub const TEST_OAEP_SEED: [u8; SHA1_LEN] = [0x5a; SHA1_LEN];
#[cfg(test)]
pub const TEST_OAEP_CIPHERTEXT_HEX: &str =
    "817268ad3bf50f4be09b05ab147b8208b67138ecdb92d509594dd01d69d4902703ef138b15263805a0971023333b0bf2ddb68155f3f68a5f8795df60e34c76f1";

/// SHA-1, used by MGF1 in MySQL's RSA-OAEP full-auth exchange.
pub fn sha1(data: &[u8]) -> [u8; SHA1_LEN] {
    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut blocks = data.chunks_exact(64);
    for block in &mut blocks {
        compress_sha1(&mut state, block);
    }
    let mut tail = Vec::with_capacity(128);
    tail.extend_from_slice(blocks.remainder());
    tail.push(0x80);
    while tail.len() % 64 != 56 {
        tail.push(0);
    }
    tail.extend_from_slice(&bit_length(data).to_be_bytes());
    for block in tail.chunks_exact(64) {
        compress_sha1(&mut state, block);
    }
    let mut digest = [0u8; SHA1_LEN];
    for (index, word) in state.iter().enumerate() {
        let offset = index * 4;
        digest[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// SHA-256, used by `caching_sha2_password` fast authentication.
pub fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    let mut state = [
        0x6a09_e667u32,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut blocks = data.chunks_exact(64);
    for block in &mut blocks {
        compress_sha256(&mut state, block);
    }
    let mut tail = Vec::with_capacity(128);
    tail.extend_from_slice(blocks.remainder());
    tail.push(0x80);
    while tail.len() % 64 != 56 {
        tail.push(0);
    }
    tail.extend_from_slice(&bit_length(data).to_be_bytes());
    for block in tail.chunks_exact(64) {
        compress_sha256(&mut state, block);
    }
    let mut digest = [0u8; SHA256_LEN];
    for (index, word) in state.iter().enumerate() {
        let offset = index * 4;
        digest[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn bit_length(data: &[u8]) -> u64 {
    u64::try_from(data.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8)
}

fn compress_sha1(state: &mut [u32; 5], block: &[u8]) {
    let mut words = [0u32; 80];
    for (index, word) in words.iter_mut().enumerate().take(16) {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..80 {
        words[index] =
            (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                .rotate_left(1);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);
    for (index, word) in words.iter().enumerate() {
        let (function, constant) = match index {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(function)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

fn compress_sha256(state: &mut [u32; 8], block: &[u8]) {
    let mut words = [0u32; 64];
    for (index, word) in words.iter_mut().enumerate().take(16) {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let s0 = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let s1 = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(s0)
            .wrapping_add(words[index - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );
    for (index, word) in words.iter().enumerate() {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(SHA256_K[index])
            .wrapping_add(*word);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// A parsed SPKI RSA public key with a bounded modulus.
pub struct RsaPublicKey {
    modulus: BigUint,
    exponent: BigUint,
    size: usize,
}

impl RsaPublicKey {
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Parse a PEM SPKI public key into its RSA modulus and exponent.
pub fn parse_spki_pem(pem: &[u8]) -> Result<RsaPublicKey, String> {
    if pem.len() > MAX_RSA_PEM_BYTES {
        return Err(format!(
            "RSA public-key PEM exceeds {MAX_RSA_PEM_BYTES} bytes"
        ));
    }
    let text =
        std::str::from_utf8(pem).map_err(|_| "RSA public-key PEM is not UTF-8".to_string())?;
    let mut body = Vec::new();
    let mut inside = false;
    let mut header = false;
    let mut footer = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN PUBLIC KEY-----" {
            header = true;
            inside = true;
        } else if line == "-----END PUBLIC KEY-----" {
            footer = true;
            inside = false;
        } else if line == "-----BEGIN RSA PUBLIC KEY-----" {
            return Err(
                "UNSUPPORTED: PKCS#1 RSA PUBLIC KEY PEM is not supported; SPKI PUBLIC KEY is required"
                    .to_string(),
            );
        } else if !line.is_empty() && line.starts_with("-----BEGIN ") {
            return Err("UNSUPPORTED: non-RSA public-key PEM is not supported".to_string());
        } else if inside {
            body.extend(line.bytes().filter(|byte| !byte.is_ascii_whitespace()));
        }
    }
    if !header || !footer || inside || body.is_empty() {
        return Err("malformed RSA public-key PEM".to_string());
    }
    let der = base64_decode(&body)?;
    parse_spki_der(&der)
}

/// Encrypt `message` with RSA-OAEP using SHA-1 and MGF1-SHA1.
pub fn encrypt_oaep_sha1(key: &RsaPublicKey, message: &[u8]) -> Result<Vec<u8>, String> {
    let mut seed = [0u8; SHA1_LEN];
    random_seed(&mut seed)?;
    encrypt_oaep_sha1_with_seed(key, message, &seed)
}

/// Deterministic OAEP encryption for known-answer tests.
pub fn encrypt_oaep_sha1_with_seed(
    key: &RsaPublicKey,
    message: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, String> {
    let encoded = oaep_encode(key.size, message, seed)?;
    let base = BigUint::from_be_bytes(&encoded);
    let cipher = base.pow_mod(&key.exponent, &key.modulus)?;
    cipher.to_fixed_bytes(key.size)
}

/// Decrypt and verify RSA-OAEP SHA-1 ciphertext. Used by conformance tests.
pub fn decrypt_oaep_sha1(
    ciphertext: &[u8],
    modulus_be: &[u8],
    exponent_be: &[u8],
) -> Result<Vec<u8>, String> {
    let modulus = BigUint::from_be_bytes(modulus_be);
    let exponent = BigUint::from_be_bytes(exponent_be);
    if modulus.is_zero() || exponent.is_zero() {
        return Err("invalid RSA private exponent or modulus".to_string());
    }
    let size = modulus
        .bit_len()
        .checked_add(7)
        .ok_or_else(|| "RSA modulus size overflow".to_string())?
        / 8;
    if size < MIN_RSA_MODULUS_BYTES
        || size > MAX_RSA_MODULUS_BYTES
        || ciphertext.len() != size
        || size < 2 * SHA1_LEN + 2
    {
        return Err("invalid RSA ciphertext or modulus size".to_string());
    }
    let cipher = BigUint::from_be_bytes(ciphertext);
    let encoded = cipher.pow_mod(&exponent, &modulus)?.to_fixed_bytes(size)?;
    if encoded.first() != Some(&0) {
        return Err("invalid RSA-OAEP leading byte".to_string());
    }
    let masked_seed = &encoded[1..1 + SHA1_LEN];
    let masked_db = &encoded[1 + SHA1_LEN..];
    let seed_mask = mgf1_sha1(masked_db, SHA1_LEN)?;
    let seed = xor(masked_seed, &seed_mask);
    let db_mask = mgf1_sha1(&seed, masked_db.len())?;
    let db = xor(masked_db, &db_mask);
    let label_hash = sha1(b"");
    if db.get(..SHA1_LEN) != Some(label_hash.as_slice()) {
        return Err("invalid RSA-OAEP label hash".to_string());
    }
    let mut position = SHA1_LEN;
    while position < db.len() && db[position] == 0 {
        position += 1;
    }
    if db.get(position) != Some(&1) {
        return Err("invalid RSA-OAEP separator".to_string());
    }
    Ok(db[position + 1..].to_vec())
}

fn oaep_encode(size: usize, message: &[u8], seed: &[u8]) -> Result<Vec<u8>, String> {
    if size < 2 * SHA1_LEN + 2 || seed.len() != SHA1_LEN {
        return Err("invalid RSA-OAEP parameters".to_string());
    }
    if message.len() > size - 2 * SHA1_LEN - 2 {
        return Err("RSA-OAEP message exceeds the modulus capacity".to_string());
    }
    let db_len = size - SHA1_LEN - 1;
    let ps_len = db_len - SHA1_LEN - 1 - message.len();
    let mut db = vec![0u8; db_len];
    db[..SHA1_LEN].copy_from_slice(&sha1(b""));
    db[SHA1_LEN + ps_len] = 1;
    db[SHA1_LEN + ps_len + 1..].copy_from_slice(message);
    let db_mask = mgf1_sha1(seed, db_len)?;
    let masked_db = xor(&db, &db_mask);
    let seed_mask = mgf1_sha1(&masked_db, SHA1_LEN)?;
    let masked_seed = xor(seed, &seed_mask);
    let mut encoded = Vec::with_capacity(size);
    encoded.push(0);
    encoded.extend_from_slice(&masked_seed);
    encoded.extend_from_slice(&masked_db);
    Ok(encoded)
}

fn mgf1_sha1(seed: &[u8], length: usize) -> Result<Vec<u8>, String> {
    if length > MAX_RSA_DER_BYTES {
        return Err("RSA-OAEP mask length exceeds the bound".to_string());
    }
    let mut output = Vec::with_capacity(length);
    let mut counter = 0u32;
    while output.len() < length {
        let mut input = Vec::with_capacity(seed.len() + 4);
        input.extend_from_slice(seed);
        input.extend_from_slice(&counter.to_be_bytes());
        output.extend_from_slice(&sha1(&input));
        counter = counter
            .checked_add(1)
            .ok_or_else(|| "RSA-OAEP MGF1 counter overflow".to_string())?;
    }
    output.truncate(length);
    Ok(output)
}

fn xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter().zip(right.iter()).map(|(a, b)| a ^ b).collect()
}

#[cfg(unix)]
fn random_seed(seed: &mut [u8]) -> Result<(), String> {
    let mut file = File::open("/dev/urandom")
        .map_err(|error| format!("UNSUPPORTED: RSA-OAEP needs /dev/urandom: {error}"))?;
    file.read_exact(seed)
        .map_err(|error| format!("UNSUPPORTED: RSA-OAEP random seed failed: {error}"))
}

#[cfg(not(unix))]
fn random_seed(_seed: &mut [u8]) -> Result<(), String> {
    Err("UNSUPPORTED: RSA-OAEP needs a Unix /dev/urandom random seed".to_string())
}

fn parse_spki_der(der: &[u8]) -> Result<RsaPublicKey, String> {
    if der.len() > MAX_RSA_DER_BYTES {
        return Err(format!("RSA DER exceeds {MAX_RSA_DER_BYTES} bytes"));
    }
    let mut top = Der::new(der);
    let spki = top.tlv(0x30, "SubjectPublicKeyInfo")?;
    top.done("SubjectPublicKeyInfo")?;
    let mut spki = Der::new(spki);
    let algorithm = spki.tlv(0x30, "AlgorithmIdentifier")?;
    let bit_string = spki.tlv(0x03, "subjectPublicKey")?;
    spki.done("SubjectPublicKeyInfo")?;
    let mut algorithm = Der::new(algorithm);
    let oid = algorithm.tlv(0x06, "algorithm OID")?;
    if oid != RSA_ENCRYPTION_OID {
        return Err("UNSUPPORTED: RSA SPKI algorithm is not rsaEncryption".to_string());
    }
    let null = algorithm.tlv(0x05, "algorithm NULL")?;
    if !null.is_empty() {
        return Err("malformed RSA AlgorithmIdentifier NULL".to_string());
    }
    algorithm.done("AlgorithmIdentifier")?;
    if bit_string.first() != Some(&0) {
        return Err("malformed RSA subjectPublicKey BIT STRING".to_string());
    }
    let mut rsa = Der::new(&bit_string[1..]);
    let sequence = rsa.tlv(0x30, "RSAPublicKey")?;
    rsa.done("RSAPublicKey")?;
    let mut sequence = Der::new(sequence);
    let modulus = der_integer(&mut sequence)?;
    let exponent = der_integer(&mut sequence)?;
    sequence.done("RSAPublicKey")?;
    if modulus.len() < MIN_RSA_MODULUS_BYTES || modulus.len() > MAX_RSA_MODULUS_BYTES {
        return Err(format!(
            "UNSUPPORTED: RSA modulus must be {MIN_RSA_MODULUS_BYTES}..{MAX_RSA_MODULUS_BYTES} bytes"
        ));
    }
    if exponent.is_empty() || exponent.len() > 4 {
        return Err("UNSUPPORTED: RSA public exponent must fit in four bytes".to_string());
    }
    let mut exponent_value = 0u32;
    for byte in &exponent {
        exponent_value = (exponent_value << 8) | u32::from(*byte);
    }
    if exponent_value < 3 || exponent_value % 2 == 0 {
        return Err("UNSUPPORTED: RSA public exponent must be odd and at least 3".to_string());
    }
    let modulus_value = BigUint::from_be_bytes(&modulus);
    let bits = modulus_value.bit_len();
    if bits < MIN_RSA_MODULUS_BYTES * 8 || bits > MAX_RSA_MODULUS_BYTES * 8 || !modulus_value.bit(0)
    {
        return Err("UNSUPPORTED: RSA modulus has an unsupported size or parity".to_string());
    }
    Ok(RsaPublicKey {
        modulus: modulus_value,
        exponent: BigUint::from_be_bytes(&exponent_value.to_be_bytes()),
        size: modulus.len(),
    })
}

fn der_integer(der: &mut Der<'_>) -> Result<Vec<u8>, String> {
    let bytes = der.tlv(0x02, "RSA INTEGER")?;
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    if bytes.is_empty() || start >= bytes.len() || (start == 0 && bytes[start] & 0x80 != 0) {
        return Err("malformed or negative RSA INTEGER".to_string());
    }
    Ok(bytes[start..].to_vec())
}

struct Der<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Der<'a> {
        Der { data, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| "DER length overflow".to_string())?;
        let bytes = self
            .data
            .get(self.position..end)
            .ok_or_else(|| "truncated DER body".to_string())?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn length(&mut self) -> Result<usize, String> {
        let first = self.u8()?;
        let length = match first {
            0..=0x7f => usize::from(first),
            0x81 => usize::from(self.u8()?),
            0x82 => {
                let bytes = self.take(2)?;
                usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            }
            _ => return Err("UNSUPPORTED: DER long-form length is not supported".to_string()),
        };
        if length > MAX_RSA_DER_BYTES {
            return Err(format!("DER length {length} exceeds {MAX_RSA_DER_BYTES}"));
        }
        Ok(length)
    }

    fn tlv(&mut self, tag: u8, what: &str) -> Result<&'a [u8], String> {
        if self.u8()? != tag {
            return Err(format!("malformed DER {what} tag"));
        }
        let length = self.length()?;
        self.take(length)
    }

    fn done(&self, what: &str) -> Result<(), String> {
        if self.position == self.data.len() {
            Ok(())
        } else {
            Err(format!("trailing bytes in DER {what}"))
        }
    }
}

fn base64_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut clean = Vec::with_capacity(input.len());
    for byte in input {
        if !byte.is_ascii_whitespace() {
            clean.push(*byte);
        }
    }
    if clean.is_empty() || clean.len() % 4 != 0 {
        return Err("malformed RSA public-key base64".to_string());
    }
    let mut output = Vec::with_capacity(clean.len() / 4 * 3);
    let chunks = clean.len() / 4;
    for (index, chunk) in clean.chunks_exact(4).enumerate() {
        let last = index + 1 == chunks;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' {
                return Err("malformed RSA public-key base64 padding".to_string());
            }
            output.push((a << 2) | (b >> 4));
        } else {
            let c = base64_value(chunk[2])?;
            if chunk[3] == b'=' {
                if !last {
                    return Err("malformed RSA public-key base64 padding".to_string());
                }
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
            } else {
                let d = base64_value(chunk[3])?;
                output.push((a << 2) | (b >> 4));
                output.push((b << 4) | (c >> 2));
                output.push((c << 6) | d);
            }
        }
    }
    if output.len() > MAX_RSA_DER_BYTES {
        return Err(format!("RSA DER exceeds {MAX_RSA_DER_BYTES} bytes"));
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("invalid RSA public-key base64 byte".to_string()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    fn from_be_bytes(bytes: &[u8]) -> BigUint {
        let mut limbs = vec![0u32; bytes.len().saturating_add(3) / 4];
        for (index, byte) in bytes.iter().rev().enumerate() {
            let limb = index / 4;
            if let Some(slot) = limbs.get_mut(limb) {
                *slot |= u32::from(*byte) << ((index % 4) * 8);
            }
        }
        BigUint { limbs }.normalized()
    }

    fn zero() -> BigUint {
        BigUint { limbs: Vec::new() }
    }

    fn one() -> BigUint {
        BigUint { limbs: vec![1] }
    }

    fn normalized(mut self) -> BigUint {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
        self
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn bit_len(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(last) => (self.limbs.len() - 1) * 32 + (32 - last.leading_zeros() as usize),
        }
    }

    fn bit(&self, index: usize) -> bool {
        self.limbs
            .get(index / 32)
            .is_some_and(|limb| (limb >> (index % 32)) & 1 == 1)
    }

    fn compare(&self, other: &BigUint) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {
                for index in (0..self.limbs.len()).rev() {
                    match self.limbs[index].cmp(&other.limbs[index]) {
                        Ordering::Equal => {}
                        ordering => return ordering,
                    }
                }
                Ordering::Equal
            }
            ordering => ordering,
        }
    }

    fn add(&self, other: &BigUint) -> BigUint {
        let count = self.limbs.len().max(other.limbs.len());
        let mut limbs = Vec::with_capacity(count + 1);
        let mut carry = 0u64;
        for index in 0..count {
            let left = u64::from(self.limbs.get(index).copied().unwrap_or(0));
            let right = u64::from(other.limbs.get(index).copied().unwrap_or(0));
            let sum = left + right + carry;
            limbs.push(sum as u32);
            carry = sum >> 32;
        }
        if carry != 0 {
            limbs.push(carry as u32);
        }
        BigUint { limbs }.normalized()
    }

    fn sub(&self, other: &BigUint) -> Result<BigUint, String> {
        use std::cmp::Ordering;
        if self.compare(other) == Ordering::Less {
            return Err("big integer subtraction underflow".to_string());
        }
        let mut limbs = self.limbs.clone();
        let mut borrow = 0i64;
        for index in 0..limbs.len() {
            let left = i64::from(limbs[index]);
            let right = i64::from(other.limbs.get(index).copied().unwrap_or(0));
            let value = left - right - borrow;
            if value < 0 {
                limbs[index] = (value + 0x1_0000_0000i64) as u32;
                borrow = 1;
            } else {
                limbs[index] = value as u32;
                borrow = 0;
            }
        }
        if borrow != 0 {
            return Err("big integer subtraction underflow".to_string());
        }
        Ok(BigUint { limbs }.normalized())
    }

    fn shl1(&mut self) {
        let mut carry = 0u32;
        for limb in &mut self.limbs {
            let next = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
    }

    fn set_bit0(&mut self) {
        if let Some(limb) = self.limbs.get_mut(0) {
            *limb |= 1;
        } else {
            self.limbs.push(1);
        }
    }

    fn rem(&self, modulus: &BigUint) -> Result<BigUint, String> {
        use std::cmp::Ordering;
        if modulus.is_zero() {
            return Err("big integer division by zero".to_string());
        }
        let mut remainder = BigUint::zero();
        for index in (0..self.bit_len()).rev() {
            remainder.shl1();
            if self.bit(index) {
                remainder.set_bit0();
            }
            while remainder.compare(modulus) != Ordering::Less {
                remainder = remainder.sub(modulus)?;
            }
        }
        Ok(remainder)
    }

    fn add_mod(&self, other: &BigUint, modulus: &BigUint) -> Result<BigUint, String> {
        use std::cmp::Ordering;
        let mut sum = self.add(other);
        while sum.compare(modulus) != Ordering::Less {
            sum = sum.sub(modulus)?;
        }
        Ok(sum)
    }

    fn mul_mod(&self, other: &BigUint, modulus: &BigUint) -> Result<BigUint, String> {
        let mut result = BigUint::zero();
        let mut base = self.rem(modulus)?;
        for index in 0..other.bit_len() {
            if other.bit(index) {
                result = result.add_mod(&base, modulus)?;
            }
            if index + 1 < other.bit_len() {
                base = base.add_mod(&base, modulus)?;
            }
        }
        Ok(result)
    }

    fn pow_mod(&self, exponent: &BigUint, modulus: &BigUint) -> Result<BigUint, String> {
        let mut result = BigUint::one().rem(modulus)?;
        let base = self.rem(modulus)?;
        for index in (0..exponent.bit_len()).rev() {
            result = result.mul_mod(&result, modulus)?;
            if exponent.bit(index) {
                result = result.mul_mod(&base, modulus)?;
            }
        }
        Ok(result)
    }

    fn to_fixed_bytes(&self, length: usize) -> Result<Vec<u8>, String> {
        let bits = length
            .checked_mul(8)
            .ok_or_else(|| "big integer byte length overflow".to_string())?;
        if self.bit_len() > bits {
            return Err("big integer does not fit the RSA modulus size".to_string());
        }
        let mut output = vec![0u8; length];
        for index in 0..length {
            let limb = self.limbs.get(index / 4).copied().unwrap_or(0);
            output[length - 1 - index] = (limb >> ((index % 4) * 8)) as u8;
        }
        Ok(output)
    }
}

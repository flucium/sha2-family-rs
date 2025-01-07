/// SHA256 table.
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA512 table.
const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// Rotates a 32-bit unsigned integer `x` to the right by `n` bits.
///
/// # Arguments
///
/// * `x` - The 32-bit unsigned integer to rotate.
/// * `n` - The number of bits to rotate.
///
/// # Returns
///
/// A 32-bit unsigned integer that is the result of the rotation.
fn rotate_right_32(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// Rotates a 64-bit unsigned integer `x` to the right by `n` bits.
///
/// # Arguments
///
/// * `x` - The 64-bit unsigned integer to rotate.
/// * `n` - The number of bits to rotate.
///
/// # Returns
///
/// A 64-bit unsigned integer that is the result of the rotation.
fn rotate_right_64(x: u64, n: u64) -> u64 {
    (x >> n) | (x << (64 - n))
}

/// SHA2 'choose' function, which selects bits from `y` or `z` based on `x`.
///
/// # Arguments
///
/// * `x` - The selector.
/// * `y` - The first input.
/// * `z` - The second input.
///
/// # Returns
///
/// A `usize` value resulting from the operation.
fn choose(x: usize, y: usize, z: usize) -> usize {
    (x & y) ^ (!x & z)
}

/// SHA2 'majority' function, which selects the majority bits among `x`, `y`, and `z`.
///
/// # Arguments
///
/// * `x` - The first input.
/// * `y` - The second input.
/// * `z` - The third input.
///
/// # Returns
///
/// A `usize` value representing the majority bits.
fn majority(x: usize, y: usize, z: usize) -> usize {
    (x & y) ^ (x & z) ^ (y & z)
}

/// SHA-256 Sigma_0 function for 32-bit inputs.
/// Combines three bitwise rotations.
///
/// # Arguments
///
/// * `x` - The input value.
///
/// # Returns
///
/// A 32-bit unsigned integer resulting from the operation.
fn sigma0_32(x: u32) -> u32 {
    rotate_right_32(x, 2) ^ rotate_right_32(x, 13) ^ rotate_right_32(x, 22)
}

/// SHA-256 Sigma_1 function for 32-bit inputs.
/// Combines three bitwise rotations.
///
/// # Arguments
///
/// * `x` - The input value.
///
/// # Returns
///
/// A 32-bit unsigned integer resulting from the operation.
fn sigma1_32(x: u32) -> u32 {
    rotate_right_32(x, 6) ^ rotate_right_32(x, 11) ^ rotate_right_32(x, 25)
}

/// SHA-512 Sigma_0 function for 64-bit inputs.
/// Combines three bitwise rotations.
///
/// # Arguments
///
/// * `x` - The input value.
///
/// # Returns
///
/// A 64-bit unsigned integer resulting from the operation.
fn sigma0_64(x: u64) -> u64 {
    rotate_right_64(x, 28) ^ rotate_right_64(x, 34) ^ rotate_right_64(x, 39)
}

/// SHA-512 Sigma_1 function for 64-bit inputs.
/// Combines three bitwise rotations.
///
/// # Arguments
///
/// * `x` - The input value.
///
/// # Returns
///
/// A 64-bit unsigned integer resulting from the operation.
fn sigma1_64(x: u64) -> u64 {
    rotate_right_64(x, 14) ^ rotate_right_64(x, 18) ^ rotate_right_64(x, 41)
}

/// SHA-256 Gamma_0 function for 32-bit inputs.
/// Combines two rotations and one right shift.
///
/// # Arguments
///
/// * `x` - The input value.
///
/// # Returns
///
/// A 32-bit unsigned integer resulting from the operation.
fn gamma0_32(x: u32) -> u32 {
    rotate_right_32(x, 7) ^ rotate_right_32(x, 18) ^ (x >> 3)
}

/// SHA-256 Gamma_1 function for 32-bit inputs.
/// Combines two rotations and one right shift.
///
/// # Arguments
///
/// * `x` - The input value.
///
/// # Returns
///
/// A 32-bit unsigned integer resulting from the operation.
fn gamma1_32(x: u32) -> u32 {
    rotate_right_32(x, 17) ^ rotate_right_32(x, 19) ^ (x >> 10)
}

/// SHA-512 Gamma_0 function for 64-bit inputs.
/// Combines two rotations and one right shift.
///
/// # Arguments
///
/// * `x` - The input value.
///
/// # Returns
///
/// A 64-bit unsigned integer resulting from the operation.
fn gamma0_64(x: u64) -> u64 {
    rotate_right_64(x, 1) ^ rotate_right_64(x, 8) ^ (x >> 7)
}

/// SHA-512 Gamma_1 function for 64-bit inputs.
/// Combines two rotations and one right shift.
///
/// # Arguments
///
/// * `x` - The input value.
///
/// # Returns
///
/// A 64-bit unsigned integer resulting from the operation.
fn gamma1_64(x: u64) -> u64 {
    rotate_right_64(x, 19) ^ rotate_right_64(x, 61) ^ (x >> 6)
}

fn sha256_block(block: &[u8], h: &mut [u32; 8]) {
    let mut w = [0u32; 64];

    for t in 0..16 {
        w[t] = ((block[t * 4] as u32) << 24)
            | ((block[t * 4 + 1] as u32) << 16)
            | ((block[t * 4 + 2] as u32) << 8)
            | (block[t * 4 + 3] as u32);
    }

    for t in 16..64 {
        w[t] = gamma1_32(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(gamma0_32(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut h_0 = h[7];

    for t in 0..64 {
        let t1 = h_0
            .wrapping_add(sigma1_32(e))
            .wrapping_add(
                choose(
                    e.try_into().unwrap(),
                    f.try_into().unwrap(),
                    g.try_into().unwrap(),
                )
                .try_into()
                .unwrap(),
            )
            .wrapping_add(SHA256_K[t])
            .wrapping_add(w[t]);
        let t2 = sigma0_32(a).wrapping_add(
            majority(
                a.try_into().unwrap(),
                b.try_into().unwrap(),
                c.try_into().unwrap(),
            )
            .try_into()
            .unwrap(),
        );

        h_0 = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(h_0);
}

fn sha256(message: &[u8]) -> [u8; 32] {
    let mut initial_hash_value = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut pad_msg = message.to_vec();
    let msg_len = pad_msg.len() as u64 * 8;

    pad_msg.push(0x80);
    while (pad_msg.len() % 64) != 56 {
        pad_msg.push(0);
    }

    for &b in &msg_len.to_be_bytes() {
        pad_msg.push(b);
    }

    for chunk in pad_msg.chunks(64) {
        sha256_block(chunk, &mut initial_hash_value);
    }

    let mut result = [0u8; 32];
    for (i, &val) in initial_hash_value.iter().enumerate() {
        result[i * 4] = (val >> 24) as u8;
        result[i * 4 + 1] = (val >> 16) as u8;
        result[i * 4 + 2] = (val >> 8) as u8;
        result[i * 4 + 3] = val as u8;
    }

    result
}

fn sha512_block(block: &[u8], h: &mut [u64; 8]) {
    let mut w = [0u64; 80];

    for t in 0..16 {
        w[t] = ((block[t * 8] as u64) << 56)
            | ((block[t * 8 + 1] as u64) << 48)
            | ((block[t * 8 + 2] as u64) << 40)
            | ((block[t * 8 + 3] as u64) << 32)
            | ((block[t * 8 + 4] as u64) << 24)
            | ((block[t * 8 + 5] as u64) << 16)
            | ((block[t * 8 + 6] as u64) << 8)
            | (block[t * 8 + 7] as u64);
    }

    for t in 16..80 {
        w[t] = gamma1_64(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(gamma0_64(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut h_0 = h[7];

    for t in 0..80 {
        let t1 = h_0
            .wrapping_add(sigma1_64(e))
            .wrapping_add(
                choose(
                    e.try_into().unwrap(),
                    f.try_into().unwrap(),
                    g.try_into().unwrap(),
                )
                .try_into()
                .unwrap(),
            )
            .wrapping_add(SHA512_K[t])
            .wrapping_add(w[t]);
        let t2 = sigma0_64(a).wrapping_add(
            majority(
                a.try_into().unwrap(),
                b.try_into().unwrap(),
                c.try_into().unwrap(),
            )
            .try_into()
            .unwrap(),
        );

        h_0 = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(h_0);
}

pub fn sha512(message: &[u8]) -> [u8; 64] {
    let mut initial_hash_value = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    let mut pad_msg: Vec<u8> = message.to_vec();
    let msg_len = (pad_msg.len() as u128) * 8;

    pad_msg.push(0x80);
    while (pad_msg.len() % 128) != 112 {
        pad_msg.push(0);
    }

    for &b in &msg_len.to_be_bytes() {
        pad_msg.push(b);
    }

    for chunk in pad_msg.chunks(128) {
        sha512_block(chunk, &mut initial_hash_value);
    }

    let mut result = [0u8; 64];
    for (i, &val) in initial_hash_value.iter().enumerate() {
        result[i * 8] = (val >> 56) as u8;
        result[i * 8 + 1] = (val >> 48) as u8;
        result[i * 8 + 2] = (val >> 40) as u8;
        result[i * 8 + 3] = (val >> 32) as u8;
        result[i * 8 + 4] = (val >> 24) as u8;
        result[i * 8 + 5] = (val >> 16) as u8;
        result[i * 8 + 6] = (val >> 8) as u8;
        result[i * 8 + 7] = val as u8;
    }

    result
}

fn sha384(message: &[u8]) -> [u8; 48] {
    let mut initial_hash_value = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];

    let mut pad_msg: Vec<u8> = message.to_vec();
    let msg_len: u128 = pad_msg.len() as u128 * 8;

    pad_msg.push(0x80);
    while (pad_msg.len() % 128) != 112 {
        pad_msg.push(0);
    }

    for &b in &msg_len.to_be_bytes() {
        pad_msg.push(b);
    }

    for chunk in pad_msg.chunks(128) {
        sha512_block(chunk, &mut initial_hash_value);
    }

    let mut result = [0u8; 48];
    for (i, &val) in initial_hash_value.iter().take(6).enumerate() {
        result[i * 8] = (val >> 56) as u8;
        result[i * 8 + 1] = (val >> 48) as u8;
        result[i * 8 + 2] = (val >> 40) as u8;
        result[i * 8 + 3] = (val >> 32) as u8;
        result[i * 8 + 4] = (val >> 24) as u8;
        result[i * 8 + 5] = (val >> 16) as u8;
        result[i * 8 + 6] = (val >> 8) as u8;
        result[i * 8 + 7] = val as u8;
    }

    result
}

fn sha224(message: &[u8]) -> [u8; 28] {
    let mut initial_hash_value: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];

    let mut padded_message = message.to_vec();
    let message_len = (padded_message.len() as u64) * 8;

    padded_message.push(0x80);
    while (padded_message.len() % 64) != 56 {
        padded_message.push(0);
    }

    for &b in &message_len.to_be_bytes() {
        padded_message.push(b);
    }

    for chunk in padded_message.chunks(64) {
        sha256_block(chunk, &mut initial_hash_value);
    }

    let mut result = [0u8; 28];
    for (i, &val) in initial_hash_value.iter().take(7).enumerate() {
        result[i * 4] = (val >> 24) as u8;
        result[i * 4 + 1] = (val >> 16) as u8;
        result[i * 4 + 2] = (val >> 8) as u8;
        result[i * 4 + 3] = val as u8;
    }

    result
}

const HEX_UPPER_TABLE: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_string = String::new();

    for &byte in bytes {
        let high = (byte >> 4) as usize;
        let low = (byte & 0x0F) as usize;
        hex_string.push(HEX_UPPER_TABLE[high]);
        hex_string.push(HEX_UPPER_TABLE[low]);
    }

    hex_string
}

fn main() {
    println!("{:?}", bytes_to_hex(&sha224(b"Hello")));
    println!("{:?}", bytes_to_hex(&sha256(b"Hello")));
    println!("{:?}", bytes_to_hex(&sha384(b"Hello")));
    println!("{:?}", bytes_to_hex(&sha512(b"Hello")));
}

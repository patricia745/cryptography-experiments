const PADDING_BYTE: u8 = 0x80;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    x >> n | x << (32 - n)
}

#[inline]
fn shr(x: u32, n: u32) -> u32 {
    x >> n
}

/// choice function. if x is 1, return the value of y. if x if 0, return the value of z
#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// choose bits set in two of x, y, and z, but not all three
#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn lower_sigma_0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
}

#[inline]
fn lower_sigma_1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
}

#[inline]
fn upper_sigma_0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

#[inline]
fn upper_sigma_1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// Each SHA256 operation has two phases:
/// 
/// 1. Preprocessing
///     a. Pad the message to ensure it is a multiple of 512 bits
///     b. Set the initial hash values
/// 2. Hash computation
/// For each 512 bit block of the padded data:
///     a. Prepare message W
///     b. Initialize working variables to previous hash values
///     c. Update working variables
///     d. Update hash values
/// e. Resulting digest is the concatenation of the hash values
pub fn sha256(input: &str) -> String {
    let mut padded_data = input.as_bytes().to_vec();
    
    // 1a. Pad the message
    
    // indicate the beginning of padding with a padding byte
    padded_data.push(PADDING_BYTE);
    
    // pad the message with 0s so that its remainder is 512 - 64 = 448
    while (padded_data.len() * 8) % 512 != 448 {
        padded_data.push(0);
    }
    
    // append length of input in 64 bits (note that the max size of input is 2^64)
    let bit_length: u64 = (input.len() as u64) * 8;
    padded_data.extend_from_slice(&bit_length.to_be_bytes());
    
    // format of padded_data:
    // ----------------------------------------------------------------
    // | 01010111 10101000 | 10000000     | 000 ... | 00000 ... 10000 |
    // ----------------------------------------------------------------
    // |    input data     | padding byte | padding | length of input |
    // ----------------------------------------------------------------
    
    // 1b. Set initial hash values
    let mut hash: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    
    for block in padded_data.chunks(512 / 8) {
        // 2a. Prepare message w
        let mut w: [u32; 64] = [0; 64];
        
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4]
                        .try_into()
                        .expect("incorrect length"));
        }
        
        for i in 16..64 {
            w[i] = lower_sigma_1(w[i-2])
                            .wrapping_add(w[i-7])
                            .wrapping_add(lower_sigma_0(w[i-15]))
                            .wrapping_add(w[i-16])
        }
        
        // 2b. Initialize working variables to previous hash values
        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut f = hash[5];
        let mut g = hash[6];
        let mut h = hash[7];
        
        // 2c. Update working variables
        for i in 0..64 {
            let t1 = h
                        .wrapping_add(upper_sigma_1(e))
                        .wrapping_add(ch(e, f, g))
                        .wrapping_add(K[i])
                        .wrapping_add(w[i]);
            let t2 = upper_sigma_0(a)
                        .wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        
        // 2d. Update hash values
        hash[0] = a.wrapping_add(hash[0]);
        hash[1] = b.wrapping_add(hash[1]);
        hash[2] = c.wrapping_add(hash[2]);
        hash[3] = d.wrapping_add(hash[3]);
        hash[4] = e.wrapping_add(hash[4]);
        hash[5] = f.wrapping_add(hash[5]);
        hash[6] = g.wrapping_add(hash[6]);
        hash[7] = h.wrapping_add(hash[7]);
    }
    
    // format as a string
    return hash.iter()
        .map(|&x| format!("{:08x}", x))  // Format each u32 as a zero-padded 8-character hex string
        .collect::<String>();
}

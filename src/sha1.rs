use anyhow::ensure;

#[inline]
fn bitwise_interleave(mask: u32, x: u32, y: u32) -> u32 {
    // Ch in FIPS.180-4
    (mask & x) ^ (!mask & y)
}

#[inline]
fn bitwise_parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline]
fn bitwise_majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
#[allow(non_snake_case)]
fn process_block(block: [u8; 64], [mut a, mut b, mut c, mut d, mut e]: [u32; 5]) -> [u32; 5] {
    // K_t = K[t/20]
    let K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
    // f_t = f[t/20]
    let f = [
        bitwise_interleave,
        bitwise_parity,
        bitwise_majority,
        bitwise_parity,
    ];
    let mut W = [0u32; 80];
    let mut M = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        M[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    for t in 0..W.len() {
        if t <= 15 {
            W[t] = M[t];
        } else {
            W[t] = (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]).rotate_left(1)
        }
    }
    let mut T;
    for t in 0..W.len() {
        T = a
            .rotate_left(5)
            .wrapping_add(f[t / 20](b, c, d))
            .wrapping_add(e)
            .wrapping_add(K[t / 20])
            .wrapping_add(W[t]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = T;
    }
    [a, b, c, d, e]
}

pub type Digest = [u8; 20];

#[allow(non_snake_case)]
pub fn sha1(message: &[u8]) -> Digest {
    const BLOCK_SIZE_BITS: usize = 512;
    const BLOCK_SIZE_BYTES: usize = BLOCK_SIZE_BITS / 8;
    let mut H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    let l = message.len() * 8;
    // 64 bytes at a time
    for (i, block) in message.chunks(BLOCK_SIZE_BYTES).enumerate() {
        if i == l.div_ceil(BLOCK_SIZE_BITS) - 1 {
            // last block
            // preprocessing
            let mut last_part = Vec::from(block);
            last_part.push(0x80); // append 1 bit
            last_part.append(&mut vec![
                0x00;
                (2 * BLOCK_SIZE_BYTES
                    - (last_part.len() % BLOCK_SIZE_BYTES)
                    - 8)
                    % BLOCK_SIZE_BYTES
            ]);
            last_part.extend((l as u64).to_be_bytes());
            for block in last_part.chunks_exact(BLOCK_SIZE_BYTES) {
                // do_block
                let H_next = process_block(*block.first_chunk::<BLOCK_SIZE_BYTES>().unwrap(), H);
                for i in 0..H.len() {
                    H[i] = H[i].wrapping_add(H_next[i])
                }
            }
            break;
        }

        let H_next = process_block(*block.first_chunk::<BLOCK_SIZE_BYTES>().unwrap(), H);
        for i in 0..H.len() {
            H[i] = H[i].wrapping_add(H_next[i])
        }
    }
    *H.map(|x| x.to_be_bytes()).concat().first_chunk().unwrap()
}

#[inline]
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x?}")).collect()
}

#[inline]
pub fn hex_decode(hex: &str) -> anyhow::Result<Digest> {
    ensure!(
        hex.len() >= 40,
        "not enough bytes to decode this string into a 160 bit hash"
    );
    ensure!(
        hex.as_bytes().iter().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(byte) || (b'A'..=b'F').contains(byte)
        }),
        "invalid characters in {hex}: only 0..9 and a..f/A..F allowed"
    );
    let mut result = vec![];
    for hex_byte in hex.as_bytes()[0..40].chunks(2) {
        result.push(u8::from_str_radix(str::from_utf8(hex_byte).unwrap(), 16).unwrap())
    }
    Ok(result[0..20].try_into().unwrap())
}

#[cfg(test)]
mod tests {

    use crate::sha1::sha1;

    #[test]
    fn test_sha1() {
        assert_eq!(
            *b"\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d",
            sha1(b"abc")
        );
        assert_eq!(
            *b"\x18\x7b\xb0\x52\x47\x9e\xbd\xaf\x30\x19\xcc\xe0\xa3\xce\xcd\xc8\xe7\x40\x26\x59",
            sha1(b"sha1 is the best hashing algorithm!")
        );
    }
}

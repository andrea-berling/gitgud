use std::{cmp::max, fmt::Display};

use anyhow::{bail, ensure, Context};

const COMPRESSION_LEVEL_MASK: u8 = 0x3;
const DEFLATE_IDENTIFIER: u8 = 0x8;

#[derive(Debug)]
pub enum CompressionLevel {
    Lowest,
    Low,
    Medium,
    Highest,
}

impl From<u8> for CompressionLevel {
    fn from(byte: u8) -> Self {
        match byte & COMPRESSION_LEVEL_MASK {
            0 => Self::Lowest,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::Highest,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub enum CompressionMethod {
    #[allow(clippy::upper_case_acronyms)]
    DEFLATE(usize), // window size
}

impl Display for CompressionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self::DEFLATE(window_size) = self;
        write!(
            f,
            "DEFLATE with window size a windows size of {window_size} bytes"
        )
    }
}

impl TryFrom<u8> for CompressionMethod {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte & 0xf {
            DEFLATE_IDENTIFIER => Ok(Self::DEFLATE(2usize.pow(8 + (byte as u32 >> 4)))),
            _ => bail!("invalid compression method: {byte}"),
        }
    }
}

// RFC 1950
#[derive(Debug)]
pub struct Stream {
    compression_method: CompressionMethod,
    preset_dictionary: Option<[u8; 4]>,
    flags_check_bits: u8,
    compression_level: CompressionLevel,
    compressed_data: Vec<u8>,
    checksum: [u8; 4],
}

impl Display for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Compression method: {}", self.compression_method)?;
        writeln!(
            f,
            "Preset dictionary (FDICT): {}",
            self.preset_dictionary
                .map(|dict| { format!("{:#x}", u32::from_be_bytes(dict)) })
                .unwrap_or("not present".to_string())
        )?;
        writeln!(f, "Compression level: {:?}", self.compression_level)?;
        writeln!(f, "Check bits: 0b{:05b}", self.flags_check_bits & 0x1f)?;
        writeln!(f, "Compressed data length: {}", self.compressed_data.len())?;
        writeln!(
            f,
            "Checksum (ADLER-32): {:#x}",
            u32::from_be_bytes(self.checksum)
        )
    }
}

impl TryFrom<&[u8]> for Stream {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // At least enough bytes for CMF, FLG and the ADLER-32 checksum
        ensure!(bytes.len() > 6, "not enough bytes");
        // FCHECK validation
        ensure!(
            u16::from_be_bytes([bytes[0], bytes[1]]) % 31 == 0,
            "corrupt stream: invalid CMF, FLG, or both"
        );
        let compression_method: CompressionMethod =
            bytes[0].try_into().context("decoding compression method")?;
        let flags_check_bits = bytes[1] & 0x1f;
        let compression_level: CompressionLevel = (bytes[1] >> 6).into();
        let has_preset_dictionary = bytes[1] & (1 << 5) == 1 << 5;
        let compressed_data_offset = 2 + usize::from(has_preset_dictionary) * 4;
        let preset_dictionary = if has_preset_dictionary {
            // We need 4 more bytes for DICTID
            ensure!(bytes.len() > 10, "not enough bytes");
            Some(bytes[2..2 + 4].try_into()?)
        } else {
            None
        };
        let checksum = bytes[bytes.len() - 4..].try_into()?;
        // NOTE: here we are just assuming that the full bytes slice is the entirety of the stream.
        // This will probably change once decompression of the data is properly implemented
        let compressed_data = bytes[compressed_data_offset..bytes.len() - 4].to_vec();
        Ok(Self {
            compression_method,
            preset_dictionary,
            flags_check_bits,
            compression_level,
            compressed_data,
            checksum,
        })
    }
}

fn adler32(bytes: &[u8]) -> [u8; 4] {
    const MOD_ADLER: u32 = 65521;
    let (mut s1, mut s2) = (1u32, 0u32);
    for &byte in bytes {
        s1 = (s1 + byte as u32) % MOD_ADLER;
        s2 = (s2 + s1) % MOD_ADLER;
    }
    ((s2 << 16) | s1).to_be_bytes()
}

// RFC 1951 section 3.2.2
fn huffman_codes(codes_bit_lengths: &[usize]) -> Vec<u16> {
    let Some(&max_code_len) = codes_bit_lengths.iter().max() else {
        return vec![];
    };
    // Count the times each length occurs
    let mut codes_bit_lengths_counts = vec![0; max_code_len + 1];
    for &len in codes_bit_lengths {
        codes_bit_lengths_counts[len] += 1;
    }
    let mut code = 0;
    // Compute the base code (i.e. the first code in lexicographic order) for a code bit length of
    // i (i = 0..=max_code_len)
    let mut next_code = vec![0u16; max_code_len + 1];
    for (i, next_code_i) in next_code.iter_mut().enumerate() {
        code = (code
            + if i == 0 {
                0
            } else {
                codes_bit_lengths_counts[i - 1]
            })
            << 1;
        *next_code_i = code;
    }
    let mut result = vec![];
    // Assign to each symbol the current base code for its len, then increase the base code + 1 to
    // go to the next symbol in the same code len
    for &len in codes_bit_lengths {
        result.push(next_code[len]);
        next_code[len] += 1;
    }
    result
}

// The alphabet of length codes is made of 29 numbers each of which is associated with an interval
// of lengths they represent
// The first number in the alphabet is 257
// The lowest length represented is 3
// The lengths represented are divided in 7 groups of the following sizes:
//   y_sizes = [8, 8, 16, 32, 64, 127, 1]
// Based on their distance from the lowest length i.e. representing the groups by the index of
// their first member in the sequence of lengths:
//   y_bases = [0, 8, 16, 32, 64, 128, 255, 256]
// A length is part of group i iff length comes after the groups[i]'th but before the groups[i+1]'th
//
// Likewise, numbers in the alphabet are also grouped in 7 groups with the following sizes:
//   x_sizes = [8, 4, 4, 4, 4, 4, 1]
// And the following "markers" of a group start:
//   x_bases = [0, 8, 12, 16, 20, 24, 28, 28]
//
// Each group i uses i extra bits to represent an offset within the interval of lengths it is
// associated to w.r.t. the first length of the group. That is, if a number n is part of group i,
// then the size of the interval of lengths it represents is 2^i
//
// With this set up, once we know which group a number n from the alphabet is part of, then we
// know:
//   - which group in the lengths it's associated to
//   - the first member of that group
//   - the distance from the member of that group
//
// That is, the length we want to encode/decode
//
// Something analogous applies for distances, with the following parameters:
//   x_offset = 0
//   x_sizes = [4,2,2,2,2,2,2,2,2,2,2,2,2,2]
//   x_bases = [0, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]
//
//   y_offset = 1
//   y_sizes = [4,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384]
//   y_bases = [0, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768]

const CODED_LENGTHS_X_BASES: [u16; 8] = [0, 8, 12, 16, 20, 24, 28, 28];
const CODED_LENGTHS_X_OFFSET: u16 = 257;
const CODED_LENGTHS_Y_BASES: [u16; 8] = [0, 8, 16, 32, 64, 128, 255, 256];
const CODED_LENGTHS_Y_OFFSET: u16 = 3;

fn len_code_to_first_len(mut code: u16) -> anyhow::Result<u16> {
    ensure!((257..=285).contains(&code));
    if code == 285 {
        return Ok(258);
    }

    let extra_bits = n_extra_bits_for_len_code(code)?;

    // See RFC 1951, Section 3.2.5.
    // Determine the group the code belongs to.
    let code_group_base = CODED_LENGTHS_X_BASES[extra_bits];
    let code_index_in_group = code - CODED_LENGTHS_X_OFFSET - code_group_base;

    // Determine the corresponding length group and its starting value.
    let length_group_base = CODED_LENGTHS_Y_BASES[extra_bits];
    let length_group_start = length_group_base + CODED_LENGTHS_Y_OFFSET;

    // Calculate the final offset within the length group.
    let length_offset = code_index_in_group * 2u16.pow(extra_bits as u32);

    Ok(length_group_start + length_offset)
}

#[inline]
fn n_extra_bits_for_len_code(mut code: u16) -> anyhow::Result<usize> {
    ensure!((257..=285).contains(&code));
    if code == 285 {
        Ok(0)
    } else {
        Ok(CODED_LENGTHS_X_BASES
            // Find the index of the group this code belongs to.
            .partition_point(|&x| x <= code - CODED_LENGTHS_X_OFFSET)
            .saturating_sub(1))
    }
}

const CODED_DISTANCES_X_BASES: [u16; 15] = [0, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30];
const CODED_DISTANCES_X_OFFSET: u16 = 0;
const CODED_DISTANCES_Y_BASES: [u16; 15] = [
    0, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
];
const CODED_DISTANCES_Y_OFFSET: u16 = 1;

fn distance_code_to_first_distance(mut code: u16) -> anyhow::Result<u16> {
    ensure!((0..=29).contains(&code));

    let extra_bits = n_extra_bits_for_distance_code(code)?;

    // See RFC 1951, Section 3.2.5.
    // Determine the group the code belongs to.
    let code_group_base = CODED_DISTANCES_X_BASES[extra_bits];
    let code_index_in_group = code - CODED_DISTANCES_X_OFFSET - code_group_base;

    // Determine the corresponding length group and its starting value.
    let distance_group_base = CODED_DISTANCES_Y_BASES[extra_bits];
    let distance_group_start = distance_group_base + CODED_DISTANCES_Y_OFFSET;

    // Calculate the final offset within the length group.
    let distance_offset = code_index_in_group * 2u16.pow(extra_bits as u32);

    Ok(distance_group_start + distance_offset)
}

#[inline]
fn n_extra_bits_for_distance_code(mut code: u16) -> anyhow::Result<usize> {
    ensure!((0..=29).contains(&code));
    Ok(CODED_DISTANCES_X_BASES
        // Find the index of the group this code belongs to.
        .partition_point(|&x| x <= code - CODED_DISTANCES_X_OFFSET)
        .saturating_sub(1))
}

#[inline]
// TODO: probably the same as the one that uses partition_point, to investigate
fn distance_to_encoded_bitlen(distance: usize) -> usize {
    max((max(distance - 1, 1)).ilog2() as usize - 1, 0)
}

fn read_bits(bytes: &[u8], mut loffset_bits: usize, mut how_many: usize) -> anyhow::Result<u16> {
    ensure!(how_many <= 16);
    if how_many == 0 {
        return Ok(0);
    }
    ensure!(bytes.len() >= (loffset_bits + how_many).div_ceil(8));
    let mut result = 0u16;

    while how_many > 0 {
        let offset_within_the_byte = loffset_bits % 8;
        let current_byte = loffset_bits / 8;
        let bits_to_extract = (8 - offset_within_the_byte).min(how_many);
        let shiftr = 8 - offset_within_the_byte - bits_to_extract;
        let mask = ((1 << bits_to_extract) - 1) as u8;
        result = (result << bits_to_extract) | (((bytes[current_byte] >> shiftr) & mask) as u16);
        how_many -= bits_to_extract;
        loffset_bits += bits_to_extract;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adler32_empty() {
        let input = b"";
        let checksum = adler32(input);
        assert_eq!([0, 0, 0, 1], checksum);
    }

    #[test]
    fn test_adler32_wikipedia() {
        let input = b"Wikipedia";
        let checksum = adler32(input);
        assert_eq!([0x11, 0xE6, 0x03, 0x98], checksum);
    }

    #[test]
    fn test_adler32_long() {
        let input = vec![b'a'; 1024];
        let checksum = adler32(&input);
        assert_eq!([0xf3, 0x78, 0x84, 0x10], checksum);
    }

    #[test]
    fn test_huffman_codes_rfc1951_section_3_2_2() {
        let input = [3, 3, 3, 3, 3, 2, 4, 4];
        assert_eq!(
            &[0b010, 0b011, 0b100, 0b101, 0b110, 0b00, 0b1110, 0b1111],
            huffman_codes(&input).as_slice()
        );
    }

    #[test]
    fn test_huffman_length_codes() {
        let length_codes_table = [
            (257, 0, 3),
            (258, 0, 4),
            (259, 0, 5),
            (260, 0, 6),
            (261, 0, 7),
            (262, 0, 8),
            (263, 0, 9),
            (264, 0, 10),
            (265, 1, 11),
            (266, 1, 13),
            (267, 1, 15),
            (268, 1, 17),
            (269, 2, 19),
            (270, 2, 23),
            (271, 2, 27),
            (272, 2, 31),
            (273, 3, 35),
            (274, 3, 43),
            (275, 3, 51),
            (276, 3, 59),
            (277, 4, 67),
            (278, 4, 83),
            (279, 4, 99),
            (280, 4, 115),
            (281, 5, 131),
            (282, 5, 163),
            (283, 5, 195),
            (284, 5, 227),
        ];

        for (code, extra_bits, first_length) in length_codes_table {
            assert_eq!(
                extra_bits,
                n_extra_bits_for_len_code(code).unwrap(),
                "Error for triple ({code},{extra_bits},{first_length})"
            );
            assert_eq!(
                first_length,
                len_code_to_first_len(code).unwrap(),
                "Error for triple ({code},{extra_bits},{first_length})"
            );
        }
    }

    #[test]
    fn test_huffman_distance_codes() {
        let distance_codes_table = [
            (0, 0, 1),
            (1, 0, 2),
            (2, 0, 3),
            (3, 0, 4),
            (4, 1, 5),
            (5, 1, 7),
            (6, 2, 9),
            (7, 2, 13),
            (8, 3, 17),
            (9, 3, 25),
            (10, 4, 33),
            (11, 4, 49),
            (12, 5, 65),
            (13, 5, 97),
            (14, 6, 129),
            (15, 6, 193),
            (16, 7, 257),
            (17, 7, 385),
            (18, 8, 513),
            (19, 8, 769),
            (20, 9, 1025),
            (21, 9, 1537),
            (22, 10, 2049),
            (23, 10, 3073),
            (24, 11, 4097),
            (25, 11, 6145),
            (26, 12, 8193),
            (27, 12, 12289),
            (28, 13, 16385),
            (29, 13, 24577),
        ];

        for (code, extra_bits, first_length) in distance_codes_table {
            assert_eq!(
                extra_bits,
                n_extra_bits_for_distance_code(code).unwrap(),
                "Error for triple ({code},{extra_bits},{first_length})"
            );
            assert_eq!(
                first_length,
                distance_code_to_first_distance(code).unwrap(),
                "Error for triple ({code},{extra_bits},{first_length})"
            );
        }
    }
}

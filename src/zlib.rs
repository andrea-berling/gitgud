use std::{
    cmp::{min, Reverse},
    collections::{BinaryHeap, HashMap},
    fmt::Display,
    io::Write,
    iter::zip,
};

use anyhow::{bail, ensure, Context};

const COMPRESSION_LEVEL_MASK: u8 = 0x3;
const BLOCK_TYPE_MASK: u8 = 0x3;
const DEFLATE_IDENTIFIER: u8 = 0x8;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
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
    size_compressed: Option<usize>,
    bytes: Vec<u8>,
}

impl Stream {
    pub fn new(
        compression_method: CompressionMethod,
        preset_dictionary: Option<[u8; 4]>,
        compression_level: CompressionLevel,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            compression_method,
            preset_dictionary,
            flags_check_bits: 0,
            compression_level,
            bytes,
            size_compressed: None,
        }
    }

    pub fn deflate(&mut self) -> anyhow::Result<&[u8]> {
        let checksum = adler32(&self.bytes);
        self.flags_check_bits = 1;
        let mut compressed_data = deflate(&self.bytes, self.compression_level)
            .context("deflating the uncompressed data")?;
        self.bytes.clear();
        self.bytes.write_all(b"\x78\x01")?;
        self.bytes.append(&mut compressed_data);
        self.bytes.write_all(&checksum)?;
        self.size_compressed = Some(compressed_data.len());
        Ok(&self.bytes)
    }

    pub fn inflate(&mut self) -> anyhow::Result<&[u8]> {
        let (result, parsed_bytes) =
            inflate(&self.bytes).context("inflating the compressed data")?;
        ensure!(
            self.bytes.len() - parsed_bytes >= 4,
            "missing ADLER-32 checksum"
        );
        let checksum: [u8; 4] = self.bytes[parsed_bytes..][..4].try_into()?;
        ensure!(
            adler32(&result) == checksum,
            "invalid checksum after the compressed data"
        );
        self.bytes = result;
        self.size_compressed = Some(parsed_bytes);
        Ok(&self.bytes)
    }

    /// Length of the stream in bytes after data has been compressed, including the header, preset
    /// dictionary, and ADLER32 checksum
    /// Returns None if the compressed size is not known yet. You can call deflate or inflate to
    /// populate the field
    pub fn serialization_len(&self) -> Option<usize> {
        self.size_compressed.map(|x| {
            x + 2
                + 4
                + match self.preset_dictionary {
                    Some(..) => 4,
                    None => 0,
                }
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
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
        writeln!(f, "Compressed data length: {}", self.bytes.len())
    }
}

impl TryFrom<&[u8]> for Stream {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // At least enough bytes for CMF
        ensure!(bytes.len() > 2, "not enough bytes to parse CMF and FLG");
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
            bail!("preset dictionaries are not supported yet");
            // We need 4 more bytes for DICTID
            ensure!(bytes.len() > 6, "not enough bytes to parse DICTID");
            Some(bytes[2..2 + 4].try_into()?)
        } else {
            None
        };
        let compressed_data = bytes[compressed_data_offset..].to_vec();
        Ok(Self {
            size_compressed: Some(compressed_data.len()),
            compression_method,
            preset_dictionary,
            flags_check_bits,
            compression_level,
            bytes: compressed_data,
        })
    }
}

#[derive(Clone, Copy)]
enum BlockType {
    NoCompression = 0b00,
    FixedHuffmanCodes = 0b01,
    DynamicHuffmanCodes = 0b10,
    Reserved = 0b11,
}

const LITERALS_ALPHABET_SIZE: usize = 288;
const DISTANCES_ALPHABET_SIZE: usize = 32;

// RFC 1951, Section 3.2.6.
const FIXED_HUFFMAN_LITERALS_CODES_LENGTHS: [usize; LITERALS_ALPHABET_SIZE] = [
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8,
];

impl From<u8> for BlockType {
    fn from(byte: u8) -> Self {
        match byte & BLOCK_TYPE_MASK {
            0b00 => Self::NoCompression,
            0b01 => Self::FixedHuffmanCodes,
            0b10 => Self::DynamicHuffmanCodes,
            0b11 => Self::Reserved,
            _ => unreachable!(),
        }
    }
}

// An iterator that pops through each bit in LSB order in a buffer of bytes
struct LSBBitsIterator<'a> {
    buffer: &'a [u8],
    bits_read_so_far: usize,
}

impl<'a> LSBBitsIterator<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            buffer: bytes,
            bits_read_so_far: 0,
        }
    }

    #[inline]
    fn exhausted(&self) -> bool {
        self.bits_read_so_far / 8 >= self.buffer.len()
    }

    fn pop_bit(&mut self) -> Option<u8> {
        if self.exhausted() {
            return None;
        }
        let bit = (self.buffer[self.bits_read_so_far / 8] >> (self.bits_read_so_far % 8)) & 1;
        self.bits_read_so_far += 1;
        Some(bit)
    }

    // Reads `n` bits from the stream LSB-first (no more than 16).
    fn pop_bits(&mut self, n: usize) -> Option<u16> {
        if n > 16 {
            return None;
        }
        if self.buffer.len() * 8 < self.bits_read_so_far + n {
            return None;
        }

        let mut result = 0u16;
        let mut bits_written = 0;

        while bits_written < n {
            let byte_pos = self.bits_read_so_far / 8;
            let shiftr = self.bits_read_so_far % 8;

            let bits_to_read_from_byte = (n - bits_written).min(8 - shiftr);

            // Take a chunk from the current byte
            let chunk = self.buffer[byte_pos] >> shiftr;

            // Mask out just the bits we want
            let mask = ((1u16 << bits_to_read_from_byte) - 1) as u8;
            let masked_chunk = chunk & mask;

            // Place the chunk into the result at the correct position
            result |= (masked_chunk as u16) << bits_written;

            // Advance cursors
            self.bits_read_so_far += bits_to_read_from_byte;
            bits_written += bits_to_read_from_byte;
        }

        Some(result)
    }

    fn pop_reversed_bits(&mut self, n: usize) -> Option<u16> {
        let val = self.pop_bits(n)?;
        // For u8, it would be .reverse_bits() >> (8 - n)
        Some(val.reverse_bits() >> (16 - n))
    }

    fn bit_cursor(&self) -> usize {
        self.bits_read_so_far
    }

    fn align_to_next_byte_if_unaligned(&mut self) -> bool {
        if self.bits_read_so_far % 8 == 0 {
            true
        } else if self.bits_read_so_far < (self.buffer.len() - 1) * 8 {
            self.bits_read_so_far += 8 - (self.bits_read_so_far % 8);
            true
        } else {
            false
        }
    }

    fn pop_byte_aligned_u16(&mut self) -> Option<u16> {
        if self.bits_read_so_far % 8 != 0 || self.buffer.len() * 8 - self.bits_read_so_far < 2 * 8 {
            return None;
        }
        let result = u16::from_le_bytes([
            self.buffer[self.bits_read_so_far / 8],
            self.buffer[self.bits_read_so_far / 8 + 1],
        ]);
        self.bits_read_so_far += 2 * 8;
        Some(result)
    }

    fn pop_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.bits_read_so_far % 8 != 0 || self.buffer.len() * 8 - self.bits_read_so_far < n * 8 {
            return None;
        }
        let current_position = self.bits_read_so_far / 8;
        self.bits_read_so_far += n * 8;
        Some(&self.buffer[current_position..][..n])
    }

    fn huffman_decode(&mut self, decompressor: &HuffmanDecompressor) -> anyhow::Result<u16> {
        let mut current_node_idx = 0;
        while !decompressor.is_leaf(current_node_idx) {
            let next_bit = self.pop_bit().ok_or(anyhow::anyhow!(
                "not enough bytes to decode this huffman encoded symbol"
            ))?;
            current_node_idx = decompressor
                .next_node_idx(current_node_idx, next_bit)
                .ok_or(anyhow::anyhow!("undexpected bit encountered"))?;
        }
        decompressor
            .decode(current_node_idx)
            .ok_or(anyhow::anyhow!("invalid code found"))
    }
}

struct LSBBitPacker {
    buffer: Vec<u8>,
    bits_written_so_far: usize,
}

impl LSBBitPacker {
    fn new() -> Self {
        Self {
            buffer: vec![],
            bits_written_so_far: 0,
        }
    }

    fn push_bit(&mut self, bit: u8) {
        if self.bits_written_so_far % 8 == 0 {
            self.buffer.push(0);
        }
        self.buffer[self.bits_written_so_far / 8] |= (bit & 1) << (self.bits_written_so_far % 8);
        self.bits_written_so_far += 1;
    }

    // Push `n` bits into the packer
    fn push_bits(&mut self, mut bits: u64, mut n_bits: usize) {
        while n_bits > 0 {
            if self.bits_written_so_far % 8 == 0 {
                self.buffer.push(0);
            }
            let byte_pos = self.bits_written_so_far / 8;
            let shiftl = self.bits_written_so_far % 8;
            let bits_we_can_write = min(8 - shiftl, n_bits) as u8;
            let mask = (1 << bits_we_can_write) - 1;

            self.buffer[byte_pos] |= (bits as u8 & mask) << shiftl;
            self.bits_written_so_far += bits_we_can_write as usize;
            n_bits -= bits_we_can_write as usize;
            bits >>= bits_we_can_write;
        }
    }

    #[inline]
    fn push_reversed_bits(&mut self, bits: u64, n_bits: usize) {
        self.push_bits(bits.reverse_bits() >> (u64::BITS as usize - n_bits), n_bits);
    }

    fn bit_cursor(&self) -> usize {
        self.bits_written_so_far
    }

    fn align_to_next_byte_if_unaligned(&mut self) {
        if self.bits_written_so_far % 8 == 0 {
            self.bits_written_so_far = (self.bits_written_so_far + 8) / 8;
        }
    }

    fn push_byte_aligned_u16_le(&mut self, val: u16) -> bool {
        if self.bits_written_so_far % 8 != 0 {
            return false;
        }

        self.align_to_next_byte_if_unaligned();
        self.buffer.extend(val.to_le_bytes());
        true
    }

    fn to_vec(self) -> Vec<u8> {
        self.buffer
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct HuffmanNode {
    left: Option<u16>,
    right: Option<u16>,
    payload: Option<u16>, // None means it's an internal node without a value
}

impl HuffmanNode {
    #[inline]
    fn is_leaf(&self) -> bool {
        self.payload.is_some()
    }
}

struct HuffmanDecompressor {
    // A Huffman tree for N symbols has at most 2N-1 nodes.
    // The largest alphabet is the fixed literal/length alphabet with 288 symbols.
    decoder: Vec<HuffmanNode>,
}

impl HuffmanDecompressor {
    fn next_node_idx(&self, current_node_idx: usize, next_bit: u8) -> Option<usize> {
        if current_node_idx > self.decoder.len() - 1 {
            return None;
        }
        if next_bit == 1 {
            self.decoder[current_node_idx].right.map(|x| x as usize)
        } else {
            self.decoder[current_node_idx].left.map(|x| x as usize)
        }
    }

    fn new(code_lengths: &[usize], symbol_map: &[u16]) -> Self {
        let num_symbols = code_lengths.len();
        let max_nodes = 2 * num_symbols - 1;
        let mut decoder = Vec::with_capacity(max_nodes);
        decoder.push(HuffmanNode::default());
        for (i, &code) in huffman_codes(code_lengths).iter().enumerate() {
            let code_len = code_lengths[i];
            let mut code_lsb = code.reverse_bits() >> (u16::BITS as usize - code_len);
            let mut current_node_idx = 0;
            for _ in 0..code_len {
                let next_bit = code_lsb as u8 & 1;
                match next_bit {
                    0 => {
                        if let Some(idx) = decoder[current_node_idx].left {
                            current_node_idx = idx as usize;
                        } else {
                            decoder.push(HuffmanNode::default());
                            let new_index = decoder.len() as u16 - 1;
                            current_node_idx =
                                *decoder[current_node_idx].left.get_or_insert(new_index) as usize;
                        }
                    }
                    1 => {
                        if let Some(idx) = decoder[current_node_idx].right {
                            current_node_idx = idx as usize;
                        } else {
                            decoder.push(HuffmanNode::default());
                            let new_index = decoder.len() as u16 - 1;
                            current_node_idx =
                                *decoder[current_node_idx].right.get_or_insert(new_index) as usize;
                        }
                    }
                    _ => unreachable!(),
                }
                code_lsb >>= 1;
            }
            let _ = decoder[current_node_idx].payload.insert(symbol_map[i]);
        }
        Self { decoder }
    }

    #[inline]
    fn is_leaf(&self, idx: usize) -> bool {
        if idx > self.decoder.len() - 1 {
            return true;
        }
        self.decoder[idx].is_leaf()
    }

    #[inline]
    fn decode(&self, idx: usize) -> Option<u16> {
        if idx > self.decoder.len() - 1 {
            return None;
        }
        self.decoder[idx].payload
    }
}

const CODE_LENGTHS_SYMBOL_MAP: [u16; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

const CODE_LENGTHS_INVERSE_SYMBOL_MAP: [u16; 19] = [
    3, 17, 15, 13, 11, 9, 7, 5, 4, 6, 8, 10, 12, 14, 16, 18, 0, 1, 2,
];

fn get_code_lengths_decoder(
    lsb_iterator: &mut LSBBitsIterator<'_>,
    n_lengths: usize,
) -> anyhow::Result<HuffmanDecompressor> {
    let mut code_lengths_codes_lengths = vec![0; CODE_LENGTHS_SYMBOL_MAP.len()];
    // There are n_lengths in the input each represented as 3 bits in LSB order. The remaining 19 -
    // n_lengths are 0
    for code_length_code_length in code_lengths_codes_lengths.iter_mut().take(n_lengths) {
        *code_length_code_length = lsb_iterator
            .pop_bits(3)
            .context("reading encoded code length")? as usize;
    }
    // Codes with a length of 0 don't partake in the Huffman encoding and should be removed before
    // constructing the Huffman tree
    let mut code_lengths_lengths_and_map: Vec<_> =
        zip(code_lengths_codes_lengths, CODE_LENGTHS_SYMBOL_MAP)
            .filter(|&(len, _)| len != 0)
            .collect();
    // This is an aspect that was not mentioned (or I missed) in the RFC: basically the codes for
    // each length should be assigned in lexicographic order, NOT in the order in which the lens
    // are found in the bit stream
    code_lengths_lengths_and_map.sort_by_key(|x| x.1);
    let (code_lengths_codes_lengths, code_lengths_symbol_map): (Vec<_>, Vec<_>) =
        code_lengths_lengths_and_map.into_iter().unzip();
    Ok(HuffmanDecompressor::new(
        &code_lengths_codes_lengths,
        &code_lengths_symbol_map,
    ))
}

fn get_decoders_from_encoded_lengths(
    lsb_iterator: &mut LSBBitsIterator<'_>,
    n_literals_lengths: usize,
    n_distances_lengths: usize,
    code_lengths_decoder: &HuffmanDecompressor,
) -> anyhow::Result<(HuffmanDecompressor, Option<HuffmanDecompressor>)> {
    let mut decoded_lengths = vec![];
    const REPEAT_LAST_CODE_LEN: usize = 16;
    const REPEAT_ZERO_3_TO_10_TIMES: usize = 17;
    const REPEAT_ZERO_11_TO_138_TIMES: usize = 18;

    while decoded_lengths.len() < n_literals_lengths + n_distances_lengths {
        match lsb_iterator.huffman_decode(code_lengths_decoder)? as usize {
            code_len @ 0..=15 => {
                decoded_lengths.push(code_len);
            }
            code_len @ REPEAT_LAST_CODE_LEN..=REPEAT_ZERO_11_TO_138_TIMES => {
                ensure!(
                    code_len != REPEAT_LAST_CODE_LEN || !decoded_lengths.is_empty(),
                    "invalid encoded code len encountered: 16 can not be the first one"
                );
                let n_extra_bits = if code_len == REPEAT_LAST_CODE_LEN {
                    2
                } else if code_len == REPEAT_ZERO_3_TO_10_TIMES {
                    3
                } else {
                    7
                };
                let base =
                    if code_len == REPEAT_LAST_CODE_LEN || code_len == REPEAT_ZERO_3_TO_10_TIMES {
                        3
                    } else {
                        11
                    };
                let extra_bits = lsb_iterator
                    .pop_bits(n_extra_bits)
                    .context(format!("reading {n_extra_bits} for the number of repetitions expressed by code length literal {code_len}"))? as usize;
                let val_to_repeat = if code_len == REPEAT_LAST_CODE_LEN {
                    decoded_lengths.last().copied().unwrap()
                } else {
                    0
                };
                decoded_lengths.append(&mut [val_to_repeat].repeat(base + extra_bits));
            }
            code_len => bail!("invalid encoded code encountered: {code_len}"),
        }
    }
    let mut literals_codes_lengths = [0; 289];
    literals_codes_lengths[0..n_literals_lengths].copy_from_slice(
        &decoded_lengths
            .iter()
            .take(n_literals_lengths)
            .copied()
            .collect::<Vec<_>>(),
    );
    let literals_symbol_map: Vec<_> = (0..LITERALS_ALPHABET_SIZE as u16).collect();

    let (literals_symbol_map, literals_codes_lengths): (Vec<u16>, Vec<usize>) =
        zip(literals_symbol_map, literals_codes_lengths)
            .filter(|&(_, len)| len != 0)
            .unzip();

    let literals_huffman_decompressor =
        HuffmanDecompressor::new(&literals_codes_lengths, &literals_symbol_map);

    let mut distances_codes_lengths = [0; DISTANCES_ALPHABET_SIZE];

    distances_codes_lengths[0..n_distances_lengths].copy_from_slice(
        &decoded_lengths
            .iter()
            .skip(n_literals_lengths)
            .copied()
            .collect::<Vec<_>>(),
    );

    // RFC 1951 Section 3.2.7, "One distance code of zero bits means that there are no distance
    // codes"
    if n_distances_lengths == 1 && distances_codes_lengths[0] == 0 {
        return Ok((literals_huffman_decompressor, None));
    }

    let distances_symbol_map: Vec<_> = (0..DISTANCES_ALPHABET_SIZE as u16).collect();

    let (distances_symbol_map, distances_codes_lengths): (Vec<u16>, Vec<usize>) =
        zip(distances_symbol_map, distances_codes_lengths)
            .filter(|&(_, len)| len != 0)
            .unzip();
    Ok((
        literals_huffman_decompressor,
        Some(HuffmanDecompressor::new(
            &distances_codes_lengths,
            &distances_symbol_map,
        )),
    ))
}

fn huffman_codes_lengths_from_huffman_tree(
    tree: &[HuffmanNode],
    root_idx: u16,
    depth: usize,
) -> anyhow::Result<Vec<(usize, u16)>> {
    ensure!(root_idx < tree.len() as u16);
    let current_node = &tree[root_idx as usize];
    if current_node.is_leaf() {
        Ok(vec![(depth, current_node.payload.unwrap())])
    } else {
        let mut left = if let Some(child) = current_node.left {
            huffman_codes_lengths_from_huffman_tree(tree, child, depth + 1)
                .context("computing huffman code length for left child")?
        } else {
            vec![]
        };
        let mut right = if let Some(child) = current_node.right {
            huffman_codes_lengths_from_huffman_tree(tree, child, depth + 1)
                .context("computing huffman code length for right child")?
        } else {
            vec![]
        };
        left.append(&mut right);
        Ok(left)
    }
}

// TODO: write tests
/// Returns the lengths and the symbol map
fn huffman_codes_lengths_from_symbols(bytes: &[u16]) -> anyhow::Result<(Vec<usize>, Vec<u16>)> {
    let mut frequencies = HashMap::new();
    for symbol in bytes {
        *frequencies.entry(*symbol).or_insert(0) += 1;
    }
    if frequencies.keys().len() == 1 {
        bail!("single symbol string not supported yet")
    }
    let mut huffman_tree: Vec<_> = frequencies
        .keys()
        .map(|&key| HuffmanNode {
            left: None,
            right: None,
            payload: Some(key),
        })
        .collect();
    let mut priority_queue = BinaryHeap::new();
    for (i, node) in huffman_tree.iter().enumerate() {
        priority_queue.push(Reverse((frequencies[&node.payload.unwrap()], i)));
    }
    let mut root_idx = 0;
    while priority_queue.len() > 1 {
        let Reverse(least_frequent) = priority_queue.pop().unwrap();
        let Reverse(second_least_frequent) = priority_queue.pop().unwrap();
        let root = HuffmanNode {
            left: Some(second_least_frequent.1 as u16),
            right: Some(least_frequent.1 as u16),
            payload: None,
        };
        huffman_tree.push(root);
        root_idx = huffman_tree.len() as u16 - 1;
        priority_queue.push(Reverse((
            least_frequent.0 + second_least_frequent.0,
            huffman_tree.len() - 1,
        )));
    }
    let mut huffman_code_lengths =
        huffman_codes_lengths_from_huffman_tree(&huffman_tree, root_idx, 0)
            .context("computing huffman codes lengths")?;
    // Canonical Huffman tree expect lexicographic order in the codes assigned to symbols
    huffman_code_lengths.sort_by(|(_, code1), (_, code2)| code1.cmp(code2));

    Ok(huffman_code_lengths.into_iter().unzip())
}

struct HuffmanCompressor {
    encoder: Vec<(u16, usize)>,
}

impl HuffmanCompressor {
    fn new(code_lengths: &[usize], symbol_map: &[u16]) -> Self {
        // TODO: put a better number than 300 here
        let mut encoder = vec![(0, 0); 300];
        for (i, &code) in huffman_codes(code_lengths).iter().enumerate() {
            encoder[symbol_map[i] as usize] = (code, code_lengths[i])
        }
        Self { encoder }
    }

    #[inline]
    fn encode(&self, symbol: u16) -> anyhow::Result<(u16, usize)> {
        ensure!(symbol < self.encoder.len().try_into().context("TODO")?);
        Ok(self.encoder[symbol as usize])
    }
}

fn deflate(bytes: &[u8], level: CompressionLevel) -> anyhow::Result<Vec<u8>> {
    if bytes.is_empty() {
        bail!("empty stream of bytes not supported yet")
    }
    let mut result = vec![];
    // TODO: a system to cleverly divide the input into blocks, select the appropriate compression
    // method for each block, and use that
    match level {
        CompressionLevel::Lowest => {
            ensure!(bytes.len() < u16::MAX as usize);
            result.write_all(b"\x01")?;
            let len = bytes.len() as u16;
            result.write_all(&len.to_le_bytes())?;
            result.write_all(&(!len).to_le_bytes())?;
            result.write_all(bytes)?;
        }
        CompressionLevel::Low => {
            // RFC 1951 Section 3.2.7
            // dynamic huffman encoding without LZ88
            let mut symbols: Vec<_> = bytes.iter().map(|&symbol| symbol as u16).collect();
            // We only have one block, and thus one end of data
            // marker
            symbols.push(256);
            let (main_huffman_code_lengths, main_huffman_symbol_map) =
                huffman_codes_lengths_from_symbols(&symbols)
                    .context("computing huffman code lengths for the bytes")?;
            let mut hlit_array = vec![0; 257];
            for i in 0..main_huffman_symbol_map.len() {
                hlit_array[main_huffman_symbol_map[i] as usize] = main_huffman_code_lengths[i];
            }
            let hlit = hlit_array.len() - 257;
            // No distance codes used
            let compact_distance_codes = [EncodedLength::Literal(0)];
            let hdist = 0;
            let (
                compact_code_lengths,
                (code_lengths_encoding_code_lengths, code_lengths_symbol_map),
            ) = code_lengths_encoding_code_lengths(&hlit_array)
                .context("computing the length of codes used to encode code lengths")?;
            let mut hclen_array = vec![0; CODE_LENGTHS_SYMBOL_MAP.len()];
            for i in 0..code_lengths_symbol_map.len() {
                hclen_array[CODE_LENGTHS_INVERSE_SYMBOL_MAP[code_lengths_symbol_map[i] as usize]
                    as usize] = code_lengths_encoding_code_lengths[i];
            }

            let hclen_array_end = hclen_array
                .iter()
                .rposition(|&x| x != 0)
                .ok_or(anyhow::anyhow!("TODO"))?
                + 1;
            hclen_array.truncate(hclen_array_end);

            let hclen = hclen_array.len() - 4;

            let code_lengths_compressor = HuffmanCompressor::new(
                &code_lengths_encoding_code_lengths,
                &code_lengths_symbol_map,
            );

            let main_compressor =
                HuffmanCompressor::new(&main_huffman_code_lengths, &main_huffman_symbol_map);

            let mut bit_packer = LSBBitPacker::new();
            bit_packer.push_bits(
                (((BlockType::DynamicHuffmanCodes as u8) << 1) | 1) as u64,
                3,
            );
            bit_packer.push_bits(hlit as u64, 5);
            bit_packer.push_bits(hdist as u64, 5);
            bit_packer.push_bits(hclen as u64, 4);
            for &len in &hclen_array {
                bit_packer.push_bits(len as u64, 3);
            }
            for &encoded_code_len in &compact_code_lengths {
                encoded_code_len
                    .compress(&mut bit_packer, &code_lengths_compressor)
                    .context("TODO")?
            }
            for encoded_code_len in &compact_distance_codes {
                encoded_code_len
                    .compress(&mut bit_packer, &code_lengths_compressor)
                    .context("TODO")?
            }
            for &byte in bytes {
                let (code, code_len) = main_compressor.encode(byte as u16).context("TODO")?;
                bit_packer.push_reversed_bits(code as u64, code_len);
            }

            let (end_block_code, end_block_code_len) =
                main_compressor.encode(256).context("TODO")?;
            bit_packer.push_bits(end_block_code as u64, end_block_code_len);
            result = bit_packer.to_vec();
        }
        CompressionLevel::Medium => panic!("not implemented"),
        CompressionLevel::Highest => panic!("not implemented"),
    }

    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodedLength {
    Literal(u8),
    RepeatPrevious(u8),
    RepeatShortSequenceOfZeros(u8),
    RepeatLongSequenceOfZeros(u8),
}

impl EncodedLength {
    fn to_code(self) -> u8 {
        match self {
            EncodedLength::Literal(n) => n,
            EncodedLength::RepeatPrevious(_) => 16,
            EncodedLength::RepeatShortSequenceOfZeros(_) => 17,
            EncodedLength::RepeatLongSequenceOfZeros(_) => 18,
        }
    }

    fn compress(
        self,
        bit_packer: &mut LSBBitPacker,
        compressor: &HuffmanCompressor,
    ) -> anyhow::Result<()> {
        match self {
            EncodedLength::Literal(n) => {
                let (code, code_len) = compressor.encode(n as u16).context("TODO")?;
                bit_packer.push_reversed_bits(code as u64, code_len);
            }
            EncodedLength::RepeatPrevious(count) => {
                let (code, code_len) = compressor.encode(self.to_code() as u16).context("TODO")?;
                bit_packer.push_reversed_bits(code as u64, code_len);
                bit_packer.push_bits(count as u64, 2);
            }
            EncodedLength::RepeatShortSequenceOfZeros(count) => {
                let (code, code_len) = compressor.encode(self.to_code() as u16).context("TODO")?;
                bit_packer.push_reversed_bits(code as u64, code_len);
                bit_packer.push_bits(count as u64 - 3, 3);
            }
            EncodedLength::RepeatLongSequenceOfZeros(count) => {
                let (code, code_len) = compressor.encode(self.to_code() as u16).context("TODO")?;
                bit_packer.push_reversed_bits(code as u64, code_len);
                bit_packer.push_bits(count as u64 - 11, 7);
            }
        }
        Ok(())
    }
}

fn code_lengths_encoding_code_lengths(
    hlit_array: &[usize],
) -> anyhow::Result<(Vec<EncodedLength>, (Vec<usize>, Vec<u16>))> {
    if hlit_array.len() == 1 {
        bail!("hlit array with single element not supported yet");
    }
    let mut compact_huffman_code_lengths_pass_1 = vec![];
    for &code_length in hlit_array {
        compact_huffman_code_lengths_pass_1.push(EncodedLength::Literal(
            code_length.try_into().context("code length does not fit in u8")?,
        ));
    }
    let mut compact_huffman_code_lengths = vec![];
    for encoded_length_run in compact_huffman_code_lengths_pass_1.chunk_by(|a, b| a == b) {
        let run_length: u8 = encoded_length_run
            .len()
            .try_into()
            .context("run length does not fit in u8")?;
        let EncodedLength::Literal(lit) = encoded_length_run[0] else {
            unreachable!()
        };
        if lit != 0 {
            if encoded_length_run.len() >= 3 {
                compact_huffman_code_lengths.extend([
                    encoded_length_run[0],
                    EncodedLength::RepeatPrevious(run_length - 1),
                ]);
            } else {
                compact_huffman_code_lengths.extend(encoded_length_run);
            }
        } else if encoded_length_run.len() >= 3 {
            if encoded_length_run.len() >= 11 {
                compact_huffman_code_lengths
                    .push(EncodedLength::RepeatLongSequenceOfZeros(run_length));
            } else {
                compact_huffman_code_lengths
                    .push(EncodedLength::RepeatShortSequenceOfZeros(run_length));
            }
        } else {
            compact_huffman_code_lengths.extend(encoded_length_run);
        }
    }

    let used_lengths: Vec<_> = compact_huffman_code_lengths
        .iter()
        .map(|code_length| code_length.to_code() as u16)
        .collect();
    let (huffman_code_lengths, symbol_map) = huffman_codes_lengths_from_symbols(&used_lengths)
        .context("computing huffman codes for used lengths")?;

    // Canonical Huffman tree expect lexicographic order in the codes assigned to symbols
    let mut huffman_lengths_and_map: Vec<_> = zip(huffman_code_lengths, symbol_map)
        .filter(|(len, _)| *len != 0)
        .collect();
    huffman_lengths_and_map.sort_by_key(|x| x.1);
    Ok((
        compact_huffman_code_lengths,
        huffman_lengths_and_map.into_iter().unzip(),
    ))
}

fn inflate(bytes: &[u8]) -> anyhow::Result<(Vec<u8>, usize)> {
    let mut lsb_iterator = LSBBitsIterator::new(bytes);
    let mut result = vec![];

    let fixed_huffman_decompressor = HuffmanDecompressor::new(
        &FIXED_HUFFMAN_LITERALS_CODES_LENGTHS,
        &(0..FIXED_HUFFMAN_LITERALS_CODES_LENGTHS.len() as u16).collect::<Vec<_>>(),
    );

    loop {
        let block_header = lsb_iterator.pop_bits(3).ok_or(anyhow::anyhow!(format!(
            "not enough bits at {}: failed to read block header (3 bits)",
            lsb_iterator.bit_cursor()
        )))?;
        let last = (block_header & 1) == 1;
        let block_type = (block_header as u8 >> 1).into();
        match block_type {
            BlockType::NoCompression => {
                if !lsb_iterator.align_to_next_byte_if_unaligned() {
                    bail!("stream ended too early: couldn't read neither LEN nor NLEN")
                }
                let Some(len) = lsb_iterator.pop_byte_aligned_u16() else {
                    bail!("stream ended too early: couldn't read LEN")
                };
                let Some(nlen) = lsb_iterator.pop_byte_aligned_u16() else {
                    bail!("stream ended too early: couldn't read NLEN")
                };
                ensure!(
                    !len == nlen,
                    "inconsistent values for LEN ({len:#x}) and NLEN ({nlen:#x}) at {}: {:#x?}",
                    lsb_iterator.bit_cursor() - 32,
                    bytes
                );
                result.extend(lsb_iterator.pop_bytes(len as usize).ok_or(anyhow::anyhow!(
                    format!(
                        "not enough bytes or wrong alignment at {}",
                        lsb_iterator.bit_cursor()
                    )
                ))?);
            }
            BlockType::FixedHuffmanCodes => {
                loop {
                    let compressed_block_literal = lsb_iterator
                        .huffman_decode(&fixed_huffman_decompressor)
                        .context("decoding bits with the fixed huffman decoder")?;
                    match compressed_block_literal {
                        0..=255 => result.push(compressed_block_literal as u8),
                        256 => break, // end of block
                        257..=285 => {
                            let n_extra_bits_for_len =
                            n_extra_bits_for_len_code(compressed_block_literal).context(format!("computing number of needed bits after len code {compressed_block_literal}"))?;
                            // length + distance
                            let extra_bits = lsb_iterator
                            .pop_bits(n_extra_bits_for_len)
                            .ok_or(anyhow::anyhow!(format!("not enough bits: after {compressed_block_literal} at {} expected {n_extra_bits_for_len} more bits", lsb_iterator.bit_cursor())))?;
                            let len = len_code_to_first_len(compressed_block_literal)?
                                + extra_bits as u16;
                            let distance_code = lsb_iterator
                                .pop_reversed_bits(5)
                                .ok_or(anyhow::anyhow!("not enough bits: after len at {} expected 5 bits for the distance code", lsb_iterator.bit_cursor()))?;
                            let n_extra_bits_for_distance =
                            n_extra_bits_for_distance_code(distance_code as u16).context(format!("computing number of needed bits after distance code {distance_code}"))?;
                            let extra_bits = lsb_iterator
                                .pop_bits(n_extra_bits_for_distance)
                                .ok_or(anyhow::anyhow!("not enough bits: after distance code {distance_code} at {} expected {n_extra_bits_for_distance} more bits", lsb_iterator.bit_cursor()))?;
                            let distance = distance_code_to_first_distance(distance_code as u16)?
                                + extra_bits as u16;
                            for _ in 0..len {
                                result.push(result[result.len() - distance as usize]);
                            }
                        }
                        _ => bail!(
                            "invalid sequence of bits encountered at {}",
                            lsb_iterator.bit_cursor()
                        ),
                    }
                }
            }
            // RFC 1951 section 3.2.7
            BlockType::DynamicHuffmanCodes => {
                let n_literals_codes = lsb_iterator.pop_bits(5).ok_or(anyhow::anyhow!(
                    "not enough bits: expected 5 bits at {} for HLIT",
                    lsb_iterator.bit_cursor()
                ))? as usize
                    + 257;
                let n_distance_codes = lsb_iterator.pop_bits(5).ok_or(anyhow::anyhow!(
                    "not enough bits: expected 5 bits at {} for HDIST",
                    lsb_iterator.bit_cursor()
                ))? as usize
                    + 1;

                let n_code_lengths_codes = lsb_iterator.pop_bits(4).ok_or(anyhow::anyhow!(
                    "not enough bits: expected 4 bits at {} for HCLEN",
                    lsb_iterator.bit_cursor()
                ))? as usize
                    + 4;

                let code_lengths_huffman_decoder =
                    get_code_lengths_decoder(&mut lsb_iterator, n_code_lengths_codes)?;

                let (literals_decoder, distances_decoder) = get_decoders_from_encoded_lengths(
                    &mut lsb_iterator,
                    n_literals_codes,
                    n_distance_codes,
                    &code_lengths_huffman_decoder,
                )?;

                loop {
                    let compressed_block_literal = lsb_iterator
                        .huffman_decode(&literals_decoder)
                        .context("decoding dynamic literals")?;
                    match compressed_block_literal {
                        0..=255 => {
                            result.push(compressed_block_literal as u8);
                        }
                        256 => break, // end of block
                        257..=285 => {
                            let Some(distances_decoder) = &distances_decoder else {
                                bail!("found an encoded (length,distance) pair without a distance huffman encoding at the start of the block")
                            };
                            let n_extra_bits_for_len =
                            n_extra_bits_for_len_code(compressed_block_literal).context(format!("computing number of needed bits after len code {compressed_block_literal}"))?;
                            // length + distance
                            let extra_bits = lsb_iterator
                                .pop_bits(n_extra_bits_for_len)
                                .ok_or(anyhow::anyhow!(format!("not enough bits: after {compressed_block_literal} at {} expected {n_extra_bits_for_len} more bits", lsb_iterator.bit_cursor())))?;
                            let len = len_code_to_first_len(compressed_block_literal)? + extra_bits;
                            let distance_code = lsb_iterator
                                .huffman_decode(distances_decoder)
                                .context("decoding dynamic distances")?;
                            let n_extra_bits_for_distance =
                            n_extra_bits_for_distance_code(distance_code).context(format!("computing number of needed bits after distance code {distance_code}"))?;
                            let extra_bits = lsb_iterator
                                .pop_bits(n_extra_bits_for_distance)
                                .ok_or(anyhow::anyhow!("not enough bits: after distance code {distance_code} at {} expected {n_extra_bits_for_distance} more bits", lsb_iterator.bit_cursor()))?;
                            let distance =
                                distance_code_to_first_distance(distance_code)? + extra_bits;
                            for _ in 0..len {
                                result.push(result[result.len() - distance as usize]);
                            }
                        }
                        _ => bail!("invalid sequence of bits encountered"),
                    }
                }
            }
            BlockType::Reserved => bail!(
                "invalid value for the block type after {} bits in the compressed data",
                lsb_iterator.bits_read_so_far
            ),
        }
        if last {
            break;
        }
    }
    Ok((result, lsb_iterator.bits_read_so_far.div_ceil(8)))
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

fn len_code_to_first_len(code: u16) -> anyhow::Result<u16> {
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
fn n_extra_bits_for_len_code(code: u16) -> anyhow::Result<usize> {
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

fn distance_code_to_first_distance(code: u16) -> anyhow::Result<u16> {
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
fn n_extra_bits_for_distance_code(code: u16) -> anyhow::Result<usize> {
    ensure!((0..=29).contains(&code), "invalid distance code: {code}");
    Ok(CODED_DISTANCES_X_BASES
        // Find the index of the group this code belongs to.
        .partition_point(|&x| x <= code - CODED_DISTANCES_X_OFFSET)
        .saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPRESSED_HELLO: &[u8] =
        b"\x78\x01\x01\x05\x00\xfa\xff\x68\x65\x6c\x6c\x6f\x06\x2c\x02\x15\x0a";

    const COMPRESSED_42_FIXED: &[u8] = b"\x78\x01\x33\x31\x02\x00\x00\x9c\x00\x67";
    const COMPRESSED_GIT_BLOB_FIXED: &[u8] = &[
        0x78, 0x1, 0x4b, 0xca, 0xc9, 0x4f, 0x52, 0x30, 0x34, 0x62, 0xd0, 0x52, 0x28, 0x49, 0xad,
        0x28, 0xb1, 0x4d, 0x2c, 0x2d, 0xc9, 0xe7, 0x2, 0x0, 0x3f, 0x6f, 0x6, 0x32,
    ];

    const COMPRESSED_GIT_TREE_FIXED: &[u8] =
        b"x\x01+)JMU065`01000P\xd0K\xceOIM.JL+I-*f\xe8\x8b\x9aT\x1a\x19#|\x87e\xd1\xdf\'\xa9\xfbg4u\x8b\x96\xfa\x19\x1a\x18\x98\x99\x98(\xe8\xa5g\x96$\x96\x94\x14e&\x95\x96\xa4\x163\x88g\xb9\xf6Oy\xf0*\xa8\xe8\\\xfa\xe1\xec\xcf\xdc\xd9/O}SFR\x99\x99\x9e\x97_\x94\xcaP\xfckC\xd1\xd1\xb5\x7f6\xac(THI\xecS\xe4Y~\xf4\xaa\x03T\x95sbQz\xbe^N~r6\xc3\x81\'\xd2.\x96\x7f\xbf\xe5>\xdf{D \xbe\xcb\x83\x93\xd1:\xbd\x1fEUI~n\x0eC\xfdV\x93\xef\x8b\xb4\xda\xb7\xb2\xae(4\xd8\xaee\xb4h\xe3\xd5u\x0cPUA\xae\x8e.\xbe\xaez\xb9)\x0c\x96\xfc,k\xb7\xc6\xc6\xde\x9afx\x7f\xe25g\x87\x88\x8c\x842_\xa8\"d\x8f\xeaU\xe6\xe604/\xee\xec\x95\x9c\xed[\xb6\xa1z\xf1\xb6#\xcd\xb5\xaf\x92\xddo\x1f\x80\x04JqQ2C\xffS\x81\x1f|\x11y\t\x95Q\xcbEO\x99\x9a^5\x13\tW740075U\xa8\xcc/-\x8a/(\xcaO/J\xcc\xd5+\xce`\xb8\xae\x92\xc1\xa2e\xef\xbeb\xf9|\x97#\x12Z}6>\x0bV\xe4\x00\x00Yg\x8b\x98";

    const COMPRESSED_GIT_BLOB_DYNAMIC: &[u8] = b"x\x01\x85\x90\xc1j\xc30\x0c\x86w\xd6S\x08\xe7\\c\'e\xeba\x1d\x83>F\xc8\xc1\x89\x95\xd8\xcc\xb1\x83\xect\xf4\xedGX\x07\x81\x1d\xa2\xab\xa4O\xdf\xaf>\xa4\x1e\xcf\xf5\xdbK\xbb\x98\xe1\xcbL\xd4A43\xe1\x15\xc5\x90,\rl\xc6B\x9cO\x93/\x02\xee\xc4\xd9\xa7\xb85\x95\xd4R\t0kq\x893^\xb1\x15\xb7\xdd<\xbe;\n!}\xee\x19\xd2\xa7\x0f\xd1\x01Y_\x9e\x90Z\xd5Z\x00\xaf\xb9\x9cvh-/J\x00\xb4\x96\x16\x8a\x96\xe2\xe0)w`\xe2\xc3\xa5\xef\xed\xb4\x96J\xbe^\x04\x1eT\x85\xc4\x9c\x18\x9d\x896\xf88A\xff(\xb4\x99\n-\x1b\xa9\x0e\xf7\x11+t\x14\x96\x8c\xb3\x89f\"\xec\xd7q$\xce0\x06S\xa8\xfe3i\xce\x87\xa4\n\x874/Ly{\x1e\x14\xe7\xf3\xaf\xd93Ks\x90\xe5_\x90\x1f>\xc7qb";

    const COMPRESSED_GIT_COMMIT_DYNAMIC: &[u8] = b"x\x01\xad\x94MO\xdc0\x10\x86{\xce\xaf\x98S\x05\x94\r\xd9e?QU\x15\xe8\x07H\xadz\x00\xce\xb5=\x9e$.\x89\xbd\xb2\'\xc0\xf6\xd7Wv\xb2\xcb\x828\xf6\x14y\x9c\xbc3\xf3\xbc3A\xd7\xb6\x86a<-&\xef\xd8\x13\xc1\\/Vr\xa9\n\x9c\x16j\xb9\x9a\xc9\xc9\xa2\x9c\x95\n\xb5\x9a\xce\x968Y\x15j*O\xd5XR\xb6\x96\x9e,\xc3b\xa2\xd5\xaa\x9c\x11\xcdQ\xa9\xf9\xb2\x18#\xaa\xf1).K\xc4\xf9j>\xd7KU.f\xb8\\d\xb2\xe3\xday8\xb7\xda\x93\x84\x0b\xf2\x8d\xb1\x95!o\xe0\xa3L\xb1\x91\xeac\x9f\xbb@>\xe4\xd6yZ7\x9b\xbc2\\w*G\xd7~\x82\xf1bv:.V\xab\xe9\x0c>\x14\x93\xa2\xc80\x95\xcf\xf4\xbfu\xb3\x92$\x9f\xc1u\xbbn\xa8\x8dm~7\x0cN\xfd!d\xa8\xa5\xd5\xb1v\x90V\x83x\xf4\x86i\x14\xd1\t\x88\xd5H\xab\xb3\xec\xda\xb2w\xbaC\n1\xb6\xf6T\x93\r\xe6\x81\xde\x94)\x9d\x07\xd58\x15\x92`T\n\xc7\x99\xb1\xd8t:f\t\xe4\x8dl\xcc_\xc9\xc6\xd9c\xd0\xf4*\x10\xab\xb8\xb9:\x1f\x8d\xa1\x96\xa16\xb6\xca\xe1\xb66!\xf3TJd\xe7\xa3\x06\x92e\x1fE(l\xbbh\\e\x10\x1e\r\xd7\xc6\x82\x08\x1eO*\xc3\xb9\x0f\"\t\x1a\xcbTy\xc9\x142\xc3\xf1\xe4\x80k\x82V\x1a\x0b\x97?\xae\xb7\x9d\x86<\xcbFpt\xb4\xff\xfd\xd1\xd1Y\x06\x000\x82s\xadI\x83\xb8h\x9c\x12\xc7 n#\xa3\xe1\xf9\xd5\xb2\xdf\xbc8\xfct:\xde&\xa6\xbf\x12h\x91d\x00\x02\xfb\x0e9\x9c\x90\xed\xda\x90hyZ{\nd9\xf6\xf6\xecL\xc8\x87\xc4;\xdbb\xfa/;`\xd4\xf7&\xbey\xd7\xde\xd4r|EO\x02\xd8K\xc3\xbdl\xef\xef\x90\xf5\x15g(\xbdk\xf78\xd3.Y\xdfeK\\;\xbd\xaf\xf3\xd288\x10[\xdfH\x1c\x1e\x0fJ\xdaT\x14\xb6\x19Q6\xd85\xc9f8\x10\xfdU|5\"AO\xfdE*\xa34\r\xc1Zr\x1d\x86b\x0fD\x8c\xff\x8e!q\xb8\xa5p\xc7&:\xaeA\x94\x12\x91B\x10\x80\xd1\xd2\x84\x10k\xc2\xfb\x88/i\xd1\x13a\xc7R\x99\xc6\xf0\x06\x8c\x1dd\x93e\xc9\xaa\xe4N\xfe\xecu\x1c\x848,\xcff\xdf\xad\xb5L\xbcQ\xf2(\x8aFw\xe3D\x8ez\xac[o\x9b\xf0rY\x02\xb0\x1b\xd25\xf4@^V\x94F\xcd\xd2\xe3\x9e\xb5\xcfK\xd7\xcfm\xc2\xb0?u\xdb\xa6w\x9b\xa7A&\x8d\xb7\x16\x14\xd8\xf5D\tdZ\xb8\xedRD\xd9\xa1\x988\xee\xd8\xf9\xf4\x8f{t>\xb1\xd2\xc6S\\\xa9\xcd@\xe2R\xfa\xca\xe5\xec\xdaF\xc0{\x18\x8e\x8d\xc3\xfb=.\xc3\x12\xec,\x90a(L\xd3\x9a\xac&\x8b\x9b<\xfb\x07\r3\xda[";

    const COMPRESSED_BLOB_MULTI_BLOCK: &[u8] = b"\x78\x01\x4a\xca\xc9\x4f\x52\x30\x35\x62\x28\x4a\x2c\x2e\x48\x4a\x2d\x2a\xaa\x54\x28\x2e\x29\x4a\x2c\x87\x30\xd3\x8b\x12\x0b\x52\x15\x12\x0b\x0a\x72\x52\x15\x0a\x32\xf3\x52\x21\xac\xa4\x9c\xd2\x54\xb0\x3c\x20\x00\x00\xff\xff\x9d\x9c\x16\xa1";

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

    #[test]
    fn test_inflate_no_compression() {
        let (uncompressed_hello, _) = inflate(&COMPRESSED_HELLO[2..]).unwrap();
        assert_eq!(b"hello", uncompressed_hello.as_slice());
    }

    #[test]
    fn test_inflate_fixed_huffman() {
        let (uncompressed_42, _) = inflate(&COMPRESSED_42_FIXED[2..]).unwrap();
        assert_eq!(b"42", uncompressed_42.as_slice());
        let (uncompressed_blob, _) = inflate(&COMPRESSED_GIT_BLOB_FIXED[2..]).unwrap();
        assert_eq!(b"blob 12\x00* text=auto\n", uncompressed_blob.as_slice());
    }

    #[test]
    fn test_inflate_multi_block() {
        let (uncompressed_42, _) = inflate(&COMPRESSED_42_FIXED[2..]).unwrap();
        assert_eq!(b"42", uncompressed_42.as_slice());
        let (uncompressed_blob, _) = inflate(&COMPRESSED_GIT_BLOB_FIXED[2..]).unwrap();
        assert_eq!(b"blob 12\x00* text=auto\n", uncompressed_blob.as_slice());

        let (uncompressed_blob, _) = inflate(&COMPRESSED_BLOB_MULTI_BLOCK[2..]).unwrap();
        assert_eq!(
            b"blob 52\x00raspberry strawberry grape apple pineapple blueberry",
            uncompressed_blob.as_slice()
        );
    }

    #[test]
    fn test_stream_inflate() {
        let mut stream: Stream = COMPRESSED_GIT_TREE_FIXED.try_into().unwrap();
        // Output is too big to compare directly, just interested in whether inflating and
        // verifying the checksum works without panicking
        stream.inflate().unwrap();
        stream = COMPRESSED_GIT_BLOB_DYNAMIC.try_into().unwrap();
        stream.inflate().unwrap();
        stream = COMPRESSED_GIT_COMMIT_DYNAMIC.try_into().unwrap();
        stream.inflate().unwrap();
    }

    #[test]
    fn test_round_trip() {
        let value_to_compress = b"hello world";
        for level in [CompressionLevel::Lowest, CompressionLevel::Low] {
            let mut stream: Stream = Stream::new(
                CompressionMethod::DEFLATE(2 << 7),
                None,
                level,
                value_to_compress.to_vec(),
            )
            .deflate()
            .unwrap()
            .try_into()
            .unwrap();
            assert_eq!(
                value_to_compress,
                &stream.inflate().unwrap(),
                "round trip failed for compression level {level:?}"
            );
        }
    }
}

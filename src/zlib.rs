use std::{fmt::Display, io::Write, iter::zip};

use anyhow::{bail, ensure, Context};

const COMPRESSION_LEVEL_MASK: u8 = 0x3;
const BLOCK_TYPE_MASK: u8 = 0x3;
const DEFLATE_IDENTIFIER: u8 = 0x8;

#[derive(Debug, Clone, Copy)]
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
        }
    }

    pub fn deflate(&mut self) -> anyhow::Result<&[u8]> {
        let checksum = adler32(&self.bytes);
        self.flags_check_bits = 1;
        let mut compressed_data = deflate(&self.bytes, self.compression_level)
            .context("deflating the compressed data")?;
        self.bytes.clear();
        self.bytes.write_all(b"\x78\x01")?;
        self.bytes.append(&mut compressed_data);
        self.bytes.write_all(&checksum)?;
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
        Ok(&self.bytes)
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
        let compressed_data = bytes[compressed_data_offset..].to_vec();
        Ok(Self {
            compression_method,
            preset_dictionary,
            flags_check_bits,
            compression_level,
            bytes: compressed_data,
        })
    }
}

enum BlockType {
    NoCompression,
    FixedHuffmanCodes,
    DynamicHuffmanCodes,
    Reserved,
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

    // Reads `n` bits from the stream LSB-first (no more than 8).
    fn pop_bits(&mut self, n: usize) -> Option<u8> {
        if n > 8 {
            return None;
        }
        if self.buffer.len() * 8 < self.bits_read_so_far + n {
            return None;
        }

        let mut result = 0u8;
        let mut bits_written = 0;

        while bits_written < n {
            let byte_pos = self.bits_read_so_far / 8;
            let shiftr = self.bits_read_so_far % 8;

            let bits_to_read_from_byte = (n - bits_written).min(8 - shiftr);

            // Take a chunk from the current byte
            let chunk = self.buffer[byte_pos] >> shiftr;

            // Mask out just the bits we want
            let mask = (1u8 << bits_to_read_from_byte) - 1;
            let masked_chunk = chunk & mask;

            // Place the chunk into the result at the correct position
            result |= masked_chunk << bits_written;

            // Advance cursors
            self.bits_read_so_far += bits_to_read_from_byte;
            bits_written += bits_to_read_from_byte;
        }

        Some(result)
    }

    fn pop_reversed_bits(&mut self, n: usize) -> Option<u8> {
        let val = self.pop_bits(n)?;
        // For u8, it would be .reverse_bits() >> (8 - n)
        Some(val.reverse_bits() >> (8 - n))
    }

    fn bit_cursor(&self) -> usize {
        self.bits_read_so_far
    }

    fn align_to_next_byte(&mut self) -> bool {
        if self.bits_read_so_far < (self.buffer.len() - 1) * 8 {
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
            let next_bit = self.pop_bit().ok_or(anyhow::anyhow!("not enough bytes"))?;
            current_node_idx = decompressor
                .next_node_idx(current_node_idx, next_bit)
                .ok_or(anyhow::anyhow!("undexpected bit encountered"))?;
        }
        decompressor
            .decode(current_node_idx)
            .ok_or(anyhow::anyhow!("invalid code found"))
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct HuffmanNode {
    left: Option<u16>,
    right: Option<u16>,
    payload: Option<u16>, // None means it's an internal node without a value
}

impl HuffmanNode {
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

fn get_code_lengths_decoder(
    lsb_iterator: &mut LSBBitsIterator<'_>,
    n_lengths: usize,
) -> anyhow::Result<HuffmanDecompressor> {
    const CODE_LENGTHS_SYMBOL_MAP: [u16; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut code_lengths_codes_lengths = vec![0; CODE_LENGTHS_SYMBOL_MAP.len()];
    // There are n_lengths in the input each represented as 3 bits in LSB order. The remaining 19 -
    // n_lengths are 0
    for code_length_code_length in code_lengths_codes_lengths.iter_mut().take(n_lengths) {
        *code_length_code_length = lsb_iterator.pop_bits(3).context("not enough bits")? as usize;
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
                    .context("not enough bits")? as usize;
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

fn deflate(bytes: &[u8], level: CompressionLevel) -> anyhow::Result<Vec<u8>> {
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
        CompressionLevel::Low => todo!(),
        CompressionLevel::Medium => todo!(),
        CompressionLevel::Highest => todo!(),
    }

    Ok(result)
}

fn inflate(bytes: &[u8]) -> anyhow::Result<(Vec<u8>, usize)> {
    let mut lsb_iterator = LSBBitsIterator::new(bytes);
    let mut result = vec![];

    let fixed_huffman_decompressor = HuffmanDecompressor::new(
        &FIXED_HUFFMAN_LITERALS_CODES_LENGTHS,
        &(0..FIXED_HUFFMAN_LITERALS_CODES_LENGTHS.len() as u16).collect::<Vec<_>>(),
    );

    loop {
        let Some(last) = lsb_iterator.pop_bit().map(|x| x == 1) else {
            bail!(
                "missing bfinal bit at position {}",
                lsb_iterator.bit_cursor()
            )
        };
        let Some(block_type) = lsb_iterator.pop_bits(2).map(|x| x.into()) else {
            bail!(
                "missing bfinal bit at position {}",
                lsb_iterator.bit_cursor()
            )
        };
        match block_type {
            BlockType::NoCompression => {
                if !lsb_iterator.align_to_next_byte() {
                    bail!("stream ended too early")
                }
                let Some(len) = lsb_iterator.pop_byte_aligned_u16() else {
                    bail!("stream ended too early: couldn't read LEN")
                };
                let Some(nlen) = lsb_iterator.pop_byte_aligned_u16() else {
                    bail!("stream ended too early: couldn't read NLEN")
                };
                ensure!(
                    !len == nlen,
                    "inconsistent values for LEN and NLEN before bit {}",
                    lsb_iterator.bit_cursor()
                );
                result.extend(lsb_iterator.pop_bytes(len as usize).ok_or(anyhow::anyhow!(
                    format!(
                        "not enough bytes or wrong alignment at {}",
                        lsb_iterator.bit_cursor()
                    )
                ))?);
            }
            BlockType::FixedHuffmanCodes => loop {
                let compressed_block_literal = lsb_iterator
                    .huffman_decode(&fixed_huffman_decompressor)
                    .context("decoding bits with the fixed huffman decoder")?;
                match compressed_block_literal {
                    0..=255 => result.push(compressed_block_literal as u8),
                    256 => break, // end of block
                    257..=285 => {
                        // length + distance
                        let extra_bits = lsb_iterator
                            .pop_bits(n_extra_bits_for_len_code(compressed_block_literal)?)
                            .ok_or(anyhow::anyhow!("not enough bits"))?;
                        let len =
                            len_code_to_first_len(compressed_block_literal)? + extra_bits as u16;
                        let distance_code = lsb_iterator
                            .pop_reversed_bits(5)
                            .ok_or(anyhow::anyhow!("not enough bits"))?;
                        let extra_bits = lsb_iterator
                            .pop_bits(n_extra_bits_for_distance_code(distance_code as u16)?)
                            .ok_or(anyhow::anyhow!("not enough bits"))?;
                        let distance = distance_code_to_first_distance(distance_code as u16)?
                            + extra_bits as u16;
                        for _ in 0..len {
                            result.push(result[result.len() - distance as usize]);
                        }
                    }
                    _ => bail!("invalid sequence of bits encountered"),
                }
            },
            // RFC 1951 section 3.2.7
            BlockType::DynamicHuffmanCodes => {
                let n_literals_codes = lsb_iterator
                    .pop_bits(5)
                    .ok_or(anyhow::anyhow!("not enough bits"))?
                    as usize
                    + 257;
                let n_distance_codes = lsb_iterator
                    .pop_bits(5)
                    .ok_or(anyhow::anyhow!("not enough bits"))?
                    as usize
                    + 1;

                let n_code_lengths_codes = lsb_iterator
                    .pop_bits(4)
                    .ok_or(anyhow::anyhow!("not enough bits"))?
                    as usize
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
                        0..=255 => result.push(compressed_block_literal as u8),
                        256 => break, // end of block
                        257..=285 => {
                            let Some(distances_decoder) = &distances_decoder else {
                                bail!("found an encoded (length,distance) pair without a distance huffman encoding at the start of the block")
                            };
                            // length + distance
                            let extra_bits = lsb_iterator
                                .pop_bits(n_extra_bits_for_len_code(compressed_block_literal)?)
                                .ok_or(anyhow::anyhow!("not enough bits"))?;
                            let len = len_code_to_first_len(compressed_block_literal)?
                                + extra_bits as u16;
                            let distance_code = lsb_iterator
                                .huffman_decode(distances_decoder)
                                .context("decoding dynamic distances")?;
                            let extra_bits = lsb_iterator
                                .pop_bits(n_extra_bits_for_distance_code(distance_code)?)
                                .ok_or(anyhow::anyhow!("not enough bits"))?;
                            let distance =
                                distance_code_to_first_distance(distance_code)? + extra_bits as u16;
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

    const COMPRESSED_HELLO: [u8; 17] =
        *b"\x78\x01\x01\x05\x00\xfa\xff\x68\x65\x6c\x6c\x6f\x06\x2c\x02\x15\x0a";

    const COMPRESSED_42_FIXED: [u8; 10] = *b"\x78\x01\x33\x31\x02\x00\x00\x9c\x00\x67";
    const COMPRESSED_GIT_BLOB_FIXED: [u8; 28] = [
        0x78, 0x1, 0x4b, 0xca, 0xc9, 0x4f, 0x52, 0x30, 0x34, 0x62, 0xd0, 0x52, 0x28, 0x49, 0xad,
        0x28, 0xb1, 0x4d, 0x2c, 0x2d, 0xc9, 0xe7, 0x2, 0x0, 0x3f, 0x6f, 0x6, 0x32,
    ];

    const COMPRESSED_GIT_TREE_FIXED: [u8; 328] =
        *b"x\x01+)JMU065`01000P\xd0K\xceOIM.JL+I-*f\xe8\x8b\x9aT\x1a\x19#|\x87e\xd1\xdf\'\xa9\xfbg4u\x8b\x96\xfa\x19\x1a\x18\x98\x99\x98(\xe8\xa5g\x96$\x96\x94\x14e&\x95\x96\xa4\x163\x88g\xb9\xf6Oy\xf0*\xa8\xe8\\\xfa\xe1\xec\xcf\xdc\xd9/O}SFR\x99\x99\x9e\x97_\x94\xcaP\xfckC\xd1\xd1\xb5\x7f6\xac(THI\xecS\xe4Y~\xf4\xaa\x03T\x95sbQz\xbe^N~r6\xc3\x81\'\xd2.\x96\x7f\xbf\xe5>\xdf{D \xbe\xcb\x83\x93\xd1:\xbd\x1fEUI~n\x0eC\xfdV\x93\xef\x8b\xb4\xda\xb7\xb2\xae(4\xd8\xaee\xb4h\xe3\xd5u\x0cPUA\xae\x8e.\xbe\xaez\xb9)\x0c\x96\xfc,k\xb7\xc6\xc6\xde\x9afx\x7f\xe25g\x87\x88\x8c\x842_\xa8\"d\x8f\xeaU\xe6\xe604/\xee\xec\x95\x9c\xed[\xb6\xa1z\xf1\xb6#\xcd\xb5\xaf\x92\xddo\x1f\x80\x04JqQ2C\xffS\x81\x1f|\x11y\t\x95Q\xcbEO\x99\x9a^5\x13\tW740075U\xa8\xcc/-\x8a/(\xcaO/J\xcc\xd5+\xce`\xb8\xae\x92\xc1\xa2e\xef\xbeb\xf9|\x97#\x12Z}6>\x0bV\xe4\x00\x00Yg\x8b\x98";

    const COMPRESSED_GIT_BLOB_DYNAMIC: &[u8; 221] = b"x\x01\x85\x90\xc1j\xc30\x0c\x86w\xd6S\x08\xe7\\c\'e\xeba\x1d\x83>F\xc8\xc1\x89\x95\xd8\xcc\xb1\x83\xect\xf4\xedGX\x07\x81\x1d\xa2\xab\xa4O\xdf\xaf>\xa4\x1e\xcf\xf5\xdbK\xbb\x98\xe1\xcbL\xd4A43\xe1\x15\xc5\x90,\rl\xc6B\x9cO\x93/\x02\xee\xc4\xd9\xa7\xb85\x95\xd4R\t0kq\x893^\xb1\x15\xb7\xdd<\xbe;\n!}\xee\x19\xd2\xa7\x0f\xd1\x01Y_\x9e\x90Z\xd5Z\x00\xaf\xb9\x9cvh-/J\x00\xb4\x96\x16\x8a\x96\xe2\xe0)w`\xe2\xc3\xa5\xef\xed\xb4\x96J\xbe^\x04\x1eT\x85\xc4\x9c\x18\x9d\x896\xf88A\xff(\xb4\x99\n-\x1b\xa9\x0e\xf7\x11+t\x14\x96\x8c\xb3\x89f\"\xec\xd7q$\xce0\x06S\xa8\xfe3i\xce\x87\xa4\n\x874/Ly{\x1e\x14\xe7\xf3\xaf\xd93Ks\x90\xe5_\x90\x1f>\xc7qb";

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
    fn test_stream_inflate() {
        let mut stream: Stream = COMPRESSED_GIT_TREE_FIXED.as_slice().try_into().unwrap();
        // Output is too big to compare directly, just interested in whether inflating and
        // verifying the checksum works without panicking
        stream.inflate().unwrap();
        stream = COMPRESSED_GIT_BLOB_DYNAMIC.as_slice().try_into().unwrap();
        stream.inflate().unwrap();
    }
}

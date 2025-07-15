use std::fmt::Display;

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

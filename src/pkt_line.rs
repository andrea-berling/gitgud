use std::io::Write;

use anyhow::{Context, Ok};

pub struct PktLines<'a> {
    bytes: &'a [u8],
    byte_cursor: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    Data(&'a [u8]),
    Flush,
    Delim,
    ResponseEnd,
}

impl<'a> Packet<'a> {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Packet::Data(items) => {
                let mut output: Vec<u8> = vec![];
                write!(&mut output, "{:04x}", items.len() + 4).unwrap();
                output.write_all(items).unwrap();
                output
            }
            Packet::Flush => b"0000".to_vec(),
            Packet::Delim => b"0001".to_vec(),
            Packet::ResponseEnd => b"0002".to_vec(),
        }
    }
}

/// Iterator over the pktlines packet encoded in a bytes buffer
impl<'a> PktLines<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            byte_cursor: 0,
        }
    }
}

impl<'a> Iterator for PktLines<'a> {
    type Item = anyhow::Result<Packet<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.byte_cursor >= self.bytes.len() || self.bytes.len() - self.byte_cursor < 4 {
            return None;
        }

        let len = u16::from_be_bytes([
            u8::from_str_radix(
                std::str::from_utf8(&self.bytes[self.byte_cursor..][..2])
                    .context("converting hex len to utf8")
                    .ok()?,
                16,
            )
            .context("converting hex len to u8")
            .ok()?,
            u8::from_str_radix(
                std::str::from_utf8(&self.bytes[self.byte_cursor + 2..][..2])
                    .context("converting hex len to utf8")
                    .ok()?,
                16,
            )
            .context("converting hex len to u8")
            .ok()?,
        ]) as usize;

        self.byte_cursor += 4;

        match len {
            0 => Some(Ok(Packet::Flush)),
            1 => Some(Ok(Packet::Delim)),
            2 => Some(Ok(Packet::ResponseEnd)),
            3 => None,
            mut len => {
                len -= 4;
                let ret = Some(Ok(Packet::Data(&self.bytes[self.byte_cursor..][..len])));
                self.byte_cursor += len;
                ret
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::pkt_line::{Packet, PktLines};

    #[test]
    fn parse_pkt_line() {
        assert_eq!(
            Packet::Data(b"a\n"),
            PktLines::new(b"0006a\n")
                .into_iter()
                .next()
                .unwrap()
                .unwrap()
        );
        assert_eq!(
            Packet::Data(b"a"),
            PktLines::new(b"0005a").into_iter().next().unwrap().unwrap()
        );
        assert_eq!(
            Packet::Data(b"foobar\n"),
            PktLines::new(b"000bfoobar\n")
                .into_iter()
                .next()
                .unwrap()
                .unwrap()
        );
        assert_eq!(
            Packet::Data(b""),
            PktLines::new(b"0004").into_iter().next().unwrap().unwrap()
        );
    }
}

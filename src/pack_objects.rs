use std::{
    cmp::min,
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use anyhow::{bail, ensure, Context};

use crate::{
    git::{self, Deserialize},
    sha1::{self, hex_encode},
    zlib,
};

const PACK_SIGNATURE: &[u8] = b"PACK";

enum PackVersion {
    V2,
    V3,
}

impl TryFrom<u32> for PackVersion {
    type Error = anyhow::Error;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            n => bail!("unsupported pack version: {n}"),
        }
    }
}

enum ObjectType {
    Blob,
    Commit,
    Tree,
    Tag,
    RefDelta,
    OfsDelta,
}

impl TryFrom<u8> for ObjectType {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match (byte >> 4) & 7 {
            1 => Ok(Self::Commit),
            2 => Ok(Self::Tree),
            3 => Ok(Self::Blob),
            4 => Ok(Self::Tag),
            6 => Ok(Self::OfsDelta),
            7 => Ok(Self::RefDelta),
            b => bail!("unsupported type: {b}"),
        }
    }
}

pub struct BytesBuffer<'a> {
    bytes: &'a [u8],
    byte_cursor: usize,
}

impl<'a> BytesBuffer<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            byte_cursor: 0,
        }
    }

    pub fn pop_byte(&mut self) -> Option<u8> {
        let ret = *self.bytes.get(self.byte_cursor)?;
        self.byte_cursor += 1;
        Some(ret)
    }

    pub fn pop_bytes(&mut self, n: usize) -> Option<&[u8]> {
        let ret = &self.bytes.get(self.byte_cursor..self.byte_cursor + n)?;
        self.byte_cursor += n;
        Some(ret)
    }

    fn byte_cursor(&self) -> usize {
        self.byte_cursor
    }

    fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

pub struct PackedObjectsStream<'a> {
    bytes: BytesBuffer<'a>,
    n_objects: usize,
    objects_parsed: usize,
    version: PackVersion,
}

impl<'a> Deref for PackedObjectsStream<'a> {
    type Target = BytesBuffer<'a>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl<'a> DerefMut for PackedObjectsStream<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl<'a> TryFrom<&'a [u8]> for PackedObjectsStream<'a> {
    type Error = anyhow::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        ensure!(
            bytes.starts_with(PACK_SIGNATURE),
            "invalid signature (expected {})",
            str::from_utf8(PACK_SIGNATURE)
                .expect("check PACK_SIGNATURE definition, it must be PACK")
        );

        let mut bytes = BytesBuffer::new(bytes);
        bytes
            .pop_bytes(4)
            .ok_or_else(|| anyhow::anyhow!("not enough bytes to read signature"))?;
        let version: PackVersion = u32::from_be_bytes(
            bytes
                .pop_bytes(4)
                .context("reading pack version")?
                .try_into()?,
        )
        .try_into()
        .context("parsing pack version")?;
        let n_objects = u32::from_be_bytes(
            bytes
                .pop_bytes(4)
                .context("reading number of objects")?
                .try_into()?,
        ) as usize;
        Ok(Self {
            bytes,
            n_objects,
            objects_parsed: 0,
            version,
        })
    }
}

#[derive(Debug)]
pub enum PackedObject {
    Object(git::Object),
    RefDelta(RefDelta),
}

impl<'a> Iterator for &mut PackedObjectsStream<'a> {
    type Item = anyhow::Result<PackedObject>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.objects_parsed >= self.n_objects {
            return None;
        }
        let first_byte = self.pop_byte()?;
        let object_type: ObjectType = match first_byte.try_into() {
            Err(e) => return Some(Err(e)),
            Ok(object_type) => object_type,
        };
        // This is the size uncompressed for things like blobs, trees and commits
        let mut size = (first_byte & 0xf) as usize;
        let mut shift = 4;
        // read size as varint
        let mut prev_byte = first_byte;
        while prev_byte & 0x80 == 0x80 {
            let new_byte = self.pop_byte()?;
            size += ((new_byte & 0x7f) as usize) << shift;
            shift += 7;
            prev_byte = new_byte;
        }

        match object_type {
            ObjectType::Commit | ObjectType::Tree | ObjectType::Blob => {
                let mut stream =
                    match zlib::Stream::try_from(self.bytes().get(self.byte_cursor()..)?) {
                        Err(e) => return Some(Err(e)),
                        Ok(stream) => stream,
                    };
                if let Err(e) = stream.inflate() {
                    return Some(Err(e));
                }
                // Move the cursor ahead
                self.pop_bytes(stream.serialization_len()?)?;
                let inflated = stream.bytes();
                let mut bytes = match object_type {
                    ObjectType::Blob => Vec::from(git::BLOB_HEADER_KEYWORD),
                    ObjectType::Commit => Vec::from(git::COMMIT_HEADER_KEYWORD),
                    ObjectType::Tree => Vec::from(git::TREE_HEADER_KEYWORD),
                    _ => unreachable!(),
                };

                bytes.push(b' ');
                bytes.extend(inflated.len().to_string().bytes());
                bytes.push(0x00);
                bytes.extend(inflated);
                self.objects_parsed += 1;
                Some(git::Object::deserialize(&bytes).map(PackedObject::Object))
            }
            ObjectType::RefDelta => {
                let ref_delta = match RefDelta::parse_from_bytes(&mut self.bytes, size) {
                    Err(e) => return Some(Err(e)),
                    Ok(ref_delta) => ref_delta,
                };
                self.objects_parsed += 1;
                Some(Ok(PackedObject::RefDelta(ref_delta)))
            }
            ObjectType::OfsDelta => {
                let mut c = self.pop_byte()?;
                let mut base_offset = (c & 0x7f) as usize;
                while c & 0x80 == 0x80 {
                    base_offset = base_offset.checked_add(1)?;
                    c = self.pop_byte()?;
                    base_offset = base_offset.checked_shl(7)?.checked_add(c as usize & 127)?;
                }
                panic!("OfsDelta not supported yet");
            }
            ObjectType::Tag => {
                panic!("tags not supported yet")
            }
        }
    }
}

const DELTA_SIZE_MIN: usize = 4;

enum PatchCommand {
    Copy { offset: usize, size: usize },
    Add(Vec<u8>),
}

impl Debug for PatchCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchCommand::Copy { offset, size } => f
                .debug_struct("Copy")
                .field("offset", &offset)
                .field("size", &size)
                .finish(),
            PatchCommand::Add(items) => f
                .debug_tuple("Add")
                .field(&{
                    let bytes_start: Vec<_> = items[..min(10, items.len())]
                        .iter()
                        .map(|byte| format!("{byte:#x}"))
                        .collect();
                    let bytes_end = if items.len() > 10 + bytes_start.len() {
                        items[items.len() - 10..]
                            .iter()
                            .map(|byte| format!("{byte:#x}"))
                            .collect()
                    } else {
                        vec![]
                    };
                    format!(
                        "[ {}{}{} ]",
                        bytes_start.join(", "),
                        if !bytes_end.is_empty() { ", ..., " } else { "" },
                        bytes_end.join(", ")
                    )
                })
                .finish(),
        }
    }
}

impl PatchCommand {
    fn parse_from_bytes(bytes: &mut BytesBuffer<'_>) -> Option<Self> {
        let cmd = bytes.pop_byte()?;
        if cmd & 0x80 == 0x80 {
            Some(parse_copy_command(bytes, cmd)?)
        } else if cmd > 0 {
            Some(Self::Add(bytes.pop_bytes(cmd as usize)?.to_vec()))
        } else {
            panic!("reserved patch command 0 encountered");
        }
    }
}

struct RefDelta {
    base: sha1::Digest,
    src_header_size: usize,
    dst_header_size: usize,
    commands: Vec<PatchCommand>,
}

impl Debug for RefDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefDelta")
            .field("base", &hex_encode(&self.base))
            .field("src_header_size", &self.src_header_size)
            .field("dst_header_size", &self.dst_header_size)
            .field("commands", &self.commands)
            .finish()
    }
}

fn parse_delta_header_size(bytes: &mut BytesBuffer, size_bytes: usize) -> Option<usize> {
    let mut header_size = 0;
    let mut processed_bytes = 0usize;
    let mut shift = 0;

    loop {
        let cmd = bytes.pop_byte()?;
        processed_bytes += 1;
        header_size |= checked_shl_no_overflow_usize(cmd as usize & 0x7f, shift)?;
        shift += 7;
        // TODO: probably not good if we reach size_bytes before we have parsed headers and
        // opcodes?
        if cmd & 0x80 != 0x80 || processed_bytes >= size_bytes {
            break;
        }
    }
    Some(header_size)
}

/// Returns offset and size
fn parse_copy_command(bytes: &mut BytesBuffer, cmd: u8) -> Option<PatchCommand> {
    let mut offset = 0usize;
    for shift in 0..4 {
        if cmd & (1 << shift) == (1 << shift) {
            offset |= (bytes.pop_byte()? as usize) << (shift * 8)
        }
    }
    let mut size = 0;
    for shift in 0..3 {
        if (cmd >> (4 + shift)) & 1 == 1 {
            size |= (bytes.pop_byte()? as usize) << (shift * 8)
        }
    }

    if size == 0 {
        size = 0x10000;
    }

    // TODO: check on the lengths and offset
    Some(PatchCommand::Copy { offset, size })
}

impl RefDelta {
    fn parse_from_bytes(
        bytes: &mut BytesBuffer<'_>,
        mut size_bytes: usize,
    ) -> anyhow::Result<Self> {
        let base: sha1::Digest = bytes
            .pop_bytes(sha1::DIGEST_SIZE)
            .ok_or_else(|| anyhow::anyhow!("not enough bytes to read base sha1"))?
            .try_into()
            .context("converting base sha1 to digest")?;
        ensure!(
            size_bytes >= DELTA_SIZE_MIN,
            "not enough bytes to read delta size"
        );

        let mut stream = zlib::Stream::try_from(
            bytes
                .bytes()
                .get(bytes.byte_cursor()..)
                .ok_or_else(|| anyhow::anyhow!("not enough bytes to read zlib stream"))?,
        )
        .context("creating zlib stream from delta bytes")?;
        stream.inflate().context("inflating delta stream")?;
        // Move the cursor ahead
        bytes
            .pop_bytes(
                stream
                    .serialization_len()
                    .ok_or_else(|| anyhow::anyhow!("could not get serialization length"))?,
            )
            .ok_or_else(|| anyhow::anyhow!("not enough bytes to pop serialized stream"))?;
        let mut delta_bytes = BytesBuffer::new(stream.bytes());

        let src_header_size = parse_delta_header_size(&mut delta_bytes, size_bytes)
            .ok_or_else(|| anyhow::anyhow!("could not parse src header size"))?;
        let dst_header_size = parse_delta_header_size(&mut delta_bytes, size_bytes)
            .ok_or_else(|| anyhow::anyhow!("could not parse dst header size"))?;

        let mut commands = vec![];
        let mut byte_cursor = delta_bytes.byte_cursor();
        while size_bytes > 0 {
            let Some(cmd) = PatchCommand::parse_from_bytes(&mut delta_bytes) else {
                break;
            };
            commands.push(cmd);
            size_bytes -= delta_bytes.byte_cursor() - byte_cursor;
            byte_cursor = delta_bytes.byte_cursor();
        }
        Ok(Self {
            base,
            src_header_size,
            dst_header_size,
            commands,
        })
    }
}

fn checked_shl_no_overflow_usize(value: usize, shift: u32) -> Option<usize> {
    if shift >= usize::BITS {
        return None;
    }

    let result = value << shift;

    // Check if we lost bits
    if value != (result >> shift) {
        None
    } else {
        Some(result)
    }
}

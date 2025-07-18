use anyhow::{bail, ensure, Context};

use crate::sha1;

pub struct Blob {
    bytes: Vec<u8>,
}

impl Blob {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl TryFrom<&[u8]> for Blob {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ensure!(&bytes[0..5] == b"blob ");
        let Some(header_end_marker) = bytes.iter().position(|&x| x == 0) else {
            bail!("no header end marker (\\x00 byte) found")
        };
        let len: usize = str::from_utf8(&bytes[5..header_end_marker])
            .context("reading blob len bytes as string")?
            .parse()
            .context("parsing blob len bytes as a usize")?;
        ensure!(bytes.len() - header_end_marker - 1 >= len);
        Ok(Self {
            bytes: bytes[header_end_marker + 1..][..len].to_vec(),
        })
    }
}

#[derive(Debug)]
pub enum TreeEntryMode {
    Regular,
    Executable,
    SymbolicLink,
    Directory,
}

impl TreeEntryMode {
    fn serialization_len(&self) -> usize {
        match self {
            TreeEntryMode::Regular | TreeEntryMode::Executable | TreeEntryMode::SymbolicLink => 6,
            TreeEntryMode::Directory => 5,
        }
    }
}

impl TryFrom<&[u8]> for TreeEntryMode {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match bytes.first().ok_or(anyhow::anyhow!(
            "not enough bytes to parse the first bit of the mode"
        ))? {
            b'4' => {
                if bytes
                    .get(0..5)
                    .ok_or(anyhow::anyhow!("not enough bytes to parse the mode"))?
                    == b"40000"
                {
                    Ok(Self::Directory)
                } else {
                    bail!("invalid mode bytes encountered (starts with 4, but is not a directory)")
                }
            }
            b'1' => {
                match bytes.get(0..6).ok_or(anyhow::anyhow!("not enough bytes to parse the mode"))?
                {
                    b"100644" => Ok(Self::Regular),
                    b"100755" => Ok(Self::Executable),
                    b"120000" => Ok(Self::SymbolicLink),
                    _ => bail!("invalid mode bytes encountered (starts with 1, but isn't regular, executable, or a symlink)")
                }
            }
            _ => bail!("unexpected bytes encountered (neither 1 or 4)"),
        }
    }
}

#[derive(Debug)]
pub struct TreeEntry {
    name: String,
    mode: TreeEntryMode,
    sha1: sha1::Digest,
}

impl TreeEntry {
    pub fn name(&self) -> &str {
        &self.name
    }

    fn serialization_len(&self) -> usize {
        self.mode.serialization_len() + 1 + self.name().len() + 1 + 20
    }
}

impl TryFrom<&[u8]> for TreeEntry {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mode: TreeEntryMode = bytes[0..]
            .try_into()
            .context("parsing first few bytes into a entry mode")?;
        let next_byte_idx = if matches!(mode, TreeEntryMode::Directory) {
            5
        } else {
            6
        };
        ensure!(
            *bytes
                .get(next_byte_idx)
                .ok_or(anyhow::anyhow!("not enough bytes to parse past the mdoe"))?
                == b' '
        );
        let Some(end_marker) = bytes.iter().position(|&x| x == 0) else {
            bail!("no string terminator byte found");
        };
        let name = bytes[next_byte_idx + 1..end_marker]
            .iter()
            .map(|&b| char::from(b))
            .collect();
        let sha1 = bytes
            .get(end_marker + 1..end_marker + 1 + 20)
            .ok_or(anyhow::anyhow!("not enough bytes to parse the sha1"))?
            .try_into()?;
        Ok(Self { name, mode, sha1 })
    }
}

pub struct Tree {
    entries: Vec<TreeEntry>,
}

impl Tree {
    pub fn entries(&self) -> &[TreeEntry] {
        &self.entries
    }
}

impl TryFrom<&[u8]> for Tree {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ensure!(
            &bytes
                .get(0..5)
                .ok_or(anyhow::anyhow!("not enough bytes to parse the header"))?
                == b"tree "
        );
        let Some(header_end_marker) = bytes.iter().position(|&x| x == 0) else {
            bail!("no header end marker (\\x00 byte) found")
        };
        let len: usize = str::from_utf8(&bytes[5..header_end_marker])
            .context("reading blob len bytes as string")?
            .parse()
            .context("parsing blob len bytes as a usize")?;
        ensure!(bytes.len() - header_end_marker - 1 >= len);
        let mut entries = vec![];
        let mut parsed_bytes = 0;
        while parsed_bytes < len {
            let new_entry = TreeEntry::try_from(&bytes[header_end_marker + 1 + parsed_bytes..])
                .context("parsing bytes into a tree entry")?;
            parsed_bytes += new_entry.serialization_len();
            entries.push(new_entry)
        }
        Ok(Self { entries })
    }
}

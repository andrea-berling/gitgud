use anyhow::{bail, ensure, Context};

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

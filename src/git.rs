#![allow(clippy::incompatible_msrv)]
use core::fmt::Debug;
use std::{
    cmp::min,
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::Write,
    os::{
        linux::fs::MetadataExt as _,
        unix::{
            ffi::OsStrExt,
            fs::{symlink, MetadataExt, OpenOptionsExt as _},
        },
    },
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const GIT_DIRECTORY_NAME: &str = ".git";
pub const OBJECTS_DIRECTORY: &str = "objects";
pub const BLOB_HEADER_KEYWORD: &[u8] = b"blob";
pub const TREE_HEADER_KEYWORD: &[u8] = b"tree";
pub const COMMIT_HEADER_KEYWORD: &[u8] = b"commit";
pub const PARENT_HEADER_KEYWORD: &[u8] = b"parent";
pub const AUTHOR_HEADER_KEYWORD: &[u8] = b"author";
pub const GPG_SIGNATURE_HEADER_KEYWORD: &[u8] = b"gpgsig";
pub const COMMITTER_HEADER_KEYWORD: &[u8] = b"committer";
pub const INDEX_HEADER_SIGNATURE: &[u8] = b"DIRC";
pub const OBJECT_TYPE_MASK: u8 = 0xf;
pub const OBJECT_STAGE_MASK: u8 = 0x3;
pub const CACHE_TREE_EXTENSION_SIGNATURE: &[u8] = b"TREE";
pub const INDEX_V2: u32 = 2;
pub const MAXIMUM_PATH_LENGTH: u16 = 0xfff;

use anyhow::{bail, ensure, Context};
use faccess::PathExt;

use crate::{
    sha1::{self, hex_encode},
    zlib,
};

pub struct Blob {
    bytes: Vec<u8>,
}

impl Debug for Blob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blob")
            .field("bytes", &{
                let bytes_start: Vec<_> = self.bytes[..min(10, self.bytes.len())]
                    .iter()
                    .map(|byte| format!("{byte:#x}"))
                    .collect();
                let bytes_end = if self.bytes().len() > 10 + bytes_start.len() {
                    self.bytes[self.bytes.len() - 10..]
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
            .field("n_bytes", &self.bytes.len())
            .finish()
    }
}

pub trait HasPayload {
    fn payload(&self) -> Vec<u8>;

    fn digest(&self) -> sha1::Digest {
        sha1::sha1(&self.payload())
    }
}

impl HasPayload for Blob {
    fn payload(&self) -> Vec<u8> {
        let mut object_bytes = Vec::from(BLOB_HEADER_KEYWORD);
        object_bytes.push(b' ');
        object_bytes.extend(self.bytes.len().to_string().as_bytes());
        object_bytes.push(b'\x00');
        object_bytes.extend(&self.bytes);
        object_bytes
    }
}

pub trait SerializeToGitObject {
    fn serialize(&self, git_dir_path: &Path) -> anyhow::Result<()>;
}

/// Path to the loose object in the git directory
pub fn object_path(git_dir_path: &Path, sha: &sha1::Digest) -> anyhow::Result<PathBuf> {
    let object_sha = sha1::hex_encode(sha);
    let dir_name = object_sha.get(0..2).ok_or(anyhow::anyhow!(format!(
        "hex digest {object_sha} too short (less than 2 chars)"
    )))?;
    let object_dir = git_dir_path.join(OBJECTS_DIRECTORY).join(dir_name);

    let file_path = object_dir.join(object_sha.get(2..40).ok_or(anyhow::anyhow!(format!(
        "hex digest {object_sha} too short (less than 40 chars)"
    )))?);
    Ok(file_path)
}

fn write_object(payload: &[u8], git_dir_path: &Path) -> anyhow::Result<()> {
    let object_sha_digest = sha1::sha1(payload);
    let object_sha = sha1::hex_encode(&object_sha_digest);
    let object_path = object_path(git_dir_path, &object_sha_digest)
        .with_context(|| format!("getting object path for {object_sha}"))?;

    if object_path.exists() {
        return Ok(());
    }

    let dir_path = object_path.parent().ok_or_else(|| {
        anyhow::anyhow!("could not get parent directory for object path {object_path:?}")
    })?;

    if !dir_path.exists() {
        std::fs::create_dir(dir_path).context(format!(
            "creating dir {:?} for serialization of {object_sha}",
            dir_path.to_str()
        ))?;
    }

    let mut stream = zlib::Stream::new(
        zlib::CompressionMethod::DEFLATE(2 << 7),
        None,
        zlib::CompressionLevel::Low,
        payload.to_vec(),
    );
    let compressed_payload = stream
        .deflate()
        .context(format!("compressing payload for {object_sha}",))?;

    std::fs::write(&object_path, compressed_payload).context(format!(
        "writing payload for {object_sha} to {:?}",
        object_path.to_str()
    ))?;

    Ok(())
}

impl<T: HasPayload> SerializeToGitObject for T {
    fn serialize(&self, git_dir_path: &Path) -> anyhow::Result<()> {
        write_object(&self.payload(), git_dir_path)
    }
}

pub trait Deserialize
where
    Self: Sized,
{
    fn deserialize(bytes: &[u8]) -> anyhow::Result<Self>;
}

pub trait FromSha1Hex
where
    Self: Sized,
{
    fn from_sha1_hex(sha1_hex: &str, git_dir_path: &Path) -> anyhow::Result<Self>;
}

impl<T: Deserialize> FromSha1Hex for T {
    fn from_sha1_hex(sha1_hex: &str, git_dir_path: &Path) -> anyhow::Result<Self> {
        let dir_name = sha1_hex.get(0..2).ok_or(anyhow::anyhow!(format!(
            "hex digest {sha1_hex} too short (less than 2 chars)"
        )))?;
        let object_dir = git_dir_path.join(OBJECTS_DIRECTORY).join(dir_name);
        if !object_dir.as_path().exists() {
            bail!("object doesn't exist (corresponding directory doesn't exist)")
        }
        let file_path = object_dir.join(sha1_hex.get(2..40).ok_or(anyhow::anyhow!(format!(
            "hex digest {sha1_hex} too short (less than 40 chars)"
        )))?);
        if !file_path.exists() {
            bail!("object doesn't exist (corresponding file doesn't exist)");
        }
        let mut stream = zlib::Stream::try_from(
            std::fs::read(&file_path)
                .context(format!("reading bytes from {:?}", file_path.to_str()))?
                .as_slice(),
        )
        .context(format!("making a zlib stream file for {sha1_hex}",))?;
        let decompressed_bytes = stream
            .inflate()
            .context(format!("decompressing object file for {sha1_hex}",))?;
        Self::deserialize(decompressed_bytes)
    }
}

impl Blob {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            bytes: fs::read(path).context(format!("reading from {:?}", path.to_str()))?,
        })
    }

    fn size(&self) -> usize {
        self.bytes.len()
    }
}

impl Deserialize for Blob {
    fn deserialize(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        ensure!(
            &bytes[0..4] == BLOB_HEADER_KEYWORD,
            "wrong header (expected {})",
            str::from_utf8(BLOB_HEADER_KEYWORD).expect(
                "check the definition of BLOB_HEADER_KEYWORD: should be a UTF8 encoded string"
            )
        );
        ensure!(
            bytes[4] == b' ',
            "expected space after {}, got {:x?}",
            str::from_utf8(BLOB_HEADER_KEYWORD).expect(
                "check the definition of BLOB_HEADER_KEYWORD: should be a UTF8 encoded string"
            ),
            bytes[4]
        );
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

#[derive(Debug, Clone, Copy)]
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

impl TryFrom<&Path> for TreeEntryMode {
    type Error = anyhow::Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        if path.is_dir() {
            Ok(Self::Directory)
        } else if path.is_symlink() {
            Ok(Self::SymbolicLink)
        } else if path.is_file() {
            if path.executable() {
                Ok(Self::Executable)
            } else {
                Ok(Self::Regular)
            }
        } else {
            bail!("not a directory, not a file, not a symlink")
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

#[derive(Clone)]
pub struct TreeEntry {
    name: String,
    mode: TreeEntryMode,
    sha1: sha1::Digest,
}

impl Debug for TreeEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeEntry")
            .field("name", &self.name)
            .field("mode", &self.mode)
            .field("sha1", &hex_encode(&self.sha1))
            .finish()
    }
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

impl From<TreeEntryMode> for String {
    fn from(value: TreeEntryMode) -> Self {
        match value {
            TreeEntryMode::Regular => "100644".into(),
            TreeEntryMode::Executable => "100755".into(),
            TreeEntryMode::SymbolicLink => "120000".into(),
            TreeEntryMode::Directory => "40000".into(),
        }
    }
}

#[derive(Debug)]
pub struct Tree {
    entries: Vec<TreeEntry>,
}

impl Tree {
    pub fn entries(&self) -> &[TreeEntry] {
        &self.entries
    }

    pub fn digest(&self) -> sha1::Digest {
        sha1::sha1(&self.payload())
    }

    pub fn serialize_recursively(
        &self,
        self_path: &Path,
        git_dir_path: &Path,
    ) -> Result<(), anyhow::Error> {
        // Serialize all the entries first
        for entry in &self.entries {
            let object_path = self_path.join(&entry.name);
            Object::from_path(object_path.as_path())
                .context(format!(
                    "making an object out of {:?}",
                    object_path.to_str()
                ))?
                .serialize(Some(&object_path), git_dir_path)
                .context(format!("serializing {}", hex_encode(&entry.sha1)))?;
        }
        write_object(&self.payload(), git_dir_path)
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let mut tree = Tree { entries: vec![] };
        for entry in path
            .read_dir()
            .context(format!("listing files in {:?}", path.to_str()))?
        {
            match entry {
                Ok(entry) => {
                    let (path, file_type) = (
                        entry.path(),
                        entry
                            .file_type()
                            .context("getting file type for new tree entry")?,
                    );
                    let name = path
                        .file_name()
                        .ok_or(anyhow::anyhow!("couldn't get name"))?
                        .to_str()
                        .ok_or(anyhow::anyhow!("couldn't read file name as a string"))?
                        .to_string();
                    if file_type.is_dir() && name == GIT_DIRECTORY_NAME {
                        continue;
                    }
                    let mode = TreeEntryMode::try_from(path.as_path())
                        .context(format!("making a tree entry out of {:?}", path.to_str()))?;
                    let sha1 = Object::from_path(path.as_path())
                        .context("making an object out of a new tree entry")?
                        .digest();
                    tree.entries.push(TreeEntry { name, mode, sha1 });
                }
                Err(err) => return Err(anyhow::anyhow!(err).context("creating a tree from a path")),
            }
        }
        Ok(tree)
    }

    fn size(&self) -> usize {
        self.entries()
            .iter()
            .map(|entry| entry.serialization_len())
            .sum()
    }
}

impl HasPayload for Tree {
    fn payload(&self) -> Vec<u8> {
        let mut object_bytes = Vec::from(TREE_HEADER_KEYWORD);
        object_bytes.push(b' ');
        let mut payload = vec![];
        let mut sorted_entries = self.entries().to_vec();
        sorted_entries.sort_by(|el1, el2| el1.name.cmp(&el2.name));
        for entry in &sorted_entries {
            payload.extend(String::from(entry.mode).bytes());
            payload.push(b' ');
            payload.extend(entry.name.as_bytes());
            payload.push(b'\x00');
            payload.extend(entry.sha1);
        }
        object_bytes.extend(payload.len().to_string().as_bytes());
        object_bytes.push(b'\x00');
        object_bytes.append(&mut payload);
        object_bytes
    }
}

impl Deserialize for Tree {
    fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            &bytes[0..4] == TREE_HEADER_KEYWORD,
            "wrong header (expected {})",
            str::from_utf8(TREE_HEADER_KEYWORD).expect(
                "check the definition of TREE_HEADER_KEYWORD: should be a UTF8 encoded string"
            )
        );
        ensure!(
            bytes[4] == b' ',
            "expected space after {}, got {:x?}",
            str::from_utf8(TREE_HEADER_KEYWORD).expect(
                "check the definition of TREE_HEADER_KEYWORD: should be a UTF8 encoded string"
            ),
            bytes[4]
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

pub struct AuthorshipInfo {
    name: String,
    email_address: String,
    epoch: u64,
    timezone: i16,
}

impl Debug for AuthorshipInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorshipInfo")
            .field("name", &self.name)
            .field("email_address", &self.email_address)
            .field("epoch", &self.epoch)
            .field("timezone", &format!("{:+05}", &self.timezone))
            .finish()
    }
}

impl TryFrom<&[u8]> for AuthorshipInfo {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let start_email_address_marker =
            bytes
                .iter()
                .position(|&b| b == b'<')
                .ok_or(anyhow::anyhow!(
                    "no start of email address marker ('<') found"
                ))?;
        let name = str::from_utf8(bytes.get(..start_email_address_marker - 1).ok_or(
            anyhow::anyhow!(
                "not enough bytes for a name (name is everything before the email address)"
            ),
        )?)
        .context("name is not valid UTF-8")?;
        let end_email_address_marker = bytes[start_email_address_marker..]
            .iter()
            .position(|&b| b == b'>')
            .map(|pos| pos + start_email_address_marker)
            .ok_or(anyhow::anyhow!(
                "no end of email address marker ('>') found"
            ))?;
        let email_address = str::from_utf8(
            bytes
                .get(start_email_address_marker + 1..end_email_address_marker)
                .ok_or(anyhow::anyhow!("not enough bytes for an email address"))?,
        )
        .context("email address is not valid UTF-8")?;
        ensure!(
            bytes.get(end_email_address_marker + 1) == Some(&b' '),
            "no space after email address"
        );
        let end_epoch_bytes = bytes
            .get(end_email_address_marker + 2..)
            .context("not enough bytes for epoch and timezone")?
            .iter()
            .position(|&b| b == b' ')
            .map(|bytes| bytes + end_email_address_marker + 2)
            .context("no space between epoch and timezone")?;
        let epoch = str::from_utf8(
            bytes
                .get(end_email_address_marker + 2..end_epoch_bytes)
                .context("not enough bytes for epoch")?,
        )
        .context("epoch is not valid UTF-8")?
        .parse()
        .context("could not parse epoch")?;
        let sign: i16 = bytes
            .get(end_epoch_bytes + 1)
            .and_then(|&b| {
                if b == b'+' {
                    Some(1)
                } else if b == b'-' {
                    Some(-1)
                } else {
                    None
                }
            })
            .ok_or(anyhow::anyhow!("no sign for timezone"))?;
        let timezone: i16 = str::from_utf8(
            bytes
                .get(end_epoch_bytes + 2..end_epoch_bytes + 6)
                .context("not enough bytes for timezone")?,
        )
        .context("timezone is not valid UTF-8")?
        .parse()
        .context("could not parse timezone")?;
        Ok(Self {
            name: name.to_string(),
            email_address: email_address.to_string(),
            epoch,
            timezone: timezone * sign,
        })
    }
}

impl From<&AuthorshipInfo> for Vec<u8> {
    fn from(author: &AuthorshipInfo) -> Self {
        let mut ret = vec![];
        ret.extend(author.name.bytes());
        ret.push(b' ');
        ret.push(b'<');
        ret.extend(author.email_address.bytes());
        ret.push(b'>');
        ret.push(b' ');
        ret.extend(author.epoch.to_string().bytes());
        ret.push(b' ');
        ret.push(if author.timezone < 0 { b'-' } else { b'+' });
        ret.extend(format!("{:04}", author.timezone.abs()).bytes());
        ret
    }
}

pub type CommiterInfo = AuthorshipInfo;

pub struct Commit {
    tree: sha1::Digest,
    parents: Vec<sha1::Digest>,
    author: AuthorshipInfo,
    committer: CommiterInfo,
    gpg_signature: Option<String>,
    message: String,
}

impl Debug for Commit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Commit")
            .field("tree", &hex_encode(&self.tree))
            .field(
                "parents",
                &self
                    .parents
                    .iter()
                    .map(|sha1| hex_encode(sha1))
                    .reduce(|acc, sha| format!("{acc}, {sha}")),
            )
            .field("author", &self.author)
            .field("message", &self.message)
            .finish()
    }
}

impl Commit {
    pub fn new_no_author_no_committer(
        tree: sha1::Digest,
        parents: Vec<sha1::Digest>,
        message: String,
    ) -> Self {
        Self {
            tree,
            parents,
            author: AuthorshipInfo {
                name: "Nobody".into(),
                email_address: "nobody@nowhere.nil".into(),
                epoch: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                timezone: 0,
            },
            committer: AuthorshipInfo {
                name: "Nobody".into(),
                email_address: "nobody@nowhere.nil".into(),
                epoch: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                timezone: 0,
            },
            gpg_signature: None,
            message,
        }
    }

    fn size(&self) -> usize {
        let mut size = 0;
        size += TREE_HEADER_KEYWORD.len();
        size += 1; // space
        size += 40; // sha1 hex
        size += 1; // newline
        for _ in &self.parents {
            size += PARENT_HEADER_KEYWORD.len();
            size += 1; // space
            size += 40; // sha1 hex
            size += 1; // newline
        }
        size += AUTHOR_HEADER_KEYWORD.len();
        size += 1; // space
        size += <Vec<u8>>::from(&self.author).len();
        size += 1; // newline
        size += COMMITTER_HEADER_KEYWORD.len();
        size += 1; // space
        size += <Vec<u8>>::from(&self.committer).len();
        size += 1; // newline
        if let Some(signature) = &self.gpg_signature {
            size += GPG_SIGNATURE_HEADER_KEYWORD.len();
            size += 1; // space
            size += signature.len();
            size += 1; // newline
        }
        size += 1; // newline
        size += self.message.len();
        size += 1; // newline
        size
    }
}

impl HasPayload for Commit {
    fn payload(&self) -> Vec<u8> {
        let mut object_bytes = Vec::from(COMMIT_HEADER_KEYWORD);
        object_bytes.push(b' ');
        let mut payload = vec![];
        payload.extend(TREE_HEADER_KEYWORD);
        payload.push(b' ');
        payload.extend(hex_encode(&self.tree).bytes());
        payload.push(b'\n');
        if !self.parents.is_empty() {
            payload.extend(PARENT_HEADER_KEYWORD);
            payload.push(b' ');
            payload.extend(
                self.parents
                    .iter()
                    .map(|parent| hex_encode(parent))
                    .reduce(|acc, el| acc + " " + &el)
                    .unwrap()
                    .bytes(),
            );
            payload.push(b'\n');
        }
        payload.extend(AUTHOR_HEADER_KEYWORD);
        payload.push(b' ');
        payload.extend(&<Vec<u8>>::from(&self.author));
        payload.push(b'\n');
        payload.extend(COMMITTER_HEADER_KEYWORD);
        payload.push(b' ');
        payload.extend(&<Vec<u8>>::from(&self.committer));
        payload.push(b'\n');
        if let Some(signature) = &self.gpg_signature {
            payload.extend(GPG_SIGNATURE_HEADER_KEYWORD);
            payload.push(b' ');
            payload.extend(signature.bytes());
            payload.push(b'\n');
        }
        payload.push(b'\n');
        payload.extend(self.message.bytes());

        object_bytes.extend(payload.len().to_string().as_bytes());
        object_bytes.push(b'\x00');
        object_bytes.append(&mut payload);
        object_bytes
    }
}

impl Deserialize for Commit {
    fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            bytes.starts_with(COMMIT_HEADER_KEYWORD),
            "wrong header (expected {})",
            str::from_utf8(COMMIT_HEADER_KEYWORD).expect(
                "check the definition of COMMIT_HEADER_KEYWORD: should be a UTF8 encoded string"
            )
        );
        ensure!(
            bytes.get(COMMIT_HEADER_KEYWORD.len()) == Some(&b' '),
            "expected space after {}, got {:#x?}",
            str::from_utf8(COMMIT_HEADER_KEYWORD).expect(
                "check the definition of COMMIT_HEADER_KEYWORD: should be a UTF8 encoded string"
            ),
            bytes[COMMIT_HEADER_KEYWORD.len()]
        );
        let Some(header_end_marker) = bytes.iter().position(|&x| x == 0) else {
            bail!("no header end marker (\x00 byte) found")
        };
        let len: usize = str::from_utf8(
            bytes
                .get(COMMIT_HEADER_KEYWORD.len() + 1..header_end_marker)
                .ok_or(anyhow::anyhow!("not enough bytes to get the header length"))?,
        )
        .context("reading commit len bytes as string")?
        .parse()
        .context("parsing commit len bytes as a usize")?;
        ensure!(bytes.len() - header_end_marker - 1 >= len);
        let mut byte_cursor = header_end_marker + 1;
        ensure!(
            bytes[byte_cursor..].starts_with(TREE_HEADER_KEYWORD),
            "missing tree header"
        );
        byte_cursor += TREE_HEADER_KEYWORD.len();
        ensure!(
            bytes[byte_cursor] == b' ',
            "missing space after tree header"
        );
        byte_cursor += 1;
        let tree_sha = sha1::hex_decode(
            str::from_utf8(&bytes[byte_cursor..byte_cursor + 40])
                .context("tree sha is not valid UTF-8")?,
        )
        .context("could not decode tree sha")?;
        byte_cursor += 40;
        ensure!(
            bytes[byte_cursor] == b'\n',
            "missing newline after tree sha"
        );
        byte_cursor += 1;
        let mut parents = vec![];
        while bytes[byte_cursor..].starts_with(PARENT_HEADER_KEYWORD) {
            byte_cursor += PARENT_HEADER_KEYWORD.len();
            ensure!(
                bytes[byte_cursor] == b' ',
                "missing space after parent header"
            );
            byte_cursor += 1;
            let parent_sha = sha1::hex_decode(
                str::from_utf8(&bytes[byte_cursor..byte_cursor + 40])
                    .context("parent sha is not valid UTF-8")?,
            )
            .context("could not decode parent sha")?;
            byte_cursor += 40;
            parents.push(parent_sha);
            ensure!(
                bytes[byte_cursor] == b'\n',
                "missing newline after parent sha"
            );
            byte_cursor += 1;
        }

        ensure!(
            bytes[byte_cursor..].starts_with(AUTHOR_HEADER_KEYWORD),
            "missing author header"
        );
        byte_cursor += AUTHOR_HEADER_KEYWORD.len();
        ensure!(
            bytes[byte_cursor] == b' ',
            "missing space after author header"
        );
        byte_cursor += 1;
        let author: AuthorshipInfo = bytes[byte_cursor..]
            .try_into()
            .context("could not parse author")?;
        byte_cursor += bytes[byte_cursor..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(anyhow::anyhow!("missing newline after author"))?;
        byte_cursor += 1;

        ensure!(
            bytes[byte_cursor..].starts_with(COMMITTER_HEADER_KEYWORD),
            "missing committer header"
        );
        byte_cursor += COMMITTER_HEADER_KEYWORD.len();
        ensure!(
            bytes[byte_cursor] == b' ',
            "missing space after committer header"
        );
        byte_cursor += 1;
        let committer: CommiterInfo = bytes[byte_cursor..]
            .try_into()
            .context("could not parse committer")?;
        byte_cursor += bytes[byte_cursor..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(anyhow::anyhow!("missing newline after committer"))?;

        ensure!(
            bytes[byte_cursor] == b'\n',
            "missing newline after committer"
        );
        byte_cursor += 1;

        let mut gpg_signature = None;
        if bytes[byte_cursor..].starts_with(GPG_SIGNATURE_HEADER_KEYWORD) {
            byte_cursor += GPG_SIGNATURE_HEADER_KEYWORD.len();
            ensure!(
                bytes[byte_cursor] == b' ',
                "missing space after parent header"
            );
            byte_cursor += 1;
            let mut end_marker = byte_cursor;
            while bytes
                .get(end_marker..end_marker + 2)
                .ok_or(anyhow::anyhow!("not enough bytes to parse gpg signature"))?
                != b"\n\n"
            {
                end_marker += 1;
            }
            gpg_signature = Some(
                String::from_utf8(bytes[byte_cursor..end_marker].to_vec())
                    .context("gpg signature is not valid UTF-8")?,
            );
            byte_cursor = end_marker + 1;
        }
        ensure!(
            bytes[byte_cursor] == b'\n',
            "missing newline before message"
        );
        byte_cursor += 1;
        let message = str::from_utf8(&bytes[byte_cursor..len + header_end_marker + 1])
            .context("message is not valid UTF-8")?;
        Ok(Self {
            tree: tree_sha,
            parents,
            author,
            committer,
            gpg_signature,
            message: message.to_string(),
        })
    }
}

#[derive(Debug)]
pub enum Object {
    Blob(Blob),
    Tree(Tree),
    Commit(Commit),
}

impl Object {
    pub fn digest(&self) -> sha1::Digest {
        match self {
            Object::Blob(blob) => blob.digest(),
            Object::Tree(tree) => tree.digest(),
            Object::Commit(commit) => commit.digest(),
        }
    }

    pub fn serialize(&self, object_path: Option<&Path>, git_dir_path: &Path) -> anyhow::Result<()> {
        match self {
            Object::Blob(blob) => blob
                .serialize(git_dir_path)
                .context("failed to serialize blob"),
            Object::Tree(tree) => {
                if let Some(object_path) = object_path {
                    tree.serialize_recursively(object_path, git_dir_path)
                        .context("failed to serialize tree recursively")
                } else {
                    tree.serialize(git_dir_path)
                        .context("failed to serialize tree")
                }
            }
            Object::Commit(commit) => commit.serialize(git_dir_path),
        }
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        if path.is_dir() {
            Ok(Self::Tree(Tree::from_path(path)?))
        } else {
            Ok(Self::Blob(Blob::from_path(path)?))
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Object::Blob(blob) => blob.size(),
            Object::Tree(tree) => tree.size(),
            Object::Commit(commit) => commit.size(),
        }
    }

    pub fn header_keyword(&self) -> &'static [u8] {
        match self {
            Object::Blob(_) => BLOB_HEADER_KEYWORD,
            Object::Tree(_) => TREE_HEADER_KEYWORD,
            Object::Commit(_) => COMMIT_HEADER_KEYWORD,
        }
    }
}

impl Deserialize for Object {
    fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.starts_with(BLOB_HEADER_KEYWORD) {
            Blob::deserialize(bytes)
                .map(Self::Blob)
                .context("deserializing blob")
        } else if bytes.starts_with(TREE_HEADER_KEYWORD) {
            Tree::deserialize(bytes)
                .map(Self::Tree)
                .context("deserializing tree")
        } else if bytes.starts_with(COMMIT_HEADER_KEYWORD) {
            Commit::deserialize(bytes)
                .map(Self::Commit)
                .context("deserializing commit")
        } else {
            bail!(
            "wrong header (expected {}, {}, or {})",
            str::from_utf8(BLOB_HEADER_KEYWORD).expect(
                "check the definition of BLOB_HEADER_KEYWORD: should be a UTF8 encoded string"
            ),
            str::from_utf8(TREE_HEADER_KEYWORD).expect(
                "check the definition of TREE_HEADER_KEYWORD: should be a UTF8 encoded string"
            ),
            str::from_utf8(COMMIT_HEADER_KEYWORD).expect(
                "check the definition of COMMIT_HEADER_KEYWORD: should be a UTF8 encoded string"
            )
        );
        }
    }
}

impl HasPayload for Object {
    fn payload(&self) -> Vec<u8> {
        match &self {
            Object::Blob(blob) => blob.payload(),
            Object::Tree(tree) => tree.payload(),
            Object::Commit(commit) => commit.payload(),
        }
    }
}

pub fn init(directory: &str) -> anyhow::Result<()> {
    let git_dir = PathBuf::from_iter([directory, GIT_DIRECTORY_NAME]);

    fs::create_dir(&git_dir).context("creating .git directory")?;
    fs::create_dir(git_dir.join("objects")).context("creating objects directory")?;
    fs::create_dir(git_dir.join("refs")).context("creating refs directory")?;
    fs::create_dir(git_dir.join("refs").join("heads")).context("creating heads directory")?;
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").context("writing to HEAD file")?;
    Ok(())
}

pub fn checkout_empty(
    commit: &str,
    workdir_path: &Path,
    git_dir_path: &Path,
) -> anyhow::Result<()> {
    let commit = Commit::from_sha1_hex(commit, git_dir_path).context(format!(
        "retrieving commit {commit} from the {git_dir_path:?} directory"
    ))?;
    let mut objects_to_checkout =
        VecDeque::from([(hex_encode(&commit.tree), workdir_path.to_owned(), None)]);
    let mut index = Index::new_empty_v2();
    let mut files_to_index = vec![];
    while let Some((sha, path, mode)) = objects_to_checkout.pop_front() {
        match Object::from_sha1_hex(&sha, git_dir_path)
            .context(format!("deserializing object {sha}"))?
        {
            Object::Blob(blob) => {
                let mode = mode.ok_or(anyhow::anyhow!(
                    "blob must have a mode defined for checkout"
                ))?;
                let mut open_options = OpenOptions::new();
                open_options.write(true).create(true);
                match mode {
                    TreeEntryMode::Regular => {}
                    TreeEntryMode::Executable => {
                        open_options.mode(0o755);
                    }
                    TreeEntryMode::SymbolicLink => {
                        symlink(
                            String::from_utf8(blob.bytes.to_vec())
                                .context("converting contents of symbolic link into a string")?,
                            &path,
                        )
                        .context("creating symbolic link")?;
                    }
                    TreeEntryMode::Directory => unreachable!(),
                }
                if !matches!(mode, TreeEntryMode::SymbolicLink) {
                    let mut file = open_options
                        .open(&path)
                        .context(format!("creating file {path:?}"))?;
                    file.write_all(&blob.bytes)
                        .context("writing blob contents to file")?;
                }
                files_to_index.push((
                    sha1::hex_decode(&sha)
                        .context(format!("decoding {sha} into a 20 byte array"))?,
                    path.clone(),
                ));
            }
            Object::Tree(tree) => {
                if !path.exists() {
                    // this literally only trips on the root dir
                    std::fs::create_dir(&path).context(format!("creating directory {path:?}"))?;
                }
                objects_to_checkout.extend(tree.entries.iter().map(|tree_entry| {
                    (
                        hex_encode(&tree_entry.sha1),
                        path.join(&tree_entry.name),
                        Some(tree_entry.mode),
                    )
                }));
            }
            Object::Commit(..) => unreachable!(),
        }
    }

    for (sha, full_path) in files_to_index {
        let relative_path = full_path.strip_prefix(workdir_path).with_context(|| {
            format!("could not strip prefix {workdir_path:?} from {full_path:?}")
        })?;
        index.add_entry(
            IndexEntry::try_from_path_and_id(full_path.as_path(), relative_path, sha)
                .context(format!("creating index entry for {relative_path:?}"))?,
        );
    }
    fs::write(git_dir_path.join("index"), Index::serialize(&mut index))
        .context("writing to index file")?;
    Ok(())
}

impl HasPayload for Index {
    fn payload(&self) -> Vec<u8> {
        let mut ret = vec![];
        ret.extend_from_slice(INDEX_HEADER_SIGNATURE);
        ret.extend_from_slice(&self.version_number.to_be_bytes());
        let n_entries = self.entries.len() as u32;
        ret.extend_from_slice(&n_entries.to_be_bytes());
        let mut entry_base = ret.len();
        for entry in &self.entries {
            ret.extend_from_slice(&(entry.ctime.as_secs() as u32).to_be_bytes());
            ret.extend_from_slice(&entry.ctime.subsec_nanos().to_be_bytes());
            ret.extend_from_slice(&(entry.mtime.as_secs() as u32).to_be_bytes());
            ret.extend_from_slice(&entry.mtime.subsec_nanos().to_be_bytes());
            ret.extend_from_slice(&entry.devnum.to_be_bytes());
            ret.extend_from_slice(&entry.inode_num.to_be_bytes());
            ret.extend_from_slice(
                &((entry.mode.object_type as u32) << 12
                    | if entry.mode.object_type == ObjectType::Regular {
                        if entry.mode.executable {
                            0o755u32
                        } else {
                            0o644u32
                        }
                    } else {
                        0
                    })
                .to_be_bytes(),
            );
            ret.extend_from_slice(&entry.uid.to_be_bytes());
            ret.extend_from_slice(&entry.gid.to_be_bytes());
            ret.extend_from_slice(&entry.file_size.to_be_bytes());
            ret.extend_from_slice(&entry.sha);
            ret.extend_from_slice(
                &(u16::from(entry.flags.assume_valid) << 15
                    | (u16::from(entry.flags.extended) << 14)
                    | (u16::from(entry.stage) << 12)
                    | (entry
                        .flags
                        .path_length
                        .map(|x| x as u16)
                        .unwrap_or(MAXIMUM_PATH_LENGTH))
                        & MAXIMUM_PATH_LENGTH)
                    .to_be_bytes(),
            );
            ret.extend_from_slice(&entry.path);
            ret.push(0x00);
            // Padding
            if (ret.len() - entry_base) % 8 != 0 {
                ret.extend_from_slice(&vec![0; 8 - (ret.len() - entry_base) % 8]);
            }
            entry_base = ret.len();
        }
        ret
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum ObjectType {
    Regular = 0b1000,
    Symlink = 0b1010,
    Gitlink = 0b1110,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectMode {
    object_type: ObjectType,
    executable: bool,
}

impl TryFrom<u32> for ObjectMode {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let object_type = match ((value >> 12) as u8) & OBJECT_TYPE_MASK {
            0b1000 => ObjectType::Regular,
            0b1010 => ObjectType::Symlink,
            0b1110 => ObjectType::Gitlink,
            _ => bail!("unknown object type: {:#06b}", value >> 12),
        };
        let mode = value & ((1 << 9) - 1);
        match (mode, object_type) {
            (0o755 | 0o644, ObjectType::Regular) => Ok(Self {
                object_type,
                executable: mode == 0o755,
            }),
            (0, ObjectType::Symlink | ObjectType::Gitlink) => Ok(Self {
                object_type,
                executable: false,
            }),
            _ => bail!("invalid (mode,object_type) bits combination: {mode:#05o}, {object_type:?}"),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ObjectFlags {
    assume_valid: bool,
    extended: bool,
    stage: u8,
    path_length: Option<usize>,
}

impl From<u16> for ObjectFlags {
    fn from(value: u16) -> Self {
        let assume_valid = value >> 15 == 1;
        let extended = (value >> 14) & 1 == 1;
        let stage = (value >> 12) as u8 & OBJECT_STAGE_MASK;
        let length = value & MAXIMUM_PATH_LENGTH;
        Self {
            assume_valid,
            extended,
            stage,
            path_length: if length != MAXIMUM_PATH_LENGTH {
                Some(length as usize)
            } else {
                None
            },
        }
    }
}

#[derive(Debug)]
pub struct Index {
    version_number: u32,
    entries: Vec<IndexEntry>,
}

impl Index {
    pub fn new_empty_v2() -> Self {
        Self {
            version_number: 2,
            entries: vec![],
        }
    }

    fn add_entry(&mut self, entry: IndexEntry) {
        self.entries.push(entry);
    }

    pub fn serialize(&mut self) -> Vec<u8> {
        if !self.entries.is_sorted() {
            self.entries.sort();
        }
        let mut payload = self.payload();
        payload.extend_from_slice(&sha1::sha1(&payload));
        payload
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexEntry {
    path: Vec<u8>,
    // This field is duplicated here for ordering. The index must have all entries sorted by path,
    // and then by stage
    stage: u8,
    ctime: Duration,
    mtime: Duration,
    devnum: u32,
    inode_num: u32,
    mode: ObjectMode,
    uid: u32,
    gid: u32,
    file_size: u32,
    sha: sha1::Digest,
    flags: ObjectFlags,
    extended_flags: Option<u16>,
}

impl Debug for IndexEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexEntry")
            .field("path", &String::from_utf8_lossy(&self.path))
            .field("stage", &self.stage)
            .field("ctime", &self.ctime)
            .field("mtime", &self.mtime)
            .field("devnum", &self.devnum)
            .field("inode_num", &self.inode_num)
            .field("mode", &self.mode)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("file_size", &self.file_size)
            .field("sha", &hex_encode(&self.sha))
            .field("flags", &self.flags)
            .finish()
    }
}

impl IndexEntry {
    fn try_from_path_and_id(
        full_path: &Path,
        relative_path: &Path,
        sha: sha1::Digest,
    ) -> Result<Self, anyhow::Error> {
        let file_info = fs::symlink_metadata(full_path)
            .context(format!("getting metadata about {full_path:?}"))?;
        Ok(Self {
            path: relative_path.as_os_str().as_bytes().to_vec(),
            stage: 0,
            ctime: Duration::new(file_info.ctime() as u64, file_info.ctime_nsec() as u32),
            mtime: Duration::new(file_info.mtime() as u64, file_info.mtime_nsec() as u32),
            devnum: file_info.dev() as u32,
            inode_num: file_info.st_ino() as u32,
            mode: if file_info.is_file() {
                ObjectMode {
                    object_type: ObjectType::Regular,
                    executable: file_info.mode() & ((1 << 9) - 1) == 0o755,
                }
            } else {
                ObjectMode {
                    object_type: ObjectType::Symlink,
                    executable: false,
                }
            },
            uid: file_info.uid(),
            gid: file_info.gid(),
            file_size: file_info.size() as u32,
            sha,
            flags: ObjectFlags {
                assume_valid: false,
                extended: false,
                stage: 0,
                path_length: Some(relative_path.as_os_str().len()),
            },
            extended_flags: None,
        })
    }
}

impl Deserialize for Index {
    fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut cursor = 0;
        ensure!(
            bytes.get(0..4).context("reading signature bytes")? == INDEX_HEADER_SIGNATURE,
            "wrong header (expected {})",
            str::from_utf8(INDEX_HEADER_SIGNATURE).expect(
                "check the definition of INDEX_HEADER_SIGNATURE: should be a UTF8 encoded string"
            )
        );
        cursor += 4;
        let version_number = u32::from_be_bytes(
            bytes
                .get(cursor..cursor + 4)
                .context("reading version number bytes")?
                .try_into()?,
        );

        ensure!(
            version_number == INDEX_V2,
            "version number {version_number} not supported"
        );

        cursor += 4;
        let n_entries = u32::from_be_bytes(
            bytes
                .get(cursor..cursor + 4)
                .context("reading version number bytes")?
                .try_into()?,
        );
        cursor += 4;

        let mut entries = Vec::new();
        let mut bytes_read_so_far = cursor;
        for _ in 0..n_entries {
            let ctime_sec = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading ctime seconds bytes")?
                    .try_into()?,
            );

            cursor += 4;
            let ctime_nano = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading ctime nano fractions bytes")?
                    .try_into()?,
            );

            cursor += 4;
            let mtime_sec = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading mtime seconds bytes")?
                    .try_into()?,
            );

            cursor += 4;
            let mtime_nano = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading mtime nano fractions bytes")?
                    .try_into()?,
            );

            cursor += 4;
            let devnum = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading device number bytes")?
                    .try_into()?,
            );

            cursor += 4;
            let inode_num = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading inode number bytes")?
                    .try_into()?,
            );

            cursor += 4;
            let mode_bytes = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading mode bytes")?
                    .try_into()?,
            );

            let mode: ObjectMode = mode_bytes.try_into().context("parsing object mode")?;

            cursor += 4;
            let uid = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading uid bytes")?
                    .try_into()?,
            );

            cursor += 4;
            let gid = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading gid bytes")?
                    .try_into()?,
            );

            cursor += 4;
            let file_size = u32::from_be_bytes(
                bytes
                    .get(cursor..cursor + 4)
                    .context("reading size bytes")?
                    .try_into()?,
            );

            cursor += 4;
            let sha: sha1::Digest = bytes
                .get(cursor..cursor + 20)
                .context("reading sha1 bytes")?
                .try_into()?;

            cursor += 20;
            let flags: ObjectFlags = u16::from_be_bytes(
                bytes
                    .get(cursor..cursor + 2)
                    .context("reading version number bytes")?
                    .try_into()?,
            )
            .into();

            ensure!(
                !flags.extended,
                "extended flag must be set to 0 in version 2"
            );
            cursor += 2;

            let path_length = flags.path_length.ok_or(anyhow::anyhow!(
                "File length larger than 0xfff not supported"
            ))?;
            let path = bytes
                .get(cursor..cursor + path_length)
                .context("reading file path bytes")?
                .to_vec();

            cursor += path_length;
            ensure!(bytes[cursor] == 0, "path is not null terminated");
            cursor += 1;

            cursor = bytes_read_so_far + (cursor - bytes_read_so_far).div_ceil(8) * 8;

            bytes_read_so_far = cursor;

            entries.push(IndexEntry {
                path,
                stage: flags.stage,
                ctime: Duration::new(ctime_sec.into(), ctime_nano),
                mtime: Duration::new(mtime_sec.into(), mtime_nano),
                devnum,
                inode_num,
                mode,
                uid,
                gid,
                file_size,
                sha,
                flags,
                extended_flags: None,
            });
        }

        ensure!(entries.is_sorted());

        loop {
            match true {
                _ if bytes[cursor..].starts_with(CACHE_TREE_EXTENSION_SIGNATURE) => {
                    cursor += 4;
                    let ext_size = u32::from_be_bytes(
                        bytes
                            .get(cursor..cursor + 4)
                            .context("reading size bytes")?
                            .try_into()?,
                    );
                    cursor += 4;
                    // We are just skipping the extension bytes
                    cursor += ext_size as usize;
                }
                _ => break,
            }
        }
        let checksum: sha1::Digest = bytes
            .get(cursor..cursor + 20)
            .context("reading checksum bytes")?
            .try_into()?;
        ensure!(sha1::sha1(&bytes[..cursor]) == checksum);

        Ok(Self {
            version_number,
            entries,
        })
    }
}

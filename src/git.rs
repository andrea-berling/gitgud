use std::{
    fs::{self},
    path::Path,
};

const GIT_DIRECTORY_NAME: &str = ".git";
const OBJECTS_DIRECTORY: &str = "objects";
const BLOB_HEADER_KEYWORD: &[u8] = b"blob";
const TREE_HEADER_KEYWORD: &[u8] = b"tree";
const COMMIT_HEADER_KEYWORD: &[u8] = b"commit";
const PARENT_HEADER_KEYWORD: &[u8] = b"parent";
const AUTHOR_HEADER_KEYWORD: &[u8] = b"author";
const COMMITTER_HEADER_KEYWORD: &[u8] = b"committer";

use anyhow::{bail, ensure, Context};
use faccess::PathExt;

use crate::{
    sha1::{self, hex_encode},
    zlib,
};

#[derive(Debug)]
pub struct Blob {
    bytes: Vec<u8>,
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

impl<T: HasPayload> SerializeToGitObject for T {
    fn serialize(&self, git_dir_path: &Path) -> anyhow::Result<()> {
        let payload = self.payload();
        let object_sha = sha1::hex_encode(&sha1::sha1(&payload));
        let dir_name = object_sha.get(0..2).ok_or(anyhow::anyhow!(format!(
            "hex digest {object_sha} too short (less than 2 chars)"
        )))?;
        let object_dir = git_dir_path.join(OBJECTS_DIRECTORY).join(dir_name);
        if !object_dir.as_path().exists() {
            std::fs::create_dir(&object_dir).context(format!(
                "creating dir {:?} for serialization of {object_sha}",
                object_dir.to_str()
            ))?;
        }
        let file_path = object_dir.join(object_sha.get(2..40).ok_or(anyhow::anyhow!(format!(
            "hex digest {object_sha} too short (less than 40 chars)"
        )))?);
        if !file_path.exists() {
            let mut stream = zlib::Stream::new(
                zlib::CompressionMethod::DEFLATE(2 << 7),
                None,
                zlib::CompressionLevel::Lowest,
                payload,
            );
            let compressed_payload = stream
                .deflate()
                .context(format!("compressing payload for {object_sha}",))?;

            std::fs::write(&file_path, compressed_payload).context(format!(
                "writing payload for {object_sha} to {:?}",
                file_path.to_str()
            ))?;
        }
        Ok(())
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
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            bytes: fs::read(path).context(format!("reading from {:?}", path.to_str()))?,
        })
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

#[derive(Debug, Clone)]
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

    pub fn digest(&self) -> sha1::Digest {
        sha1::sha1(&self.payload())
    }

    pub fn serialize(&self, self_path: &Path, git_dir_path: &Path) -> Result<(), anyhow::Error> {
        // Serialize all the entries first
        for entry in &self.entries {
            let object_path = self_path.join(&entry.name);
            Object::from_path(object_path.as_path())
                .context(format!(
                    "making an object out of {:?}",
                    object_path.to_str()
                ))?
                .serialize(&object_path, git_dir_path)
                .context(format!("serializing {}", hex_encode(&entry.sha1)))?;
        }
        let payload = self.payload();
        let object_sha = sha1::hex_encode(&sha1::sha1(&payload));
        let dir_name = object_sha.get(0..2).ok_or(anyhow::anyhow!(format!(
            "hex digest {object_sha} too short (less than 2 chars)"
        )))?;
        let object_dir = git_dir_path.join(OBJECTS_DIRECTORY).join(dir_name);
        if !object_dir.as_path().exists() {
            std::fs::create_dir(&object_dir).context(format!(
                "creating dir {:?} for serialization of {object_sha}",
                object_dir.to_str()
            ))?;
        }
        let file_path = object_dir.join(object_sha.get(2..40).ok_or(anyhow::anyhow!(format!(
            "hex digest {object_sha} too short (less than 40 chars)"
        )))?);
        if !file_path.exists() {
            let mut stream = zlib::Stream::new(
                zlib::CompressionMethod::DEFLATE(2 << 7),
                None,
                zlib::CompressionLevel::Lowest,
                payload,
            );
            let compressed_payload = stream
                .deflate()
                .context(format!("compressing payload for {object_sha}",))?;

            std::fs::write(&file_path, compressed_payload).context(format!(
                "writing payload for {object_sha} to {:?}",
                file_path.to_str()
            ))?;
        }
        Ok(())
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

#[derive(Debug)]
pub struct Commit {
    tree: sha1::Digest,
    parents: Vec<sha1::Digest>,
    author: String,
    committer: String,
    message: String,
}

impl Commit {
    pub fn new(tree: sha1::Digest, parents: Vec<sha1::Digest>, message: String) -> Self {
        Self {
            tree,
            parents,
            author: "Nobody".into(),
            committer: "Nobody".into(),
            message,
        }
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
        payload.extend(self.author.bytes());
        payload.push(b' ');
        payload.push(b'0');
        payload.push(b' ');
        payload.extend(b"+0200");
        payload.push(b'\n');
        payload.extend(COMMITTER_HEADER_KEYWORD);
        payload.push(b' ');
        payload.extend(self.committer.bytes());
        payload.push(b' ');
        payload.push(b'0');
        payload.push(b' ');
        payload.extend(b"+0200");
        payload.push(b'\n');
        payload.push(b'\n');
        payload.extend(self.message.bytes());
        payload.push(b'\n');

        object_bytes.extend(payload.len().to_string().as_bytes());
        object_bytes.push(b'\x00');
        object_bytes.append(&mut payload);
        object_bytes
    }
}

#[derive(Debug)]
pub enum Object {
    Blob(Blob),
    Tree(Tree),
    Commit(Commit),
}

impl Object {
    fn digest(&self) -> sha1::Digest {
        match self {
            Object::Blob(blob) => blob.digest(),
            Object::Tree(tree) => tree.digest(),
            Object::Commit(commit) => commit.digest(),
        }
    }

    fn serialize(&self, object_path: &Path, git_dir_path: &Path) -> anyhow::Result<()> {
        match self {
            Object::Blob(blob) => blob.serialize(git_dir_path),
            Object::Tree(tree) => tree.serialize(object_path, git_dir_path),
            Object::Commit(commit) => commit.serialize(git_dir_path),
        }
    }

    fn from_path(path: &Path) -> anyhow::Result<Self> {
        if path.is_dir() {
            Ok(Self::Tree(Tree::from_path(path)?))
        } else {
            Ok(Self::Blob(Blob::from_path(path)?))
        }
    }
}

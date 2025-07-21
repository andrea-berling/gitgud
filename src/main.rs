use std::fs;
use std::io::stdout;
use std::io::Write;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use anyhow::Ok;
use clap::{Parser, Subcommand};

mod git;
mod sha1;
mod zlib;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize a new git repository
    Init,
    /// Provide content or type and size information for repository objects
    CatFile {
        /// Pretty-print the contents of <object> based on its type
        #[arg(short = 'p')]
        pretty_print: bool,
        /// The object to display
        object: String,
    },
    /// Compute object ID and optionally creates a blob from a file
    HashObject {
        /// Write the new object into the object database
        #[arg(short = 'w')]
        write: bool,
        /// Read object from <file>
        file: String,
    },
    /// List the contents of a tree object
    LsTree {
        /// Show only filenames, not the mode, object type, and SHA-1 of the object.
        #[arg(long = "name-only")]
        name_only: bool,
        /// The tree object to list
        tree_sha: String,
    },
    /// Print zlib metadata from a file
    ZlibMetadata {
        /// The file to read
        file: String,
    },
    /// Inflate a zlib compressed file
    ZlibInflate {
        /// The file to inflate
        file: String,
    },
}

fn main() -> anyhow::Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.

    // Uncomment this block to pass the first stage
    let cli = Cli::parse();

    match &cli.command {
        Command::Init => {
            fs::create_dir(".git").unwrap();
            fs::create_dir(".git/objects").unwrap();
            fs::create_dir(".git/refs").unwrap();
            fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
            println!("Initialized git directory");
            Ok(())
        }
        Command::CatFile {
            pretty_print,
            object,
        } => {
            if !pretty_print {
                bail!("cat-file currently only supports the -p option");
            }
            let object_sha = object;
            let file_bytes = fs::read(PathBuf::from_iter([
                ".git",
                "objects",
                &object_sha[..2],
                &object_sha[2..],
            ]))
            .context(format!("reading from object file for {object_sha}"))?;
            let mut stream = zlib::Stream::try_from(file_bytes.as_slice())
                .context(format!("decompressing object file for {object_sha}",))?;
            let object_bytes = stream
                .inflate()
                .context(format!("decompressing object file for {object_sha}",))?;
            let blob: git::Blob = object_bytes
                .try_into()
                .context("interpreting object bytes as a blob")?;
            stdout().write_all(blob.bytes())?;
            stdout().flush()?;
            Ok(())
        }
        Command::HashObject { write, file } => {
            if !write {
                bail!("hash-object currently only supports the -w option");
            }
            let object_filename = file;
            let blob_payload =
                fs::read(object_filename).context(format!("reading from {object_filename}"))?;
            let object_bytes = [
                b"blob ",
                blob_payload.len().to_string().as_bytes(),
                b"\x00",
                &blob_payload,
            ]
            .concat();
            let object_sha = sha1::hex_encode(&sha1::sha1(&object_bytes));

            let mut stream = zlib::Stream::new(
                zlib::CompressionMethod::DEFLATE(2 << 7),
                None,
                zlib::CompressionLevel::Lowest,
                object_bytes,
            );
            let object_bytes = stream
                .deflate()
                .context(format!("decompressing object file for {object_filename}",))?;

            let dir_path = PathBuf::from_iter([".git", "objects", &object_sha[..2]]);
            if !fs::exists(&dir_path)? {
                fs::create_dir(&dir_path)?;
            }
            fs::write(dir_path.join(&object_sha[2..]), object_bytes)
                .context(format!("writing into object file for {object_sha}"))?;
            println!("{object_sha}");
            Ok(())
        }
        Command::LsTree {
            name_only,
            tree_sha,
        } => {
            if !name_only {
                bail!("ls-tree currently only supports the --name-only option");
            }
            let file_bytes = fs::read(PathBuf::from_iter([
                ".git",
                "objects",
                &tree_sha[..2],
                &tree_sha[2..],
            ]))
            .context(format!("reading from object file for {tree_sha}"))?;
            let mut stream = zlib::Stream::try_from(file_bytes.as_slice())
                .context(format!("decompressing object file for {tree_sha}",))?;
            let tree_bytes = stream
                .inflate()
                .context(format!("decompressing object file for {tree_sha}",))?;
            let tree: git::Tree = tree_bytes
                .try_into()
                .context("interpreting object bytes as a tree")?;
            for entry in tree.entries() {
                println!("{}", entry.name());
            }
            Ok(())
        }
        Command::ZlibMetadata { file } => {
            let bytes = fs::read(file).context(format!("reading from {}", file))?;
            let stream: zlib::Stream =
                bytes.as_slice().try_into().context("decoding read bytes")?;
            print!("{stream}");
            Ok(())
        }
        Command::ZlibInflate { file } => {
            let bytes = fs::read(file).context(format!("reading from {}", file))?;
            let mut stream: zlib::Stream =
                bytes.as_slice().try_into().context("decoding read bytes")?;
            stdout().write_all(stream.inflate()?)?;
            stdout().flush()?;
            Ok(())
        }
    }
}

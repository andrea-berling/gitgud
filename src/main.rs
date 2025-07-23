use std::fs;
use std::io::stdout;
use std::io::Write;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use anyhow::Ok;
use clap::{Parser, Subcommand};
use git::FromSha1Hex;
use git::HasPayload;
use git::SerializeToGitObject;
use pack_objects::PackedObjectsStream;
use sha1::hex_encode;

mod git;
mod pack_objects;
mod pkt_line;
mod sha1;
mod sideband;
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
        object_sha: String,
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
    /// Write the current working directory to a new tree object
    WriteTree,
    /// Write the given tree into a new commit object using the given message and optional parent
    /// commit
    CommitTree {
        /// The tree object to use as the commit root
        tree_sha: String,
        /// The parent commit
        #[arg(short = 'p')]
        parent: Option<String>,
        /// The commit message
        #[arg(short = 'm')]
        message: String,
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
    /// List the objects in a packfile
    ListPack {
        /// The pack file to list
        file: String,
    },
}

fn main() -> anyhow::Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.

    // Uncomment this block to pass the first stage
    let cli = Cli::parse();

    let git_dir = PathBuf::from(git::GIT_DIRECTORY_NAME);

    match &cli.command {
        Command::Init => {
            fs::create_dir(&git_dir).context("creating .git directory")?;
            fs::create_dir(git_dir.join("objects")).context("creating objects directory")?;
            fs::create_dir(git_dir.join("refs")).context("creating refs directory")?;
            fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n")
                .context("writing to HEAD file")?;
            println!("Initialized git directory");
            Ok(())
        }
        Command::CatFile {
            pretty_print,
            object_sha: object,
        } => {
            if !pretty_print {
                bail!("cat-file currently only supports the -p option");
            }
            let blob = git::Blob::from_sha1_hex(object, &git_dir)
                .context(format!("making a blob from {object}"))?;
            stdout().write_all(blob.bytes())?;
            stdout().flush()?;
            Ok(())
        }
        Command::HashObject { write, file } => {
            if !write {
                bail!("hash-object currently only supports the -w option");
            }
            let blob = git::Blob::from_path(&PathBuf::from(&file))
                .context(format!("making a blob from {file}"))?;
            blob.serialize(&git_dir)
                .context(format!("serializing {file} into the git database"))?;
            println!("{}", sha1::hex_encode(&blob.digest()));
            Ok(())
        }
        Command::LsTree {
            name_only,
            tree_sha,
        } => {
            if !name_only {
                bail!("ls-tree currently only supports the --name-only option");
            }

            let tree = git::Tree::from_sha1_hex(tree_sha, &git_dir)
                .context(format!("fetching tree for {tree_sha}"))?;
            for entry in tree.entries() {
                println!("{}", entry.name());
            }
            Ok(())
        }
        Command::ZlibMetadata { file } => {
            let bytes = fs::read(file).context(format!("reading from {file}",))?;
            let stream: zlib::Stream =
                bytes.as_slice().try_into().context("decoding read bytes")?;
            print!("{stream}");
            Ok(())
        }
        Command::ZlibInflate { file } => {
            let bytes = fs::read(file).context(format!("reading from {file}",))?;
            let mut stream: zlib::Stream =
                bytes.as_slice().try_into().context("decoding read bytes")?;
            stdout().write_all(stream.inflate()?)?;
            stdout().flush()?;
            Ok(())
        }
        Command::WriteTree => {
            let cwd = &PathBuf::from(".");
            let tree = git::Tree::from_path(cwd)
                .context("making a tree object from the current directory")?;
            tree.serialize(cwd, &git_dir)
                .context("serializing tree for current directory")?;
            println!("{}", sha1::hex_encode(&tree.digest()));
            Ok(())
        }
        Command::CommitTree {
            tree_sha,
            parent,
            message,
        } => {
            let commit_object = git::Commit::new_no_author_no_committer(
                sha1::hex_decode(tree_sha)
                    .context(format!("decoding {tree_sha} into a SHA1 digest"))?,
                if let Some(parent) = parent {
                    vec![sha1::hex_decode(parent)
                        .context(format!("decoding {parent} into a SHA1 digest"))?]
                } else {
                    vec![]
                },
                message.clone(),
            );
            let digest = hex_encode(&commit_object.digest());
            commit_object
                .serialize(&git_dir)
                .context(format!("serializing commit object {digest}",))?;
            println!("{digest}");
            Ok(())
        }
        Command::ListPack { file } => {
            let bytes = std::fs::read(file).context("reading pack file")?;
            let mut object_stream: PackedObjectsStream = bytes[8..].try_into().context("parsing pack file")?;
            for object in &mut object_stream {
                println!("{object:#?}");
            }
            Ok(())
        }
    }
}

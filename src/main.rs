use std::fs;
use std::io::stdout;
use std::io::Write;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use clap::{Parser, Subcommand};
use git::Deserialize as _;
use git::FromSha1Hex;
use git::HasPayload;
use git::SerializeToGitObject;
use pack_objects::PackedObjectsStream;
use sha1::hex_encode;

mod git;
mod http;
mod pack_objects;
mod pkt_line;
mod sha1;
mod sideband;
mod smart_http;
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
    /// Clone a repository to the given directory
    Clone {
        /// HTTP(S) url to the repo
        repo_url: String,
        /// The directory to clone the repo to
        directory: Option<String>,
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
    /// Deflate a file into a zlib stream
    ZlibDeflate {
        /// The file to deflate
        file: String,
        #[arg(short = 'l')]
        level: Option<zlib::CompressionLevel>,
    },
    /// List the objects in a packfile
    ListPack {
        /// The pack file to list
        file: String,
    },
    /// Unpack objects from a packfile
    UnpackObjects {
        /// The pack file to unpack
        file: String,
    },
    /// Parse the index file, re-serialize it and print it back to stdout. It will ignore any
    /// extensions and will only work with index version 2
    PrintIndex {
        /// Print a pretty version of the existing index. It will include a list of all entries
        /// with their attributes as rust structs, but will skip over the extensions.
        #[arg(short = 'p')]
        pretty: bool,
    },
}

fn main() -> anyhow::Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.

    // Uncomment this block to pass the first stage
    let cli = Cli::parse();

    let git_dir = PathBuf::from(git::GIT_DIRECTORY_NAME);

    match cli.command {
        Command::Init => {
            git::init(".").context("initializing the current directory as a repository")?;
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
            let blob = git::Blob::from_sha1_hex(&object, &git_dir)
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

            let tree = git::Tree::from_sha1_hex(&tree_sha, &git_dir)
                .context(format!("fetching tree for {tree_sha}"))?;
            for entry in tree.entries() {
                println!("{}", entry.name());
            }
            Ok(())
        }
        Command::ZlibMetadata { file } => {
            let bytes = fs::read(&file).context(format!("reading from {file}",))?;
            let stream: zlib::Stream =
                bytes.as_slice().try_into().context("decoding read bytes")?;
            print!("{stream}");
            Ok(())
        }
        Command::ZlibInflate { file } => {
            let bytes = fs::read(&file).context(format!("reading from {file}",))?;
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
            tree.serialize_recursively(cwd, &git_dir)
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
                sha1::hex_decode(&tree_sha)
                    .context(format!("decoding {tree_sha} into a SHA1 digest"))?,
                if let Some(parent) = parent {
                    vec![sha1::hex_decode(&parent)
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
            let mut object_stream: PackedObjectsStream =
                bytes.as_slice().try_into().context("parsing pack file")?;
            for object in &mut object_stream {
                println!("{:#?}", object.context("checking the unpacked object")?);
            }
            Ok(())
        }
        Command::UnpackObjects { file } => {
            let bytes = std::fs::read(file).context("reading pack file")?;
            let mut object_stream: PackedObjectsStream =
                bytes.as_slice().try_into().context("parsing pack file")?;
            object_stream
                .unpack_all(&git_dir)
                .context(format!("unpacking all objects into {git_dir:?}"))
        }
        Command::ZlibDeflate { file, level } => {
            let mut stream = zlib::Stream::new(
                zlib::CompressionMethod::DEFLATE(2 << 7),
                None,
                level.unwrap_or(zlib::CompressionLevel::Lowest),
                std::fs::read(&file).context(format!("reading file {file}",))?,
            );
            stdout().write_all(stream.deflate().context("deflating stream")?)?;
            stdout().flush().context("flushing stdout")
        }
        Command::Clone {
            repo_url,
            directory,
        } => {
            let directory = directory.unwrap_or({
                let mut components_it = repo_url.rsplit("/");
                let Some(component) = components_it.next() else {
                    bail!("URL is malformed: couldn't extract a directory name from it");
                };
                component
                    .strip_suffix(".git")
                    .unwrap_or(component)
                    .to_string()
            });
            let mut smart_http_client = smart_http::Client::new_from_url(&repo_url)
                .context("making a smart HTTP client form the given URL")?;
            let refs_info = smart_http_client
                .fetch_refs_info()
                .context("fetching information about refs from the repo URL")?;
            let head_ref_packfile = smart_http_client
                .fetch_ref_packfile(refs_info.head_sha())
                .context("fetching the packfile for the repository head from the repo URL")?;
            std::fs::create_dir(&directory).context("creating the repo directory")?;
            git::init(&directory).context("initilaizing the repo directory")?;

            let mut object_stream: PackedObjectsStream = head_ref_packfile
                .as_slice()
                .try_into()
                .context("parsing pack file")?;

            let git_dir = PathBuf::from_iter([directory.clone(), ".git".to_string()]);

            object_stream
                .unpack_all(&git_dir)
                .context(format!("unpacking all objects to {git_dir:?}"))?;

            fs::write(
                git_dir.join("HEAD"),
                format!("ref: {}\n", refs_info.head_ref()),
            )
            .context("writing to HEAD file")?;
            let ref_name = refs_info
                .head_ref()
                .rsplit("/")
                .next()
                .ok_or(anyhow::anyhow!(
                    "the ref name must be a / separated string (e.g. refs/heads/master)"
                ))?;
            fs::write(
                git_dir.join("HEAD"),
                format!("ref: {}\n", refs_info.head_ref()),
            )
            .context("writing to HEAD file")?;
            fs::write(
                git_dir.join("refs").join("heads").join(ref_name),
                refs_info.head_sha(),
            )
            .context(format!("creating ref file for {ref_name}"))?;

            let remotes_path = git_dir.join("refs/remotes/origin");
            std::fs::create_dir_all(&remotes_path).context("creating the remotes directory")?;
            std::fs::write(remotes_path.join(ref_name), refs_info.head_sha())
                .context(format!("creating remote ref file for {ref_name}"))?;
            fs::write(
                remotes_path.join("HEAD"),
                format!("ref: refs/remotes/heads/{ref_name}\n"),
            )
            .context("writing to remote HEAD file")?;

            fs::write(
                git_dir.join("config"),
                format!(
                    r#"[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = {repo_url}
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "{ref_name}"]
        remote = origin
        merge = refs/heads/{ref_name}"#
                ),
            )
            .context("writing git config file")?;

            git::checkout_empty(refs_info.head_sha(), &PathBuf::from(directory), &git_dir)
                .context(format!(
                    "checking out commit {} in empty repository",
                    refs_info.head_sha()
                ))?;
            Ok(())
        }
        Command::PrintIndex { pretty } => {
            let mut index: git::Index = git::Index::deserialize(
                &std::fs::read(git_dir.join("index")).context("reading from the index file")?,
            )
            .context("parsing bytes into index")?;
            if pretty {
                println!("{index:#?}");
            } else {
                stdout().write_all(&git::Index::serialize(&mut index))?;
                stdout().write_all(&git::Index::serialize(&mut index))?;
                stdout().flush()?;
                stdout().flush()?;
            }
            Ok(())
        }
    }
}

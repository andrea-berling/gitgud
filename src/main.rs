use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod commands;
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
        Command::Init => commands::init(),
        Command::CatFile {
            pretty_print,
            object_sha,
        } => commands::cat_file(pretty_print, &object_sha, &git_dir),
        Command::HashObject { write, file } => commands::hash_object(write, &file, &git_dir),
        Command::LsTree {
            name_only,
            tree_sha,
        } => commands::ls_tree(name_only, &tree_sha, &git_dir),
        Command::ZlibMetadata { file } => commands::zlib_metadata(&file),
        Command::ZlibInflate { file } => commands::zlib_inflate(&file),
        Command::WriteTree => commands::write_tree(&git_dir),
        Command::CommitTree {
            tree_sha,
            parent,
            message,
        } => commands::commit_tree(&tree_sha, parent, message, &git_dir),
        Command::ListPack { file } => commands::list_pack(&file),
        Command::UnpackObjects { file } => commands::unpack_objects(&file, &git_dir),
        Command::ZlibDeflate { file, level } => commands::zlib_deflate(&file, level),
        Command::Clone {
            repo_url,
            directory,
        } => commands::clone(&repo_url, directory),
        Command::PrintIndex { pretty } => commands::print_index(pretty, &git_dir),
    }
}

use std::env;
use std::fs;
use std::io::stdout;
use std::io::Write;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Ok;

mod git;
mod sha1;
mod zlib;

fn main() -> anyhow::Result<()> {
    // You can use print statements as follows for debugging, they'll be visible when running tests.

    // Uncomment this block to pass the first stage
    let args: Vec<String> = env::args().collect();
    match args[1].as_str() {
        "init" => {
            fs::create_dir(".git").unwrap();
            fs::create_dir(".git/objects").unwrap();
            fs::create_dir(".git/refs").unwrap();
            fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
            println!("Initialized git directory");
            Ok(())
        }
        "cat-file" => {
            ensure!(args[2] == "-p");
            let object_sha = &args[3];
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
        "hash-object" => {
            ensure!(args[2] == "-w");
            let object_filename = &args[3];
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
        "ls-tree" => {
            ensure!(args[2] == "--name-only");
            let tree_sha = &args[3];
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
        "zlib_metadata" => {
            let bytes = fs::read(&args[2]).context(format!("reading from {}", &args[2]))?;
            let stream: zlib::Stream =
                bytes.as_slice().try_into().context("decoding read bytes")?;
            print!("{stream}");
            Ok(())
        }
        "zlib_inflate" => {
            let bytes = fs::read(&args[2]).context(format!("reading from {}", &args[2]))?;
            let mut stream: zlib::Stream =
                bytes.as_slice().try_into().context("decoding read bytes")?;
            stdout().write_all(stream.inflate()?)?;
            stdout().flush()?;
            Ok(())
        }
        _ => {
            bail!("unknown command: {}", args[1])
        }
    }
}

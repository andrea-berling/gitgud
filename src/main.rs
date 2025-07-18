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
            let object_bytes: Vec<u8> = zlib::Stream::try_from(file_bytes.as_slice())
                .context(format!("decompressing object file for {object_sha}",))?
                .inflate()
                .context(format!("decompressing object file for {object_sha}",))?;
            let blob: git::Blob = object_bytes
                .as_slice()
                .try_into()
                .context("interpreting object bytes as a blob")?;
            stdout().write_all(blob.bytes())?;
            stdout().flush()?;
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
            let stream: zlib::Stream =
                bytes.as_slice().try_into().context("decoding read bytes")?;
            stdout().write_all(&stream.inflate()?)?;
            stdout().flush()?;
            Ok(())
        }
        _ => {
            bail!("unknown command: {}", args[1])
        }
    }
}

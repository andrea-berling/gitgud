use std::env;
use std::fs;
use std::io::stdout;
use std::io::Write;

use anyhow::bail;
use anyhow::Context;
use anyhow::Ok;

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

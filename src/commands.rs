use std::{
    fs,
    io::{stdout, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context};

use crate::{
    git::{self, Deserialize, FromSha1Hex, HasPayload, SerializeToGitObject},
    pack_objects::PackedObjectsStream,
    sha1, smart_http, zlib,
};

pub fn init() -> anyhow::Result<()> {
    git::init(".").context("initializing the current directory as a repository")?;
    println!("Initialized git directory");
    Ok(())
}

pub fn cat_file(pretty_print: bool, object_sha: &str, git_dir: &Path) -> anyhow::Result<()> {
    if !pretty_print {
        bail!("cat-file currently only supports the -p option");
    }
    let blob = git::Blob::from_sha1_hex(object_sha, git_dir)
        .context(format!("making a blob from {object_sha}"))?;
    stdout().write_all(blob.bytes())?;
    stdout().flush()?;
    Ok(())
}

pub fn hash_object(write: bool, file: &str, git_dir: &Path) -> anyhow::Result<()> {
    if !write {
        bail!("hash-object currently only supports the -w option");
    }
    let blob =
        git::Blob::from_path(&PathBuf::from(file)).context(format!("making a blob from {file}"))?;
    blob.serialize(git_dir)
        .context(format!("serializing {file} into the git database"))?;
    println!("{}", sha1::hex_encode(&blob.digest()));
    Ok(())
}

pub fn ls_tree(name_only: bool, tree_sha: &str, git_dir: &Path) -> anyhow::Result<()> {
    if !name_only {
        bail!("ls-tree currently only supports the --name-only option");
    }

    let tree = git::Tree::from_sha1_hex(tree_sha, git_dir)
        .context(format!("fetching tree for {tree_sha}"))?;
    for entry in tree.entries() {
        println!("{}", entry.name());
    }
    Ok(())
}

pub fn write_tree(git_dir: &Path) -> anyhow::Result<()> {
    let cwd = &PathBuf::from(".");
    let tree =
        git::Tree::from_path(cwd).context("making a tree object from the current directory")?;
    tree.serialize_recursively(cwd, git_dir)
        .context("serializing tree for current directory")?;
    println!("{}", sha1::hex_encode(&tree.digest()));
    Ok(())
}

pub fn commit_tree(
    tree_sha: &str,
    parent: Option<String>,
    message: String,
    git_dir: &Path,
) -> anyhow::Result<()> {
    let commit_object = git::Commit::new_no_author_no_committer(
        sha1::hex_decode(tree_sha).context(format!("decoding {tree_sha} into a SHA1 digest"))?,
        if let Some(parent) = parent {
            vec![sha1::hex_decode(&parent)
                .context(format!("decoding {parent} into a SHA1 digest"))?]
        } else {
            vec![]
        },
        message,
    );
    let digest = sha1::hex_encode(&commit_object.digest());
    commit_object
        .serialize(git_dir)
        .context(format!("serializing commit object {digest}",))?;
    println!("{digest}");
    Ok(())
}

pub fn clone(repo_url: &str, directory: Option<String>) -> anyhow::Result<()> {
    let directory = directory.unwrap_or({
        let mut components_it = repo_url.rsplit('/');
        let Some(component) = components_it.next() else {
            bail!("URL is malformed: couldn't extract a directory name from it");
        };
        component
            .strip_suffix(".git")
            .unwrap_or(component)
            .to_string()
    });
    let mut smart_http_client = smart_http::Client::new_from_url(repo_url)
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
        .rsplit('/')
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
        format!("ref: refs/remotes/heads/{ref_name}\n",),
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

    git::checkout_empty(refs_info.head_sha(), &PathBuf::from(directory), &git_dir).context(
        format!(
            "checking out commit {} in empty repository",
            refs_info.head_sha()
        ),
    )?;
    Ok(())
}

pub fn zlib_metadata(file: &str) -> anyhow::Result<()> {
    let bytes = fs::read(file).context(format!("reading from {file}",))?;
    let stream: zlib::Stream = bytes.as_slice().try_into().context("decoding read bytes")?;
    print!("{stream}");
    Ok(())
}

pub fn zlib_inflate(file: &str) -> anyhow::Result<()> {
    let bytes = fs::read(file).context(format!("reading from {file}",))?;
    let mut stream: zlib::Stream = bytes.as_slice().try_into().context("decoding read bytes")?;
    stdout().write_all(stream.inflate()?)?;
    stdout().flush()?;
    Ok(())
}

pub fn zlib_deflate(file: &str, level: Option<zlib::CompressionLevel>) -> anyhow::Result<()> {
    let mut stream = zlib::Stream::new(
        zlib::CompressionMethod::DEFLATE(2 << 7),
        None,
        level.unwrap_or(zlib::CompressionLevel::Lowest),
        std::fs::read(file).context(format!("reading file {file}",))?,
    );
    stdout().write_all(stream.deflate().context("deflating stream")?)?;
    stdout().flush().context("flushing stdout")
}

pub fn list_pack(file: &str) -> anyhow::Result<()> {
    let bytes = std::fs::read(file).context("reading pack file")?;
    let mut object_stream: PackedObjectsStream =
        bytes.as_slice().try_into().context("parsing pack file")?;
    for object in &mut object_stream {
        println!("{:#?}", object.context("checking the unpacked object")?);
    }
    Ok(())
}

pub fn unpack_objects(file: &str, git_dir: &Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(file).context("reading pack file")?;
    let mut object_stream: PackedObjectsStream =
        bytes.as_slice().try_into().context("parsing pack file")?;
    object_stream
        .unpack_all(git_dir)
        .context(format!("unpacking all objects into {git_dir:?}"))
}

pub fn print_index(pretty: bool, git_dir: &Path) -> anyhow::Result<()> {
    let mut index: git::Index = git::Index::deserialize(
        &std::fs::read(git_dir.join("index")).context("reading from the index file")?,
    )
    .context("parsing bytes into index")?;
    if pretty {
        println!("{index:#?}");
    } else {
        stdout().write_all(&git::Index::serialize(&mut index))?;
        stdout().flush()?;
    }
    Ok(())
}

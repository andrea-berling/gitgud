# gitgud: A Git Implementation in Rust

`gitgud` is a simple, educational implementation of Git written in Rust. It provides a command-line interface to perform basic Git operations, including initializing repositories, creating and inspecting objects, and cloning remote repositories. This project was built as part of the CodeCrafters ["Build your own Git" challenge](https://app.codecrafters.io/courses/git/overview).

An noteworthy feature of this project is that it's very light on third-party dependencies: only clap for argument parsing, anyhow for error handling, faccess to check if a file is executable, and rustls with webpki-roots for TLS. This project contains a RFC 1950 and RFC 1951 compliant implementation of the zlib and DEFLATE file formats, built from scratch with full support for decompression and some minimal support for compression. It also has its own FIPS-180.4 compliant implementation of the SHA1 algorithm, as well as a custom HTTP(s) client that can deal with chunked transfer encoding.

## Features

*   **Initialize Repositories:** Create a new Git repository in the current directory.
*   **Object Management:** Create, inspect, and manage Git objects (blobs, trees, and commits).
*   **Tree Manipulation:** List the contents of tree objects and create new tree objects from the current directory.
*   **Committing:** Create new commit objects with a given tree and parent commit.
*   **Cloning:** Clone remote repositories over HTTP.
*   **Packfile Handling:** List and unpack objects from packfiles.
*   **Zlib Support:** Inflate and deflate files using zlib compression.

## Getting Started

### Prerequisites

To build and run this project, you need to have the Rust toolchain installed. You can install it from [rustup.rs](https://rustup.rs/).

### Build

1.  Clone the repository:
    ```sh
    git clone https://github.com/your-username/gitgud
    cd gitgud
    ```

2.  Build the project in release mode:
    ```sh
    cargo build --release
    ```

The final executable will be located at `target/release/gitgud`.

## Usage

The CLI is structured with several subcommands to handle different tasks.

```sh
gitgud <COMMAND>
```

### Commands

*   `init`
    *   Initializes a new Git repository in the current directory.

*   `cat-file -p <OBJECT_SHA>`
    *   Pretty-prints the contents of a Git object.

*   `hash-object -w <FILE>`
    *   Computes the object ID of a file and writes it to the object database.

*   `ls-tree --name-only <TREE_SHA>`
    *   Lists the contents of a tree object.

*   `write-tree`
    *   Creates a new tree object from the current working directory.

*   `commit-tree <TREE_SHA> -p <PARENT_SHA> -m <MESSAGE>`
    *   Creates a new commit object.

*   `clone <REPO_URL> [DIRECTORY]`
    *   Clones a remote repository over HTTPs into a new directory.

*   `list-pack <PACK_FILE>`
    *   Lists the objects in a packfile.

*   `unpack-objects <PACK_FILE>`
    *   Unpacks objects from a packfile.

*   `zlib-metadata <FILE>`
    *   Prints zlib metadata from a file.

*   `zlib-inflate <FILE>`
    *   Inflates a zlib compressed file.

*   `zlib-deflate <FILE>`
    *   Deflates a file into a zlib stream.

## Examples

### `init`

Initializes a new Git repository.

```sh
$ mkdir new_repository && cd new_repository
$ gitgud init
Initialized git directory
$ git status
On branch main

No commits yet

nothing to commit (create/copy files and use "git add" to track)
```

### `hash-object`

Hashes a file and writes it to the object database.

```sh
$ echo "hello world" > hello.txt
$ gitgud hash-object -w hello.txt
3b18e512dba79e4c8300dd08aeb37f8e728b8dad
```

### `cat-file`

Pretty-prints the contents of an object.

```sh
$ gitgud cat-file -p 3b18e512dba79e4c8300dd08aeb37f8e728b8dad
hello world
```

### `write-tree`

Creates a new tree object from the current directory.

```sh
$ gitgud write-tree
68aba62e560c0ebc3396e8ae9335232cd93a3f60
```

### `ls-tree`

Lists the contents of a tree object.

```sh
$ gitgud ls-tree --name-only 68aba62e560c0ebc3396e8ae9335232cd93a3f60
hello.txt
```

### `commit-tree`

Creates a new commit object.

```sh
$ gitgud commit-tree 68aba62e560c0ebc3396e8ae9335232cd93a3f60 -m "Initial commit"
0679447453dbaa46def88a0686490b3a7065894e
$ git cat-file -p 0679447453dbaa46def88a0686490b3a7065894e
tree 68aba62e560c0ebc3396e8ae9335232cd93a3f60
author Nobody <nobody@nowhere.nil> 1754039029 +0000
committer Nobody <nobody@nowhere.nil> 1754039029 +0000

Initial commit
```

### `clone`

Clones a remote repository over HTTPs.

```sh
$ gitgud clone https://github.com/andrea-berling/gitgud
$ cd gitgud
$ tree
.
├── Cargo.lock
├── Cargo.toml
├── codecrafters.yml
├── LICENSE
├── README.md
├── src
│   ├── commands.rs
│   ├── git.rs
│   ├── http.rs
│   ├── main.rs
│   ├── pack_objects.rs
│   ├── pkt_line.rs
│   ├── sha1.rs
│   ├── sideband.rs
│   ├── smart_http.rs
│   └── zlib.rs
└── your_program.sh

2 directories, 16 files
$ git status
On branch master
Your branch is up to date with 'origin/master'.

nothing to commit, working tree clean
$ git -P log -n 3 --pretty=short 7cd604c4647451a8ec3437784b2292d5fed7983d
commit 7cd604c4647451a8ec3437784b2292d5fed7983d
Author: Andrea Berlingieri <andrea-berling@users.noreply.github.com>

    Refactor: Improve code structure and clarity

commit 4d924c1d077110b73e86340542d7ea501313d40c
Author: Andrea Berlingieri <andrea-berling@users.noreply.github.com>

    feat(clone): Generate index and configure remote tracking

commit 05f7aa5dd67d5e93bf70b6f6afaec627b695f391
Author: Andrea Berlingieri <andrea-berling@users.noreply.github.com>

    Fix: Correct commit object parsing for GPG signatures

```

## License

This project is licensed under the MIT License.

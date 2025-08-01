use std::{
    collections::HashMap,
    io::{BufRead, Write},
};

use anyhow::{bail, ensure, Context};

use crate::{
    http,
    pkt_line::{self, PktLines},
};

#[derive(Debug)]
pub struct RefsInfo {
    head_sha: String,
    head_ref: String,
}

impl RefsInfo {
    pub fn head_sha(&self) -> &str {
        &self.head_sha
    }

    pub fn head_ref(&self) -> &str {
        &self.head_ref
    }
}

pub struct Client {
    connection: http::PersistentHTTPConnection,
    url: http::URL,
}

impl Client {
    pub fn new_from_url(repo_url: &str) -> anyhow::Result<Self> {
        let url: http::URL = repo_url
            .as_bytes()
            .try_into()
            .context("parsing given URL")?;
        Ok(Self {
            connection: (&url)
                .try_into()
                .context("establish connection to the given URL")?,
            url,
        })
    }

    pub fn fetch_refs_info(&mut self) -> anyhow::Result<RefsInfo> {
        let mut request_url = http::URL::new(
            *self.url.scheme(),
            vec![],
            self.url.path_components().to_vec(),
            vec![http::QueryParam::new(
                b"service".into(),
                b"git-upload-pack".into(),
            )],
        );

        request_url
            .path_components_mut()
            .extend([b"info".into(), b"refs".into()]);

        let request = http::Request::new(
            self.url.host().to_owned(),
            http::Method::GET,
            request_url.uri(),
            vec![],
            None,
        );

        self.connection
            .write_request(request)
            .context("sending GET /info/refs request")?;
        let response = self
            .connection
            .read_response()
            .context("reading response for GET /info/refs request")?;
        let mut packets_it = PktLines::new(
            response
                .body()
                .ok_or(anyhow::anyhow!("expected body from response"))?,
        );
        ensure!(matches!(
            packets_it.next(),
            Some(Ok(pkt_line::Packet::Data(b"# service=git-upload-pack\n")))
        ));
        ensure!(matches!(
            packets_it.next(),
            Some(Ok(pkt_line::Packet::Flush))
        ));
        let Some(Ok(pkt_line::Packet::Data(info))) = packets_it.next() else {
            bail!("expected a data packet with info about HEAD and refs");
        };
        let mut info_it = info.split(|&b| b == 0x00);
        let Some(head) = info_it.next() else {
            bail!("expected a null byte between HEAD information and capabilities");
        };
        let mut head_it = head.split(|&b| b == b' ');
        let Some(head_sha) = head_it.next() else {
            bail!("HEAD sha should be separated by HEAD by a whitespace");
        };
        let head_sha = String::from_utf8(head_sha.to_vec())
            .context("parsing the head sha as a UTF8 string")?;
        ensure!(matches!(head_it.next(), Some(b"HEAD")));

        let Some(metadata) = info_it.next() else {
            bail!("information about the advertised capabilities should be available");
        };

        let mut head_ref = String::new();
        for metadatum in metadata.split(|&b| b == b' ') {
            if let Some(metadatum) = metadatum.strip_prefix(b"symref=") {
                let mut metadatum_it = metadatum.split(|&b| b == b':');
                let Some(symref) = metadatum_it.next() else {
                    bail!("symrefs must be separated by a ':' from their value");
                };
                if symref == b"HEAD" {
                    head_ref = String::from_utf8(
                        metadatum_it
                            .next()
                            .ok_or(anyhow::anyhow!("expected a value after ':'"))?
                            .to_vec(),
                    )
                    .context("parsing the head ref as a UTF8 encoded string")?;
                    break;
                }
            }
        }

        let Some(Ok(pkt_line::Packet::Data(refs_bytes))) = packets_it.next() else {
            bail!("expected a list of available refs for download");
        };

        let mut refs_heads = HashMap::new();

        for reference in refs_bytes.lines() {
            let reference = reference.context("going through each reference line by line")?;
            let mut split = reference.split_whitespace();
            let Some(sha) = split.next() else {
                bail!("refs names and shas must be separated by a whitespace");
            };
            refs_heads.insert(
                split
                    .next()
                    .ok_or(anyhow::anyhow!("expected a sha"))?
                    .to_string(),
                sha.to_string(),
            );
        }

        ensure!(matches!(
            packets_it.next(),
            Some(Ok(pkt_line::Packet::Flush))
        ));

        ensure!(packets_it.next().is_none());
        Ok(RefsInfo { head_sha, head_ref })
    }

    pub fn fetch_ref_packfile(&mut self, reference_sha: &str) -> anyhow::Result<Vec<u8>> {
        let mut body =
            pkt_line::Packet::Data(format!("want {reference_sha}\n").as_bytes()).to_bytes();
        body.write_all(&pkt_line::Packet::Flush.to_bytes())?;
        body.write_all(&pkt_line::Packet::Data(b"done\n").to_bytes())?;

        let mut request_url = http::URL::new(
            *self.url.scheme(),
            vec![],
            self.url.path_components().to_vec(),
            vec![],
        );

        request_url
            .path_components_mut()
            .push(b"git-upload-pack".into());

        let request = http::Request::new(
            self.url.host().to_owned(),
            http::Method::POST,
            request_url.uri(),
            vec![(
                b"content-type".into(),
                b"application/x-git-upload-pack-request".into(),
            )],
            Some(body),
        );

        self.connection
            .write_request(request)
            .context("sending POST /git-upload-pack request")?;
        let response = self
            .connection
            .read_response()
            .context("reading response for POST /git-upload-pack request")?;

        let response_bytes = response
            .body()
            .ok_or(anyhow::anyhow!("expected a body in the response"))?;
        ensure!(response_bytes.starts_with(b"0008NAK\n"));
        response_bytes
            .strip_prefix(b"0008NAK\n")
            .ok_or(anyhow::anyhow!(
                "expected a single 0008NAK<NL> before the pack"
            ))
            .map(<[u8]>::to_vec)
    }
}

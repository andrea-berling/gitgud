#![allow(clippy::incompatible_msrv)]
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
    vec,
};

use anyhow::{bail, ensure, Context, Error};
use rustls::StreamOwned;

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

#[allow(clippy::large_enum_variant)]
pub enum PersistentHTTPConnection {
    Http(TcpStream),
    Tls(StreamOwned<rustls::ClientConnection, TcpStream>),
}

impl Read for PersistentHTTPConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            PersistentHTTPConnection::Http(tcp_stream) => tcp_stream.read(buf),
            PersistentHTTPConnection::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for PersistentHTTPConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            PersistentHTTPConnection::Http(tcp_stream) => tcp_stream.write(buf),
            PersistentHTTPConnection::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            PersistentHTTPConnection::Http(tcp_stream) => tcp_stream.flush(),
            PersistentHTTPConnection::Tls(stream) => stream.flush(),
        }
    }
}

impl PersistentHTTPConnection {
    pub fn write_request(&mut self, request: Request) -> anyhow::Result<()> {
        self.write_all(&<Vec<u8>>::from(request))
            .context("writing request into the TCP stream")
    }

    pub fn read_response(&mut self) -> anyhow::Result<Response> {
        let mut http_connection = HttpResponseReader::new(self);
        http_connection.read_response()
    }
}

struct HttpResponseReader<'a> {
    reader: BufReader<&'a mut PersistentHTTPConnection>,
}

impl<'a> HttpResponseReader<'a> {
    fn new(connection: &'a mut PersistentHTTPConnection) -> Self {
        Self {
            reader: BufReader::new(connection),
        }
    }

    fn read_response(&mut self) -> anyhow::Result<Response> {
        let mut status_line = String::new();
        self.reader
            .read_line(&mut status_line)
            .context("reading status line")?;

        ensure!(
            status_line.starts_with("HTTP/1.1 "),
            "status line does not start with HTTP/1.1"
        );

        let status_code = &status_line[9..12];
        let status = match status_code {
            "200" => Status::Ok,
            "301" => Status::MovedPermanently,
            _ => bail!(
                "unexpected status code: {}",
                String::from_utf8_lossy(status_code.as_bytes())
            ),
        };

        let mut headers = HashMap::new();
        let mut chunked = false;
        loop {
            let mut header_line = String::new();
            self.reader
                .read_line(&mut header_line)
                .context("reading header line")?;
            if header_line == "\r\n" {
                break;
            }
            if let Some(colon_index) = header_line.find(':') {
                let key = header_line[..colon_index].trim();
                let value = header_line[colon_index + 1..].trim();
                if key.eq_ignore_ascii_case("Transfer-Encoding")
                    && value.eq_ignore_ascii_case("chunked")
                {
                    chunked = true;
                }
                headers.insert(key.to_ascii_lowercase(), value.to_string());
            }
        }

        let body = if chunked {
            let mut body = vec![];
            loop {
                let mut chunk_size_line = String::new();
                self.reader
                    .read_line(&mut chunk_size_line)
                    .context("reading chunk size")?;
                let chunk_size = usize::from_str_radix(chunk_size_line.trim(), 16)
                    .context("parsing chunk size")?;
                if chunk_size == 0 {
                    break;
                }
                let mut chunk = vec![0; chunk_size];
                self.reader
                    .read_exact(&mut chunk)
                    .context("reading chunk")?;
                body.extend_from_slice(&chunk);
                let mut crlf = [0; 2];
                self.reader
                    .read_exact(&mut crlf)
                    .context("reading chunk trailer")?;
                ensure!(b"\r\n".eq_ignore_ascii_case(&crlf));
            }
            Some(body)
        } else if let Some(content_length) = headers.get("content-length") {
            let content_length = content_length
                .parse::<usize>()
                .context("parsing content length")?;
            let mut body = vec![0; content_length];
            self.reader.read_exact(&mut body).context("reading body")?;
            Some(body)
        } else {
            None
        };

        Ok(Response {
            _status: status,
            _headers: headers,
            body,
            _chunked: chunked,
        })
    }
}

impl TryFrom<&URL> for PersistentHTTPConnection {
    type Error = anyhow::Error;

    fn try_from(url: &URL) -> Result<Self, Self::Error> {
        let host = String::from_utf8(url.host.clone()).context("decoding URL")?;
        let mut socket_addr = format!("{host}:{}", url.scheme.port())
            .to_socket_addrs()
            .context("parsing the host into a socket address")?;
        let connection = std::net::TcpStream::connect(
            socket_addr
                .next()
                .ok_or(anyhow::anyhow!("no address could be parsed from host"))?,
        )
        .context("connecting to the host")?;
        if url.scheme.tls() {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let client = rustls::ClientConnection::new(
                Arc::new(config),
                host.clone()
                    .try_into()
                    .context("converting host into a server name")?,
            )
            .context("making a TLS client connection configuration")?;

            Ok(PersistentHTTPConnection::Tls(StreamOwned::new(
                client, connection,
            )))
        } else {
            Ok(PersistentHTTPConnection::Http(connection))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub enum Scheme {
    HTTP,
    HTTPS,
}

impl Scheme {
    #[inline]
    fn serialization_len(&self) -> usize {
        match self {
            Scheme::HTTP => b"http://".len(),
            Scheme::HTTPS => b"https://".len(),
        }
    }

    #[inline]
    fn port(&self) -> u16 {
        match self {
            Scheme::HTTP => HTTP_PORT,
            Scheme::HTTPS => HTTPS_PORT,
        }
    }

    #[inline]
    fn tls(&self) -> bool {
        match self {
            Scheme::HTTP => false,
            Scheme::HTTPS => true,
        }
    }
}

impl TryFrom<&[u8]> for Scheme {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ensure!(bytes.starts_with(b"http"));
        let mut cursor = b"http".len();
        match bytes.get(cursor).ok_or(anyhow::anyhow!(
            "not enough bytes to parse a scheme: expected s or :"
        ))? {
            b':' => {
                cursor += 1;
                ensure!(
                    bytes.get(cursor..cursor + 2).ok_or(anyhow::anyhow!(
                        "not enough bytes to parse a scheme: expected //"
                    ))? == b"//",
                    "expected //"
                );
                Ok(Self::HTTP)
            }
            b's' => {
                cursor += 1;
                ensure!(
                    bytes.get(cursor..cursor + 3).ok_or(anyhow::anyhow!(
                        "not enough bytes to parse a scheme: expected :// after https"
                    ))? == b"://",
                    "expected ://"
                );
                Ok(Self::HTTPS)
            }
            b => bail!("unexpected byte after http: {b:#x}"),
        }
    }
}

struct URLParser<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a, 'b> URLParser<'a> {
    fn new(bytes: &'b [u8]) -> Self
    where
        'b: 'a,
    {
        Self { bytes, cursor: 0 }
    }
}

impl<'a> URLParser<'a> {
    fn parse_scheme(&mut self) -> anyhow::Result<Scheme> {
        let ret: Scheme = self.bytes[self.cursor..]
            .try_into()
            .context("parsing scheme from URL")?;
        self.cursor += ret.serialization_len();
        Ok(ret)
    }

    fn parse_host(&mut self) -> anyhow::Result<&'a [u8]> {
        let host_len = self.bytes[self.cursor..]
            .iter()
            .position(|&c| c == b'/')
            .unwrap_or(self.bytes.len() - self.cursor);
        let return_value = &self.bytes[self.cursor..][..host_len];
        self.cursor += (host_len + 1).min(self.bytes.len() - self.cursor);
        Ok(return_value)
    }

    fn parse_path(&mut self) -> anyhow::Result<Vec<&'a [u8]>> {
        let path_len = self.bytes[self.cursor..]
            .iter()
            .position(|&c| c == b'?')
            .unwrap_or(self.bytes.len() - self.cursor);
        let mut result = vec![];
        if self.cursor >= self.bytes.len() {
            return Ok(result);
        }
        for component in self.bytes[self.cursor..][..path_len].split(|&c| c == b'/') {
            result.push(component);
        }
        self.cursor += (path_len + 1).min(self.bytes.len() - self.cursor);
        Ok(result)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct QueryParam {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl QueryParam {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Self {
        Self { key, value }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub struct URL {
    scheme: Scheme,
    host: Vec<u8>,
    path_components: Vec<Vec<u8>>,
    query_params: Vec<QueryParam>,
}

impl TryFrom<&[u8]> for URL {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut parser = URLParser::new(value);
        Ok(Self {
            scheme: parser.parse_scheme()?,
            host: parser
                .parse_host()
                .context("parsing host from URL")?
                .to_vec(),
            path_components: parser
                .parse_path()
                .context("parsing path from URL")?
                .iter()
                .map(|slice| slice.to_vec())
                .collect(),
            query_params: vec![],
        })
    }
}

impl URL {
    pub fn new(
        scheme: Scheme,
        host: Vec<u8>,
        path_components: Vec<Vec<u8>>,
        query_params: Vec<QueryParam>,
    ) -> Self {
        Self {
            scheme,
            host,
            path_components,
            query_params,
        }
    }

    pub fn host(&self) -> &[u8] {
        &self.host
    }

    pub fn scheme(&self) -> &Scheme {
        &self.scheme
    }

    pub fn uri(&self) -> Vec<u8> {
        let mut uri = vec![];
        for component in &self.path_components {
            uri.push(b'/');
            uri.extend_from_slice(component);
        }
        if !self.query_params.is_empty() {
            uri.push(b'?');
            for (i, param) in self.query_params.iter().enumerate() {
                if i > 0 {
                    uri.push(b'&');
                }
                uri.extend_from_slice(&param.key);
                uri.push(b'=');
                uri.extend_from_slice(&param.value);
            }
        }
        uri
    }

    pub fn path_components(&self) -> &[Vec<u8>] {
        &self.path_components
    }

    pub fn path_components_mut(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.path_components
    }
}

#[derive(Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum Method {
    GET,
    POST,
}

impl From<Method> for Vec<u8> {
    fn from(value: Method) -> Self {
        match value {
            Method::GET => b"GET".into(),
            Method::POST => b"POST".into(),
        }
    }
}

#[derive(Debug)]
pub struct Request {
    host: Vec<u8>,
    method: Method,
    uri: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Option<Vec<u8>>,
}

impl Request {
    pub fn new(
        host: Vec<u8>,
        method: Method,
        uri: Vec<u8>,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        body: Option<Vec<u8>>,
    ) -> Self {
        Self {
            host,
            method,
            uri,
            headers,
            body,
        }
    }

    pub fn add_header(&mut self, header: Vec<u8>, value: Vec<u8>) {
        self.headers.push((header, value));
    }

    pub fn add_body(&mut self, body: Vec<u8>) {
        self.body = Some(body);
    }
}

impl From<Request> for Vec<u8> {
    fn from(mut value: Request) -> Self {
        let mut result = vec![];
        result.append(&mut value.method.into());
        result.push(b' ');
        result.append(&mut value.uri);
        result.push(b' ');
        result.extend_from_slice(b"HTTP/1.1");
        result.extend_from_slice(b"\r\n");
        result.extend_from_slice(b"Host: ");
        result.append(&mut value.host);
        result.extend_from_slice(b"\r\n");
        for (header, value) in &value.headers {
            result.extend_from_slice(header);
            result.push(b':');
            result.extend_from_slice(value);
            result.extend_from_slice(b"\r\n");
        }
        if value.body.is_some() {
            result.extend_from_slice(b"Content-Length: ");
            if let Some(body) = &value.body {
                result.extend_from_slice(body.len().to_string().as_bytes());
            } else {
                result.extend_from_slice(b"0");
            }
            result.extend_from_slice(b"\r\n");
        } else {
            result.extend_from_slice(b"Content-Length: 0\r\n");
        }
        result.extend_from_slice(b"\r\n");
        if let Some(body) = value.body {
            result.extend_from_slice(&body);
        }
        result
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Status {
    Ok,
    MovedPermanently,
}

#[derive(Debug)]
pub struct Response {
    _status: Status,
    _headers: HashMap<String, String>,
    body: Option<Vec<u8>>,
    _chunked: bool,
}

impl Response {
    pub fn body(&self) -> Option<&Vec<u8>> {
        self.body.as_ref()
    }
}

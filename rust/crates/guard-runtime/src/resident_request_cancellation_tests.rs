use super::*;
use crate::resident_transport::ResidentStream;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

#[test]
fn live_tcp_input_timeouts_do_not_cancel_but_extra_input_does_and_reply_still_works() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let watch = Watch::start(server.disconnect_input().unwrap()).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert!(!watch.cancelled.load(Ordering::Acquire));
    client.write_all(b"unexpected second request").unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !watch.cancelled.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    drop(watch);
    server.write_all(b"response").unwrap();
    let mut response = [0; 8];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"response");
}

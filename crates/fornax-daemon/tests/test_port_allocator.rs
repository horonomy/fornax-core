//! The shared test-port allocator never hands the same port to two callers
//! (FORNX-455).

mod common;

use std::collections::HashSet;

#[test]
fn concurrent_callers_never_receive_the_same_port() {
    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| (0..60).map(|_| common::free_tcp_port()).collect::<Vec<_>>())
        })
        .collect();
    let ports: Vec<u16> = threads
        .into_iter()
        .flat_map(|t| t.join().expect("allocator thread"))
        .collect();
    let distinct: HashSet<u16> = ports.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        ports.len(),
        "{} ports handed out, only {} distinct",
        ports.len(),
        distinct.len()
    );
}

//! Port allocation shared by the daemon integration tests (FORNX-455).
//!
//! The tests used to pick a port by binding a probe listener and dropping it,
//! then spawn a daemon that binds the port later. Under load the daemon
//! intermittently exited with "Address already in use" while another process
//! was listening on the chosen port. In failing runs `lsof` showed that
//! holder as a child of the same test process, a few hundred milliseconds
//! old. The explanation that fits: on macOS std creates a socket and only
//! then sets close-on-exec, so a daemon another test thread spawns inside
//! that gap inherits the probe listener and keeps the port in LISTEN for its
//! whole life. (Linux creates sockets close-on-exec atomically, so this
//! probably never hit CI.) Not directly proven. The rule that follows: no
//! listening socket may be open in this process while any thread can spawn.
//! This allocator never binds a probe: it claims a port with a cross-process
//! lock and checks that nothing is listening by connecting.
//!
//! `File::try_lock` needs Rust 1.89, newer than the workspace
//! `rust-version`; CI uses the stable toolchain.

use std::fs::{File, OpenOptions};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

/// Locks held for the life of the process. An advisory lock is released by
/// the kernel when the process exits, even if it crashes, so no lock file
/// can go stale.
static HELD: Mutex<Vec<File>> = Mutex::new(Vec::new());

/// Ports below the OS ephemeral range (49152-65535 on macOS).
const CANDIDATES: std::ops::Range<u16> = 20_000..30_000;

/// A port nothing is listening on, claimed so no other test picks it.
pub fn free_tcp_port() -> u16 {
    let dir = std::env::temp_dir().join("fornax-test-ports");
    std::fs::create_dir_all(&dir).expect("create the shared test-port directory");
    loop {
        let port = random_port();
        let claim = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(port.to_string()))
            .expect("open the port claim file");
        if claim.try_lock().is_err() {
            continue;
        }
        // Claimed first so the connect below never pokes another test's
        // live daemon. A refused connection means no listener.
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            continue; // dropping `claim` releases the lock
        }
        HELD.lock().expect("port claim list").push(claim);
        return port;
    }
}

/// A uniformly random port from `CANDIDATES`, without a new dependency: the
/// standard hasher is randomly seeded per instance.
fn random_port() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    CANDIDATES.start + (random % u64::from(CANDIDATES.end - CANDIDATES.start)) as u16
}

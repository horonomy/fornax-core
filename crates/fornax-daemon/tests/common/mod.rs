//! Port allocation shared by the daemon integration tests (FORNX-455).
//!
//! The tests used to pick a port by binding `127.0.0.1:0` and dropping the
//! listener, then spawn a daemon that binds it later. Under load the daemon
//! intermittently exited with "Address already in use" while another process
//! was listening on the chosen port. In failing runs `lsof` showed that
//! holder as a child of the same test process, a few hundred milliseconds
//! old. The explanation that fits: another test thread's `fork` copied the
//! open probe listener, and the child kept the socket alive until its `exec`
//! closed it. So no listening socket may be open in this process while any
//! thread can fork. This allocator never binds a probe: it claims a port with
//! a cross-process lock and checks that nothing is listening by connecting.

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
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        // A refused connection means no listener; success means taken.
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            continue;
        }
        let claim = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(port.to_string()))
            .expect("open the port claim file");
        if claim.try_lock().is_ok() {
            HELD.lock().expect("port claim list").push(claim);
            return port;
        }
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

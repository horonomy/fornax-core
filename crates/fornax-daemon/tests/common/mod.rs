//! Port allocation shared by the daemon integration tests (FORNX-455).
//!
//! The tests used to pick a port by binding `127.0.0.1:0` and dropping the
//! listener, then start a daemon that binds it hundreds of milliseconds
//! later. Under several concurrent test binaries the daemon then
//! intermittently failed with "Address already in use". Ephemeral ports are
//! random (a just-released port was not reissued in 3,000 tries on macOS), so
//! the likely collision is two tests picking the same port while neither
//! daemon has bound it yet. This claims each port with a cross-process lock
//! to rule that out; it cannot guard against arbitrary other programs.

use std::fs::{File, OpenOptions};
use std::net::TcpListener;
use std::sync::Mutex;

/// Locks held for the life of the process. An advisory lock is released by
/// the kernel when the process exits, even if it crashes, so no lock file
/// can go stale.
static HELD: Mutex<Vec<File>> = Mutex::new(Vec::new());

/// A currently free port that no other test in any process has claimed.
pub fn free_tcp_port() -> u16 {
    let dir = std::env::temp_dir().join("fornax-test-ports");
    std::fs::create_dir_all(&dir).expect("create the shared test-port directory");
    loop {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = probe.local_addr().expect("local addr").port();
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

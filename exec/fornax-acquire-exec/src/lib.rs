//! Library half of `fornax-acquire-exec` (FORNX-346 Part 2, ADR 0022) --
//! exists purely so `exec/fornax-acquire-exec/tests/*.rs` can exercise the
//! real `grants`/`rerun`/`ci` modules directly, the same way any other
//! crate in this workspace is integration-tested. `src/main.rs` is a thin
//! binary over this library; see its own module docs for the full flow.

pub mod ci;
pub mod grants;
pub mod rerun;

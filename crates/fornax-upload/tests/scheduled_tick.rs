//! The automatic monthly upload (FORNX-464) against a loopback receiver:
//! it must stay silent without a live personal consent, and send exactly once
//! when a closed month is due under one. One test function: it sets process
//! environment, so scenarios must not interleave.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::{Duration, Utc};
use fornax_store::Store;
use fornax_types::egress::{Profile, Purpose};
use fornax_types::{AgentEvent, EgressContentClass, EventKind, Provider};
use fornax_upload::{scheduled_tick, TickOutcome};
use uuid::Uuid;

fn mock() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/v1/metadata-batches",
        listener.local_addr().unwrap()
    );
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (mut head_end, mut want) = (None, 0usize);
            loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if head_end.is_none() {
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        head_end = Some(i + 4);
                        let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                        want = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                    }
                }
                if let Some(h) = head_end {
                    if buf.len() >= h + want {
                        break;
                    }
                }
            }
            seen.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(
                b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    (url, count)
}

async fn record_old_event(store: &Store) {
    let ts = (Utc::now() - Duration::days(40)).to_rfc3339();
    store
        .insert_event(&AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s-old".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: ts,
            tool_name: Some("Bash".into()),
            tool_input: Some(serde_json::json!({"command": "CANARY-SECRET"})),
            tool_response: None,
            raw: serde_json::json!({}),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn the_schedule_is_inert_without_a_live_personal_consent_and_sends_once_with_one() {
    let home = std::env::temp_dir().join(format!("fnx-sched-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&home).unwrap();
    let db = home.join("fornax.db");
    let store = Store::open(&db).await.unwrap();
    let (url, count) = mock();

    std::env::set_var("FORNAX_CLOUD_SYNC_ENABLED", "1");
    std::env::set_var("FORNX_DEVICE_ID", "device-test");
    std::env::set_var("FORNAX_UPLOAD_BACKOFF_MS", "1");
    let cred = home.join("device-credential");
    std::fs::write(&cred, "fnxd_v1_test-credential\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cred, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // 1. Unconfigured profile: nothing is scheduled, nothing connects.
    record_old_event(&store).await;
    assert!(matches!(
        scheduled_tick(&store, &home).await.unwrap(),
        TickOutcome::NoConsent
    ));

    // 2. Personal + allowlist + consent (backdated so the old record is
    //    eligible): the closed month is sent exactly once.
    store
        .set_egress_profile(Profile::Personal, "t", false)
        .await
        .unwrap();
    store
        .add_egress_allowlist(Purpose::EvidenceBatchUpload, &url, "t")
        .await
        .unwrap();
    let classes: BTreeSet<EgressContentClass> = [
        EgressContentClass::EvidenceMetadata,
        EgressContentClass::FindingVerdicts,
    ]
    .into_iter()
    .collect();
    let consent = store
        .grant_egress_consent(Purpose::EvidenceBatchUpload, &url, &classes, 30, None, "t")
        .await
        .unwrap();
    let sixty = (Utc::now() - Duration::days(60)).to_rfc3339();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    for sql in [
        "UPDATE egress_consents SET granted_at = ?1",
        "UPDATE egress_profile_log SET changed_at = ?1",
    ] {
        sqlx::query(sql).bind(&sixty).execute(&pool).await.unwrap();
    }
    match scheduled_tick(&store, &home).await.unwrap() {
        TickOutcome::Ran(r) => assert_eq!((r.sent, r.poisoned, r.pending), (1, 0, 0)),
        other => panic!("expected a run, got {other:?}"),
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // 2b. A held lock (another run in progress) makes the tick a no-op.
    std::fs::write(home.join("upload.lock"), "1").unwrap();
    assert!(matches!(
        scheduled_tick(&store, &home).await.unwrap(),
        TickOutcome::Busy | TickOutcome::NothingDue
    ));
    std::fs::remove_file(home.join("upload.lock")).ok();

    // 3. Nothing further is due: no second request.
    assert!(matches!(
        scheduled_tick(&store, &home).await.unwrap(),
        TickOutcome::NothingDue
    ));
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // 4. Consent revoked, with new due work: silent.
    store
        .revoke_egress_consent(&consent, "t", "t")
        .await
        .unwrap();
    record_old_event(&store).await;
    assert!(matches!(
        scheduled_tick(&store, &home).await.unwrap(),
        TickOutcome::NoConsent
    ));
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // 5. Corporate profile: even a fresh consent cannot exist, and the
    //    schedule stays silent.
    store
        .set_egress_profile(Profile::Corporate, "t", false)
        .await
        .unwrap();
    assert!(matches!(
        scheduled_tick(&store, &home).await.unwrap(),
        TickOutcome::NoConsent
    ));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(&home).ok();
}

/// A consent renewal to a different destination must never re-aim a batch
/// that was sealed for the earlier destination at the new one.
#[tokio::test]
async fn a_batch_sealed_for_one_destination_is_never_sent_to_a_renewed_consents_url() {
    let home = std::env::temp_dir().join(format!("fnx-renew-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&home).unwrap();
    let db = home.join("fornax.db");
    let store = Store::open(&db).await.unwrap();
    let (url_a, count_a) = mock();
    let (url_b, count_b) = mock();
    std::env::set_var("FORNAX_CLOUD_SYNC_ENABLED", "1");
    std::env::set_var("FORNX_DEVICE_ID", "device-test");
    let cred = home.join("device-credential");
    std::fs::write(&cred, "fnxd_v1_test-credential\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cred, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    record_old_event(&store).await;
    store
        .set_egress_profile(Profile::Personal, "t", false)
        .await
        .unwrap();
    let classes: BTreeSet<EgressContentClass> = [
        EgressContentClass::EvidenceMetadata,
        EgressContentClass::FindingVerdicts,
    ]
    .into_iter()
    .collect();
    for url in [&url_a, &url_b] {
        store
            .add_egress_allowlist(Purpose::EvidenceBatchUpload, url, "t")
            .await
            .unwrap();
    }
    let consent_a = store
        .grant_egress_consent(
            Purpose::EvidenceBatchUpload,
            &url_a,
            &classes,
            30,
            None,
            "t",
        )
        .await
        .unwrap();
    let sixty = (Utc::now() - Duration::days(60)).to_rfc3339();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    for sql in [
        "UPDATE egress_consents SET granted_at = ?1",
        "UPDATE egress_profile_log SET changed_at = ?1",
    ] {
        sqlx::query(sql).bind(&sixty).execute(&pool).await.unwrap();
    }
    store.stage_upload_records().await.unwrap();
    let window = store
        .pending_upload_windows()
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    store
        .seal_upload_batch(&window, &consent_a, &url_a)
        .await
        .unwrap()
        .expect("sealed for destination A");

    // Renew to destination B while A's consent is still valid.
    store
        .grant_egress_consent(
            Purpose::EvidenceBatchUpload,
            &url_b,
            &classes,
            30,
            None,
            "t",
        )
        .await
        .unwrap();
    match scheduled_tick(&store, &home).await.unwrap() {
        TickOutcome::Ran(r) => {
            assert_eq!((r.sent, r.poisoned), (0, 0));
            assert_eq!(r.skipped.len(), 1, "the A-sealed batch is skipped");
        }
        other => panic!("expected a run, got {other:?}"),
    }
    assert_eq!(count_a.load(Ordering::SeqCst), 0, "A is not the live URL");
    assert_eq!(
        count_b.load(Ordering::SeqCst),
        0,
        "B never receives A's batch"
    );
    std::fs::remove_dir_all(&home).ok();
}

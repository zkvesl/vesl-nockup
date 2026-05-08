//! Smoke test for `vesl-test watch` (RM4 §6 acceptance #6).
//!
//! Boots a kernel composed from `settle-graft`, drives the watch
//! module's `drive()` loop with three settle-register pokes piped
//! through an in-memory reader, and asserts the rendered output
//! captures the heartbeat plus three event rows with correct cause +
//! effect head-tags.
//!
//! `drive()` is generic over `R: AsyncBufRead` / `W: AsyncWrite`, so
//! the test substitutes a `&[u8]` reader and a `Vec<u8>` writer —
//! exercising the full poke → broadcast → render path without
//! subprocess overhead.

mod fixtures;

use std::time::Duration;

use anyhow::Result;
use nockapp::NockApp;
use nockapp::kernel::boot;
use serde_json::Value;
use vesl_core::Mint;
use vesl_test::watch::{self, WatchOpts};
use vesl_test::{TEST_PAYLOAD, build_register_poke, init_capture_tracing};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_smoke_captures_three_events() -> Result<()> {
    let jam_path = fixtures::compose_and_compile("watch_smoke", &["settle-graft"])?;

    let mut boot_cli = boot::default_boot_cli(false);
    init_capture_tracing(&boot_cli);
    boot_cli.save_interval = None; // skip periodic saves during the smoke run

    let kernel_bytes = std::fs::read(&jam_path)?;
    let mut app: NockApp = boot::setup(
        &kernel_bytes,
        boot_cli,
        &[],
        "watch-smoke",
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("boot setup failed: {e}"))?;

    let handle = app.get_handle();
    let effect_rx = handle.effect_sender.subscribe();
    let run_join = tokio::spawn(async move { app.run().await });

    // Build three settle-register pokes against distinct hulls so each
    // succeeds (no duplicate-register slogs to disambiguate). Pipe
    // them through stdin as `poke-jam <hex> tag=settle-register` rows,
    // then `quit`.
    let mut mint = Mint::new();
    let root = mint.commit(&[TEST_PAYLOAD]);
    let mut stdin_input = String::new();
    for hull in [1u64, 2, 3] {
        let slab = build_register_poke(hull, &root);
        let bytes = watch::jam_slab(&slab);
        let hex = watch::hex_encode(&bytes);
        stdin_input.push_str(&format!("poke-jam {hex} tag=settle-register\n"));
    }
    stdin_input.push_str("quit\n");

    let opts = WatchOpts {
        jam: jam_path.clone(),
        json: true,
        filter: None,
        // Small kernels boot fast; 200ms is plenty of slack for the
        // post-ack broadcast to produce its single effect.
        effect_window: Duration::from_millis(200),
    };

    let reader = tokio::io::BufReader::new(stdin_input.as_bytes());
    let mut writer: Vec<u8> = Vec::new();

    watch::drive(opts, handle, run_join, effect_rx, reader, &mut writer).await?;

    let output = String::from_utf8(writer)?;
    let lines: Vec<&str> = output.lines().filter(|l| !l.trim().is_empty()).collect();

    assert!(
        lines.len() >= 4,
        "expected ≥4 lines (heartbeat + 3 events), got {}: {}",
        lines.len(),
        output
    );

    let hb: Value = serde_json::from_str(lines[0])?;
    assert_eq!(hb["kind"], "heartbeat", "first line must be heartbeat: {}", lines[0]);

    for (i, line) in (1u64..=3).zip(&lines[1..4]) {
        let v: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("event {i} not JSON: {e}\nline: {line}"));
        assert_eq!(
            v["event_num"], i,
            "event_num mismatch on event {i}: {v}"
        );
        assert_eq!(
            v["cause_tag"], "settle-register",
            "cause_tag mismatch on event {i}: {v}"
        );
        let effects = v["effect_tags"]
            .as_array()
            .unwrap_or_else(|| panic!("effect_tags missing on event {i}: {v}"));
        let tags: Vec<&str> = effects.iter().filter_map(Value::as_str).collect();
        assert!(
            tags.contains(&"settle-registered"),
            "event {i} missing settle-registered: tags={tags:?} (full: {v})"
        );
        assert_eq!(
            v["ack"], "ack",
            "expected ack=Ack on event {i}: {v}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_smoke_filter_drops_non_matching_events() -> Result<()> {
    let jam_path = fixtures::compose_and_compile("watch_smoke_filter", &["settle-graft"])?;

    let mut boot_cli = boot::default_boot_cli(false);
    init_capture_tracing(&boot_cli);
    boot_cli.save_interval = None;
    let kernel_bytes = std::fs::read(&jam_path)?;
    let mut app: NockApp =
        boot::setup(&kernel_bytes, boot_cli, &[], "watch-smoke-filter", None)
            .await
            .map_err(|e| anyhow::anyhow!("boot setup failed: {e}"))?;
    let handle = app.get_handle();
    let effect_rx = handle.effect_sender.subscribe();
    let run_join = tokio::spawn(async move { app.run().await });

    // Issue one settle-register and one poke-tag (which the kernel
    // won't recognize — but the parse layer still tags it as
    // "noop-tag"). With `--filter cause=settle-register`, only the
    // settle-register row should appear.
    let mut mint = Mint::new();
    let root = mint.commit(&[TEST_PAYLOAD]);
    let slab = build_register_poke(7, &root);
    let bytes = watch::jam_slab(&slab);
    let hex = watch::hex_encode(&bytes);
    let stdin_input = format!(
        "poke-jam {hex} tag=settle-register\npoke-tag noop-tag\nquit\n"
    );

    let opts = WatchOpts {
        jam: jam_path.clone(),
        json: true,
        filter: Some(watch::Filter::Cause("settle-register".to_string())),
        effect_window: Duration::from_millis(200),
    };

    let reader = tokio::io::BufReader::new(stdin_input.as_bytes());
    let mut writer: Vec<u8> = Vec::new();
    watch::drive(opts, handle, run_join, effect_rx, reader, &mut writer).await?;

    let output = String::from_utf8(writer)?;
    let event_lines: Vec<&str> = output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| l.contains("\"event_num\""))
        .collect();

    assert_eq!(
        event_lines.len(),
        1,
        "filter cause=settle-register should keep exactly 1 event, got {}: {output}",
        event_lines.len()
    );
    let v: Value = serde_json::from_str(event_lines[0])?;
    assert_eq!(v["cause_tag"], "settle-register");

    Ok(())
}

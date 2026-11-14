use opurom_db::*;
use std::time::{Duration, Instant};

// ---- Pure helper math with injected samples ----

#[test]
fn speedup_x100_rounds_down_measured_integer_ratio() {
    assert_eq!(speedup_x100(0, 1), Some(0));
    assert_eq!(speedup_x100(1_000, 2_000), Some(50));
    assert_eq!(speedup_x100(1_999, 1_000), Some(199));
    assert_eq!(speedup_x100(1, 3), Some(33));
    // <= 100 is a valid measurement: small N may not benefit from an index.
    assert_eq!(speedup_x100(800, 1_000), Some(80));
    assert_eq!(speedup_x100(1_000, 1_000), Some(100));
    // Zero indexed time has no ratio.
    assert_eq!(speedup_x100(1_000, 0), None);
}

#[test]
fn percentile_ms_uses_nearest_rank_on_injected_samples() {
    let samples = [
        Duration::from_millis(40),
        Duration::from_millis(10),
        Duration::from_millis(30),
        Duration::from_millis(20),
        Duration::from_millis(50),
    ];
    assert_eq!(percentile_ms(&samples, 0), None);
    assert_eq!(percentile_ms(&samples, 101), None);
    assert_eq!(percentile_ms(&[], 50), None);
    assert_eq!(percentile_ms(&samples, 50), Some(30));
    assert_eq!(percentile_ms(&samples, 95), Some(50));
    assert_eq!(percentile_ms(&samples, 100), Some(50));
    let one = [Duration::from_millis(7)];
    assert_eq!(percentile_ms(&one, 95), Some(7));
}

#[test]
fn filter_keys_are_deterministic_and_in_range() {
    let workload = Workload {
        rows: 1_000,
        selects: 500,
        repeats: 3,
        seed: WORKLOAD_SEED,
    };
    let a = filter_keys(&workload).unwrap();
    let b = filter_keys(&workload).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 500);
    assert!(a.iter().all(|k| (1..=1_000).contains(k)));
    // A different seed gives a different key sequence.
    let other = filter_keys(&Workload {
        seed: WORKLOAD_SEED ^ 0xffff,
        ..workload
    })
    .unwrap();
    assert_ne!(a, other);
}

#[test]
fn workload_validation_rejects_empty_shapes() {
    for workload in [
        Workload {
            rows: 0,
            selects: 1,
            repeats: 1,
            seed: 1,
        },
        Workload {
            rows: 1,
            selects: 0,
            repeats: 1,
            seed: 1,
        },
        Workload {
            rows: 1,
            selects: 1,
            repeats: 0,
            seed: 1,
        },
    ] {
        assert!(workload.validate().is_err());
    }
    assert!(BENCHMARK_WORKLOAD.validate().is_ok());
}

/// A non-SQLite runner with a scripted clock and counter proves the harness
/// stays pure and injectable; no timing here comes from the host.
struct ScriptRunner {
    statements: u64,
}

impl BenchmarkRunner for ScriptRunner {
    fn begin_run(&mut self) -> Result<(), DbError> {
        self.statements += 2;
        Ok(())
    }
    fn insert_rows(&mut self, _rows: u32) -> Result<(), DbError> {
        self.statements += 2;
        Ok(())
    }
    fn prepare_selects(&mut self) -> Result<(), DbError> {
        self.statements += 1;
        Ok(())
    }
    fn select_indexed(&mut self, keys: &[i64]) -> Result<u64, DbError> {
        self.statements += keys.len() as u64;
        Ok(keys.len() as u64)
    }
    fn select_scan(&mut self, keys: &[i64]) -> Result<u64, DbError> {
        self.statements += keys.len() as u64;
        Ok(keys.len() as u64)
    }
    fn plans(&mut self, workload: &Workload, _keys: &[i64]) -> Result<BenchmarkPlans, DbError> {
        self.statements += 2;
        let plan = Plan {
            scan: Scan::TableScan,
            index: None,
            matched_columns: 0,
            estimated_rows: u64::from(workload.rows),
        };
        Ok(BenchmarkPlans {
            planner_indexed: plan.clone(),
            planner_scan: plan,
            sqlite_indexed: vec!["SEARCH".to_string()],
            sqlite_scan: vec!["SCAN".to_string()],
        })
    }
    fn statements_executed(&self) -> u64 {
        self.statements
    }
}

/// Scripted clock advanced by fixed scripted offsets; no host timing.
struct ScriptClock {
    origin: Instant,
    offsets: Vec<Duration>,
    step: usize,
}

impl Clock for ScriptClock {
    fn now(&mut self) -> Instant {
        let elapsed = self.offsets[self.step];
        self.step += 1;
        self.origin + elapsed
    }
}

#[test]
fn measure_queries_matches_hand_computed_math() {
    // Two repeats, three selects: 4 timed phases per repeat, 2 clock reads each.
    let workload = Workload {
        rows: 10,
        selects: 3,
        repeats: 2,
        seed: 7,
    };
    let mut runner = ScriptRunner { statements: 0 };
    let mut clock = ScriptClock {
        origin: Instant::now(),
        offsets: vec![
            Duration::from_millis(0),
            Duration::from_millis(10), // insert #1
            Duration::from_millis(10),
            Duration::from_millis(14), // indexed #1
            Duration::from_millis(14),
            Duration::from_millis(24), // scan #1
            Duration::from_millis(24),
            Duration::from_millis(30), // insert #2
            Duration::from_millis(30),
            Duration::from_millis(34), // indexed #2
            Duration::from_millis(34),
            Duration::from_millis(40), // scan #2
        ],
        step: 0,
    };
    let report = measure_queries(&mut runner, workload, &mut clock).unwrap();
    assert_eq!(report.insert_ms, 16); // 10 + 6
    assert_eq!(report.indexed_select_ms, 8); // 4 + 4
    assert_eq!(report.scan_select_ms, 16); // 10 + 6
    assert_eq!(report.indexed_rows_returned, 6); // 3 keys x 2 repeats
    assert_eq!(report.scan_rows_returned, 6);
    assert_eq!(report.rows_returned, 12);
    // 16000 * 100 / 8000 = 200.
    assert_eq!(report.speedup_x100, Some(200));
    assert_eq!(report.statements_executed, expected_statements(&workload));
    // Nearest rank over [6, 10].
    assert_eq!(report.insert_p50_ms, 6);
    assert_eq!(report.insert_p95_ms, 10);
    assert_eq!(report.indexed_select_p50_ms, 4);
    // Scan samples are [10, 6]; nearest rank sorts to [6, 10].
    assert_eq!(report.scan_select_p50_ms, 6);
    assert_eq!(report.scan_select_p95_ms, 10);
}

#[test]
fn expected_statements_tracks_workload_shape() {
    let workload = Workload {
        rows: 5,
        selects: 4,
        repeats: 3,
        seed: 1,
    };
    // 3 * (2 + 2 + 1 + 8) + 2 = 3 * 13 + 2 = 41.
    assert_eq!(expected_statements(&workload), 41);
}

// ---- Real SQLite: measured baseline with index plan and scan plan ----

fn open_runner() -> Option<SqliteRunner> {
    let db = Sqlite::open(":memory:").ok()?;
    SqliteRunner::new(db).ok()
}

#[test]
fn real_sqlite_benchmark_measures_index_scan_and_rows() {
    let Some(mut runner) = open_runner() else {
        eprintln!("SKIP real_sqlite_benchmark: SQLite FFI could not open :memory:");
        return;
    };
    let mut clock = MonotonicClock;
    let report = measure_queries(&mut runner, BENCHMARK_WORKLOAD, &mut clock).unwrap();
    let w = report.workload;

    // Indexed path: the pure planner and SQLite both report index use.
    assert_eq!(report.plans.planner_indexed.scan, Scan::IndexScan);
    assert_eq!(
        report.plans.planner_indexed.index.as_deref(),
        Some("by_score")
    );
    assert!(
        report
            .plans
            .sqlite_indexed
            .iter()
            .any(|detail| detail.starts_with("SEARCH") && detail.contains("USING INDEX")),
        "indexed plan must SEARCH via the index: {:?}",
        report.plans.sqlite_indexed
    );
    // Scan path: no declared index, so the pure planner and SQLite scan.
    assert_eq!(report.plans.planner_scan.scan, Scan::TableScan);
    assert!(report.plans.planner_scan.index.is_none());
    assert!(
        report
            .plans
            .sqlite_scan
            .iter()
            .any(|detail| detail.starts_with("SCAN")),
        "unindexed plan must SCAN: {:?}",
        report.plans.sqlite_scan
    );

    // Every equality key matches exactly one row per path per repetition.
    let per_run = u64::from(w.selects);
    let total = per_run * w.repeats as u64;
    assert_eq!(report.indexed_rows_returned, total);
    assert_eq!(report.scan_rows_returned, total);
    assert_eq!(report.rows_returned, 2 * total);

    // Statement count is deterministic and matches the workload shape.
    assert_eq!(report.statements_executed, expected_statements(&w));

    // Honest measurement: a ratio at or below 100 (<=1x) is a valid result.
    let speedup = report
        .speedup_x100
        .expect("measured indexed duration is nonzero");
    assert!(speedup > 0, "a measured speedup must be reported");

    eprintln!(
        "MEASURED (host-specific) rows={} selects={} repeats={} insert_ms={} indexed_select_ms={} scan_select_ms={} speedup_x100={} indexed_plan={:?} scan_plan={:?} p50_ms(i/s)={}/{} p95_ms(i/s)={}/{}",
        w.rows,
        w.selects,
        w.repeats,
        report.insert_ms,
        report.indexed_select_ms,
        report.scan_select_ms,
        speedup,
        report.plans.sqlite_indexed,
        report.plans.sqlite_scan,
        report.indexed_select_p50_ms,
        report.scan_select_p50_ms,
        report.indexed_select_p95_ms,
        report.scan_select_p95_ms,
    );
}

#[test]
fn real_sqlite_statement_counts_are_deterministic() {
    let Some(mut runner) = open_runner() else {
        eprintln!("SKIP real_sqlite_statement_counts: SQLite FFI could not open :memory:");
        return;
    };
    let mut clock = MonotonicClock;
    let first_report = measure_queries(&mut runner, BENCHMARK_WORKLOAD, &mut clock).unwrap();
    let Some(mut second) = open_runner() else {
        eprintln!("SKIP real_sqlite_statement_counts: second SQLite open failed");
        return;
    };
    let second_report =
        measure_queries(&mut second, BENCHMARK_WORKLOAD, &mut MonotonicClock).unwrap();
    assert_eq!(
        first_report.statements_executed, second_report.statements_executed,
        "statement count must not depend on timing"
    );
    assert_eq!(
        first_report.statements_executed,
        expected_statements(&BENCHMARK_WORKLOAD)
    );
    // Rows returned are identical across independent runs.
    assert_eq!(first_report.rows_returned, second_report.rows_returned);
    assert_eq!(
        first_report.indexed_rows_returned,
        second_report.indexed_rows_returned
    );
    assert_eq!(
        first_report.scan_rows_returned,
        second_report.scan_rows_returned
    );
}

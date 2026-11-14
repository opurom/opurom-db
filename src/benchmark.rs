//! Reproducible indexed-versus-scan SQLite benchmarks.
//!
//! [`measure_queries`] owns neither a database nor a clock: the runner and
//! clock are injected. `SqliteRunner` is the production runner and uses the
//! existing `Sqlite` driver against `:memory:`.

use crate::{
    explain as plan_query, schema_sql, Database, DbError, Field, FieldType, Filter, Model, Plan,
    Query, Sqlite, Value,
};
use std::time::{Duration, Instant};

/// Fixed, public workload seed. Key selection is deterministic arithmetic.
pub const WORKLOAD_SEED: u64 = 0x4f50_5552_4f4d_4442;

/// The fixed benchmark shape: 4,096 rows in each table, 256 equality selects
/// on each path, and seven measured repetitions of the whole workload.
pub const BENCHMARK_WORKLOAD: Workload = Workload {
    rows: 4_096,
    selects: 256,
    repeats: 7,
    seed: WORKLOAD_SEED,
};

const INDEXED_TABLE: &str = "BenchmarkIndexed";
const PLAIN_TABLE: &str = "BenchmarkPlain";
const INDEX_NAME: &str = "by_score";
const SETUP_CALLS: u64 = 2;
const INSERT_CALLS: u64 = 2;
const ANALYZE_CALLS: u64 = 1;
const PLAN_CALLS: u64 = 2;

/// Fixed workload shape. `seed` mixes filter keys without a random generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Workload {
    pub rows: u32,
    pub selects: u32,
    pub repeats: usize,
    pub seed: u64,
}

impl Workload {
    pub fn validate(&self) -> Result<(), DbError> {
        if self.rows == 0 {
            return Err(DbError::new("benchmark rows must be positive"));
        }
        if self.selects == 0 {
            return Err(DbError::new("benchmark selects must be positive"));
        }
        if self.repeats == 0 {
            return Err(DbError::new("benchmark repeats must be positive"));
        }
        Ok(())
    }
}

/// Deterministic equality-filter keys in `1..=rows`.
pub fn filter_keys(workload: &Workload) -> Result<Vec<i64>, DbError> {
    workload.validate()?;
    let rows = u64::from(workload.rows);
    Ok((0..workload.selects)
        .map(|i| {
            let mixed = (u64::from(i) + 1)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(workload.seed);
            i64::try_from(mixed % rows + 1).unwrap_or(i64::MAX)
        })
        .collect())
}

/// Driver calls [`measure_queries`] will make, derived from the workload shape.
/// `Sqlite::executed_statements()` counts driver calls, not visited rows.
pub fn expected_statements(workload: &Workload) -> u64 {
    let per_run = SETUP_CALLS + INSERT_CALLS + ANALYZE_CALLS + 2 * u64::from(workload.selects);
    u64::try_from(workload.repeats)
        .unwrap_or(u64::MAX)
        .saturating_mul(per_run)
        .saturating_add(PLAN_CALLS)
}

/// Injected monotonic time source.
pub trait Clock {
    fn now(&mut self) -> Instant;
}

/// Real host clock; every reported duration comes from this source.
#[derive(Clone, Copy, Debug, Default)]
pub struct MonotonicClock;

impl Clock for MonotonicClock {
    fn now(&mut self) -> Instant {
        Instant::now()
    }
}

/// Pure-planner output plus SQLite's own row-access evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkPlans {
    pub planner_indexed: Plan,
    pub planner_scan: Plan,
    pub sqlite_indexed: Vec<String>,
    pub sqlite_scan: Vec<String>,
}

/// Injected workload runner. Implementations own the database and its counter.
pub trait BenchmarkRunner {
    fn begin_run(&mut self) -> Result<(), DbError>;
    fn insert_rows(&mut self, rows: u32) -> Result<(), DbError>;
    fn prepare_selects(&mut self) -> Result<(), DbError>;
    fn select_indexed(&mut self, keys: &[i64]) -> Result<u64, DbError>;
    fn select_scan(&mut self, keys: &[i64]) -> Result<u64, DbError>;
    fn plans(&mut self, workload: &Workload, keys: &[i64]) -> Result<BenchmarkPlans, DbError>;
    fn statements_executed(&self) -> u64;
}

/// Integer-only measured result. `*_ms` fields are sums across all repetitions;
/// `speedup_x100` uses the unrounded nanosecond totals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkReport {
    pub workload: Workload,
    pub insert_ms: u64,
    pub indexed_select_ms: u64,
    pub scan_select_ms: u64,
    pub insert_ns: u128,
    pub indexed_select_ns: u128,
    pub scan_select_ns: u128,
    pub rows_returned: u64,
    pub indexed_rows_returned: u64,
    pub scan_rows_returned: u64,
    pub statements_executed: u64,
    /// `floor(scan_ns * 100 / indexed_ns)`; `None` when no repetition measured
    /// a nonzero indexed-select duration (ratio would be undefined).
    pub speedup_x100: Option<u64>,
    pub insert_p50_ms: u64,
    pub insert_p95_ms: u64,
    pub indexed_select_p50_ms: u64,
    pub indexed_select_p95_ms: u64,
    pub scan_select_p50_ms: u64,
    pub scan_select_p95_ms: u64,
    pub plans: BenchmarkPlans,
}

/// Nearest-rank percentile over measured durations, rounded down to whole ms.
pub fn percentile_ms(samples: &[Duration], percentile: u8) -> Option<u64> {
    if samples.is_empty() || percentile == 0 || percentile > 100 {
        return None;
    }
    let mut values = samples.iter().copied().map(duration_ms).collect::<Vec<_>>();
    values.sort_unstable();
    // Integer-only nearest rank keeps repeated runs comparable across hosts.
    let rank = values
        .len()
        .saturating_mul(usize::from(percentile))
        .saturating_add(99)
        / 100;
    values.get(rank.saturating_sub(1)).copied()
}

/// `floor(scan_ns * 100 / indexed_ns)`; a value at or below 100 is valid.
pub fn speedup_x100(scan_ns: u128, indexed_ns: u128) -> Option<u64> {
    if indexed_ns == 0 {
        return None;
    }
    let ratio = scan_ns.saturating_mul(100) / indexed_ns;
    if ratio > u128::from(u64::MAX) {
        return None;
    }
    Some(ratio as u64)
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn percentiles(samples: &[Duration]) -> Result<(u64, u64), DbError> {
    let p50 = percentile_ms(samples, 50)
        .ok_or_else(|| DbError::new("benchmark has no p50 timing samples"))?;
    let p95 = percentile_ms(samples, 95)
        .ok_or_else(|| DbError::new("benchmark has no p95 timing samples"))?;
    Ok((p50, p95))
}

fn timed<C: Clock, T>(
    clock: &mut C,
    action: impl FnOnce() -> Result<T, DbError>,
) -> Result<(Duration, T), DbError> {
    let start = clock.now();
    let value = action()?;
    let end = clock.now();
    let elapsed = end
        .checked_duration_since(start)
        .ok_or_else(|| DbError::new("benchmark clock moved backwards"))?;
    Ok((elapsed, value))
}

/// Run the fixed insert/select workload through `runner`, timing three phases
/// with `clock` on every repetition. All reported numbers are measured.
pub fn measure_queries<R: BenchmarkRunner, C: Clock>(
    runner: &mut R,
    workload: Workload,
    clock: &mut C,
) -> Result<BenchmarkReport, DbError> {
    workload.validate()?;
    let keys = filter_keys(&workload)?;
    let statement_start = runner.statements_executed();
    let mut insert_samples = Vec::with_capacity(workload.repeats);
    let mut indexed_samples = Vec::with_capacity(workload.repeats);
    let mut scan_samples = Vec::with_capacity(workload.repeats);
    let mut insert_total = Duration::ZERO;
    let mut indexed_total = Duration::ZERO;
    let mut scan_total = Duration::ZERO;
    let mut indexed_rows_returned = 0u64;
    let mut scan_rows_returned = 0u64;

    for _ in 0..workload.repeats {
        runner.begin_run()?;
        let (insert_elapsed, ()) = timed(&mut *clock, || runner.insert_rows(workload.rows))?;
        runner.prepare_selects()?;
        let (indexed_elapsed, indexed_rows) = timed(&mut *clock, || runner.select_indexed(&keys))?;
        let (scan_elapsed, scan_rows) = timed(&mut *clock, || runner.select_scan(&keys))?;
        insert_samples.push(insert_elapsed);
        indexed_samples.push(indexed_elapsed);
        scan_samples.push(scan_elapsed);
        insert_total += insert_elapsed;
        indexed_total += indexed_elapsed;
        scan_total += scan_elapsed;
        indexed_rows_returned = indexed_rows_returned.saturating_add(indexed_rows);
        scan_rows_returned = scan_rows_returned.saturating_add(scan_rows);
    }

    let plans = runner.plans(&workload, &keys)?;
    let statements_executed = runner.statements_executed().saturating_sub(statement_start);
    let insert_ns = insert_total.as_nanos();
    let indexed_select_ns = indexed_total.as_nanos();
    let scan_select_ns = scan_total.as_nanos();
    let speedup = speedup_x100(scan_select_ns, indexed_select_ns);
    let (insert_p50_ms, insert_p95_ms) = percentiles(&insert_samples)?;
    let (indexed_select_p50_ms, indexed_select_p95_ms) = percentiles(&indexed_samples)?;
    let (scan_select_p50_ms, scan_select_p95_ms) = percentiles(&scan_samples)?;

    Ok(BenchmarkReport {
        workload,
        insert_ms: duration_ms(insert_total),
        indexed_select_ms: duration_ms(indexed_total),
        scan_select_ms: duration_ms(scan_total),
        insert_ns,
        indexed_select_ns,
        scan_select_ns,
        rows_returned: indexed_rows_returned.saturating_add(scan_rows_returned),
        indexed_rows_returned,
        scan_rows_returned,
        statements_executed,
        speedup_x100: speedup,
        insert_p50_ms,
        insert_p95_ms,
        indexed_select_p50_ms,
        indexed_select_p95_ms,
        scan_select_p50_ms,
        scan_select_p95_ms,
        plans,
    })
}

fn benchmark_model(name: &str, indexed: bool) -> Model {
    let mut model = Model {
        name: name.to_string(),
        fields: vec![
            Field {
                name: "id".to_string(),
                ty: FieldType::Int,
                primary: true,
                default: None,
            },
            Field {
                name: "score".to_string(),
                ty: FieldType::Int,
                primary: false,
                default: None,
            },
            Field {
                name: "payload".to_string(),
                ty: FieldType::Text,
                primary: false,
                default: None,
            },
        ],
        relations: Vec::new(),
        indexes: Vec::new(),
    };
    if indexed {
        model = model.index(INDEX_NAME, &["score"], false);
    }
    model
}

fn insert_sql(table: &str) -> String {
    // The payload column forces a real row lookup instead of a covering index.
    format!(
        "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?) \
         INSERT INTO {table} (id, score, payload) SELECT n, n, 'row-' || n FROM seq;"
    )
}

fn select_sql(table: &str) -> String {
    format!("SELECT * FROM {table} WHERE score = ?;")
}

/// Production runner over an injected in-memory `Sqlite` handle.
pub struct SqliteRunner {
    db: Sqlite,
    indexed_model: Model,
    plain_model: Model,
    schema: String,
}

impl SqliteRunner {
    pub fn new(db: Sqlite) -> Result<SqliteRunner, DbError> {
        let indexed_model = benchmark_model(INDEXED_TABLE, true);
        let plain_model = benchmark_model(PLAIN_TABLE, false);
        let schema = schema_sql(&[indexed_model.clone(), plain_model.clone()])?;
        Ok(SqliteRunner {
            db,
            indexed_model,
            plain_model,
            schema,
        })
    }

    fn select(&mut self, table: &str, keys: &[i64]) -> Result<u64, DbError> {
        let sql = select_sql(table);
        let mut rows_returned = 0u64;
        for &key in keys {
            let rows = self.db.query_params(&sql, &[Value::Int(key)])?;
            rows_returned =
                rows_returned.saturating_add(u64::try_from(rows.len()).unwrap_or(u64::MAX));
        }
        Ok(rows_returned)
    }

    fn sqlite_plan(&mut self, sql: &str) -> Result<Vec<String>, DbError> {
        let rows = self.db.query(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                row.get("detail")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect())
    }
}

impl BenchmarkRunner for SqliteRunner {
    fn begin_run(&mut self) -> Result<(), DbError> {
        self.db.exec(&format!(
            "DROP TABLE IF EXISTS {INDEXED_TABLE}; DROP TABLE IF EXISTS {PLAIN_TABLE};"
        ))?;
        self.db.exec(&self.schema)
    }

    fn insert_rows(&mut self, rows: u32) -> Result<(), DbError> {
        let params = [Value::Int(i64::from(rows))];
        let indexed = insert_sql(INDEXED_TABLE);
        let plain = insert_sql(PLAIN_TABLE);
        self.db.exec_params(&indexed, &params)?;
        self.db.exec_params(&plain, &params)
    }

    fn prepare_selects(&mut self) -> Result<(), DbError> {
        self.db.exec("ANALYZE;")
    }

    fn select_indexed(&mut self, keys: &[i64]) -> Result<u64, DbError> {
        self.select(INDEXED_TABLE, keys)
    }

    fn select_scan(&mut self, keys: &[i64]) -> Result<u64, DbError> {
        self.select(PLAIN_TABLE, keys)
    }

    fn plans(&mut self, workload: &Workload, keys: &[i64]) -> Result<BenchmarkPlans, DbError> {
        let key = *keys
            .first()
            .ok_or_else(|| DbError::new("benchmark workload has no select keys"))?;
        let indexed_sql = format!("SELECT * FROM {INDEXED_TABLE} WHERE score = {key};");
        let scan_sql = format!("SELECT * FROM {PLAIN_TABLE} WHERE score = {key};");
        let sqlite_indexed = self.sqlite_plan(&indexed_sql)?;
        let sqlite_scan = self.sqlite_plan(&scan_sql)?;
        let filters = [Filter {
            field: "score",
            op: "=",
            value: Value::Int(key),
        }];
        let table_rows = u64::from(workload.rows);
        Ok(BenchmarkPlans {
            planner_indexed: plan_query(&Query::new(&self.indexed_model, &filters, table_rows)),
            planner_scan: plan_query(&Query::new(&self.plain_model, &filters, table_rows)),
            sqlite_indexed,
            sqlite_scan,
        })
    }

    fn statements_executed(&self) -> u64 {
        self.db.executed_statements()
    }
}

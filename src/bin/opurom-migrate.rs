use opurom_db::{parse_models, write_migrations, DbError};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("opurom-migrate: {e}");
            ExitCode::from(1)
        }
    }
}

fn usage() -> DbError {
    DbError::new("usage: opurom-migrate <fullstack-ir.json> -o <dir>")
}

fn parse_args() -> Result<(String, PathBuf), DbError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut input: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-o" || arg == "--output" {
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| DbError::new("missing directory after -o"))?;
            output = Some(PathBuf::from(value));
        } else if arg.starts_with('-') {
            return Err(DbError::new(format!("unknown option {arg:?}")));
        } else if input.is_none() {
            input = Some(arg.clone());
        } else {
            return Err(DbError::new("unexpected extra argument"));
        }
        i += 1;
    }
    Ok((
        input.ok_or_else(usage)?,
        normalize(output.ok_or_else(usage)?),
    ))
}

/// Callers may pass the migrations directory itself; use its parent as base.
fn normalize(out: PathBuf) -> PathBuf {
    if out.file_name().and_then(|s| s.to_str()) == Some("migrations") {
        match out.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        }
    } else {
        out
    }
}

fn run() -> Result<(), DbError> {
    let (input, out) = parse_args()?;
    let text = std::fs::read_to_string(&input)
        .map_err(|e| DbError::new(format!("cannot read IR {input:?}: {e}")))?;
    let models = parse_models(&text)?;
    for path in write_migrations(&models, &out)? {
        println!("{}", path.display());
    }
    Ok(())
}

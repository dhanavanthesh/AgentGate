mod catalogs;
mod corpus;
mod measurement;
mod oracle;
mod recursive;
mod report;

use std::env;
use std::fs;
use std::path::PathBuf;

use report::EvaluationReport;

fn main() -> Result<(), String> {
    let options = Options::parse()?;
    if matches!(
        options.suite.as_str(),
        "maskforge-memory" | "oc-earley-memory"
    ) {
        let engine = options
            .suite
            .strip_suffix("-memory")
            .ok_or_else(|| "invalid memory suite".to_owned())?;
        let completed = recursive::memory_exercise(engine, options.samples)?;
        let encoded = serde_json::to_string_pretty(&serde_json::json!({
            "format_version": 1,
            "engine": engine,
            "completed_sequences": completed,
            "measurement": "external process working set"
        }))
        .map_err(|error| error.to_string())?;
        if let Some(path) = options.output {
            fs::write(path, format!("{encoded}\n")).map_err(|error| error.to_string())?;
        } else {
            println!("{encoded}");
        }
        return Ok(());
    }
    let workloads = corpus::workloads();
    let recursive = if options.suite == "catalog" {
        Vec::new()
    } else {
        recursive::run(&workloads, options.warmup, options.samples)?
    };
    let catalogs = if options.suite == "recursive" {
        Vec::new()
    } else {
        catalogs::run(options.samples, options.suite == "smoke")?
    };
    let catalog_semantic_shapes = if options.suite == "recursive" {
        Vec::new()
    } else {
        catalogs::run_semantic_shapes(options.samples)?
    };
    let report = EvaluationReport {
        format_version: 1,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        threads: 1,
        warmup: options.warmup,
        samples: options.samples,
        agentgate_source: "source-manifest",
        maskforge_commit: env!("AGENTGATE_EVAL_MASKFORGE_REV"),
        oc_sidememory_commit: env!("AGENTGATE_EVAL_SIDE_MEMORY_REV"),
        oc_earley_commit: env!("AGENTGATE_EVAL_OC_EARLEY_REV"),
        recursive,
        catalogs,
        catalog_semantic_shapes,
    };
    let encoded = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    if let Some(path) = options.output {
        fs::write(path, format!("{encoded}\n")).map_err(|error| error.to_string())?;
    } else {
        println!("{encoded}");
    }
    Ok(())
}

struct Options {
    warmup: usize,
    samples: usize,
    suite: String,
    output: Option<PathBuf>,
}

impl Options {
    fn parse() -> Result<Self, String> {
        let mut warmup = 1;
        let mut samples = 3;
        let mut suite = "all".to_owned();
        let mut output = None;
        let mut arguments = env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--warmup" => warmup = parse_usize(arguments.next(), "--warmup")?,
                "--samples" => samples = parse_usize(arguments.next(), "--samples")?,
                "--suite" => {
                    suite = arguments
                        .next()
                        .ok_or_else(|| "--suite requires a value".to_owned())?
                }
                "--output" => {
                    output = Some(PathBuf::from(
                        arguments
                            .next()
                            .ok_or_else(|| "--output requires a path".to_owned())?,
                    ))
                }
                _ => return Err(format!("unknown argument: {argument}")),
            }
        }
        if warmup > 10 || samples == 0 || samples > 100 {
            return Err("warmup or sample count is outside the evaluator limits".to_owned());
        }
        if !matches!(
            suite.as_str(),
            "all" | "recursive" | "catalog" | "smoke" | "maskforge-memory" | "oc-earley-memory"
        ) {
            return Err("suite is not supported".to_owned());
        }
        Ok(Self {
            warmup,
            samples,
            suite,
            output,
        })
    }
}

fn parse_usize(value: Option<String>, name: &str) -> Result<usize, String> {
    value
        .ok_or_else(|| format!("{name} requires a value"))?
        .parse()
        .map_err(|_| format!("{name} must be an unsigned integer"))
}

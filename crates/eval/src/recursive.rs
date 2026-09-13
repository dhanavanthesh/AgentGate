use agentgate_core::routing::maskforge_compiler;
use agentgate_core::{PreparedVocabulary, VocabularySpec};
use maskforge_core::TokenId;
use oc_earley::vocabulary::Vocabulary;
use oc_earley::{CompileOptions, CompiledSchema, RuntimeLimits};
use serde::Serialize;

use crate::corpus::{oracle, within_contract_depth, Workload, CONTRACT_DEPTH_LIMIT};
use crate::measurement::{measure, Distribution};
use crate::oracle::verify_expectations;

#[derive(Serialize)]
pub struct EngineMetrics {
    pub compile: Distribution,
    pub session: Distribution,
    pub first_mask: Distribution,
    pub warm_mask: Distribution,
    pub advance_per_token: Distribution,
    pub recognizer_replay: Distribution,
    pub full_token_gate: Distribution,
}

#[derive(Serialize)]
pub struct WorkloadReport {
    pub name: &'static str,
    pub cases: usize,
    pub candidate_bytes: usize,
    pub maskforge: EngineMetrics,
    pub oc_earley: EngineMetrics,
    pub oracle_validation: Distribution,
    pub maskforge_tokens_per_second: f64,
    pub oc_earley_tokens_per_second: f64,
    pub maskforge_false_accepts: usize,
    pub maskforge_false_rejects: usize,
    pub oc_earley_false_accepts: usize,
    pub oc_earley_false_rejects: usize,
    pub engine_disagreements: usize,
    pub p95_full_token_gate_speedup: f64,
    pub oc_earley_backend: String,
    pub contract_depth_limit: usize,
    pub depth_boundaries: Vec<DepthBoundaryReport>,
}

#[derive(Serialize)]
pub struct DepthBoundaryReport {
    pub depth: usize,
    pub within_contract_limit: bool,
    pub schema_expected: bool,
    pub maskforge_accepts: bool,
    pub oc_earley_accepts: bool,
}

pub fn run(
    workloads: &[Workload],
    warmup: usize,
    samples: usize,
) -> Result<Vec<WorkloadReport>, String> {
    let prepared = PreparedVocabulary::new(
        VocabularySpec::byte_vocabulary().map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let earley_vocabulary = earley_vocabulary()?;
    let mut reports = Vec::with_capacity(workloads.len());
    for workload in workloads {
        verify_expectations(workload)?;
        for _ in 0..warmup {
            let _ = compile_maskforge(workload.schema, &prepared)?;
            let _ = compile_earley(workload.schema, &earley_vocabulary)?;
        }
        let mut mask_compile = Vec::with_capacity(samples);
        let mut earley_compile = Vec::with_capacity(samples);
        for _ in 0..samples {
            let (compiled, elapsed) = measure(|| compile_maskforge(workload.schema, &prepared));
            compiled?;
            mask_compile.push(elapsed);
            let (compiled, elapsed) =
                measure(|| compile_earley(workload.schema, &earley_vocabulary));
            compiled?;
            earley_compile.push(elapsed);
        }
        let mask = compile_maskforge(workload.schema, &prepared)?;
        let earley = compile_earley(workload.schema, &earley_vocabulary)?;
        let backend = format!("{:?}", earley.report.selected_backend);
        let mask_metrics = measure_maskforge(&mask, workload, samples)?;
        let earley_metrics = measure_earley(&earley, workload, samples)?;
        let candidate = workload
            .cases
            .iter()
            .find(|case| case.expected)
            .ok_or_else(|| "workload lacks valid candidate".to_owned())?
            .bytes
            .as_slice();
        let mut validation = Vec::with_capacity(samples);
        for _ in 0..samples {
            let (accepted, elapsed) = measure(|| oracle(workload.kind, candidate));
            if !accepted {
                return Err("independent oracle rejected its valid candidate".to_owned());
            }
            validation.push(elapsed);
        }
        let mut mask_false_accepts = 0;
        let mut mask_false_rejects = 0;
        let mut earley_false_accepts = 0;
        let mut earley_false_rejects = 0;
        let mut disagreements = 0;
        let mut depth_boundaries = Vec::new();
        for case in &workload.cases {
            let expected = oracle(workload.kind, &case.bytes);
            let mask_accepts = maskforge_accepts(&mask, &case.bytes);
            let earley_accepts = earley_accepts(&earley, &case.bytes);
            mask_false_accepts += usize::from(mask_accepts && !expected);
            mask_false_rejects += usize::from(!mask_accepts && expected);
            earley_false_accepts += usize::from(earley_accepts && !expected);
            earley_false_rejects += usize::from(!earley_accepts && expected);
            disagreements += usize::from(mask_accepts != earley_accepts);
            if let Some(depth) = case.depth {
                depth_boundaries.push(DepthBoundaryReport {
                    depth,
                    within_contract_limit: within_contract_depth(workload.kind, &case.bytes),
                    schema_expected: expected,
                    maskforge_accepts: mask_accepts,
                    oc_earley_accepts: earley_accepts,
                });
            }
        }
        let speedup = ratio(
            mask_metrics.full_token_gate.p95_ns,
            earley_metrics.full_token_gate.p95_ns,
        );
        reports.push(WorkloadReport {
            name: workload.name,
            cases: workload.cases.len(),
            candidate_bytes: candidate.len(),
            maskforge_tokens_per_second: throughput(
                candidate.len(),
                mask_metrics.full_token_gate.p50_ns,
            ),
            oc_earley_tokens_per_second: throughput(
                candidate.len(),
                earley_metrics.full_token_gate.p50_ns,
            ),
            maskforge: EngineMetrics {
                compile: Distribution::from_samples(mask_compile),
                ..mask_metrics
            },
            oc_earley: EngineMetrics {
                compile: Distribution::from_samples(earley_compile),
                ..earley_metrics
            },
            oracle_validation: Distribution::from_samples(validation),
            maskforge_false_accepts: mask_false_accepts,
            maskforge_false_rejects: mask_false_rejects,
            oc_earley_false_accepts: earley_false_accepts,
            oc_earley_false_rejects: earley_false_rejects,
            engine_disagreements: disagreements,
            p95_full_token_gate_speedup: speedup,
            oc_earley_backend: backend,
            contract_depth_limit: CONTRACT_DEPTH_LIMIT,
            depth_boundaries,
        });
    }
    Ok(reports)
}

fn measure_maskforge(
    bound: &maskforge_core::BoundSchema,
    workload: &Workload,
    samples: usize,
) -> Result<EngineMetrics, String> {
    let candidate = workload
        .cases
        .iter()
        .find(|case| case.expected)
        .ok_or_else(|| "workload lacks valid candidate".to_owned())?
        .bytes
        .as_slice();
    let mut sessions = Vec::with_capacity(samples);
    let mut first_masks = Vec::with_capacity(samples);
    let mut warm_masks = Vec::with_capacity(samples);
    let mut advances = Vec::with_capacity(samples);
    let mut recognizer_replay = Vec::with_capacity(samples);
    let mut full_token_gate = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (session, elapsed) =
            measure(|| bound.start_session().map_err(|error| error.to_string()));
        let mut session = session?;
        sessions.push(elapsed);
        let mut mask = vec![0; session.mask_vocab_size().div_ceil(32)];
        let (result, elapsed) = measure(|| {
            session
                .write_mask(&mut mask)
                .map_err(|error| error.to_string())
        });
        result?;
        first_masks.push(elapsed);
        let (result, elapsed) = measure(|| {
            session
                .write_mask(&mut mask)
                .map_err(|error| error.to_string())
        });
        result?;
        warm_masks.push(elapsed);
        let (result, elapsed) = measure(|| {
            for byte in candidate {
                let token = TokenId::try_from(usize::from(*byte)).expect("byte token");
                session.advance(token).map_err(|error| error.to_string())?;
            }
            Ok::<_, String>(session.is_accepting())
        });
        if !result? {
            return Err("MaskForge rejected the oracle-valid benchmark candidate".to_owned());
        }
        advances.push(elapsed / u64::try_from(candidate.len()).unwrap_or(1).max(1));
        let mut replay = bound.start_session().map_err(|error| error.to_string())?;
        let (accepted, elapsed) = measure(|| maskforge_advance_all(&mut replay, candidate));
        if !accepted {
            return Err("MaskForge recognizer replay rejected the valid candidate".to_owned());
        }
        recognizer_replay.push(elapsed);
        let mut gated = bound.start_session().map_err(|error| error.to_string())?;
        let mut gated_mask = vec![0; gated.mask_word_count()];
        let (accepted, elapsed) =
            measure(|| maskforge_gate_all(&mut gated, &mut gated_mask, candidate));
        if !accepted {
            return Err("MaskForge full token gate rejected the valid candidate".to_owned());
        }
        full_token_gate.push(elapsed);
    }
    Ok(EngineMetrics {
        compile: Distribution::from_samples(Vec::new()),
        session: Distribution::from_samples(sessions),
        first_mask: Distribution::from_samples(first_masks),
        warm_mask: Distribution::from_samples(warm_masks),
        advance_per_token: Distribution::from_samples(advances),
        recognizer_replay: Distribution::from_samples(recognizer_replay),
        full_token_gate: Distribution::from_samples(full_token_gate),
    })
}

fn measure_earley(
    compiled: &CompiledSchema,
    workload: &Workload,
    samples: usize,
) -> Result<EngineMetrics, String> {
    let candidate = workload
        .cases
        .iter()
        .find(|case| case.expected)
        .ok_or_else(|| "workload lacks valid candidate".to_owned())?
        .bytes
        .as_slice();
    let mut sessions = Vec::with_capacity(samples);
    let mut first_masks = Vec::with_capacity(samples);
    let mut warm_masks = Vec::with_capacity(samples);
    let mut advances = Vec::with_capacity(samples);
    let mut recognizer_replay = Vec::with_capacity(samples);
    let mut full_token_gate = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (guide, elapsed) = measure(|| compiled.guide(32, RuntimeLimits::default()));
        let mut guide = guide.map_err(|error| error.to_string())?;
        sessions.push(elapsed);
        let mut mask = vec![0; guide.mask_words()];
        let (result, elapsed) = measure(|| guide.fill_mask(&mut mask));
        result.map_err(|error| error.to_string())?;
        first_masks.push(elapsed);
        let (result, elapsed) = measure(|| guide.fill_mask(&mut mask));
        result.map_err(|error| error.to_string())?;
        warm_masks.push(elapsed);
        let (result, elapsed) = measure(|| {
            for byte in candidate {
                guide
                    .advance(u32::from(*byte))
                    .map_err(|error| error.to_string())?;
            }
            Ok::<_, String>(guide.is_accepting())
        });
        if !result? {
            return Err("OC-Earley rejected the oracle-valid benchmark candidate".to_owned());
        }
        advances.push(elapsed / u64::try_from(candidate.len()).unwrap_or(1).max(1));
        let mut replay = compiled
            .guide(32, RuntimeLimits::default())
            .map_err(|error| error.to_string())?;
        let (accepted, elapsed) = measure(|| earley_advance_all(&mut replay, candidate));
        if !accepted {
            return Err("OC-Earley recognizer replay rejected the valid candidate".to_owned());
        }
        recognizer_replay.push(elapsed);
        let mut gated = compiled
            .guide(32, RuntimeLimits::default())
            .map_err(|error| error.to_string())?;
        let mut gated_mask = vec![0; gated.mask_words()];
        let (accepted, elapsed) =
            measure(|| earley_gate_all(&mut gated, &mut gated_mask, candidate));
        if !accepted {
            return Err("OC-Earley full token gate rejected the valid candidate".to_owned());
        }
        full_token_gate.push(elapsed);
    }
    Ok(EngineMetrics {
        compile: Distribution::from_samples(Vec::new()),
        session: Distribution::from_samples(sessions),
        first_mask: Distribution::from_samples(first_masks),
        warm_mask: Distribution::from_samples(warm_masks),
        advance_per_token: Distribution::from_samples(advances),
        recognizer_replay: Distribution::from_samples(recognizer_replay),
        full_token_gate: Distribution::from_samples(full_token_gate),
    })
}

fn compile_maskforge(
    schema: &str,
    vocabulary: &PreparedVocabulary,
) -> Result<maskforge_core::BoundSchema, String> {
    maskforge_compiler(16 << 20, 16 << 20)
        .compile_json_schema(schema)
        .and_then(|program| program.bind(vocabulary.maskforge()))
        .map_err(|error| error.to_string())
}

fn compile_earley(schema: &str, vocabulary: &Vocabulary) -> Result<CompiledSchema, String> {
    CompiledSchema::compile(schema.as_bytes(), vocabulary, &CompileOptions::default())
        .map_err(|error| error.to_string())
}

fn earley_vocabulary() -> Result<Vocabulary, String> {
    let mut vocabulary = Vocabulary::new(256);
    for byte in u8::MIN..=u8::MAX {
        vocabulary
            .try_insert(vec![byte], u32::from(byte))
            .map_err(|error| error.to_string())?;
    }
    Ok(vocabulary)
}

fn maskforge_accepts(bound: &maskforge_core::BoundSchema, candidate: &[u8]) -> bool {
    let Ok(mut session) = bound.start_session() else {
        return false;
    };
    maskforge_advance_all(&mut session, candidate)
}

fn maskforge_advance_all(session: &mut maskforge_core::Session, candidate: &[u8]) -> bool {
    for byte in candidate {
        let Ok(token) = TokenId::try_from(usize::from(*byte)) else {
            return false;
        };
        if session.advance(token).is_err() {
            return false;
        }
    }
    session.is_accepting()
}

fn maskforge_gate_all(
    session: &mut maskforge_core::Session,
    mask: &mut [u32],
    candidate: &[u8],
) -> bool {
    for byte in candidate {
        if session.write_mask(mask).is_err() || !mask_contains(mask, u32::from(*byte)) {
            return false;
        }
        let Ok(token) = TokenId::try_from(usize::from(*byte)) else {
            return false;
        };
        if session.advance(token).is_err() {
            return false;
        }
    }
    session.is_accepting()
}

fn earley_accepts(compiled: &CompiledSchema, candidate: &[u8]) -> bool {
    let Ok(mut guide) = compiled.guide(32, RuntimeLimits::default()) else {
        return false;
    };
    earley_advance_all(&mut guide, candidate)
}

fn earley_advance_all(guide: &mut oc_earley::Guide, candidate: &[u8]) -> bool {
    candidate
        .iter()
        .all(|byte| guide.advance(u32::from(*byte)).is_ok())
        && guide.is_accepting()
}

fn earley_gate_all(guide: &mut oc_earley::Guide, mask: &mut [u32], candidate: &[u8]) -> bool {
    for byte in candidate {
        if guide.fill_mask(mask).is_err() || !mask_contains(mask, u32::from(*byte)) {
            return false;
        }
        if guide.advance(u32::from(*byte)).is_err() {
            return false;
        }
    }
    guide.is_accepting()
}

fn mask_contains(mask: &[u32], token: u32) -> bool {
    let Ok(index) = usize::try_from(token) else {
        return false;
    };
    mask.get(index / 32)
        .is_some_and(|word| word & (1_u32 << (index % 32)) != 0)
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn throughput(tokens: usize, elapsed_ns: u64) -> f64 {
    if elapsed_ns == 0 {
        0.0
    } else {
        tokens as f64 * 1_000_000_000.0 / elapsed_ns as f64
    }
}

pub fn memory_exercise(engine: &str, repeats: usize) -> Result<usize, String> {
    let workloads = crate::corpus::workloads();
    let prepared = PreparedVocabulary::new(
        VocabularySpec::byte_vocabulary().map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let earley_vocabulary = earley_vocabulary()?;
    let mut completed = 0usize;
    for workload in &workloads {
        let candidate = workload
            .cases
            .iter()
            .find(|case| case.expected && case.depth.is_none())
            .ok_or_else(|| "workload lacks a baseline candidate".to_owned())?
            .bytes
            .as_slice();
        match engine {
            "maskforge" => {
                let bound = compile_maskforge(workload.schema, &prepared)?;
                for _ in 0..repeats {
                    let mut session = bound.start_session().map_err(|error| error.to_string())?;
                    let mut mask = vec![0; session.mask_word_count()];
                    if !maskforge_gate_all(&mut session, &mut mask, candidate) {
                        return Err("MaskForge memory exercise rejected a candidate".to_owned());
                    }
                    completed = completed.saturating_add(1);
                }
            }
            "oc-earley" => {
                let compiled = compile_earley(workload.schema, &earley_vocabulary)?;
                for _ in 0..repeats.saturating_mul(20) {
                    let mut guide = compiled
                        .guide(32, RuntimeLimits::default())
                        .map_err(|error| error.to_string())?;
                    let mut mask = vec![0; guide.mask_words()];
                    if !earley_gate_all(&mut guide, &mut mask, candidate) {
                        return Err("OC-Earley memory exercise rejected a candidate".to_owned());
                    }
                    completed = completed.saturating_add(1);
                }
            }
            _ => return Err("memory engine must be maskforge or oc-earley".to_owned()),
        }
    }
    Ok(completed)
}

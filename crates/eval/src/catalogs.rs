use std::collections::BTreeSet;
use std::sync::Arc;

use agentgate_core::digest::{canonical_json, sha256_hex};
use agentgate_core::registry::{Registry, COMMENT_TOOL};
use agentgate_core::{PreparedVocabulary, ToolId, VocabularySpec};
use oc_sidememory::{
    compile_schema, CompileOptions, ExtensionPlanV1, Guide, GuideOptions, ImportedMemory,
};
use serde::Serialize;

use crate::measurement::{measure, Distribution};

pub const CONFIGURED_MAXIMUM: usize = 20_000;

#[derive(Serialize)]
pub struct CatalogReport {
    pub size: usize,
    pub input_bytes: usize,
    pub digest: String,
    pub import_build: Distribution,
    pub session_create: Distribution,
    pub first_mask: Distribution,
    pub warm_mask: Distribution,
    pub accepted_first_lookup: Distribution,
    pub accepted_middle_lookup: Distribution,
    pub accepted_last_lookup: Distribution,
    pub rejected_lookup: Distribution,
    pub accounted_retained_bytes: usize,
    pub alpha_from_previous: Option<f64>,
}

#[derive(Serialize)]
pub struct SemanticShapeReport {
    pub name: &'static str,
    pub candidates: usize,
    pub false_accepts: usize,
    pub false_rejects: usize,
    pub full_token_gate: Distribution,
}

pub fn run(samples: usize, smoke: bool) -> Result<Vec<CatalogReport>, String> {
    let registry = Registry::github().map_err(|error| error.to_string())?;
    let spec = registry
        .require_exact(&ToolId::new(COMMENT_TOOL, "1"))
        .map_err(|error| error.to_string())?;
    let mut reports = Vec::new();
    let mut previous: Option<(usize, u64)> = None;
    let sizes: &[usize] = if smoke {
        &[10, 100]
    } else {
        &[10, 100, 1_000, 10_000, CONFIGURED_MAXIMUM]
    };
    for &size in sizes {
        let values = catalog_values(size);
        let document = serde_json::json!({ "writable_issue_handles": values });
        let canonical = canonical_json(&document).map_err(|error| error.to_string())?;
        let digest = sha256_hex(canonical.as_bytes());
        let set: BTreeSet<_> = values.iter().cloned().collect();
        let first = values.first().ok_or_else(|| "empty catalog".to_owned())?;
        let middle = &values[values.len() / 2];
        let last = values.last().ok_or_else(|| "empty catalog".to_owned())?;
        let mut import_build = Vec::with_capacity(samples);
        let mut sessions = Vec::with_capacity(samples);
        let mut first_masks = Vec::with_capacity(samples);
        let mut warm_masks = Vec::with_capacity(samples);
        let mut first_lookup = Vec::with_capacity(samples);
        let mut middle_lookup = Vec::with_capacity(samples);
        let mut last_lookup = Vec::with_capacity(samples);
        let mut rejected_lookup = Vec::with_capacity(samples);
        for _ in 0..samples {
            let (imports, elapsed) = measure(|| {
                ImportedMemory::from_json("catalog-eval", "1", &canonical)
                    .map(Arc::new)
                    .map_err(|error| error.to_string())
            });
            let imports = imports?;
            import_build.push(elapsed);
            let (session, elapsed) = measure(|| spec.artifact.start_session(Some(imports), 32));
            let mut session = session.map_err(|error| error.to_string())?;
            sessions.push(elapsed);
            let mut mask = vec![0; session.mask_word_count()];
            let (result, elapsed) = measure(|| session.write_mask(&mut mask));
            result.map_err(|error| error.to_string())?;
            first_masks.push(elapsed);
            let (result, elapsed) = measure(|| session.write_mask(&mut mask));
            result.map_err(|error| error.to_string())?;
            warm_masks.push(elapsed);
            first_lookup.push(measure(|| set.contains(first)).1);
            middle_lookup.push(measure(|| set.contains(middle)).1);
            last_lookup.push(measure(|| set.contains(last)).1);
            rejected_lookup
                .push(measure(|| set.contains("github:tenant_acme:repo_R1:issue_missing")).1);
        }
        let import_build = Distribution::from_samples(import_build);
        let alpha_from_previous = previous.map(|(previous_size, previous_p95)| {
            let time_ratio = import_build.p95_ns as f64 / previous_p95.max(1) as f64;
            let size_ratio = size as f64 / previous_size as f64;
            time_ratio.ln() / size_ratio.ln()
        });
        previous = Some((size, import_build.p95_ns));
        reports.push(CatalogReport {
            size,
            input_bytes: canonical.len(),
            digest,
            import_build,
            session_create: Distribution::from_samples(sessions),
            first_mask: Distribution::from_samples(first_masks),
            warm_mask: Distribution::from_samples(warm_masks),
            accepted_first_lookup: Distribution::from_samples(first_lookup),
            accepted_middle_lookup: Distribution::from_samples(middle_lookup),
            accepted_last_lookup: Distribution::from_samples(last_lookup),
            rejected_lookup: Distribution::from_samples(rejected_lookup),
            accounted_retained_bytes: canonical.len().saturating_add(512),
            alpha_from_previous,
        });
    }
    Ok(reports)
}

pub fn run_semantic_shapes(samples: usize) -> Result<Vec<SemanticShapeReport>, String> {
    let prepared = PreparedVocabulary::new(
        VocabularySpec::byte_vocabulary().map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    semantic_shapes()
        .into_iter()
        .map(|shape| measure_shape(shape, &prepared, samples))
        .collect()
}

struct SemanticShape {
    name: &'static str,
    value_schema: &'static str,
    imports: serde_json::Value,
    cases: Vec<(Vec<u8>, bool)>,
}

fn semantic_shapes() -> Vec<SemanticShape> {
    vec![
        SemanticShape {
            name: "common_prefix_and_missing_string",
            value_schema: r#"{"type":"string"}"#,
            imports: serde_json::json!(["resource:0001", "resource:0002"]),
            cases: value_cases(&[
                (serde_json::json!("resource:0001"), true),
                (serde_json::json!("resource:0003"), false),
            ]),
        },
        SemanticShape {
            name: "unicode_distinct",
            value_schema: r#"{"type":"string"}"#,
            imports: serde_json::json!(["\u{00e9}"]),
            cases: value_cases(&[
                (serde_json::json!("\u{00e9}"), true),
                (serde_json::json!("e\u{301}"), false),
            ]),
        },
        SemanticShape {
            name: "exact_numeric_aliases",
            value_schema: r#"{"type":"number"}"#,
            imports: serde_json::json!([1]),
            cases: vec![
                (br#"{"value":1}"#.to_vec(), true),
                (br#"{"value":1.0}"#.to_vec(), true),
                (br#"{"value":1e0}"#.to_vec(), true),
                (br#"{"value":2}"#.to_vec(), false),
            ],
        },
        SemanticShape {
            name: "array_equality",
            value_schema: r#"{"type":"array","items":{"type":"number"},"minItems":2,"maxItems":2}"#,
            imports: serde_json::json!([[1, 2]]),
            cases: value_cases(&[
                (serde_json::json!([1, 2]), true),
                (serde_json::json!([1, 3]), false),
            ]),
        },
        SemanticShape {
            name: "object_key_order_independence",
            value_schema: r#"{"type":"object","properties":{"id":{"type":"number"},"name":{"type":"string"}},"required":["id","name"],"additionalProperties":false}"#,
            imports: serde_json::from_str(r#"[{"name":"a","id":1}]"#).expect("static JSON"),
            cases: vec![
                (br#"{"value":{"id":1,"name":"a"}}"#.to_vec(), true),
                (br#"{"value":{"id":1,"name":"b"}}"#.to_vec(), false),
            ],
        },
        SemanticShape {
            name: "duplicate_import_values",
            value_schema: r#"{"type":"string"}"#,
            imports: serde_json::json!(["same", "same"]),
            cases: value_cases(&[
                (serde_json::json!("same"), true),
                (serde_json::json!("different"), false),
            ]),
        },
    ]
}

fn value_cases(values: &[(serde_json::Value, bool)]) -> Vec<(Vec<u8>, bool)> {
    values
        .iter()
        .map(|(value, expected)| {
            (
                serde_json::to_vec(&serde_json::json!({ "value": value }))
                    .expect("static semantic candidate"),
                *expected,
            )
        })
        .collect()
}

fn measure_shape(
    shape: SemanticShape,
    prepared: &PreparedVocabulary,
    samples: usize,
) -> Result<SemanticShapeReport, String> {
    let schema = format!(
        r#"{{"type":"object","properties":{{"value":{}}},"required":["value"],"additionalProperties":false}}"#,
        shape.value_schema
    );
    let extension = ExtensionPlanV1::from_json(
        r#"{"version":1,"objects":[{"schemaPath":"$","propertyOrder":["value"],"relations":[{"targetProperty":"value","operator":"memberOf","import":"catalog"}]}]}"#,
    )
    .map_err(|error| error.to_string())?;
    let compiled = Arc::new(
        compile_schema(
            schema.as_bytes(),
            prepared.side_memory(),
            prepared.spec().model_width(),
            &CompileOptions {
                extension_plan: Some(extension),
                ..CompileOptions::default()
            },
        )
        .map_err(|error| error.to_string())?,
    );
    let import_document = serde_json::to_string(&serde_json::json!({ "catalog": shape.imports }))
        .map_err(|error| error.to_string())?;
    let imports = Arc::new(
        ImportedMemory::from_json("semantic-shape", "1", &import_document)
            .map_err(|error| error.to_string())?,
    );
    let mut false_accepts = 0;
    let mut false_rejects = 0;
    for (candidate, expected) in &shape.cases {
        let accepted = side_memory_accepts(Arc::clone(&compiled), Arc::clone(&imports), candidate)?;
        false_accepts += usize::from(accepted && !expected);
        false_rejects += usize::from(!accepted && *expected);
    }
    let mut timings = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (result, elapsed) = measure(|| {
            shape
                .cases
                .iter()
                .map(|(candidate, _)| {
                    side_memory_accepts(Arc::clone(&compiled), Arc::clone(&imports), candidate)
                })
                .collect::<Result<Vec<_>, _>>()
        });
        result?;
        timings.push(elapsed);
    }
    Ok(SemanticShapeReport {
        name: shape.name,
        candidates: shape.cases.len(),
        false_accepts,
        false_rejects,
        full_token_gate: Distribution::from_samples(timings),
    })
}

fn side_memory_accepts(
    compiled: Arc<oc_sidememory::CompiledSchema>,
    imports: Arc<ImportedMemory>,
    candidate: &[u8],
) -> Result<bool, String> {
    let mut guide = Guide::new_with_imports(compiled, GuideOptions::default(), imports)
        .map_err(|error| error.to_string())?;
    let mut mask = vec![0_u32; guide.model_width().div_ceil(32)];
    for byte in candidate {
        guide
            .write_mask(&mut mask)
            .map_err(|error| error.to_string())?;
        let token = usize::from(*byte);
        if mask
            .get(token / 32)
            .is_none_or(|word| word & (1_u32 << (token % 32)) == 0)
        {
            return Ok(false);
        }
        if guide.advance(u32::from(*byte)).is_err() {
            return Ok(false);
        }
    }
    guide.is_accepting().map_err(|error| error.to_string())
}

fn catalog_values(size: usize) -> Vec<String> {
    (0..size)
        .map(|index| format!("github:tenant_acme:repo_R1:issue_I{index:05}"))
        .collect()
}

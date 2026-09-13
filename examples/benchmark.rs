use std::fs;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Instant;

use agentgate_core::cache::ArtifactCache;
use agentgate_core::registry::{Registry, COMMENT_TOOL};
use agentgate_core::session::{GenerationConfig, GuideSession};
use agentgate_core::{
    ApprovalSemantics, ArtifactKey, ConversationId, GenerationNonce, OperationId, PrincipalId,
    Runtime, TenantId, ToolId, WriteRequest,
};

const WARMUP: usize = 10;
const SAMPLES: usize = 100;
const HANDLE: &str = "github:tenant_acme:repo_R1:issue_I12";

#[derive(Clone, Copy)]
struct Stats {
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_path = std::env::args().nth(1).ok_or("output path is required")?;
    for _ in 0..WARMUP {
        std::hint::black_box(Registry::github()?);
    }
    let mut registration = samples(|| Registry::github().map(std::hint::black_box))?;

    let runtime = Runtime::github()?;
    let principal = PrincipalId::new("user:42");
    let tenant = TenantId::new("tenant_acme");
    let nonce = GenerationNonce::new("benchmark-generation");
    let conversation = ConversationId::new("benchmark-conversation");
    let mut snapshot_latency = Vec::with_capacity(SAMPLES);
    for sample in 0..(WARMUP + SAMPLES) {
        let started = Instant::now();
        let snapshot = runtime.list_issues(
            principal.clone(),
            tenant.clone(),
            120_000,
            nonce.clone(),
            conversation.clone(),
        )?;
        if sample >= WARMUP {
            snapshot_latency.push(elapsed_ns(started));
        }
        std::hint::black_box(snapshot);
    }
    let snapshot = runtime.list_issues(
        principal.clone(),
        tenant.clone(),
        120_000,
        nonce.clone(),
        conversation.clone(),
    )?;
    runtime.inspect_issue(
        principal.clone(),
        tenant.clone(),
        &snapshot,
        HANDLE,
        conversation.clone(),
    )?;

    let registry = Registry::github()?;
    let spec = registry.require_exact(&ToolId::new(COMMENT_TOOL, "1"))?;
    let hit_cache = Arc::new(ArtifactCache::new(256, 16 * 1024 * 1024, 4));
    let hit_key = ArtifactKey::new("benchmark-hit");
    hit_cache.get_or_build(hit_key.clone(), 1024, || Ok(Arc::clone(&spec.artifact)))?;
    for _ in 0..WARMUP {
        std::hint::black_box(hit_cache.get_or_build(hit_key.clone(), 1024, || {
            panic!("prepared cache hit must not build")
        })?);
    }
    let mut cache_hit = samples(|| {
        hit_cache.get_or_build(hit_key.clone(), 1024, || {
            panic!("prepared cache hit must not build")
        })
    })?;
    let miss_cache = ArtifactCache::new(256, 16 * 1024 * 1024, 4);
    let mut miss_index = 0_u64;
    let mut cache_miss = samples(|| {
        miss_index = miss_index.saturating_add(1);
        miss_cache.get_or_build(
            ArtifactKey::new(format!("benchmark-miss-{miss_index}")),
            1024,
            || Ok(Arc::clone(&spec.artifact)),
        )
    })?;
    let mut cache_contention = contended_cache_hits(Arc::clone(&hit_cache), hit_key)?;
    let imports = snapshot.to_imports()?;
    let target = action("benchmark");
    let mut mask = Vec::new();
    let mut selection = Vec::new();
    let mut advance = Vec::new();
    let mut total_token = Vec::new();
    for sample in 0..(WARMUP + SAMPLES) {
        let config = GenerationConfig::exact(&spec);
        let mut session = GuideSession::new(Arc::clone(&spec), Some(Arc::clone(&imports)), config)?;
        let generated = session.generate_target(&target)?;
        if sample >= WARMUP {
            for ((mask_ns, select_ns), advance_ns) in generated
                .mask_ns
                .iter()
                .zip(&generated.selection_ns)
                .zip(&generated.advance_ns)
            {
                mask.push(*mask_ns);
                selection.push(*select_ns);
                advance.push(*advance_ns);
                total_token.push(
                    mask_ns
                        .saturating_add(*select_ns)
                        .saturating_add(*advance_ns),
                );
            }
        }
    }

    let mut end_to_end = Vec::with_capacity(SAMPLES);
    let mut execute = Vec::with_capacity(SAMPLES);
    let mut policy = Vec::with_capacity(SAMPLES);
    let mut approval = Vec::with_capacity(SAMPLES);
    let mut normalize = Vec::with_capacity(SAMPLES);
    for sample in 0..(WARMUP + SAMPLES) {
        let operation = OperationId::new(format!("benchmark-{sample}"));
        let approval_token =
            runtime.approval_for_comment(agentgate_core::CommentApprovalRequest {
                principal: &principal,
                tenant: &tenant,
                snapshot: &snapshot,
                issue_handle: HANDLE,
                body: "benchmark",
                operation_id: &operation,
                conversation_id: &conversation,
                ttl_ms: 30_000,
                semantics: ApprovalSemantics::OneTime,
            })?;
        let started = Instant::now();
        let receipt = runtime.run_write(WriteRequest {
            principal: principal.clone(),
            tenant: tenant.clone(),
            action_json: &target,
            snapshot: &snapshot,
            generation_nonce: &nonce,
            operation_id: operation,
            conversation_id: conversation.clone(),
            approval: &approval_token,
        })?;
        let elapsed = elapsed_ns(started);
        if sample >= WARMUP {
            end_to_end.push(elapsed);
            let retained = runtime.audit().retained()?.0;
            let entries = runtime.audit().page(retained.saturating_sub(1), 1)?;
            if let Some(entry) = entries.last() {
                execute.push(entry.latency.execute_ns);
                policy.push(entry.latency.policy_ns);
                approval.push(entry.latency.approve_ns);
                normalize.push(entry.latency.normalize_ns);
            }
        }
        std::hint::black_box(receipt);
    }
    let cache = registry.cache_stats()?;
    let report = format!(
        concat!(
            "{{\n",
            "  \"build_mode\": \"release\",\n",
            "  \"warmup\": {warmup},\n",
            "  \"samples\": {sample_count},\n",
            "  \"threads\": 1,\n",
            "  \"host\": {host:?},\n",
            "  \"model\": \"model-free deterministic target\",\n",
            "  \"tokenizer\": \"exact byte vocabulary\",\n",
            "  \"catalog_values\": {catalog_values},\n",
            "  \"catalog_bytes\": {catalog_bytes},\n",
            "  \"peak_rss_bytes\": null,\n",
            "  \"retained_rollback_bytes\": null,\n",
            "  \"oc_sidememory_commit\": \"1085aab4d96a99f73f1400caed05bda9959cbca7\",\n",
            "  \"maskforge_commit\": \"9426a469f91782821748e796a2d13e29c196606c\",\n",
            "  \"artifact_cache\": {{\"entries\":{cache_entries},\"accounted_bytes\":{cache_bytes},\"hits\":{cache_hits},\"misses\":{cache_misses}}},\n",
            "  \"latency_ns\": {{\n",
            "    \"registration_compile_bind\": {registration},\n",
            "    \"artifact_cache_hit\": {cache_hit},\n",
            "    \"artifact_cache_miss_insert\": {cache_miss},\n",
            "    \"artifact_cache_contended_hit\": {cache_contention},\n",
            "    \"snapshot_end_to_end\": {snapshot},\n",
            "    \"write_mask\": {mask},\n",
            "    \"selection\": {selection},\n",
            "    \"advance\": {advance},\n",
            "    \"total_token_gate\": {total_token},\n",
            "    \"policy\": {policy},\n",
            "    \"approval_validation\": {approval},\n",
            "    \"adapter_transaction\": {execute},\n",
            "    \"normalization\": {normalize},\n",
            "    \"end_to_end_write\": {end_to_end}\n",
            "  }}\n",
            "}}\n"
        ),
        warmup = WARMUP,
        sample_count = SAMPLES,
        host = std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "unknown".to_owned()),
        catalog_values = snapshot
            .values("writable_issue_handles")
            .map_or(0, <[String]>::len),
        catalog_bytes = snapshot.serialized_bytes(),
        cache_entries = cache.entries,
        cache_bytes = cache.accounted_bytes,
        cache_hits = cache.hits,
        cache_misses = cache.misses,
        registration = format_stats(stats(&mut registration)),
        cache_hit = format_stats(stats(&mut cache_hit)),
        cache_miss = format_stats(stats(&mut cache_miss)),
        cache_contention = format_stats(stats(&mut cache_contention)),
        snapshot = format_stats(stats(&mut snapshot_latency)),
        mask = format_stats(stats(&mut mask)),
        selection = format_stats(stats(&mut selection)),
        advance = format_stats(stats(&mut advance)),
        total_token = format_stats(stats(&mut total_token)),
        policy = format_stats(stats(&mut policy)),
        approval = format_stats(stats(&mut approval)),
        execute = format_stats(stats(&mut execute)),
        normalize = format_stats(stats(&mut normalize)),
        end_to_end = format_stats(stats(&mut end_to_end)),
    );
    fs::write(output_path, &report)?;
    print!("{report}");
    Ok(())
}

fn contended_cache_hits(
    cache: Arc<ArtifactCache>,
    key: ArtifactKey,
) -> Result<Vec<u64>, agentgate_core::GateError> {
    let barrier = Arc::new(Barrier::new(5));
    let measurements = Arc::new(Mutex::new(Vec::with_capacity(SAMPLES)));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let cache = Arc::clone(&cache);
        let key = key.clone();
        let barrier = Arc::clone(&barrier);
        let measurements = Arc::clone(&measurements);
        workers.push(thread::spawn(
            move || -> Result<(), agentgate_core::GateError> {
                barrier.wait();
                for _ in 0..(SAMPLES / 4) {
                    let started = Instant::now();
                    std::hint::black_box(cache.get_or_build(key.clone(), 1024, || {
                        panic!("prepared cache hit must not build")
                    })?);
                    let elapsed = elapsed_ns(started);
                    measurements
                        .lock()
                        .map_err(|_| {
                            agentgate_core::GateError::new(
                                agentgate_core::ErrorCode::InternalInvariant,
                                "benchmark measurement lock poisoned",
                            )
                        })?
                        .push(elapsed);
                }
                Ok(())
            },
        ));
    }
    barrier.wait();
    for worker in workers {
        worker.join().map_err(|_| {
            agentgate_core::GateError::new(
                agentgate_core::ErrorCode::InternalInvariant,
                "benchmark worker panicked",
            )
        })??;
    }
    Arc::try_unwrap(measurements)
        .map_err(|_| {
            agentgate_core::GateError::new(
                agentgate_core::ErrorCode::InternalInvariant,
                "benchmark measurements remained shared",
            )
        })?
        .into_inner()
        .map_err(|_| {
            agentgate_core::GateError::new(
                agentgate_core::ErrorCode::InternalInvariant,
                "benchmark measurement lock poisoned",
            )
        })
}

fn samples<T>(
    mut operation: impl FnMut() -> Result<T, agentgate_core::GateError>,
) -> Result<Vec<u64>, agentgate_core::GateError> {
    let mut values = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        std::hint::black_box(operation()?);
        values.push(elapsed_ns(started));
    }
    Ok(values)
}

fn action(body: &str) -> Vec<u8> {
    format!(
        "{{\"tool\":\"github.comment_issue\",\"issue_handle\":\"{HANDLE}\",\"body\":{}}}",
        serde_json::to_string(body).expect("static benchmark body serializes")
    )
    .into_bytes()
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn stats(values: &mut [u64]) -> Stats {
    values.sort_unstable();
    Stats {
        p50: percentile(values, 50),
        p95: percentile(values, 95),
        p99: percentile(values, 99),
        max: values.last().copied().unwrap_or(0),
    }
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let numerator = percentile.saturating_mul(values.len().saturating_sub(1));
    values[numerator.div_ceil(100)]
}

fn format_stats(stats: Stats) -> String {
    format!(
        "{{\"p50\":{},\"p95\":{},\"p99\":{},\"max\":{}}}",
        stats.p50, stats.p95, stats.p99, stats.max
    )
}

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import agentgate


MODEL_ID = "Qwen/Qwen2.5-0.5B-Instruct"


def peak_rss_bytes() -> int | None:
    if sys.platform != "win32":
        return None

    import ctypes

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("page_fault_count", ctypes.c_ulong),
            ("peak_working_set_size", ctypes.c_size_t),
            ("working_set_size", ctypes.c_size_t),
            ("quota_peak_paged_pool_usage", ctypes.c_size_t),
            ("quota_paged_pool_usage", ctypes.c_size_t),
            ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
            ("quota_non_paged_pool_usage", ctypes.c_size_t),
            ("pagefile_usage", ctypes.c_size_t),
            ("peak_pagefile_usage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    psapi.GetProcessMemoryInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ProcessMemoryCounters),
        ctypes.c_ulong,
    ]
    if not psapi.GetProcessMemoryInfo(
        kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
    return counters.peak_working_set_size


def main() -> None:
    cache_root = Path(os.environ.get("HF_HOME", ""))
    cached_model = cache_root / "hub" / "models--Qwen--Qwen2.5-0.5B-Instruct"
    if not cached_model.exists():
        print("SKIP: pinned Qwen2.5-0.5B-Instruct is not cached")
        return
    try:
        import oc_sidememory
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as error:
        print(f"SKIP: cached model dependency unavailable: {error.name}")
        return

    snapshots = sorted((cached_model / "snapshots").iterdir())
    if len(snapshots) != 1:
        raise RuntimeError("cached model must contain exactly one pinned snapshot")
    model_path = snapshots[0]
    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_path, local_files_only=True, dtype=torch.float32
    ).eval()
    runtime = agentgate.Runtime()
    snapshot = runtime.list_issues(ttl_ms=120_000, nonce="model-generation")
    schema = {
        "type": "object",
        "properties": {
            "tool": {"type": "string", "const": "github.comment_issue"},
            "issue_handle": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["tool", "issue_handle", "body"],
        "additionalProperties": False,
    }
    extensions = {
        "version": 1,
        "objects": [{
            "schemaPath": "$",
            "propertyOrder": ["tool", "issue_handle", "body"],
            "captures": [],
            "relations": [{
                "targetProperty": "issue_handle",
                "operator": "memberOf",
                "import": "writable_issue_handles",
            }],
        }],
    }
    vocabulary = oc_sidememory.Vocabulary.from_transformers(tokenizer)
    if vocabulary.get_eos_token_id() != tokenizer.eos_token_id:
        raise RuntimeError("VOCAB_MISMATCH: EOS identity differs")
    compiled = oc_sidememory.compile_schema(
        json.dumps(schema), vocabulary, model.config.vocab_size,
        extensions_json=json.dumps(extensions),
    )
    imports = oc_sidememory.ImportedMemory.from_json(
        snapshot.snapshot_id, snapshot.source_revision,
        json.dumps({"writable_issue_handles": snapshot.writable_issue_handles}),
    )
    guide = oc_sidememory.SidememoryGuide(compiled, imports=imports, max_rollback=32)
    prompt = (
        "Return only compact JSON. Comment on the supplied issue with a short thank-you. "
        f"The issue handle is {snapshot.writable_issue_handles[0]}."
    )
    messages = [
        {"role": "system", "content": "Return only JSON matching the required property order."},
        {"role": "user", "content": prompt},
    ]
    rendered = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    input_ids = tokenizer(rendered, return_tensors="pt").input_ids
    generated: list[int] = []
    past_key_values = None
    started = time.perf_counter()
    with torch.inference_mode():
        for _ in range(256):
            result = model(input_ids=input_ids, past_key_values=past_key_values, use_cache=True)
            past_key_values = result.past_key_values
            allowed = guide.get_tokens()
            if not allowed:
                raise RuntimeError("EMPTY_MASK")
            logits = result.logits[0, -1]
            if logits.shape[-1] != model.config.vocab_size:
                raise RuntimeError("VOCAB_MISMATCH: logits width differs")
            allowed_tensor = torch.tensor(allowed, dtype=torch.long)
            allowed_logits = logits[allowed_tensor]
            finite = torch.isfinite(allowed_logits)
            if not torch.any(finite):
                raise RuntimeError("NO_FINITE_ALLOWED_LOGIT")
            masked = torch.where(finite, allowed_logits, torch.tensor(float("-inf")))
            token = allowed_tensor[torch.argmax(masked)].item()
            guide.advance(token)
            if token == tokenizer.eos_token_id:
                if not (guide.is_terminated() or guide.is_accepting()):
                    raise RuntimeError("NOT_ACCEPTING")
                break
            generated.append(token)
            input_ids = torch.tensor([[token]], dtype=torch.long)
            if guide.is_accepting():
                break
        else:
            raise RuntimeError("TOKEN_BUDGET_EXCEEDED")
    if not guide.is_accepting():
        raise RuntimeError("NOT_ACCEPTING")
    output = tokenizer.decode(generated, skip_special_tokens=False)
    action = json.loads(output)
    runtime.inspect_issue(snapshot, action["issue_handle"])
    approval = runtime.approve_comment(
        snapshot,
        action["issue_handle"],
        action["body"],
        operation_id="model-operation",
    )
    receipt = runtime.comment_issue(
        snapshot,
        action["issue_handle"],
        action["body"],
        approval,
        operation_id="model-operation",
    )
    seconds = time.perf_counter() - started
    report = json.dumps({
        "model": MODEL_ID,
        "model_snapshot": model_path.name,
        "tokenizer": tokenizer.__class__.__name__,
        "tokens": len(generated),
        "elapsed_seconds": seconds,
        "tokens_per_second": len(generated) / seconds,
        "peak_rss_bytes": peak_rss_bytes(),
        "action": action,
        "receipt": receipt,
    }, ensure_ascii=False)
    output_path = os.environ.get("AGENTGATE_MODEL_OUTPUT")
    if output_path:
        Path(output_path).write_text(report + "\n", encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()

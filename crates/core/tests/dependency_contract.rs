use std::sync::Arc;

use oc_sidememory::{
    compile_schema, CompileOptions, ExtensionPlanV1, Guide, GuideOptions, ImportedMemory,
    Vocabulary,
};

fn membership_schema(property: &str, value_type: &str) -> (Vec<u8>, ExtensionPlanV1) {
    let schema = format!(
        r#"{{"type":"object","properties":{{"{property}":{{"type":"{value_type}"}}}},"required":["{property}"],"additionalProperties":false}}"#
    );
    let extension = format!(
        r#"{{"version":1,"objects":[{{"schemaPath":"$","propertyOrder":["{property}"],"relations":[{{"targetProperty":"{property}","operator":"memberOf","import":"allowed"}}]}}]}}"#
    );
    (
        schema.into_bytes(),
        ExtensionPlanV1::from_json(&extension).expect("extension compiles"),
    )
}

#[test]
fn sparse_and_whole_document_tokens_preserve_membership() {
    let document = br#"{"issue_handle":"github:tenant_acme:repo_R1:issue_I12"}"#;
    let eos = 2_000;
    let token = 1_337;
    let mut vocabulary = Vocabulary::new(eos);
    vocabulary
        .try_insert(document.to_vec(), token)
        .expect("sparse token inserts");
    let (schema, extension_plan) = membership_schema("issue_handle", "string");
    let options = CompileOptions {
        extension_plan: Some(extension_plan),
        ..CompileOptions::default()
    };
    let compiled =
        Arc::new(compile_schema(&schema, &vocabulary, 2_001, &options).expect("schema compiles"));
    let imports = Arc::new(
        ImportedMemory::from_json(
            "snapshot",
            "v1",
            r#"{"allowed":["github:tenant_acme:repo_R1:issue_I12"]}"#,
        )
        .expect("imports"),
    );
    let mut guide =
        Guide::new_with_imports(compiled, GuideOptions::default(), imports).expect("guide builds");
    assert!(
        guide.probe_sequence(&[token], true).expect("probe")
            == oc_sidememory::sidememory::SequenceDecision::Allow
    );
}

#[test]
fn exact_numbers_accept_aliases_and_large_integers() {
    let documents: [&[u8]; 3] = [
        br#"{"n":1.0}"#,
        br#"{"n":9007199254740993}"#,
        br#"{"n":-0}"#,
    ];
    let eos = 5_000;
    let mut vocabulary = Vocabulary::new(eos);
    for (offset, document) in documents.iter().enumerate() {
        let id = 1_000_u32 + u32::try_from(offset).expect("small test offset");
        vocabulary
            .try_insert(document.to_vec(), id)
            .expect("token inserts");
    }
    let (schema, extension_plan) = membership_schema("n", "number");
    let options = CompileOptions {
        extension_plan: Some(extension_plan),
        ..CompileOptions::default()
    };
    let compiled =
        Arc::new(compile_schema(&schema, &vocabulary, 5_001, &options).expect("schema compiles"));
    let imports = Arc::new(
        ImportedMemory::from_json("snapshot", "v1", r#"{"allowed":[1,9007199254740993,0]}"#)
            .expect("imports"),
    );
    for offset in 0..documents.len() {
        let mut guide = Guide::new_with_imports(
            Arc::clone(&compiled),
            GuideOptions::default(),
            Arc::clone(&imports),
        )
        .expect("guide builds");
        let id = 1_000_u32 + u32::try_from(offset).expect("small test offset");
        assert!(
            guide.probe_sequence(&[id], true).expect("probe")
                == oc_sidememory::sidememory::SequenceDecision::Allow
        );
    }
}

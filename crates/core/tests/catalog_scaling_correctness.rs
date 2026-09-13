use std::collections::BTreeSet;
use std::sync::Arc;

use oc_sidememory::{
    compile_schema, CompileOptions, ExtensionPlanV1, Guide, GuideOptions, ImportedMemory,
    Vocabulary,
};

const CONFIGURED_MAXIMUM: usize = 20_000;

#[test]
fn catalog_sizes_are_unique_ordered_and_importable() {
    let sizes = [10, 100, 1_000, 10_000, CONFIGURED_MAXIMUM];
    assert!(sizes.windows(2).all(|pair| pair[0] < pair[1]));

    for size in sizes {
        let values: Vec<_> = (0..size)
            .map(|index| format!("resource:tenant_acme:item_{index:05}"))
            .collect();
        let unique: BTreeSet<_> = values.iter().collect();
        assert_eq!(unique.len(), size);
        let document = serde_json::json!({ "catalog": values }).to_string();
        ImportedMemory::from_json("catalog-test", "1", &document).expect("bounded import");
    }
}

#[test]
fn semantic_shapes_pass_real_membership_masks() {
    assert_membership(
        r#"{"type":"string"}"#,
        r#"["resource:0001","resource:0002"]"#,
        &[
            (br#"{"value":"resource:0001"}"#, true),
            (br#"{"value":"resource:0003"}"#, false),
        ],
    );
    assert_membership(
        r#"{"type":"string"}"#,
        r#"["é","same","same"]"#,
        &[
            (br#"{"value":"\u00e9"}"#, true),
            (br#"{"value":"e\u0301"}"#, false),
            (br#"{"value":"same"}"#, true),
        ],
    );
    assert_membership(
        r#"{"type":"number"}"#,
        r#"[1]"#,
        &[
            (br#"{"value":1}"#, true),
            (br#"{"value":1.0}"#, true),
            (br#"{"value":1e0}"#, true),
            (br#"{"value":2}"#, false),
        ],
    );
    assert_membership(
        r#"{"type":"array","items":{"type":"number"},"minItems":2,"maxItems":2}"#,
        r#"[[1,2]]"#,
        &[
            (br#"{"value":[1,2]}"#, true),
            (br#"{"value":[1,3]}"#, false),
        ],
    );
    assert_membership(
        r#"{"type":"object","properties":{"id":{"type":"number"},"name":{"type":"string"}},"required":["id","name"],"additionalProperties":false}"#,
        r#"[{"name":"a","id":1}]"#,
        &[
            (br#"{"value":{"id":1,"name":"a"}}"#, true),
            (br#"{"value":{"id":1,"name":"b"}}"#, false),
        ],
    );
}

fn assert_membership(value_schema: &str, import_values: &str, cases: &[(&[u8], bool)]) {
    let eos = 2_000;
    let mut vocabulary = Vocabulary::new(eos);
    for (index, (candidate, _)) in cases.iter().enumerate() {
        vocabulary
            .try_insert(
                candidate.to_vec(),
                1_000 + u32::try_from(index).expect("bounded case index"),
            )
            .expect("candidate token");
    }
    let schema = format!(
        r#"{{"type":"object","properties":{{"value":{value_schema}}},"required":["value"],"additionalProperties":false}}"#
    );
    let extension = ExtensionPlanV1::from_json(
        r#"{"version":1,"objects":[{"schemaPath":"$","propertyOrder":["value"],"relations":[{"targetProperty":"value","operator":"memberOf","import":"catalog"}]}]}"#,
    )
    .expect("extension");
    let compiled = Arc::new(
        compile_schema(
            schema.as_bytes(),
            &vocabulary,
            2_001,
            &CompileOptions {
                extension_plan: Some(extension),
                ..CompileOptions::default()
            },
        )
        .expect("semantic schema"),
    );
    let imports = Arc::new(
        ImportedMemory::from_json(
            "shape-test",
            "1",
            &format!(r#"{{"catalog":{import_values}}}"#),
        )
        .expect("semantic imports"),
    );
    for (index, (_, expected)) in cases.iter().enumerate() {
        let token = 1_000 + u32::try_from(index).expect("bounded case index");
        let mut guide = Guide::new_with_imports(
            Arc::clone(&compiled),
            GuideOptions::default(),
            Arc::clone(&imports),
        )
        .expect("semantic guide");
        let mut mask = vec![0; 2_001_usize.div_ceil(32)];
        guide.write_mask(&mut mask).expect("semantic mask");
        let allowed =
            mask[usize::try_from(token / 32).expect("word index")] & (1_u32 << (token % 32)) != 0;
        assert_eq!(allowed, *expected, "membership decision differs");
        if *expected {
            guide.advance(token).expect("accepted candidate");
            assert!(guide.is_accepting().expect("accepting state"));
        }
    }
}

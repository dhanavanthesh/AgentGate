use serde_json::Value;

pub const CONTRACT_DEPTH_LIMIT: usize = 32;

#[derive(Clone, Copy)]
pub enum WorkloadKind {
    LinkedNode,
    RecursiveArray,
    BranchingTree,
}

pub struct Case {
    pub bytes: Vec<u8>,
    pub expected: bool,
    pub depth: Option<usize>,
}

pub struct Workload {
    pub name: &'static str,
    pub kind: WorkloadKind,
    pub schema: &'static str,
    pub cases: Vec<Case>,
}

pub fn workloads() -> Vec<Workload> {
    vec![
        Workload {
            name: "linked_node",
            kind: WorkloadKind::LinkedNode,
            schema: r##"{"$defs":{"node":{"type":"object","properties":{"next":{"anyOf":[{"type":"null"},{"$ref":"#/$defs/node"}]},"value":{"type":"integer"}},"required":["next","value"],"additionalProperties":false}},"$ref":"#/$defs/node"}"##,
            cases: linked_cases(),
        },
        Workload {
            name: "recursive_array",
            kind: WorkloadKind::RecursiveArray,
            schema: r##"{"$defs":{"node":{"type":"array","items":{"anyOf":[{"type":"integer"},{"$ref":"#/$defs/node"}]},"maxItems":4}},"$ref":"#/$defs/node"}"##,
            cases: array_cases(),
        },
        Workload {
            name: "branching_tree",
            kind: WorkloadKind::BranchingTree,
            schema: r##"{"$defs":{"node":{"type":"object","properties":{"children":{"type":"array","items":{"$ref":"#/$defs/node"},"maxItems":3},"label":{"type":"string"}},"required":["children","label"],"additionalProperties":false}},"$ref":"#/$defs/node"}"##,
            cases: tree_cases(),
        },
    ]
}

fn linked_cases() -> Vec<Case> {
    let mut cases = vec![
        plain(br#"{"next":null,"value":1}"#, true),
        plain(br#"{"next":{"next":null,"value":2},"value":1}"#, true),
        plain(br#"{"next":null}"#, false),
        plain(br#"{"next":false,"value":1}"#, false),
        plain(br#"{"next":null,"value":"1"}"#, false),
    ];
    cases.extend(depths().map(|depth| boundary(linked_value(depth), depth)));
    cases
}

fn array_cases() -> Vec<Case> {
    let mut cases = vec![
        plain(br#"[]"#, true),
        plain(br#"[1,[2,3],4]"#, true),
        plain(br#"[1,"x"]"#, false),
        plain(br#"[1,[2,"x"]]"#, false),
        plain(br#"[1,2,3,4,5]"#, false),
    ];
    cases.extend(depths().map(|depth| boundary(array_value(depth), depth)));
    cases
}

fn tree_cases() -> Vec<Case> {
    let mut cases = vec![
        plain(br#"{"children":[],"label":"root"}"#, true),
        plain(
            br#"{"children":[{"children":[],"label":"leaf"}],"label":"root"}"#,
            true,
        ),
        plain(br#"{"children":[],"label":1}"#, false),
        plain(br#"{"children":[null],"label":"root"}"#, false),
        plain(br#"{"children":[],"extra":1,"label":"root"}"#, false),
    ];
    cases.extend(depths().map(|depth| boundary(tree_value(depth), depth)));
    cases
}

fn depths() -> impl Iterator<Item = usize> {
    [0, 1, 31, CONTRACT_DEPTH_LIMIT, CONTRACT_DEPTH_LIMIT + 1].into_iter()
}

fn plain(bytes: &[u8], expected: bool) -> Case {
    Case {
        bytes: bytes.to_vec(),
        expected,
        depth: None,
    }
}

fn boundary(bytes: Vec<u8>, depth: usize) -> Case {
    Case {
        bytes,
        expected: true,
        depth: Some(depth),
    }
}

fn linked_value(depth: usize) -> Vec<u8> {
    let mut value = "null".to_owned();
    for _ in 0..=depth {
        value = format!(r#"{{"next":{value},"value":1}}"#);
    }
    value.into_bytes()
}

fn array_value(depth: usize) -> Vec<u8> {
    let mut value = "[]".to_owned();
    for _ in 0..depth {
        value = format!("[{value}]");
    }
    value.into_bytes()
}

fn tree_value(depth: usize) -> Vec<u8> {
    let mut value = r#"{"children":[],"label":"leaf"}"#.to_owned();
    for _ in 0..depth {
        value = format!(r#"{{"children":[{value}],"label":"node"}}"#);
    }
    value.into_bytes()
}

pub fn oracle(kind: WorkloadKind, bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice(bytes) else {
        return false;
    };
    match kind {
        WorkloadKind::LinkedNode => linked(&value, 0),
        WorkloadKind::RecursiveArray => array(&value, 0),
        WorkloadKind::BranchingTree => tree(&value, 0),
    }
}

pub fn within_contract_depth(kind: WorkloadKind, bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice(bytes) else {
        return false;
    };
    measured_depth(kind, &value).is_some_and(|depth| depth <= CONTRACT_DEPTH_LIMIT)
}

fn linked(value: &Value, depth: usize) -> bool {
    if depth > CONTRACT_DEPTH_LIMIT + 1 {
        return false;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == 2
        && object.get("value").is_some_and(Value::is_i64)
        && object
            .get("next")
            .is_some_and(|next| next.is_null() || linked(next, depth + 1))
}

fn array(value: &Value, depth: usize) -> bool {
    if depth > CONTRACT_DEPTH_LIMIT + 1 {
        return false;
    }
    let Some(values) = value.as_array() else {
        return false;
    };
    values.len() <= 4
        && values
            .iter()
            .all(|value| value.is_i64() || array(value, depth + 1))
}

fn tree(value: &Value, depth: usize) -> bool {
    if depth > CONTRACT_DEPTH_LIMIT + 1 {
        return false;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    let Some(children) = object.get("children").and_then(Value::as_array) else {
        return false;
    };
    object.len() == 2
        && object.get("label").is_some_and(Value::is_string)
        && children.len() <= 3
        && children.iter().all(|child| tree(child, depth + 1))
}

fn measured_depth(kind: WorkloadKind, value: &Value) -> Option<usize> {
    match kind {
        WorkloadKind::LinkedNode => {
            let next = value.as_object()?.get("next")?;
            if next.is_null() {
                Some(0)
            } else {
                measured_depth(kind, next)?.checked_add(1)
            }
        }
        WorkloadKind::RecursiveArray => {
            let values = value.as_array()?;
            values
                .iter()
                .filter(|value| value.is_array())
                .map(|value| measured_depth(kind, value))
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .max()
                .unwrap_or(0)
                .checked_add(usize::from(values.iter().any(Value::is_array)))
        }
        WorkloadKind::BranchingTree => {
            let children = value.as_object()?.get("children")?.as_array()?;
            children
                .iter()
                .map(|child| measured_depth(kind, child))
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .max()
                .unwrap_or(0)
                .checked_add(usize::from(!children.is_empty()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_recursive_shape_covers_the_depth_boundary() {
        for workload in workloads() {
            let observed: Vec<_> = workload
                .cases
                .iter()
                .filter_map(|case| case.depth)
                .collect();
            assert_eq!(observed, [0, 1, 31, 32, 33]);
            for case in workload.cases.iter().filter(|case| case.depth.is_some()) {
                assert!(oracle(workload.kind, &case.bytes));
                assert_eq!(
                    within_contract_depth(workload.kind, &case.bytes),
                    case.depth.expect("depth") <= CONTRACT_DEPTH_LIMIT
                );
            }
        }
    }
}

use std::collections::BTreeSet;

fn next_bytes(language: &[&[u8]], prefix: &[u8]) -> BTreeSet<u8> {
    language
        .iter()
        .filter_map(|word| {
            word.strip_prefix(prefix)
                .and_then(|rest| rest.first())
                .copied()
        })
        .collect()
}

#[test]
fn intersected_next_tokens_do_not_prove_a_common_completion() {
    let first: &[&[u8]] = &[b"ab"];
    let second: &[&[u8]] = &[b"ac"];
    let initial: BTreeSet<_> = next_bytes(first, b"")
        .intersection(&next_bytes(second, b""))
        .copied()
        .collect();
    assert_eq!(initial, BTreeSet::from(*b"a"));
    assert!(next_bytes(first, b"a").is_disjoint(&next_bytes(second, b"a")));
    assert!(!first.iter().any(|word| second.contains(word)));
}

#[test]
fn eos_requires_simultaneous_acceptance() {
    let first: &[&[u8]] = &[b"a"];
    let second: &[&[u8]] = &[b"a", b"ab"];
    let prefix = b"a";
    let first_accepting = first.contains(&prefix.as_slice());
    let second_accepting = second.contains(&prefix.as_slice());
    assert!(first_accepting && second_accepting);

    let different_prefix = b"ab";
    assert!(!first.contains(&different_prefix.as_slice()));
    assert!(second.contains(&different_prefix.as_slice()));
}

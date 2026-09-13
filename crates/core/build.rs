use std::env;
use std::path::Path;
use std::process::Command;

const MASKFORGE: &str = "9426a469f91782821748e796a2d13e29c196606c";
const SIDE_MEMORY: &str = "1085aab4d96a99f73f1400caed05bda9959cbca7";
const OC_EARLEY: &str = "cd2db9fb8eb66346bcbd2957f5646168fdcf46dd";

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_VERIFIED_PROVENANCE");
    if env::var_os("CARGO_FEATURE_VERIFIED_PROVENANCE").is_none() {
        println!("cargo:rustc-env=AGENTGATE_MASKFORGE_REV={MASKFORGE}");
        println!("cargo:rustc-env=AGENTGATE_SIDE_MEMORY_REV={SIDE_MEMORY}");
        println!("cargo:rustc-env=AGENTGATE_OC_EARLEY_REV={OC_EARLEY}");
        return;
    }
    verify("../../../maskforge", MASKFORGE, "AGENTGATE_MASKFORGE_REV");
    verify(
        "../../../oc-sidememory",
        SIDE_MEMORY,
        "AGENTGATE_SIDE_MEMORY_REV",
    );
    verify("../../../oc-earley", OC_EARLEY, "AGENTGATE_OC_EARLEY_REV");
}

fn verify(relative: &str, expected: &str, variable: &str) {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest directory");
    let repository = Path::new(&manifest).join(relative);
    println!(
        "cargo:rerun-if-changed={}",
        repository.join(".git/HEAD").display()
    );
    let output = Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git is required for verified local dependency provenance");
    assert!(output.status.success(), "dependency revision lookup failed");
    let observed = String::from_utf8(output.stdout)
        .expect("dependency revision must be UTF-8")
        .trim()
        .to_owned();
    assert_eq!(observed, expected, "dependency revision differs");
    println!("cargo:rustc-env={variable}={observed}");
}

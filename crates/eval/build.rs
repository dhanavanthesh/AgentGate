use std::env;
use std::path::Path;
use std::process::Command;

const REVISIONS: [(&str, &str, &str); 3] = [
    (
        "../../../maskforge",
        "9426a469f91782821748e796a2d13e29c196606c",
        "AGENTGATE_EVAL_MASKFORGE_REV",
    ),
    (
        "../../../oc-sidememory",
        "1085aab4d96a99f73f1400caed05bda9959cbca7",
        "AGENTGATE_EVAL_SIDE_MEMORY_REV",
    ),
    (
        "../../../oc-earley",
        "cd2db9fb8eb66346bcbd2957f5646168fdcf46dd",
        "AGENTGATE_EVAL_OC_EARLEY_REV",
    ),
];

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest directory");
    for (relative, expected, variable) in REVISIONS {
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
            .expect("git is required for evaluator provenance");
        assert!(output.status.success(), "dependency revision lookup failed");
        let observed = String::from_utf8(output.stdout)
            .expect("dependency revision must be UTF-8")
            .trim()
            .to_owned();
        assert_eq!(observed, expected, "dependency revision differs");
        println!("cargo:rustc-env={variable}={observed}");
    }
}

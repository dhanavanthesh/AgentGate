use crate::corpus::{oracle, Workload};

pub fn verify_expectations(workload: &Workload) -> Result<(), String> {
    for case in &workload.cases {
        let observed = oracle(workload.kind, &case.bytes);
        if observed != case.expected {
            return Err(format!(
                "independent oracle expectation differs for {}",
                workload.name
            ));
        }
    }
    Ok(())
}

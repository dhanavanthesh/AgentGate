use serde::Serialize;

use crate::catalogs::{CatalogReport, SemanticShapeReport};
use crate::recursive::WorkloadReport;

#[derive(Serialize)]
pub struct EvaluationReport {
    pub format_version: u32,
    pub build_profile: &'static str,
    pub threads: usize,
    pub warmup: usize,
    pub samples: usize,
    pub agentgate_source: &'static str,
    pub maskforge_commit: &'static str,
    pub oc_sidememory_commit: &'static str,
    pub oc_earley_commit: &'static str,
    pub recursive: Vec<WorkloadReport>,
    pub catalogs: Vec<CatalogReport>,
    pub catalog_semantic_shapes: Vec<SemanticShapeReport>,
}

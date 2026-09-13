use std::sync::Arc;

use maskforge_core::{BoundSchema, Session as MaskForgeSession, TokenId as MaskForgeTokenId};
use oc_earley::{CompiledSchema as OcEarleyCompiledSchema, Guide as OcEarleyGuide, RuntimeLimits};
use oc_sidememory::sidememory::{Guide, GuideError, GuideOptions, ImportedMemory};
use oc_sidememory::CompiledSchema;

use crate::error::{ErrorCode, GateError, GateResult};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EngineKind {
    SideMemory,
    MaskForge,
    OcEarley,
}

impl EngineKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SideMemory => "sidememory",
            Self::MaskForge => "maskforge",
            Self::OcEarley => "oc-earley",
        }
    }

    #[must_use]
    pub const fn version(self) -> &'static str {
        match self {
            Self::SideMemory => "0.1.0",
            Self::MaskForge => "0.1.1",
            Self::OcEarley => "0.1.0",
        }
    }

    #[must_use]
    pub const fn provenance(self) -> &'static str {
        match self {
            Self::SideMemory => {
                concat!(
                    "oc-sidememory@0.1.0+git.",
                    env!("AGENTGATE_SIDE_MEMORY_REV"),
                    ";profile=checked-json-extensions-v1"
                )
            }
            Self::MaskForge => {
                concat!(
                    "maskforge-core@0.1.1+git.",
                    env!("AGENTGATE_MASKFORGE_REV"),
                    ";profile=json-schema-2020-12"
                )
            }
            Self::OcEarley => {
                concat!(
                    "oc-earley@0.1.0+git.",
                    env!("AGENTGATE_OC_EARLEY_REV"),
                    ";profile=recursive-json-schema-v1"
                )
            }
        }
    }
}

pub struct SideMemoryArtifact {
    pub compiled: Arc<CompiledSchema>,
    pub model_width: usize,
    pub eos_token_id: u32,
}

pub struct MaskForgeArtifact {
    pub bound: BoundSchema,
}

pub struct OcEarleyArtifact {
    pub compiled: Arc<OcEarleyCompiledSchema>,
    pub model_width: usize,
    pub eos_token_id: u32,
}

pub enum EngineArtifact {
    SideMemory(Arc<SideMemoryArtifact>),
    MaskForge(Arc<MaskForgeArtifact>),
    OcEarley(Arc<OcEarleyArtifact>),
}

impl EngineArtifact {
    #[must_use]
    pub fn engine_kind(&self) -> EngineKind {
        match self {
            Self::SideMemory(_) => EngineKind::SideMemory,
            Self::MaskForge(_) => EngineKind::MaskForge,
            Self::OcEarley(_) => EngineKind::OcEarley,
        }
    }

    #[must_use]
    pub fn mask_word_count(&self) -> usize {
        self.model_width().div_ceil(32)
    }

    #[must_use]
    pub fn model_width(&self) -> usize {
        match self {
            Self::SideMemory(artifact) => artifact.model_width,
            Self::MaskForge(artifact) => artifact.bound.mask_vocab_size(),
            Self::OcEarley(artifact) => artifact.model_width,
        }
    }

    #[must_use]
    pub fn eos_token_id(&self) -> u32 {
        match self {
            Self::SideMemory(artifact) => artifact.eos_token_id,
            Self::MaskForge(artifact) => artifact.bound.eos_token_id().get(),
            Self::OcEarley(artifact) => artifact.eos_token_id,
        }
    }

    pub fn start_session(
        &self,
        imports: Option<Arc<ImportedMemory>>,
        max_rollback: usize,
    ) -> GateResult<EngineSession> {
        match self {
            Self::SideMemory(artifact) => {
                let options = GuideOptions {
                    max_rollback_tokens: max_rollback,
                    ..GuideOptions::default()
                };
                let guide = match imports {
                    Some(imports) => {
                        Guide::new_with_imports(Arc::clone(&artifact.compiled), options, imports)
                    }
                    None => Guide::new(Arc::clone(&artifact.compiled), options),
                }
                .map_err(map_side_error)?;
                Ok(EngineSession::SideMemory(Box::new(SideMemorySession {
                    guide,
                    eos_token_id: artifact.eos_token_id,
                })))
            }
            Self::MaskForge(artifact) => {
                if imports.is_some() {
                    return Err(GateError::new(
                        ErrorCode::InternalInvariant,
                        "MaskForge session cannot receive semantic imports",
                    ));
                }
                artifact
                    .bound
                    .start_session()
                    .map(|session| EngineSession::MaskForge(Box::new(session)))
                    .map_err(map_maskforge_error)
            }
            Self::OcEarley(artifact) => {
                if imports.is_some() {
                    return Err(GateError::new(
                        ErrorCode::InternalInvariant,
                        "OC-Earley session cannot receive semantic imports",
                    ));
                }
                artifact
                    .compiled
                    .guide(max_rollback, RuntimeLimits::default())
                    .map(|guide| EngineSession::OcEarley(Box::new(guide)))
                    .map_err(map_oc_earley_error)
            }
        }
    }
}

pub struct SideMemorySession {
    guide: Guide,
    eos_token_id: u32,
}

pub enum EngineSession {
    SideMemory(Box<SideMemorySession>),
    MaskForge(Box<MaskForgeSession>),
    OcEarley(Box<OcEarleyGuide>),
}

impl EngineSession {
    #[must_use]
    pub fn engine_kind(&self) -> EngineKind {
        match self {
            Self::SideMemory(_) => EngineKind::SideMemory,
            Self::MaskForge(_) => EngineKind::MaskForge,
            Self::OcEarley(_) => EngineKind::OcEarley,
        }
    }

    #[must_use]
    pub fn mask_word_count(&self) -> usize {
        self.model_width().div_ceil(32)
    }

    #[must_use]
    pub fn model_width(&self) -> usize {
        match self {
            Self::SideMemory(session) => session.guide.model_width(),
            Self::MaskForge(session) => session.mask_vocab_size(),
            Self::OcEarley(session) => session.vocab_size(),
        }
    }

    #[must_use]
    pub fn eos_token_id(&self) -> u32 {
        match self {
            Self::SideMemory(session) => session.eos_token_id,
            Self::MaskForge(session) => session.eos_token_id().get(),
            Self::OcEarley(session) => session.eos_token_id(),
        }
    }

    pub fn write_mask(&mut self, mask: &mut [u32]) -> GateResult<()> {
        match self {
            Self::SideMemory(session) => session
                .guide
                .write_mask(mask)
                .map(|_| ())
                .map_err(map_side_error),
            Self::MaskForge(session) => session.write_mask(mask).map_err(map_maskforge_error),
            Self::OcEarley(session) => session.fill_mask(mask).map_err(map_oc_earley_error),
        }
    }

    pub fn advance(&mut self, token_id: u32) -> GateResult<()> {
        match self {
            Self::SideMemory(session) => session.guide.advance(token_id).map_err(map_side_error),
            Self::MaskForge(session) => {
                let token =
                    MaskForgeTokenId::try_from(usize::try_from(token_id).map_err(|_| {
                        GateError::new(ErrorCode::VocabMismatch, "token id conversion failed")
                    })?)
                    .map_err(|_| GateError::new(ErrorCode::VocabMismatch, "token id is invalid"))?;
                session.advance(token).map_err(map_maskforge_error)
            }
            Self::OcEarley(session) => session.advance(token_id).map_err(map_oc_earley_error),
        }
    }

    pub fn is_accepting(&mut self) -> GateResult<bool> {
        match self {
            Self::SideMemory(session) => session.guide.is_accepting().map_err(map_side_error),
            Self::MaskForge(session) => Ok(session.is_accepting()),
            Self::OcEarley(session) => Ok(session.is_accepting()),
        }
    }

    #[must_use]
    pub fn is_terminated(&self) -> bool {
        match self {
            Self::SideMemory(session) => session.guide.is_terminated(),
            Self::MaskForge(session) => session.is_stopped(),
            Self::OcEarley(session) => session.is_finished(),
        }
    }

    pub fn reset(&mut self) -> GateResult<()> {
        match self {
            Self::SideMemory(session) => session.guide.reset().map_err(map_side_error),
            Self::MaskForge(session) => session.reset().map_err(map_maskforge_error),
            Self::OcEarley(session) => session.reset().map_err(map_oc_earley_error),
        }
    }

    pub fn rollback(&mut self, count: usize) -> GateResult<()> {
        match self {
            Self::SideMemory(session) => session.guide.rollback(count).map_err(map_side_error),
            Self::MaskForge(_) => Err(GateError::new(
                ErrorCode::InvalidToolSpec,
                "selected engine does not expose cross-token rollback",
            )),
            Self::OcEarley(session) => session.rollback(count).map_err(map_oc_earley_error),
        }
    }
}

fn map_oc_earley_error(error: oc_earley::RuntimeError) -> GateError {
    let code = match error {
        oc_earley::RuntimeError::RejectedByte { .. }
        | oc_earley::RuntimeError::GuideFinished
        | oc_earley::RuntimeError::EosNotAccepting
        | oc_earley::RuntimeError::TokenNotAllowed { .. } => ErrorCode::TokenRejected,
        oc_earley::RuntimeError::UnknownTokenId { .. } => ErrorCode::VocabMismatch,
        oc_earley::RuntimeError::ResourceLimitExceeded { .. }
        | oc_earley::RuntimeError::AllocationFailed { .. } => ErrorCode::CatalogTooLarge,
        oc_earley::RuntimeError::RollbackUnavailable { .. }
        | oc_earley::RuntimeError::InvalidCheckpoint { .. } => ErrorCode::InvalidToolSpec,
        _ => ErrorCode::InternalInvariant,
    };
    GateError::new(code, "OC-Earley session operation failed")
}

fn map_side_error(error: GuideError) -> GateError {
    let code = match error {
        GuideError::MissingImport { .. } => ErrorCode::CatalogMissing,
        GuideError::Resource(_) => ErrorCode::CatalogTooLarge,
        GuideError::StructuralRejection { .. } | GuideError::SemanticRejection(_) => {
            ErrorCode::TokenRejected
        }
        GuideError::Vocabulary(_)
        | GuideError::UnknownToken { .. }
        | GuideError::InvalidMaskBuffer { .. } => ErrorCode::VocabMismatch,
        _ => ErrorCode::InternalInvariant,
    };
    GateError::new(code, "OC-Sidememory session operation failed")
}

fn map_maskforge_error(error: maskforge_core::SessionError) -> GateError {
    let code = match error {
        maskforge_core::SessionError::Matcher(maskforge_core::MatcherError::IllegalToken {
            ..
        })
        | maskforge_core::SessionError::IllegalToken { .. } => ErrorCode::TokenRejected,
        maskforge_core::SessionError::UnknownToken { .. }
        | maskforge_core::SessionError::MaskBufferLength { .. }
        | maskforge_core::SessionError::MaskByteBufferLength { .. }
        | maskforge_core::SessionError::MaskWidthOverflow { .. } => ErrorCode::VocabMismatch,
        maskforge_core::SessionError::SessionStopped => ErrorCode::TokenRejected,
        _ => ErrorCode::InternalInvariant,
    };
    GateError::new(code, "MaskForge session operation failed")
}

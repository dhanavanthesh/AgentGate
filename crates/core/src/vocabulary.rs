use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use maskforge_core::{CompiledVocabulary as MaskForgeVocabulary, Vocabulary as RawMaskForge};
use oc_earley::vocabulary::Vocabulary as OcEarleyVocabulary;
use oc_sidememory::Vocabulary as SideMemoryVocabulary;

use crate::digest::sha256_hex;
use crate::error::{ErrorCode, GateError, GateResult};

const FINGERPRINT_VERSION: &[u8] = b"agentgate-vocabulary-v1";

#[derive(Clone, Debug)]
pub struct VocabularySpec {
    model_width: usize,
    eos_id: u32,
    token_bytes: Arc<BTreeMap<u32, Arc<[u8]>>>,
    fingerprint: String,
    total_token_bytes: usize,
}

impl VocabularySpec {
    pub fn new(
        model_width: usize,
        eos_id: u32,
        entries: impl IntoIterator<Item = (u32, Vec<u8>)>,
        max_total_token_bytes: usize,
    ) -> GateResult<Self> {
        if model_width == 0
            || usize::try_from(eos_id)
                .ok()
                .is_none_or(|id| id >= model_width)
        {
            return Err(GateError::new(
                ErrorCode::VocabMismatch,
                "EOS id is outside model width",
            ));
        }
        let mut token_bytes = BTreeMap::new();
        let mut seen_ids = BTreeSet::new();
        let mut total_token_bytes = 0usize;
        for (id, bytes) in entries {
            if !seen_ids.insert(id) {
                return Err(GateError::new(
                    ErrorCode::VocabMismatch,
                    "duplicate token id",
                ));
            }
            if bytes.is_empty() || usize::try_from(id).ok().is_none_or(|id| id >= model_width) {
                return Err(GateError::new(
                    ErrorCode::VocabMismatch,
                    "token is empty or outside model width",
                ));
            }
            if id == eos_id {
                return Err(GateError::new(
                    ErrorCode::VocabMismatch,
                    "EOS id collides with an ordinary token",
                ));
            }
            total_token_bytes = total_token_bytes.checked_add(bytes.len()).ok_or_else(|| {
                GateError::new(ErrorCode::VocabMismatch, "token byte count overflow")
            })?;
            if total_token_bytes > max_total_token_bytes {
                return Err(GateError::new(
                    ErrorCode::CatalogTooLarge,
                    "vocabulary token bytes exceed limit",
                ));
            }
            token_bytes.insert(id, Arc::from(bytes));
        }
        if token_bytes.is_empty() {
            return Err(GateError::new(
                ErrorCode::VocabMismatch,
                "vocabulary has no ordinary tokens",
            ));
        }
        let mut material = Vec::new();
        push_field(&mut material, FINGERPRINT_VERSION)?;
        push_field(&mut material, &u64_bytes(model_width)?)?;
        push_field(&mut material, &eos_id.to_le_bytes())?;
        for (id, bytes) in &token_bytes {
            push_field(&mut material, &id.to_le_bytes())?;
            push_field(&mut material, bytes)?;
        }
        let fingerprint = sha256_hex(&material);
        Ok(Self {
            model_width,
            eos_id,
            token_bytes: Arc::new(token_bytes),
            fingerprint,
            total_token_bytes,
        })
    }

    pub fn byte_vocabulary() -> GateResult<Self> {
        Self::new(
            257,
            256,
            (u8::MIN..=u8::MAX).map(|byte| (u32::from(byte), vec![byte])),
            256,
        )
    }

    #[must_use]
    pub fn model_width(&self) -> usize {
        self.model_width
    }

    #[must_use]
    pub fn eos_id(&self) -> u32 {
        self.eos_id
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    #[must_use]
    pub fn token_bytes(&self, id: u32) -> Option<&[u8]> {
        self.token_bytes.get(&id).map(AsRef::as_ref)
    }

    pub fn entries(&self) -> impl Iterator<Item = (u32, &[u8])> {
        self.token_bytes
            .iter()
            .map(|(id, bytes)| (*id, bytes.as_ref()))
    }

    #[must_use]
    pub fn total_token_bytes(&self) -> usize {
        self.total_token_bytes
    }
}

pub struct PreparedVocabulary {
    spec: Arc<VocabularySpec>,
    side_memory: SideMemoryVocabulary,
    maskforge: MaskForgeVocabulary,
    oc_earley: OcEarleyVocabulary,
}

impl PreparedVocabulary {
    pub fn new(spec: VocabularySpec) -> GateResult<Self> {
        let spec = Arc::new(spec);
        let mut side_memory = SideMemoryVocabulary::new(spec.eos_id());
        let mut maskforge = RawMaskForge::new(spec.eos_id());
        let mut oc_earley = OcEarleyVocabulary::new(spec.eos_id());
        for (id, bytes) in spec.entries() {
            side_memory.try_insert(bytes.to_vec(), id).map_err(|_| {
                GateError::new(
                    ErrorCode::VocabMismatch,
                    "OC-Sidememory rejected vocabulary",
                )
            })?;
            maskforge.try_insert(bytes.to_vec(), id).map_err(|_| {
                GateError::new(ErrorCode::VocabMismatch, "MaskForge rejected vocabulary")
            })?;
            oc_earley.try_insert(bytes.to_vec(), id).map_err(|_| {
                GateError::new(ErrorCode::VocabMismatch, "OC-Earley rejected vocabulary")
            })?;
        }
        let maskforge =
            MaskForgeVocabulary::with_logits_vocab_size(Arc::new(maskforge), spec.model_width())
                .map_err(|_| {
                    GateError::new(
                        ErrorCode::VocabMismatch,
                        "MaskForge vocabulary binding failed",
                    )
                })?;
        Ok(Self {
            spec,
            side_memory,
            maskforge,
            oc_earley,
        })
    }

    #[must_use]
    pub fn spec(&self) -> &Arc<VocabularySpec> {
        &self.spec
    }

    #[must_use]
    pub fn side_memory(&self) -> &SideMemoryVocabulary {
        &self.side_memory
    }

    #[must_use]
    pub fn maskforge(&self) -> &MaskForgeVocabulary {
        &self.maskforge
    }

    #[must_use]
    pub fn oc_earley(&self) -> &OcEarleyVocabulary {
        &self.oc_earley
    }
}

fn u64_bytes(value: usize) -> GateResult<[u8; 8]> {
    u64::try_from(value)
        .map(u64::to_le_bytes)
        .map_err(|_| GateError::new(ErrorCode::VocabMismatch, "vocabulary width overflow"))
}

fn push_field(output: &mut Vec<u8>, field: &[u8]) -> GateResult<()> {
    let length = u64::try_from(field.len())
        .map_err(|_| GateError::new(ErrorCode::VocabMismatch, "fingerprint field overflow"))?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(field);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PreparedVocabulary, VocabularySpec};
    use crate::ErrorCode;

    #[test]
    fn fingerprint_covers_ids_bytes_width_and_eos() {
        let base = VocabularySpec::new(8, 7, [(1, b"a".to_vec()), (4, b"b".to_vec())], 8)
            .expect("valid sparse vocabulary");
        let same = VocabularySpec::new(8, 7, [(4, b"b".to_vec()), (1, b"a".to_vec())], 8)
            .expect("ordering is normalized");
        let changed = VocabularySpec::new(9, 7, [(1, b"a".to_vec()), (4, b"b".to_vec())], 8)
            .expect("different width is valid");
        assert_eq!(base.fingerprint(), same.fingerprint());
        assert_ne!(base.fingerprint(), changed.fingerprint());
        assert_eq!(base.token_bytes(4), Some(b"b".as_slice()));
        PreparedVocabulary::new(base).expect("both engines accept sparse ids");
    }

    #[test]
    fn invalid_vocabulary_fails_closed() {
        let duplicate = VocabularySpec::new(4, 3, [(1, vec![b'a']), (1, vec![b'b'])], 8)
            .expect_err("duplicate id");
        assert_eq!(duplicate.code, ErrorCode::VocabMismatch);
        assert!(VocabularySpec::new(4, 4, [(1, vec![b'a'])], 8).is_err());
        assert!(VocabularySpec::new(4, 3, [(1, Vec::new())], 8).is_err());
        assert!(VocabularySpec::new(4, 3, [(1, vec![b'a', b'b'])], 1).is_err());
        assert!(VocabularySpec::new(4, 3, [(3, vec![b'a'])], 8).is_err());
    }
}

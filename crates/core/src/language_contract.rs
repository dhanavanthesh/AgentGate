use crate::engine::EngineKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyOrder {
    ExtensionDefined,
    SchemaDefined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WhitespacePolicy {
    JsonInsignificant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnicodePolicy {
    ExactDecodedCodePoints,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumberPolicy {
    ExactJsonValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalEncodingPolicy {
    CompactJsonWithDeclaredObjectOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedSchemaOutcome {
    RegistrationFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LanguageLimits {
    pub max_generated_tokens: usize,
    pub max_rollback_tokens: usize,
    pub max_action_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferencePolicy {
    None,
    InternalOnly,
    ExplicitResourcesOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LanguageContract {
    pub engine: EngineKind,
    pub dialect: &'static str,
    pub profile: &'static str,
    pub profile_version: &'static str,
    pub property_order: PropertyOrder,
    pub whitespace: WhitespacePolicy,
    pub unicode: UnicodePolicy,
    pub numbers: NumberPolicy,
    pub canonical_encoding: CanonicalEncodingPolicy,
    pub references: ReferencePolicy,
    pub limits: LanguageLimits,
    pub unsupported_schema: UnsupportedSchemaOutcome,
    pub prefix_completion_is_checked: bool,
    pub eos_requires_accepting_state: bool,
    pub rejected_advance_is_atomic: bool,
    pub reset_restores_initial_state: bool,
    pub cross_token_rollback: bool,
}

#[must_use]
pub const fn language_contract(engine: EngineKind) -> LanguageContract {
    match engine {
        EngineKind::SideMemory => LanguageContract {
            engine,
            dialect: "JSON Schema Draft 2020-12 subset",
            profile: "checked structural profile with extensions-v1",
            profile_version: "sidememory-profile-v1",
            property_order: PropertyOrder::ExtensionDefined,
            whitespace: WhitespacePolicy::JsonInsignificant,
            unicode: UnicodePolicy::ExactDecodedCodePoints,
            numbers: NumberPolicy::ExactJsonValue,
            canonical_encoding: CanonicalEncodingPolicy::CompactJsonWithDeclaredObjectOrder,
            references: ReferencePolicy::None,
            limits: default_limits(),
            unsupported_schema: UnsupportedSchemaOutcome::RegistrationFailure,
            prefix_completion_is_checked: true,
            eos_requires_accepting_state: true,
            rejected_advance_is_atomic: true,
            reset_restores_initial_state: true,
            cross_token_rollback: true,
        },
        EngineKind::MaskForge => LanguageContract {
            engine,
            dialect: "JSON Schema Draft 2020-12",
            profile: "documented MaskForge supported profile",
            profile_version: "maskforge-json-schema-profile-v1",
            property_order: PropertyOrder::SchemaDefined,
            whitespace: WhitespacePolicy::JsonInsignificant,
            unicode: UnicodePolicy::ExactDecodedCodePoints,
            numbers: NumberPolicy::ExactJsonValue,
            canonical_encoding: CanonicalEncodingPolicy::CompactJsonWithDeclaredObjectOrder,
            references: ReferencePolicy::ExplicitResourcesOnly,
            limits: default_limits(),
            unsupported_schema: UnsupportedSchemaOutcome::RegistrationFailure,
            prefix_completion_is_checked: true,
            eos_requires_accepting_state: true,
            rejected_advance_is_atomic: true,
            reset_restores_initial_state: true,
            cross_token_rollback: false,
        },
        EngineKind::OcEarley => LanguageContract {
            engine,
            dialect: "JSON Schema Draft 2020-12 subset",
            profile: "measured recursive internal-reference profile",
            profile_version: "oc-earley-recursive-json-profile-v1",
            property_order: PropertyOrder::SchemaDefined,
            whitespace: WhitespacePolicy::JsonInsignificant,
            unicode: UnicodePolicy::ExactDecodedCodePoints,
            numbers: NumberPolicy::ExactJsonValue,
            canonical_encoding: CanonicalEncodingPolicy::CompactJsonWithDeclaredObjectOrder,
            references: ReferencePolicy::InternalOnly,
            limits: default_limits(),
            unsupported_schema: UnsupportedSchemaOutcome::RegistrationFailure,
            prefix_completion_is_checked: true,
            eos_requires_accepting_state: true,
            rejected_advance_is_atomic: true,
            reset_restores_initial_state: true,
            cross_token_rollback: true,
        },
    }
}

const fn default_limits() -> LanguageLimits {
    LanguageLimits {
        max_generated_tokens: 1024,
        max_rollback_tokens: 32,
        max_action_bytes: 128 * 1024,
    }
}

#[must_use]
pub const fn token_is_allowed(transition_remains_live: bool) -> bool {
    transition_remains_live
}

#[must_use]
pub const fn eos_is_allowed(accepting: bool) -> bool {
    accepting
}

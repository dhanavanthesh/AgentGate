use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_id!(PrincipalId);
string_id!(TenantId);
string_id!(SnapshotId);
string_id!(GenerationNonce);
string_id!(SourceRevision);
string_id!(OperationId);
string_id!(ActionDigest);
string_id!(SnapshotDigest);
string_id!(IdempotencyKey);
string_id!(OpaqueHandle);
string_id!(ConversationId);
string_id!(PolicyDigest);
string_id!(ApprovalId);
string_id!(ArtifactKey);
string_id!(ReceiptDigest);
string_id!(ReconciliationReference);

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ToolName(String);

impl ToolName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ToolVersion(String);

impl ToolVersion {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ToolId {
    name: ToolName,
    version: ToolVersion,
}

impl ToolId {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: ToolName::new(name),
            version: ToolVersion::new(version),
        }
    }

    pub fn name(&self) -> &ToolName {
        &self.name
    }
    pub fn version(&self) -> &ToolVersion {
        &self.version
    }
}

impl fmt::Display for ToolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name.as_str(), self.version.as_str())
    }
}

impl FromStr for ToolId {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, version) = value.rsplit_once('@').ok_or("tool id requires @version")?;
        if name.is_empty() || version.is_empty() {
            return Err("tool name and version are required");
        }
        Ok(Self::new(name, version))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::ToolId;

    #[test]
    fn tool_id_round_trips_and_rejects_malformed_values() {
        let parsed = ToolId::from_str("github.comment_issue@1").expect("valid tool id");
        assert_eq!(parsed.to_string(), "github.comment_issue@1");
        for malformed in ["github.comment_issue", "@1", "github.comment_issue@"] {
            assert!(ToolId::from_str(malformed).is_err(), "{malformed}");
        }
    }
}

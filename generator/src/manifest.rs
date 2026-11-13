//! Manifest types. The on-disk format is described by `schema/manifest.schema.json`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const SCHEMA_VERSION: &str = "0.2.0";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: String,
    pub built_with: BuiltWith,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuiltWith {
    pub stellar_xdr_crate: String,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub xdr_type: String,
    pub file: String,
    pub size: u64,
    pub sha256: String,
    pub caps: Vec<String>,
    pub protocol: Protocol,
    pub synthetic: bool,
    pub source: Source,
    pub shapes: Vec<String>,
    pub expect: Expect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<Build>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sightings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Protocol {
    pub introduced: u32,
    pub captured: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Source {
    #[serde(rename = "synthetic")]
    Synthetic {
        generator: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        network_passphrase: Option<String>,
    },
    #[serde(rename = "network")]
    Network {
        network_passphrase: String,
        ledger_seq: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        tx_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        retrieved_from: Option<String>,
    },
    #[serde(rename = "local-core")]
    LocalCore {
        core_version: String,
        network_passphrase: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ledger_seq: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scenario: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Expect {
    pub probe: String,
    pub values: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub may_refuse: Vec<String>,
}

/// Encode-side cases, for SDK builders that take untyped input such as strings.
///
/// `accept` lists canonical inputs and what the builder must encode for each.
/// `refuse` lists inputs that are not a canonical value in range; a builder must
/// raise an error for them instead of encoding some other value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Build {
    pub probe: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept: Vec<BuildAccept>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refuse: Vec<Map<String, Value>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuildAccept {
    pub input: Map<String, Value>,
    pub encodes: String,
}

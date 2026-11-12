//! Corpus entries taken from ledgers closed by stellar-core on a public network.
//!
//! The bytes are committed under `corpus/entries/`. Each entry pins the SHA-256 of
//! its file and the values a decoder must report. Those values were checked against
//! an independent source (Horizon) when the entry was added, and the generator
//! re-derives them from the bytes on every run.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    GeneralizedTransactionSet, LedgerCloseMeta, LedgerCloseMetaBatch, LedgerEntryChange,
    LedgerEntryChanges, LedgerEntryData, LedgerHeaderHistoryEntry, Limits, OperationBody, ReadXdr,
    SignerKey, TransactionEnvelope, TransactionMeta, TransactionPhase, TxSetComponent, WriteXdr,
};

use crate::entries::{Built, Network};
use crate::manifest::{Expect, Protocol, Source};
use crate::BoxError;

type Values = Map<String, Value>;
/// Re-derives an entry's expected values from its bytes.
type Derive = fn(&[u8], &Network) -> Result<Values, BoxError>;

struct Captured {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    xdr_type: &'static str,
    sha256: &'static str,
    caps: &'static [&'static str],
    introduced: u32,
    captured_protocol: u32,
    network: Network,
    ledger_seq: u32,
    tx_hash: Option<&'static str>,
    retrieved_from: &'static str,
    shapes: &'static [&'static str],
    probe: &'static str,
    values: fn() -> Value,
    derive: Derive,
    sightings: &'static [&'static str],
}

const ENTRIES: &[Captured] = &[Captured {
    id: "testnet-4437357-signed-payload-signer",
    title: "Testnet ledger 4437357: an account adds a signed-payload signer",
    description: "A whole ledger as stellar-core emitted it. One SetOptions operation adds a \
                  CAP-0040 signed-payload signer, whose P address is longer than an account \
                  address. The signer appears in the transaction envelope and again in the \
                  account entry in the transaction meta.",
    xdr_type: "LedgerCloseMeta",
    sha256: "582e694b96bf69f894763909a1b058c1a2523d5634f2e0947393cee9765f4e0e",
    caps: &["CAP-0040"],
    introduced: 19,
    captured_protocol: 28,
    network: Network::TESTNET,
    ledger_seq: 4_437_357,
    tx_hash: Some("d9f78749cd01297cd5f22c7f2c798c9eec93d56f399e1c4cc2f8977ca52b9fed"),
    retrieved_from: "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/testnet/2025-12-18/FFBC9DFF--4416000-4479999/FFBC4A92--4437357.xdr.zst",
    shapes: &[
        "ledger-close-meta.v2",
        "signer.signed-payload.in-envelope",
        "signer.signed-payload.in-meta",
        "strkey.signed-payload",
    ],
    probe: "ledger_signed_payload_signers",
    values: || {
        json!({
            "ledger_seq": 4_437_357,
            "ledger_hash": "0984e28878f8b074c3710f52630f5b6bc5a369bf61a15e7364b6123edf1881b6",
            "protocol_version": 28,
            "tx_count": 12,
            "signers_in_envelopes": "PBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSAAAAAAB55LN6AANMS",
            "signers_in_meta": "PBCK2RYYLIYOSHBEL2FQLAVRSHRH3GP3ID476SGKBV7BEZHMQ6NSAAAAAAB55LN6AANMS",
            "signer_tx_hashes": "d9f78749cd01297cd5f22c7f2c798c9eec93d56f399e1c4cc2f8977ca52b9fed",
        })
    },
    derive: ledger_signed_payload_signers,
    sightings: &["https://github.com/stellar/wallet-backend/pull/729"],
}];

pub fn all(captured_from: &Path) -> Result<Vec<Built>, BoxError> {
    ENTRIES.iter().map(|e| load(e, captured_from)).collect()
}

fn load(entry: &Captured, captured_from: &Path) -> Result<Built, BoxError> {
    let path = captured_from
        .join("entries")
        .join(format!("{}.xdr", entry.id));
    let bytes = fs::read(&path).map_err(|e| {
        format!(
            "{}: cannot read {}: {e}. Captured entries are committed files; restore it or \
             re-import it with `import-ledger` from {}",
            entry.id,
            path.display(),
            entry.retrieved_from
        )
    })?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if sha256 != entry.sha256 {
        return Err(format!(
            "{}: {} has sha256 {sha256}, the generator pins {}",
            entry.id,
            path.display(),
            entry.sha256
        )
        .into());
    }

    let Value::Object(pinned) = (entry.values)() else {
        return Err(format!("{}: pinned values are not an object", entry.id).into());
    };
    let derived = (entry.derive)(&bytes, &entry.network)?;
    if derived != pinned {
        return Err(format!(
            "{}: values derived from the bytes differ from the pinned values\n derived: {}\n pinned:  {}",
            entry.id,
            Value::Object(derived),
            Value::Object(pinned)
        )
        .into());
    }

    Ok(Built {
        id: entry.id,
        title: entry.title,
        description: entry.description,
        xdr_type: entry.xdr_type,
        bytes,
        caps: entry.caps,
        protocol: Protocol {
            introduced: entry.introduced,
            captured: entry.captured_protocol,
        },
        source: Source::Network {
            network_passphrase: entry.network.passphrase.into(),
            ledger_seq: entry.ledger_seq,
            tx_hash: entry.tx_hash.map(Into::into),
            retrieved_from: Some(entry.retrieved_from.into()),
        },
        shapes: entry.shapes,
        expect: Expect {
            probe: entry.probe.into(),
            values: pinned,
            may_refuse: vec![],
        },
        sightings: entry.sightings,
    })
}

/// Extracts the single ledger from an uncompressed Galexie batch file and returns
/// its XDR. The bytes are checked to re-encode identically.
pub fn ledger_from_batch(batch: &[u8]) -> Result<(u32, Vec<u8>), BoxError> {
    let decoded = LedgerCloseMetaBatch::from_xdr(batch, Limits::none())?;
    if decoded.to_xdr(Limits::none())? != batch {
        return Err("batch does not re-encode to the same bytes".into());
    }
    if decoded.start_sequence != decoded.end_sequence || decoded.ledger_close_metas.len() != 1 {
        return Err(format!(
            "expected a batch holding one ledger, got {}..={} with {} ledgers",
            decoded.start_sequence,
            decoded.end_sequence,
            decoded.ledger_close_metas.len()
        )
        .into());
    }
    let ledger = decoded
        .ledger_close_metas
        .first()
        .ok_or("batch holds no ledger")?;
    Ok((decoded.start_sequence, ledger.to_xdr(Limits::none())?))
}

/// The parts of a ledger the probe reads, for the `LedgerCloseMeta` versions that
/// carry a generalized transaction set.
struct LedgerParts<'a> {
    header: &'a LedgerHeaderHistoryEntry,
    tx_set: &'a GeneralizedTransactionSet,
    /// Every ledger entry change list in the ledger, in order.
    changes: Vec<&'a LedgerEntryChanges>,
    tx_count: usize,
}

fn meta_changes(meta: &TransactionMeta) -> Result<Vec<&LedgerEntryChanges>, BoxError> {
    Ok(match meta {
        TransactionMeta::V0(ops) => ops.iter().map(|op| &op.changes).collect(),
        TransactionMeta::V1(m) => std::iter::once(&m.tx_changes)
            .chain(m.operations.iter().map(|op| &op.changes))
            .collect(),
        TransactionMeta::V2(m) => std::iter::once(&m.tx_changes_before)
            .chain(m.operations.iter().map(|op| &op.changes))
            .chain(std::iter::once(&m.tx_changes_after))
            .collect(),
        TransactionMeta::V3(m) => std::iter::once(&m.tx_changes_before)
            .chain(m.operations.iter().map(|op| &op.changes))
            .chain(std::iter::once(&m.tx_changes_after))
            .collect(),
        TransactionMeta::V4(m) => std::iter::once(&m.tx_changes_before)
            .chain(m.operations.iter().map(|op| &op.changes))
            .chain(std::iter::once(&m.tx_changes_after))
            .collect(),
    })
}

fn ledger_parts(ledger: &LedgerCloseMeta) -> Result<LedgerParts<'_>, BoxError> {
    match ledger {
        LedgerCloseMeta::V0(_) => Err("LedgerCloseMeta v0 is not supported by this probe".into()),
        LedgerCloseMeta::V1(v1) => {
            let mut changes = Vec::new();
            for tx in v1.tx_processing.iter() {
                changes.push(&tx.fee_processing);
                changes.extend(meta_changes(&tx.tx_apply_processing)?);
            }
            Ok(LedgerParts {
                header: &v1.ledger_header,
                tx_set: &v1.tx_set,
                changes,
                tx_count: v1.tx_processing.len(),
            })
        }
        LedgerCloseMeta::V2(v2) => {
            let mut changes = Vec::new();
            for tx in v2.tx_processing.iter() {
                changes.push(&tx.fee_processing);
                changes.extend(meta_changes(&tx.tx_apply_processing)?);
                changes.push(&tx.post_tx_apply_fee_processing);
            }
            Ok(LedgerParts {
                header: &v2.ledger_header,
                tx_set: &v2.tx_set,
                changes,
                tx_count: v2.tx_processing.len(),
            })
        }
    }
}

fn envelopes(tx_set: &GeneralizedTransactionSet) -> Vec<&TransactionEnvelope> {
    let GeneralizedTransactionSet::V1(set) = tx_set;
    let mut out = Vec::new();
    for phase in set.phases.iter() {
        match phase {
            TransactionPhase::V0(components) => {
                for component in components.iter() {
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) = component;
                    out.extend(c.txs.iter());
                }
            }
            TransactionPhase::V1(parallel) => {
                for stage in parallel.execution_stages.iter() {
                    for cluster in stage.0.iter() {
                        out.extend(cluster.0.iter());
                    }
                }
            }
        }
    }
    out
}

fn operations(envelope: &TransactionEnvelope) -> &[stellar_xdr::Operation] {
    match envelope {
        TransactionEnvelope::TxV0(e) => e.tx.operations.as_slice(),
        TransactionEnvelope::Tx(e) => e.tx.operations.as_slice(),
        TransactionEnvelope::TxFeeBump(e) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &e.tx.inner_tx;
            inner.tx.operations.as_slice()
        }
    }
}

fn joined(set: BTreeSet<String>) -> Value {
    json!(set.into_iter().collect::<Vec<_>>().join(","))
}

/// Reports where signed-payload signers appear in a ledger: in the envelopes of the
/// transaction set, and in the account entries of the ledger entry changes.
fn ledger_signed_payload_signers(bytes: &[u8], network: &Network) -> Result<Values, BoxError> {
    let ledger = LedgerCloseMeta::from_xdr(bytes, Limits::none())?;
    let parts = ledger_parts(&ledger)?;

    let mut in_envelopes = BTreeSet::new();
    let mut tx_hashes = BTreeSet::new();
    for envelope in envelopes(parts.tx_set) {
        for op in operations(envelope) {
            let OperationBody::SetOptions(set_options) = &op.body else {
                continue;
            };
            let Some(signer) = &set_options.signer else {
                continue;
            };
            if let SignerKey::Ed25519SignedPayload(_) = &signer.key {
                in_envelopes.insert(signer.key.to_string());
                tx_hashes.insert(hex::encode(envelope.hash(network.id())?));
            }
        }
    }

    let mut in_meta = BTreeSet::new();
    for changes in &parts.changes {
        for change in changes.iter() {
            let entry = match change {
                LedgerEntryChange::Created(e)
                | LedgerEntryChange::Updated(e)
                | LedgerEntryChange::State(e)
                | LedgerEntryChange::Restored(e) => e,
                LedgerEntryChange::Removed(_) => continue,
            };
            let LedgerEntryData::Account(account) = &entry.data else {
                continue;
            };
            for signer in account.signers.iter() {
                if let SignerKey::Ed25519SignedPayload(_) = &signer.key {
                    in_meta.insert(signer.key.to_string());
                }
            }
        }
    }

    let Value::Object(values) = json!({
        "ledger_seq": parts.header.header.ledger_seq,
        "ledger_hash": hex::encode(parts.header.hash.0),
        "protocol_version": parts.header.header.ledger_version,
        "tx_count": parts.tx_count,
        "signers_in_envelopes": joined(in_envelopes),
        "signers_in_meta": joined(in_meta),
        "signer_tx_hashes": joined(tx_hashes),
    }) else {
        unreachable!("json! object literal");
    };
    Ok(values)
}

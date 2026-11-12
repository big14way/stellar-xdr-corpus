//! Synthetic corpus entries.
//!
//! Every builder is deterministic: keys are derived from fixed labels and nothing
//! reads the clock or a random source, so two runs produce the same bytes.

use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, AlphaNum4, Asset, AssetCode4, ChangeTrustAsset, ChangeTrustOp, DecoratedSignature,
    Limits, LiquidityPoolConstantProductParameters, LiquidityPoolParameters, Memo, MuxedAccount,
    MuxedAccountMed25519, Operation, OperationBody, PaymentOp, Preconditions, PublicKey, ScMap,
    ScMapEntry, ScString, ScSymbol, ScVal, SequenceNumber, Signature, SignatureHint, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, Validate, WriteXdr,
};

use crate::manifest::{Expect, Protocol, Source};
use crate::BoxError;

/// Fee charged by every constant-product pool, in basis points (CAP-0038).
const LIQUIDITY_POOL_FEE_V18: i32 = 30;
/// Smallest integer a 64-bit float cannot represent.
const FIRST_UNSAFE_INTEGER: u64 = (1 << 53) + 1;

/// An entry before it is written to disk.
pub struct Built {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub xdr_type: &'static str,
    pub bytes: Vec<u8>,
    pub caps: &'static [&'static str],
    pub protocol: Protocol,
    pub source: Source,
    pub shapes: &'static [&'static str],
    pub expect: Expect,
    pub sightings: &'static [&'static str],
}

/// The network a signed entry is built for.
pub struct Network {
    pub passphrase: &'static str,
}

impl Network {
    pub const TESTNET: Network = Network {
        passphrase: "Test SDF Network ; September 2015",
    };
    pub const PUBNET: Network = Network {
        passphrase: "Public Global Stellar Network ; September 2015",
    };

    fn id(&self) -> [u8; 32] {
        Sha256::digest(self.passphrase.as_bytes()).into()
    }
}

pub fn all(network: &Network, captured_protocol: u32) -> Result<Vec<Built>, BoxError> {
    let mut entries = vec![
        scval_map_keys_collide_as_native(captured_protocol)?,
        change_trust_pool_issuer_order(network, captured_protocol)?,
        payment_muxed_ids_beyond_f64(network, captured_protocol)?,
    ];
    entries.sort_by_key(|e| e.id);
    Ok(entries)
}

fn key(label: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(format!("stellar-xdr-corpus/v1/{label}")).into();
    SigningKey::from_bytes(&seed)
}

fn public_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

fn g_address(public: [u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(public).to_string().to_string()
}

fn m_address(public: [u8; 32], id: u64) -> String {
    stellar_strkey::ed25519::MuxedAccount { ed25519: public, id }
        .to_string()
        .to_string()
}

fn account_id(public: [u8; 32]) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public)))
}

fn muxed(public: [u8; 32], id: u64) -> MuxedAccount {
    MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id,
        ed25519: Uint256(public),
    })
}

fn values(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => unreachable!("expected values are always written as a JSON object"),
    }
}

/// Signs `tx` with `signer` and returns the envelope with its hash.
fn sign(
    tx: Transaction,
    signer: &SigningKey,
    network: &Network,
) -> Result<(TransactionEnvelope, [u8; 32]), BoxError> {
    let hash = tx.hash(network.id())?;
    let signature = signer.sign(&hash);
    signer.verifying_key().verify(&hash, &signature)?;
    let public = public_bytes(signer);
    let hint: [u8; 4] = public[28..].try_into()?;
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(signature.to_bytes().to_vec().try_into()?),
        }]
        .try_into()?,
    });
    Ok((envelope, hash))
}

/// A Soroban map whose keys are distinct on the network but print the same.
///
/// `u32 1`, `string "1"` and `symbol "1"` are three different keys. A decoder that
/// turns the map into a string-keyed object keeps only one of them.
fn scval_map_keys_collide_as_native(captured_protocol: u32) -> Result<Built, BoxError> {
    let entries = vec![
        ScMapEntry {
            key: ScVal::U32(1),
            val: ScVal::U32(10),
        },
        ScMapEntry {
            key: ScVal::String(ScString("1".try_into()?)),
            val: ScVal::U32(20),
        },
        ScMapEntry {
            key: ScVal::Symbol(ScSymbol("1".try_into()?)),
            val: ScVal::U32(30),
        },
    ];
    // The host only accepts maps whose keys are sorted and unique. Building the map
    // through the sorting constructor and validating it proves this one is.
    let map = ScMap::sorted_from_entries(entries.clone().into_iter())?;
    if map.0.as_slice() != entries.as_slice() {
        return Err("map entries are not written in host order".into());
    }
    let value = ScVal::Map(Some(map));
    value.validate()?;

    Ok(Built {
        id: "scval-map-keys-collide-as-native",
        title: "Soroban map with u32, string and symbol keys that all print as 1",
        description: "Three distinct, correctly sorted map keys. Converting the map to a \
                      string-keyed native object must keep all three entries or fail loudly.",
        xdr_type: "ScVal",
        bytes: value.to_xdr(Limits::none())?,
        caps: &["CAP-0046-01"],
        protocol: Protocol {
            introduced: 20,
            captured: captured_protocol,
        },
        source: Source::Synthetic {
            generator: "scval_map_keys_collide_as_native".into(),
            network_passphrase: None,
        },
        shapes: &["scval.map.keys-collide-as-native"],
        expect: Expect {
            probe: "scval_map".into(),
            values: values(json!({
                "raw_entry_count": 3,
                "native_entry_count": 3,
            })),
            may_refuse: vec!["native_entry_count".into()],
        },
        sightings: &["https://github.com/stellar/js-stellar-sdk/issues/1789"],
    })
}

/// Finds two issuers whose order by key bytes is the reverse of their order by strkey.
///
/// The network orders assets by the issuer's raw key. Strkeys are base32, where the
/// digits `2`-`7` stand for larger values than the letters but sort before them as
/// text, so the two orders can disagree.
fn issuers_ordered_differently() -> Result<([u8; 32], [u8; 32]), BoxError> {
    let first = public_bytes(&key("issuer-order/0"));
    for n in 1..10_000u32 {
        let other = public_bytes(&key(&format!("issuer-order/{n}")));
        let (low, high) = if first < other { (first, other) } else { (other, first) };
        if g_address(low) > g_address(high) {
            return Ok((low, high));
        }
    }
    Err("no issuer pair with reversed strkey order found".into())
}

/// A trustline to a liquidity pool whose two assets differ only by issuer, with the
/// issuers in network order (by key bytes) but reverse strkey order.
fn change_trust_pool_issuer_order(
    network: &Network,
    captured_protocol: u32,
) -> Result<Built, BoxError> {
    let (issuer_a, issuer_b) = issuers_ordered_differently()?;
    let usd = |issuer: [u8; 32]| {
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer: account_id(issuer),
        })
    };
    let (asset_a, asset_b) = (usd(issuer_a), usd(issuer_b));
    if asset_a >= asset_b {
        return Err("pool assets are not in network order".into());
    }
    let params = LiquidityPoolParameters::LiquidityPoolConstantProduct(
        LiquidityPoolConstantProductParameters {
            asset_a,
            asset_b,
            fee: LIQUIDITY_POOL_FEE_V18,
        },
    );
    // CAP-0038: the pool ID is the SHA-256 of the XDR-encoded parameters.
    let pool_id: [u8; 32] = Sha256::digest(params.to_xdr(Limits::none())?).into();

    let source = key("change-trust-pool/source");
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(public_bytes(&source))),
        fee: 100,
        seq_num: SequenceNumber((1_000_000 << 32) + 1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::PoolShare(params),
                limit: i64::MAX,
            }),
        }]
        .try_into()?,
        ext: TransactionExt::V0,
    };
    let (envelope, hash) = sign(tx, &source, network)?;

    Ok(Built {
        id: "change-trust-pool-issuers-strkey-order-reversed",
        title: "Liquidity pool trustline whose issuers sort one way as bytes and the other as strkeys",
        description: "Both pool assets are USD and differ only by issuer. The issuers are in \
                      network order by raw key, which is the reverse of their order as G \
                      addresses. A decoder must accept the pair and derive the same pool ID.",
        xdr_type: "TransactionEnvelope",
        bytes: envelope.to_xdr(Limits::none())?,
        caps: &["CAP-0038"],
        protocol: Protocol {
            introduced: 18,
            captured: captured_protocol,
        },
        source: Source::Synthetic {
            generator: "change_trust_pool_issuer_order".into(),
            network_passphrase: Some(network.passphrase.into()),
        },
        shapes: &[
            "asset.issuer-order.strkey-differs-from-bytes",
            "liquidity-pool.change-trust",
        ],
        expect: Expect {
            probe: "liquidity_pool_change_trust".into(),
            values: values(json!({
                "asset_a": format!("USD:{}", g_address(issuer_a)),
                "asset_b": format!("USD:{}", g_address(issuer_b)),
                "fee": LIQUIDITY_POOL_FEE_V18,
                "limit": i64::MAX.to_string(),
                "pool_id": hex::encode(pool_id),
                "tx_hash": hex::encode(hash),
            })),
            may_refuse: vec![],
        },
        sightings: &["https://github.com/stellar/js-stellar-sdk/pull/1766"],
    })
}

/// A payment between muxed accounts whose IDs and amount do not fit in a 64-bit float.
fn payment_muxed_ids_beyond_f64(
    network: &Network,
    captured_protocol: u32,
) -> Result<Built, BoxError> {
    let source = key("muxed-payment/source");
    let destination = public_bytes(&key("muxed-payment/destination"));
    let source_public = public_bytes(&source);
    let amount = i64::try_from(FIRST_UNSAFE_INTEGER)?;

    let tx = Transaction {
        source_account: muxed(source_public, FIRST_UNSAFE_INTEGER),
        fee: 100,
        seq_num: SequenceNumber((1_000_000 << 32) + 1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            // ID 0 is a real muxed account, not the same thing as the plain G address.
            source_account: Some(muxed(source_public, 0)),
            body: OperationBody::Payment(PaymentOp {
                destination: muxed(destination, u64::MAX),
                asset: Asset::Native,
                amount,
            }),
        }]
        .try_into()?,
        ext: TransactionExt::V0,
    };
    let (envelope, hash) = sign(tx, &source, network)?;

    Ok(Built {
        id: "payment-muxed-ids-beyond-f64",
        title: "Payment between muxed accounts with IDs 2^53+1, 0 and 2^64-1",
        description: "The transaction source, operation source and destination are all muxed. \
                      Two IDs and the amount are above 2^53, so a decoder that passes them \
                      through a 64-bit float reports different numbers.",
        xdr_type: "TransactionEnvelope",
        bytes: envelope.to_xdr(Limits::none())?,
        caps: &["CAP-0027"],
        protocol: Protocol {
            introduced: 13,
            captured: captured_protocol,
        },
        source: Source::Synthetic {
            generator: "payment_muxed_ids_beyond_f64".into(),
            network_passphrase: Some(network.passphrase.into()),
        },
        shapes: &[
            "muxed.transaction-source",
            "muxed.operation-source",
            "muxed.destination",
            "muxed.id-zero",
            "muxed.id-above-2-53",
            "muxed.id-max-u64",
            "amount.above-2-53",
        ],
        expect: Expect {
            probe: "muxed_payment".into(),
            values: values(json!({
                "source": m_address(source_public, FIRST_UNSAFE_INTEGER),
                "source_id": FIRST_UNSAFE_INTEGER.to_string(),
                "source_base": g_address(source_public),
                "op_source": m_address(source_public, 0),
                "op_source_id": "0",
                "destination": m_address(destination, u64::MAX),
                "destination_id": u64::MAX.to_string(),
                "destination_base": g_address(destination),
                "amount_stroops": amount.to_string(),
                "tx_hash": hex::encode(hash),
            })),
            may_refuse: vec![],
        },
        sightings: &[
            "https://github.com/stellar/js-stellar-sdk/issues/1785",
            "https://github.com/stellar/wallet-backend/issues/716",
        ],
    })
}

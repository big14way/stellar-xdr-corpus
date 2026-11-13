//! Synthetic corpus entries.
//!
//! Every builder is deterministic: keys are derived from fixed labels and nothing
//! reads the clock or a random source, so two runs produce the same bytes.

use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, AlphaNum4, Asset, AssetCode4, ChangeTrustAsset, ChangeTrustOp, DecoratedSignature,
    Limits, LiquidityPoolConstantProductParameters, LiquidityPoolParameters, ManageBuyOfferOp,
    ManageSellOfferOp, Memo, MuxedAccount, MuxedAccountMed25519, Operation, OperationBody,
    PaymentOp, Preconditions, Price, PublicKey, ScMap, ScMapEntry, ScString, ScSymbol, ScVal,
    SequenceNumber, Signature, SignatureHint, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, Validate, WriteXdr,
};

use crate::manifest::{Build, BuildAccept, Expect, Protocol, Source};
use crate::BoxError;

/// Fee charged by every constant-product pool, in basis points (CAP-0038).
const LIQUIDITY_POOL_FEE_V18: i32 = 30;
/// Smallest integer a 64-bit float cannot represent.
const FIRST_UNSAFE_INTEGER: u64 = (1 << 53) + 1;
/// An integer above 2^53 that a 64-bit float does represent. A builder handed this
/// as a float cannot tell whether the caller meant it or a neighbour that was rounded.
const UNSAFE_FLOAT: u64 = (1 << 53) + 2;
const _: () = assert!(UNSAFE_FLOAT > (1 << 53));

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
    pub build: Option<Build>,
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

    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(self.passphrase.as_bytes()).into()
    }
}

pub fn all(network: &Network, captured_protocol: u32) -> Result<Vec<Built>, BoxError> {
    let mut entries = vec![
        scval_map_keys_collide_as_native(captured_protocol)?,
        change_trust_pool_issuer_order(network, captured_protocol)?,
        manage_offers_ids_beyond_f64(network, captured_protocol)?,
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
    stellar_strkey::ed25519::PublicKey(public)
        .to_string()
        .to_string()
}

fn m_address(public: [u8; 32], id: u64) -> String {
    stellar_strkey::ed25519::MuxedAccount {
        ed25519: public,
        id,
    }
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

/// A canonical builder input and what the builder must encode for it.
fn accept(input: Value, encodes: impl Into<String>) -> BuildAccept {
    BuildAccept {
        input: values(input),
        encodes: encodes.into(),
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
        build: None,
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
        let (low, high) = if first < other {
            (first, other)
        } else {
            (other, first)
        };
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
        title:
            "Liquidity pool trustline whose issuers sort one way as bytes and the other as strkeys",
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
        build: None,
        sightings: &["https://github.com/stellar/js-stellar-sdk/pull/1766"],
    })
}

/// A sell offer and a buy offer whose IDs do not fit in a 64-bit float.
fn manage_offers_ids_beyond_f64(
    network: &Network,
    captured_protocol: u32,
) -> Result<Built, BoxError> {
    let source = key("manage-offers/source");
    let usd = Asset::CreditAlphanum4(AlphaNum4 {
        asset_code: AssetCode4(*b"USD\0"),
        issuer: account_id(public_bytes(&key("manage-offers/issuer"))),
    });
    let sell_offer_id = i64::try_from(FIRST_UNSAFE_INTEGER)?;
    let buy_offer_id = i64::MAX;
    let one_to_one = Price { n: 1, d: 1 };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(public_bytes(&source))),
        fee: 200,
        seq_num: SequenceNumber((1_000_000 << 32) + 1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![
            Operation {
                source_account: None,
                body: OperationBody::ManageSellOffer(ManageSellOfferOp {
                    selling: usd.clone(),
                    buying: Asset::Native,
                    amount: 10_000_000,
                    price: one_to_one.clone(),
                    offer_id: sell_offer_id,
                }),
            },
            Operation {
                source_account: None,
                body: OperationBody::ManageBuyOffer(ManageBuyOfferOp {
                    selling: Asset::Native,
                    buying: usd,
                    buy_amount: 10_000_000,
                    price: one_to_one,
                    offer_id: buy_offer_id,
                }),
            },
        ]
        .try_into()?,
        ext: TransactionExt::V0,
    };
    let (envelope, hash) = sign(tx, &source, network)?;

    Ok(Built {
        id: "manage-offers-ids-beyond-f64",
        title: "Sell and buy offers that update offers 2^53+1 and 2^63-1",
        description: "Both operations name an existing offer by an ID above 2^53. A decoder \
                      that passes the ID through a 64-bit float reports a different offer, \
                      and a builder that accepts a loosely written ID changes or creates the \
                      wrong one: ID 0 means create a new offer.",
        xdr_type: "TransactionEnvelope",
        bytes: envelope.to_xdr(Limits::none())?,
        caps: &["CAP-0006"],
        protocol: Protocol {
            introduced: 11,
            captured: captured_protocol,
        },
        source: Source::Synthetic {
            generator: "manage_offers_ids_beyond_f64".into(),
            network_passphrase: Some(network.passphrase.into()),
        },
        shapes: &[
            "offer.manage-sell",
            "offer.manage-buy",
            "offer.id-above-2-53",
            "offer.id-max-i64",
        ],
        expect: Expect {
            probe: "manage_offers".into(),
            values: values(json!({
                "sell_offer_id": sell_offer_id.to_string(),
                "sell_amount_stroops": "10000000",
                "buy_offer_id": buy_offer_id.to_string(),
                "buy_amount_stroops": "10000000",
                "tx_hash": hex::encode(hash),
            })),
            may_refuse: vec![],
        },
        build: Some(Build {
            probe: "manage_offer_id".into(),
            accept: vec![
                accept(
                    json!({ "offer_id": sell_offer_id.to_string() }),
                    sell_offer_id.to_string(),
                ),
                accept(
                    json!({ "offer_id": buy_offer_id.to_string() }),
                    buy_offer_id.to_string(),
                ),
            ],
            refuse: vec![
                values(json!({ "offer_id": "" })),
                values(json!({ "offer_id": " 16 " })),
                values(json!({ "offer_id": "0x10" })),
                values(json!({ "offer_id": "-1" })),
                values(json!({ "offer_id": { "float": UNSAFE_FLOAT.to_string() } })),
            ],
        }),
        sightings: &["https://github.com/stellar/js-stellar-sdk/issues/1785"],
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
        build: Some(Build {
            probe: "muxed_account_id".into(),
            accept: vec![
                accept(
                    json!({ "base": g_address(source_public), "id": FIRST_UNSAFE_INTEGER.to_string() }),
                    m_address(source_public, FIRST_UNSAFE_INTEGER),
                ),
                accept(
                    json!({ "base": g_address(source_public), "id": "0" }),
                    m_address(source_public, 0),
                ),
                accept(
                    json!({ "base": g_address(destination), "id": u64::MAX.to_string() }),
                    m_address(destination, u64::MAX),
                ),
            ],
            refuse: vec![
                values(json!({ "base": g_address(source_public), "id": "" })),
                values(json!({ "base": g_address(source_public), "id": " 16 " })),
                values(json!({ "base": g_address(source_public), "id": "0x10" })),
            ],
        }),
        sightings: &[
            "https://github.com/stellar/js-stellar-sdk/issues/1785",
            "https://github.com/stellar/wallet-backend/issues/716",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::ReadXdr;

    #[test]
    fn issuer_pair_orders_differently_as_bytes_and_as_strkeys() {
        let (low, high) = issuers_ordered_differently().unwrap();
        assert!(low < high, "issuers must be in byte order");
        assert!(
            g_address(low) > g_address(high),
            "strkey order must be the reverse of byte order"
        );
    }

    #[test]
    fn builds_are_deterministic() {
        let a = all(&Network::TESTNET, 30).unwrap();
        let b = all(&Network::TESTNET, 30).unwrap();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(x.id, y.id);
            assert_eq!(x.bytes, y.bytes);
            assert_eq!(x.expect, y.expect);
            assert_eq!(x.build, y.build);
        }
    }

    #[test]
    fn entry_ids_are_sorted_and_unique() {
        let ids: Vec<_> = all(&Network::TESTNET, 30)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn network_changes_signed_entries_only() {
        let testnet = all(&Network::TESTNET, 30).unwrap();
        let pubnet = all(&Network::PUBNET, 30).unwrap();
        for (t, p) in testnet.iter().zip(&pubnet) {
            let signed = matches!(
                &t.source,
                Source::Synthetic {
                    network_passphrase: Some(_),
                    ..
                }
            );
            assert_eq!(t.bytes != p.bytes, signed, "{}", t.id);
        }
    }

    #[test]
    fn signatures_verify_against_the_transaction_hash() {
        for network in [Network::TESTNET, Network::PUBNET] {
            for entry in all(&network, 30).unwrap() {
                if entry.xdr_type != "TransactionEnvelope" {
                    continue;
                }
                let envelope = TransactionEnvelope::from_xdr(&entry.bytes, Limits::none()).unwrap();
                let TransactionEnvelope::Tx(v1) = &envelope else {
                    panic!("{} is not a v1 envelope", entry.id);
                };
                let public = match &v1.tx.source_account {
                    MuxedAccount::Ed25519(Uint256(public)) => public,
                    MuxedAccount::MuxedEd25519(m) => &m.ed25519.0,
                };
                let hash = envelope.hash(network.id()).unwrap();
                assert_eq!(entry.expect.values["tx_hash"], hex::encode(hash));
                let key = ed25519_dalek::VerifyingKey::from_bytes(public).unwrap();
                let signature =
                    ed25519_dalek::Signature::from_slice(v1.signatures[0].signature.0.as_slice())
                        .unwrap();
                key.verify(&hash, &signature).unwrap();
                assert_eq!(v1.signatures[0].hint.0, public[28..]);
            }
        }
    }

    #[test]
    fn muxed_ids_survive_only_as_integers() {
        // The point of the entry: these values change when passed through an f64.
        assert_ne!(FIRST_UNSAFE_INTEGER as f64 as u64, FIRST_UNSAFE_INTEGER);
        assert_ne!((u64::MAX - 1) as f64 as u64, u64::MAX - 1);
    }

    #[test]
    fn offer_ids_do_not_survive_a_float() {
        assert_ne!(FIRST_UNSAFE_INTEGER as f64 as u64, FIRST_UNSAFE_INTEGER);
        assert_ne!(i64::MAX as f64 as i128, i64::MAX as i128);
        // The float case in the build section must be a value a float holds exactly,
        // so that the builder really receives the number the manifest names.
        assert_eq!(UNSAFE_FLOAT as f64 as u64, UNSAFE_FLOAT);
    }

    #[test]
    fn build_cases_are_canonical_or_not() {
        // Every accepted input is a plain decimal string; no refused input is.
        let canonical = |v: &Value| {
            v.as_str().is_some_and(|s| {
                !s.is_empty()
                    && s.bytes().all(|b| b.is_ascii_digit())
                    && (s == "0" || !s.starts_with('0'))
            })
        };
        let id_field = |input: &Map<String, Value>| {
            input
                .get("id")
                .or_else(|| input.get("offer_id"))
                .cloned()
                .unwrap()
        };
        let mut with_build = 0;
        for entry in all(&Network::TESTNET, 30).unwrap() {
            let Some(build) = &entry.build else { continue };
            with_build += 1;
            assert!(
                !build.accept.is_empty() && !build.refuse.is_empty(),
                "{}",
                entry.id
            );
            for case in &build.accept {
                assert!(canonical(&id_field(&case.input)), "{}", entry.id);
            }
            for input in &build.refuse {
                assert!(!canonical(&id_field(input)), "{}", entry.id);
            }
        }
        assert_eq!(with_build, 2);
    }
}

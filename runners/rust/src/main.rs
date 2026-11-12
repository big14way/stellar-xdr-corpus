//! Conformance runner for the Rust XDR library (`stellar-xdr`).
//!
//!   conformance-rust [--corpus <dir>] [--out <file>]
//!
//! Decodes every corpus entry, re-encodes it, and applies the entry's probe to
//! compare decoded values with the manifest. The report has the same layout as the
//! reports of the other runners. This crate deliberately shares no code with the
//! generator, so it reads the manifest as plain JSON.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    Asset, ChangeTrustAsset, Limits, LiquidityPoolParameters, MuxedAccount, OperationBody, ReadXdr,
    ScVal, Transaction, TransactionEnvelope, Type, TypeVariant, WriteXdr,
};

type BoxError = Box<dyn std::error::Error>;
/// One probed value: the manifest key and what the library reported for it.
type Probed = Vec<(&'static str, Result<Value, String>)>;

const DECODE_DEPTH: u32 = 500;

fn limits(bytes: &[u8]) -> Limits {
    Limits {
        depth: DECODE_DEPTH,
        len: bytes.len(),
    }
}

fn round_trip(xdr_type: &str, bytes: &[u8]) -> (&'static str, Option<String>) {
    let Ok(variant) = TypeVariant::from_str(xdr_type) else {
        return ("unsupported", Some(format!("{xdr_type} is not defined in this library")));
    };
    match Type::from_xdr(variant, bytes, limits(bytes)).and_then(|v| v.to_xdr(Limits::none())) {
        Ok(reencoded) if reencoded == bytes => ("ok", None),
        Ok(_) => ("mismatch", None),
        Err(e) => ("threw", Some(e.to_string())),
    }
}

fn g_address(public: &[u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(*public).to_string().to_string()
}

fn muxed_parts(account: &MuxedAccount) -> Result<(u64, String), String> {
    match account {
        MuxedAccount::MuxedEd25519(m) => Ok((m.id, g_address(&m.ed25519.0))),
        MuxedAccount::Ed25519(_) => Err("account is not muxed".into()),
    }
}

fn describe_asset(asset: &Asset) -> Result<String, String> {
    let (code, issuer): (&[u8], _) = match asset {
        Asset::Native => return Ok("native".into()),
        Asset::CreditAlphanum4(a) => (&a.asset_code.0, &a.issuer),
        Asset::CreditAlphanum12(a) => (&a.asset_code.0, &a.issuer),
    };
    let end = code.iter().position(|b| *b == 0).unwrap_or(code.len());
    let code = std::str::from_utf8(&code[..end]).map_err(|e| e.to_string())?;
    Ok(format!("{code}:{issuer}"))
}

fn first_v1_transaction(bytes: &[u8]) -> Result<(TransactionEnvelope, Transaction), String> {
    let envelope = TransactionEnvelope::from_xdr(bytes, limits(bytes)).map_err(|e| e.to_string())?;
    match &envelope {
        TransactionEnvelope::Tx(v1) => {
            let tx = v1.tx.clone();
            Ok((envelope, tx))
        }
        _ => Err("expected a v1 transaction envelope".into()),
    }
}

fn tx_hash(envelope: &TransactionEnvelope, entry: &Value) -> Result<Value, String> {
    let passphrase = entry["source"]["network_passphrase"]
        .as_str()
        .ok_or("entry has no network passphrase")?;
    let network_id: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
    envelope
        .hash(network_id)
        .map(|h| json!(hex::encode(h)))
        .map_err(|e| e.to_string())
}

fn probe_scval_map(bytes: &[u8], _entry: &Value) -> Result<Probed, String> {
    let value = ScVal::from_xdr(bytes, limits(bytes)).map_err(|e| e.to_string())?;
    let ScVal::Map(Some(map)) = value else {
        return Err("value is not a map".into());
    };
    // `native_entry_count` is left out: this library has no conversion from a map
    // to a native collection, so there is nothing to compare.
    Ok(vec![("raw_entry_count", Ok(json!(map.len())))])
}

fn probe_liquidity_pool_change_trust(bytes: &[u8], entry: &Value) -> Result<Probed, String> {
    let (envelope, tx) = first_v1_transaction(bytes)?;
    let op = tx.operations.first().ok_or("transaction has no operations")?;
    let OperationBody::ChangeTrust(change_trust) = &op.body else {
        return Err("first operation is not ChangeTrust".into());
    };
    let ChangeTrustAsset::PoolShare(params) = &change_trust.line else {
        return Err("trustline is not a pool share".into());
    };
    let LiquidityPoolParameters::LiquidityPoolConstantProduct(pool) = params;
    Ok(vec![
        ("asset_a", describe_asset(&pool.asset_a).map(Value::from)),
        ("asset_b", describe_asset(&pool.asset_b).map(Value::from)),
        ("fee", Ok(json!(pool.fee))),
        ("limit", Ok(json!(change_trust.limit.to_string()))),
        (
            "pool_id",
            params
                .to_xdr(Limits::none())
                .map(|xdr| json!(hex::encode(Sha256::digest(xdr))))
                .map_err(|e| e.to_string()),
        ),
        ("tx_hash", tx_hash(&envelope, entry)),
    ])
}

fn probe_muxed_payment(bytes: &[u8], entry: &Value) -> Result<Probed, String> {
    let (envelope, tx) = first_v1_transaction(bytes)?;
    let op = tx.operations.first().ok_or("transaction has no operations")?;
    let OperationBody::Payment(payment) = &op.body else {
        return Err("first operation is not Payment".into());
    };
    let op_source = op.source_account.as_ref().ok_or("operation has no source account")?;
    let source = muxed_parts(&tx.source_account);
    let op_source_parts = muxed_parts(op_source);
    let destination = muxed_parts(&payment.destination);
    Ok(vec![
        ("source", Ok(json!(tx.source_account.to_string()))),
        ("source_id", source.clone().map(|(id, _)| json!(id.to_string()))),
        ("source_base", source.map(|(_, base)| json!(base))),
        ("op_source", Ok(json!(op_source.to_string()))),
        ("op_source_id", op_source_parts.map(|(id, _)| json!(id.to_string()))),
        ("destination", Ok(json!(payment.destination.to_string()))),
        ("destination_id", destination.clone().map(|(id, _)| json!(id.to_string()))),
        ("destination_base", destination.map(|(_, base)| json!(base))),
        ("amount_stroops", Ok(json!(payment.amount.to_string()))),
        ("tx_hash", tx_hash(&envelope, entry)),
    ])
}

fn run_probe(name: &str, bytes: &[u8], entry: &Value) -> Option<Result<Probed, String>> {
    match name {
        "scval_map" => Some(probe_scval_map(bytes, entry)),
        "liquidity_pool_change_trust" => Some(probe_liquidity_pool_change_trust(bytes, entry)),
        "muxed_payment" => Some(probe_muxed_payment(bytes, entry)),
        _ => None,
    }
}

fn check_entry(corpus: &Path, entry: &Value) -> Result<Value, BoxError> {
    let id = entry["id"].as_str().ok_or("entry has no id")?;
    let file = entry["file"].as_str().ok_or("entry has no file")?;
    let xdr_type = entry["xdr_type"].as_str().ok_or("entry has no xdr_type")?;
    let probe_name = entry["expect"]["probe"].as_str().ok_or("entry has no probe")?;
    let expected = entry["expect"]["values"].as_object().ok_or("entry has no expected values")?;
    let may_refuse: Vec<&str> = entry["expect"]["may_refuse"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let bytes = fs::read(corpus.join(file))?;
    if Some(hex::encode(Sha256::digest(&bytes)).as_str()) != entry["sha256"].as_str() {
        return Ok(json!({
            "id": id, "integrity": "sha256 mismatch", "roundtrip": "ok", "values": {}, "status": "error",
        }));
    }

    let (roundtrip, roundtrip_detail) = round_trip(xdr_type, &bytes);
    let probed = run_probe(probe_name, &bytes, entry);

    let mut values = Map::new();
    for (key, expected_value) in expected {
        let mut value = Map::new();
        value.insert("expected".into(), expected_value.clone());
        let (outcome, detail): (&str, Option<String>) = match &probed {
            None => ("unsupported", Some(format!("runner has no probe named {probe_name}"))),
            Some(Err(e)) => ("threw", Some(e.clone())),
            Some(Ok(pairs)) => match pairs.iter().find(|(k, _)| k == key) {
                None => ("not_applicable", Some("this SDK has no equivalent helper".into())),
                Some((_, Ok(actual))) => {
                    value.insert("actual".into(), actual.clone());
                    (if actual == expected_value { "match" } else { "mismatch" }, None)
                }
                Some((_, Err(e))) => (
                    if may_refuse.contains(&key.as_str()) { "refused" } else { "threw" },
                    Some(e.clone()),
                ),
            },
        };
        value.insert("outcome".into(), json!(outcome));
        if let Some(detail) = detail {
            value.insert("detail".into(), json!(detail));
        }
        values.insert(key.clone(), Value::Object(value));
    }

    let has = |outcome: &str| values.values().any(|v| v["outcome"] == outcome);
    let status = if roundtrip == "mismatch" || has("mismatch") {
        "diverged_silent"
    } else if roundtrip == "threw" || has("threw") {
        "diverged_error"
    } else if roundtrip == "unsupported" || has("unsupported") {
        "unsupported"
    } else {
        "pass"
    };

    let mut result = Map::new();
    result.insert("id".into(), json!(id));
    result.insert("integrity".into(), json!("ok"));
    result.insert("roundtrip".into(), json!(roundtrip));
    if let Some(detail) = roundtrip_detail {
        result.insert("roundtrip_detail".into(), json!(detail));
    }
    result.insert("values".into(), Value::Object(values));
    result.insert("status".into(), json!(status));
    Ok(Value::Object(result))
}

fn run() -> Result<(), BoxError> {
    let mut corpus = PathBuf::from("corpus");
    let mut out: Option<PathBuf> = None;
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let value = argv.next().ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--corpus" => corpus = PathBuf::from(value),
            "--out" => out = Some(PathBuf::from(value)),
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let manifest: Value = serde_json::from_str(&fs::read_to_string(corpus.join("manifest.json"))?)?;
    let entries = manifest["entries"].as_array().ok_or("manifest has no entries")?;
    let results = entries
        .iter()
        .map(|entry| check_entry(&corpus, entry))
        .collect::<Result<Vec<_>, _>>()?;

    let report = json!({
        "sdk": "rs-stellar-xdr",
        "package": "stellar-xdr",
        "version": stellar_xdr::VERSION.pkg,
        "runtime": concat!("rustc ", env!("RUSTC_VERSION")),
        "manifest_schema_version": manifest["schema_version"],
        "results": results,
    });
    let text = format!("{}\n", serde_json::to_string_pretty(&report)?);
    match out {
        Some(path) => fs::write(path, text)?,
        None => print!("{text}"),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

//! Corpus generator.
//!
//! `generate` writes the entries and the manifest. `check` verifies that what is on
//! disk is exactly what `generate` would write, and that every entry decodes and
//! re-encodes to the same bytes with the Rust XDR library. `import-ledger` extracts
//! one ledger from a Galexie batch file. None of the commands use the network.

mod captured;
mod entries;
mod manifest;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use sha2::{Digest, Sha256};
use stellar_xdr::{Limits, Type, TypeVariant, WriteXdr};

use entries::{Built, Network};
use manifest::{BuiltWith, Entry, Manifest, SCHEMA_VERSION};

pub type BoxError = Box<dyn std::error::Error>;

/// Protocol version of the XDR definitions the pinned `stellar-xdr` crate is built from.
const PROTOCOL_VERSION: u32 = 30;
/// Recursion cap used when decoding. No corpus entry comes close to it.
const DECODE_DEPTH: u32 = 500;

struct Args {
    command: String,
    network: Network,
    out: PathBuf,
    captured_from: PathBuf,
    batch: Option<PathBuf>,
    id: Option<String>,
}

const USAGE: &str = "usage:
  corpus-generator generate      [--network testnet|pubnet] [--out <dir>] [--captured-from <dir>]
  corpus-generator check         [--network testnet|pubnet] [--out <dir>] [--captured-from <dir>]
  corpus-generator import-ledger --batch <uncompressed Galexie batch file> --id <entry id> [--out <dir>]";

fn parse_args() -> Result<Args, BoxError> {
    let mut argv = std::env::args().skip(1);
    let command = argv.next().ok_or(USAGE)?;
    let mut args = Args {
        command,
        network: Network::TESTNET,
        out: PathBuf::from("corpus"),
        captured_from: PathBuf::from("corpus"),
        batch: None,
        id: None,
    };
    while let Some(flag) = argv.next() {
        let value = argv
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--network" => {
                args.network = match value.as_str() {
                    "testnet" => Network::TESTNET,
                    "pubnet" => Network::PUBNET,
                    other => return Err(format!("unknown network {other}").into()),
                }
            }
            "--out" => args.out = PathBuf::from(value),
            "--captured-from" => args.captured_from = PathBuf::from(value),
            "--batch" => args.batch = Some(PathBuf::from(value)),
            "--id" => args.id = Some(value),
            other => return Err(format!("unknown argument {other}\n{USAGE}").into()),
        }
    }
    Ok(args)
}

fn file_name(id: &str) -> String {
    format!("entries/{id}.xdr")
}

/// Decodes `bytes` as `xdr_type` and checks that it re-encodes to the same bytes.
fn check_round_trip(xdr_type: &str, bytes: &[u8]) -> Result<(), BoxError> {
    let variant = TypeVariant::from_str(xdr_type)
        .map_err(|_| format!("{xdr_type} is not a known XDR type"))?;
    let limits = Limits {
        depth: DECODE_DEPTH,
        len: bytes.len(),
    };
    let value = Type::from_xdr(variant, bytes, limits)?;
    if value.to_xdr(Limits::none())? != bytes {
        return Err(format!("{xdr_type} does not re-encode to the same bytes").into());
    }
    Ok(())
}

fn build(network: &Network, captured_from: &Path) -> Result<(Manifest, Vec<Built>), BoxError> {
    let mut built = entries::all(network, PROTOCOL_VERSION)?;
    built.extend(captured::all(captured_from)?);
    built.sort_by_key(|e| e.id);
    let mut ids = BTreeSet::new();
    let mut manifest_entries = Vec::with_capacity(built.len());
    for entry in &built {
        if !ids.insert(entry.id) {
            return Err(format!("duplicate entry id {}", entry.id).into());
        }
        check_round_trip(entry.xdr_type, &entry.bytes).map_err(|e| format!("{}: {e}", entry.id))?;
        for key in &entry.expect.may_refuse {
            if !entry.expect.values.contains_key(key) {
                return Err(format!("{}: may_refuse names unknown value {key}", entry.id).into());
            }
        }
        manifest_entries.push(Entry {
            id: entry.id.into(),
            title: entry.title.into(),
            description: Some(entry.description.into()),
            xdr_type: entry.xdr_type.into(),
            file: file_name(entry.id),
            size: entry.bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&entry.bytes)),
            caps: entry.caps.iter().map(|s| s.to_string()).collect(),
            protocol: entry.protocol.clone(),
            synthetic: matches!(entry.source, manifest::Source::Synthetic { .. }),
            source: entry.source.clone(),
            shapes: entry.shapes.iter().map(|s| s.to_string()).collect(),
            expect: entry.expect.clone(),
            sightings: entry.sightings.iter().map(|s| s.to_string()).collect(),
        });
    }
    let manifest = Manifest {
        schema_version: SCHEMA_VERSION.into(),
        built_with: BuiltWith {
            stellar_xdr_crate: stellar_xdr::VERSION.pkg.into(),
            protocol_version: PROTOCOL_VERSION,
        },
        entries: manifest_entries,
    };
    Ok((manifest, built))
}

fn manifest_text(manifest: &Manifest) -> Result<String, BoxError> {
    Ok(format!("{}\n", serde_json::to_string_pretty(manifest)?))
}

fn generate(out: &Path, network: &Network, captured_from: &Path) -> Result<(), BoxError> {
    let (manifest, built) = build(network, captured_from)?;
    let entries_dir = out.join("entries");
    fs::create_dir_all(&entries_dir)?;

    // Remove entry files that are no longer part of the corpus.
    let wanted: BTreeSet<String> = built.iter().map(|e| format!("{}.xdr", e.id)).collect();
    for item in fs::read_dir(&entries_dir)? {
        let item = item?;
        let name = item.file_name().to_string_lossy().into_owned();
        if name.ends_with(".xdr") && !wanted.contains(&name) {
            fs::remove_file(item.path())?;
        }
    }

    for entry in &built {
        fs::write(out.join(file_name(entry.id)), &entry.bytes)?;
    }
    fs::write(out.join("manifest.json"), manifest_text(&manifest)?)?;
    println!("wrote {} entries to {}", built.len(), out.display());
    Ok(())
}

fn check(out: &Path, network: &Network, captured_from: &Path) -> Result<(), BoxError> {
    let (expected, built) = build(network, captured_from)?;
    let mut problems = Vec::new();

    let on_disk_text = fs::read_to_string(out.join("manifest.json"))?;
    let on_disk: Manifest = serde_json::from_str(&on_disk_text)?;
    if on_disk_text != manifest_text(&expected)? {
        problems.push("manifest.json differs from what the generator produces".to_string());
    }

    // Every file listed in the manifest must match its recorded size and hash and
    // must round-trip, whether or not this generator built it.
    for entry in &on_disk.entries {
        let bytes = match fs::read(out.join(&entry.file)) {
            Ok(bytes) => bytes,
            Err(e) => {
                problems.push(format!("{}: cannot read {}: {e}", entry.id, entry.file));
                continue;
            }
        };
        if bytes.len() as u64 != entry.size {
            problems.push(format!(
                "{}: size is {}, manifest says {}",
                entry.id,
                bytes.len(),
                entry.size
            ));
        }
        if hex::encode(Sha256::digest(&bytes)) != entry.sha256 {
            problems.push(format!("{}: sha256 does not match the manifest", entry.id));
        }
        if let Err(e) = check_round_trip(&entry.xdr_type, &bytes) {
            problems.push(format!("{}: {e}", entry.id));
        }
    }

    // Synthetic entries must be byte-identical to a fresh build, and captured
    // entries to the committed file whose hash the generator pins.
    for entry in &built {
        match fs::read(out.join(file_name(entry.id))) {
            Ok(bytes) if bytes == entry.bytes => {}
            Ok(_) => problems.push(format!("{}: file differs from a fresh build", entry.id)),
            Err(e) => problems.push(format!("{}: {e}", entry.id)),
        }
    }

    // No stray files.
    let listed: BTreeSet<&str> = on_disk.entries.iter().map(|e| e.file.as_str()).collect();
    for item in fs::read_dir(out.join("entries"))? {
        let name = format!("entries/{}", item?.file_name().to_string_lossy());
        if !listed.contains(name.as_str()) {
            problems.push(format!("{name} is not listed in the manifest"));
        }
    }

    if problems.is_empty() {
        println!(
            "ok: {} entries verified in {}",
            on_disk.entries.len(),
            out.display()
        );
        Ok(())
    } else {
        Err(problems.join("\n").into())
    }
}

/// Extracts the ledger from an uncompressed Galexie batch file into the corpus.
///
/// This only writes the entry file. The entry still has to be described in
/// `captured.rs`, with the hash this prints, before `generate` will list it.
fn import_ledger(out: &Path, batch: &Path, id: &str) -> Result<(), BoxError> {
    let (ledger_seq, bytes) = captured::ledger_from_batch(&fs::read(batch)?)?;
    check_round_trip("LedgerCloseMeta", &bytes)?;
    let path = out.join(file_name(id));
    fs::create_dir_all(out.join("entries"))?;
    fs::write(&path, &bytes)?;
    println!(
        "wrote ledger {ledger_seq} to {} ({} bytes, sha256 {})",
        path.display(),
        bytes.len(),
        hex::encode(Sha256::digest(&bytes))
    );
    Ok(())
}

fn run() -> Result<(), BoxError> {
    let args = parse_args()?;
    match args.command.as_str() {
        "generate" => generate(&args.out, &args.network, &args.captured_from),
        "check" => check(&args.out, &args.network, &args.captured_from),
        "import-ledger" => import_ledger(
            &args.out,
            args.batch.as_deref().ok_or("--batch is required")?,
            args.id.as_deref().ok_or("--id is required")?,
        ),
        other => Err(format!("unknown command {other}").into()),
    }
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

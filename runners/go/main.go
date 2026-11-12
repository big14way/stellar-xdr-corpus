// Conformance runner for the Go SDK (github.com/stellar/go-stellar-sdk).
//
//	go run . [--corpus <dir>] [--out <file>]
//
// Decodes every corpus entry, re-encodes it, and applies the entry's probe to
// compare decoded values with the manifest. The report has the same layout as
// the reports of the other runners.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const sdkModule = "github.com/stellar/go-stellar-sdk"

type manifest struct {
	SchemaVersion string  `json:"schema_version"`
	Entries       []entry `json:"entries"`
}

type entry struct {
	ID      string `json:"id"`
	XdrType string `json:"xdr_type"`
	File    string `json:"file"`
	Sha256  string `json:"sha256"`
	Source  struct {
		NetworkPassphrase string `json:"network_passphrase"`
	} `json:"source"`
	Expect struct {
		Probe     string                     `json:"probe"`
		Values    map[string]json.RawMessage `json:"values"`
		MayRefuse []string                   `json:"may_refuse"`
	} `json:"expect"`
}

type value struct {
	Expected json.RawMessage `json:"expected"`
	Actual   any             `json:"actual,omitempty"`
	Outcome  string          `json:"outcome"`
	Detail   string          `json:"detail,omitempty"`
}

type result struct {
	ID              string           `json:"id"`
	Integrity       string           `json:"integrity"`
	Roundtrip       string           `json:"roundtrip"`
	RoundtripDetail string           `json:"roundtrip_detail,omitempty"`
	Values          map[string]value `json:"values"`
	Status          string           `json:"status"`
}

type report struct {
	Sdk                   string   `json:"sdk"`
	Package               string   `json:"package"`
	Version               string   `json:"version"`
	Runtime               string   `json:"runtime"`
	ManifestSchemaVersion string   `json:"manifest_schema_version"`
	Results               []result `json:"results"`
}

// probed holds one thunk per manifest key. Each is evaluated on its own so one
// failing helper does not hide the values the others report.
type probed map[string]func() (any, error)

// xdrValue is what every generated XDR type implements.
type xdrValue interface {
	encoding.BinaryMarshaler
}

// newXdrValue returns an empty value of the named top-level XDR type.
func newXdrValue(name string) (xdrValue, bool) {
	switch name {
	case "ScVal":
		return &xdr.ScVal{}, true
	case "TransactionEnvelope":
		return &xdr.TransactionEnvelope{}, true
	case "TransactionMeta":
		return &xdr.TransactionMeta{}, true
	case "TransactionResult":
		return &xdr.TransactionResult{}, true
	case "LedgerEntry":
		return &xdr.LedgerEntry{}, true
	case "LedgerKey":
		return &xdr.LedgerKey{}, true
	case "LedgerCloseMeta":
		return &xdr.LedgerCloseMeta{}, true
	default:
		return nil, false
	}
}

func roundTrip(name string, data []byte) (string, string) {
	v, ok := newXdrValue(name)
	if !ok {
		return "unsupported", fmt.Sprintf("runner has no constructor for %s", name)
	}
	if err := xdr.SafeUnmarshal(data, v); err != nil {
		return "threw", err.Error()
	}
	reencoded, err := v.MarshalBinary()
	if err != nil {
		return "threw", err.Error()
	}
	if !bytes.Equal(reencoded, data) {
		return "mismatch", ""
	}
	return "ok", ""
}

func firstV1Operation(data []byte) (xdr.TransactionEnvelope, xdr.Operation, error) {
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshal(data, &env); err != nil {
		return env, xdr.Operation{}, err
	}
	if env.Type != xdr.EnvelopeTypeEnvelopeTypeTx || env.V1 == nil {
		return env, xdr.Operation{}, errors.New("expected a v1 transaction envelope")
	}
	if len(env.V1.Tx.Operations) == 0 {
		return env, xdr.Operation{}, errors.New("transaction has no operations")
	}
	return env, env.V1.Tx.Operations[0], nil
}

func txHash(env xdr.TransactionEnvelope, e entry) func() (any, error) {
	return func() (any, error) {
		hash, err := network.HashTransactionInEnvelope(env, e.Source.NetworkPassphrase)
		if err != nil {
			return nil, err
		}
		return hex.EncodeToString(hash[:]), nil
	}
}

func describeAsset(a xdr.Asset) func() (any, error) {
	return func() (any, error) {
		// Extract trims the NUL padding of the code; GetCode returns it padded.
		var assetType, code, issuer string
		if err := a.Extract(&assetType, &code, &issuer); err != nil {
			return nil, err
		}
		return code + ":" + issuer, nil
	}
}

func muxedID(m xdr.MuxedAccount) func() (any, error) {
	return func() (any, error) {
		id, err := m.GetId()
		if err != nil {
			return nil, err
		}
		return strconv.FormatUint(id, 10), nil
	}
}

func muxedAddress(m xdr.MuxedAccount) func() (any, error) {
	return func() (any, error) { return m.GetAddress() }
}

func muxedBase(m xdr.MuxedAccount) func() (any, error) {
	return func() (any, error) {
		id := m.ToAccountId()
		return id.GetAddress()
	}
}

func probeScvalMap(data []byte, _ entry) (probed, error) {
	var v xdr.ScVal
	if err := xdr.SafeUnmarshal(data, &v); err != nil {
		return nil, err
	}
	m, ok := v.GetMap()
	if !ok || m == nil {
		return nil, errors.New("value is not a map")
	}
	// native_entry_count is left out: this SDK has no conversion from a map to a
	// native collection, so there is nothing to compare.
	return probed{
		"raw_entry_count": func() (any, error) { return len(*m), nil },
	}, nil
}

func probeLiquidityPoolChangeTrust(data []byte, e entry) (probed, error) {
	env, op, err := firstV1Operation(data)
	if err != nil {
		return nil, err
	}
	changeTrust, ok := op.Body.GetChangeTrustOp()
	if !ok {
		return nil, errors.New("first operation is not ChangeTrust")
	}
	params, ok := changeTrust.Line.GetLiquidityPool()
	if !ok {
		return nil, errors.New("trustline is not a pool share")
	}
	pool, ok := params.GetConstantProduct()
	if !ok {
		return nil, errors.New("pool is not constant product")
	}
	return probed{
		"asset_a": describeAsset(pool.AssetA),
		"asset_b": describeAsset(pool.AssetB),
		"fee":     func() (any, error) { return int(pool.Fee), nil },
		"limit":   func() (any, error) { return strconv.FormatInt(int64(changeTrust.Limit), 10), nil },
		"pool_id": func() (any, error) {
			id, err := xdr.NewPoolId(pool.AssetA, pool.AssetB, pool.Fee)
			if err != nil {
				return nil, err
			}
			return hex.EncodeToString(id[:]), nil
		},
		"tx_hash": txHash(env, e),
	}, nil
}

func probeMuxedPayment(data []byte, e entry) (probed, error) {
	env, op, err := firstV1Operation(data)
	if err != nil {
		return nil, err
	}
	payment, ok := op.Body.GetPaymentOp()
	if !ok {
		return nil, errors.New("first operation is not Payment")
	}
	if op.SourceAccount == nil {
		return nil, errors.New("operation has no source account")
	}
	source := env.V1.Tx.SourceAccount
	return probed{
		"source":           muxedAddress(source),
		"source_id":        muxedID(source),
		"source_base":      muxedBase(source),
		"op_source":        muxedAddress(*op.SourceAccount),
		"op_source_id":     muxedID(*op.SourceAccount),
		"destination":      muxedAddress(payment.Destination),
		"destination_id":   muxedID(payment.Destination),
		"destination_base": muxedBase(payment.Destination),
		"amount_stroops":   func() (any, error) { return strconv.FormatInt(int64(payment.Amount), 10), nil },
		"tx_hash":          txHash(env, e),
	}, nil
}

// metaChangeLists returns every ledger entry change list of one transaction's
// meta, for any meta version.
func metaChangeLists(meta xdr.TransactionMeta) ([]xdr.LedgerEntryChanges, error) {
	var lists []xdr.LedgerEntryChanges
	switch meta.V {
	case 0:
		if meta.Operations != nil {
			for _, op := range *meta.Operations {
				lists = append(lists, op.Changes)
			}
		}
	case 1:
		lists = append(lists, meta.V1.TxChanges)
		for _, op := range meta.V1.Operations {
			lists = append(lists, op.Changes)
		}
	case 2:
		lists = append(lists, meta.V2.TxChangesBefore)
		for _, op := range meta.V2.Operations {
			lists = append(lists, op.Changes)
		}
		lists = append(lists, meta.V2.TxChangesAfter)
	case 3:
		lists = append(lists, meta.V3.TxChangesBefore)
		for _, op := range meta.V3.Operations {
			lists = append(lists, op.Changes)
		}
		lists = append(lists, meta.V3.TxChangesAfter)
	case 4:
		lists = append(lists, meta.V4.TxChangesBefore)
		for _, op := range meta.V4.Operations {
			lists = append(lists, op.Changes)
		}
		lists = append(lists, meta.V4.TxChangesAfter)
	default:
		return nil, fmt.Errorf("unknown TransactionMeta version %d", meta.V)
	}
	return lists, nil
}

// changedEntry returns the ledger entry a change carries, if it carries one.
func changedEntry(change xdr.LedgerEntryChange) *xdr.LedgerEntry {
	switch change.Type {
	case xdr.LedgerEntryChangeTypeLedgerEntryCreated:
		return change.Created
	case xdr.LedgerEntryChangeTypeLedgerEntryUpdated:
		return change.Updated
	case xdr.LedgerEntryChangeTypeLedgerEntryState:
		return change.State
	case xdr.LedgerEntryChangeTypeLedgerEntryRestored:
		return change.Restored
	default:
		return nil
	}
}

func sortedJoin(items []string) string {
	seen := map[string]bool{}
	unique := []string{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			unique = append(unique, item)
		}
	}
	sort.Strings(unique)
	return strings.Join(unique, ",")
}

func isSignedPayload(key xdr.SignerKey) bool {
	return key.Type == xdr.SignerKeyTypeSignerKeyTypeEd25519SignedPayload
}

func probeLedgerSignedPayloadSigners(data []byte, e entry) (probed, error) {
	var ledger xdr.LedgerCloseMeta
	if err := xdr.SafeUnmarshal(data, &ledger); err != nil {
		return nil, err
	}
	if ledger.V != 1 && ledger.V != 2 {
		return nil, fmt.Errorf("LedgerCloseMeta v%d is not supported", ledger.V)
	}

	// signerEnvelopes returns the envelopes that add a signed-payload signer,
	// with the signer addresses found in them.
	signerEnvelopes := func() ([]xdr.TransactionEnvelope, []string, error) {
		var envelopes []xdr.TransactionEnvelope
		var signers []string
		for _, envelope := range ledger.TransactionEnvelopes() {
			found := false
			for _, op := range envelope.Operations() {
				setOptions, ok := op.Body.GetSetOptionsOp()
				if !ok || setOptions.Signer == nil || !isSignedPayload(setOptions.Signer.Key) {
					continue
				}
				address, err := setOptions.Signer.Key.GetAddress()
				if err != nil {
					return nil, nil, err
				}
				signers = append(signers, address)
				found = true
			}
			if found {
				envelopes = append(envelopes, envelope)
			}
		}
		return envelopes, signers, nil
	}

	return probed{
		"ledger_seq": func() (any, error) { return ledger.LedgerSequence(), nil },
		"ledger_hash": func() (any, error) {
			hash := ledger.LedgerHash()
			return hex.EncodeToString(hash[:]), nil
		},
		"protocol_version": func() (any, error) { return ledger.ProtocolVersion(), nil },
		"tx_count":         func() (any, error) { return ledger.CountTransactions(), nil },
		"signers_in_envelopes": func() (any, error) {
			_, signers, err := signerEnvelopes()
			return sortedJoin(signers), err
		},
		"signers_in_meta": func() (any, error) {
			var found []string
			for i := 0; i < ledger.CountTransactions(); i++ {
				lists := []xdr.LedgerEntryChanges{ledger.FeeProcessing(i)}
				metaLists, err := metaChangeLists(ledger.TxApplyProcessing(i))
				if err != nil {
					return nil, err
				}
				lists = append(lists, metaLists...)
				if ledger.V == 2 {
					lists = append(lists, ledger.V2.TxProcessing[i].PostTxApplyFeeProcessing)
				}
				for _, changes := range lists {
					for _, change := range changes {
						ledgerEntry := changedEntry(change)
						if ledgerEntry == nil {
							continue
						}
						account, ok := ledgerEntry.Data.GetAccount()
						if !ok {
							continue
						}
						for _, signer := range account.Signers {
							if !isSignedPayload(signer.Key) {
								continue
							}
							address, err := signer.Key.GetAddress()
							if err != nil {
								return nil, err
							}
							found = append(found, address)
						}
					}
				}
			}
			return sortedJoin(found), nil
		},
		"signer_tx_hashes": func() (any, error) {
			envelopes, _, err := signerEnvelopes()
			if err != nil {
				return nil, err
			}
			var hashes []string
			for _, envelope := range envelopes {
				hash, err := network.HashTransactionInEnvelope(envelope, e.Source.NetworkPassphrase)
				if err != nil {
					return nil, err
				}
				hashes = append(hashes, hex.EncodeToString(hash[:]))
			}
			return sortedJoin(hashes), nil
		},
	}, nil
}

var probes = map[string]func([]byte, entry) (probed, error){
	"scval_map":                     probeScvalMap,
	"liquidity_pool_change_trust":   probeLiquidityPoolChangeTrust,
	"muxed_payment":                 probeMuxedPayment,
	"ledger_signed_payload_signers": probeLedgerSignedPayloadSigners,
}

// sameJSON reports whether actual, once encoded, is the same JSON value as expected.
func sameJSON(expected json.RawMessage, actual any) bool {
	encoded, err := json.Marshal(actual)
	if err != nil {
		return false
	}
	var a, b any
	if json.Unmarshal(expected, &a) != nil || json.Unmarshal(encoded, &b) != nil {
		return false
	}
	return a == b
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func checkEntry(corpus string, e entry) (result, error) {
	res := result{ID: e.ID, Integrity: "ok", Roundtrip: "ok", Values: map[string]value{}}
	data, err := os.ReadFile(filepath.Join(corpus, e.File))
	if err != nil {
		return res, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != e.Sha256 {
		res.Integrity = "sha256 mismatch"
		res.Status = "error"
		return res, nil
	}

	res.Roundtrip, res.RoundtripDetail = roundTrip(e.XdrType, data)

	probe, known := probes[e.Expect.Probe]
	var thunks probed
	var probeErr error
	if known {
		thunks, probeErr = probe(data, e)
	}

	outcomes := map[string]bool{}
	for key, expected := range e.Expect.Values {
		v := value{Expected: expected}
		switch {
		case !known:
			v.Outcome = "unsupported"
			v.Detail = "runner has no probe named " + e.Expect.Probe
		case probeErr != nil:
			v.Outcome = "threw"
			v.Detail = probeErr.Error()
		case thunks[key] == nil:
			v.Outcome = "not_applicable"
			v.Detail = "this SDK has no equivalent helper"
		default:
			actual, err := thunks[key]()
			switch {
			case err != nil && contains(e.Expect.MayRefuse, key):
				v.Outcome = "refused"
				v.Detail = err.Error()
			case err != nil:
				v.Outcome = "threw"
				v.Detail = err.Error()
			case sameJSON(expected, actual):
				v.Actual = actual
				v.Outcome = "match"
			default:
				v.Actual = actual
				v.Outcome = "mismatch"
			}
		}
		outcomes[v.Outcome] = true
		res.Values[key] = v
	}

	switch {
	case res.Roundtrip == "mismatch" || outcomes["mismatch"]:
		res.Status = "diverged_silent"
	case res.Roundtrip == "threw" || outcomes["threw"]:
		res.Status = "diverged_error"
	case res.Roundtrip == "unsupported" || outcomes["unsupported"]:
		res.Status = "unsupported"
	default:
		res.Status = "pass"
	}
	return res, nil
}

func sdkVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == sdkModule {
			return dep.Version
		}
	}
	return "unknown"
}

func run() error {
	corpus := flag.String("corpus", filepath.Join("..", "..", "corpus"), "corpus directory")
	out := flag.String("out", "", "write the report to this file instead of stdout")
	flag.Parse()

	raw, err := os.ReadFile(filepath.Join(*corpus, "manifest.json"))
	if err != nil {
		return err
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}

	rep := report{
		Sdk:                   "go-stellar-sdk",
		Package:               sdkModule,
		Version:               sdkVersion(),
		Runtime:               runtime.Version(),
		ManifestSchemaVersion: m.SchemaVersion,
		Results:               []result{},
	}
	for _, e := range m.Entries {
		res, err := checkEntry(*corpus, e)
		if err != nil {
			return fmt.Errorf("%s: %w", e.ID, err)
		}
		rep.Results = append(rep.Results, res)
	}

	text, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	text = append(text, '\n')
	if *out != "" {
		return os.WriteFile(*out, text, 0o644)
	}
	_, err = os.Stdout.Write(text)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

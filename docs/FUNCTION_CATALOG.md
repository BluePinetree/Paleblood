# Function intelligence catalog

`tools/function_catalog.py` turns the committed function inventory and optional analysis artifacts
into a local, resumable SQLite catalog. It stores no executable bytes and never records the path to
the executable. The portable `export` command writes JSON without machine-specific source paths.

## Evidence and unknowns

The current `symbols/ghidra_functions.csv` has an entry address and byte size for every function in
the Ghidra export. Those are Ghidra-defined extents, not independently confirmed boundaries. The
catalog does not infer instruction counts from byte sizes. `symbols/functions.csv` and
`symbols/verification.csv` provide named replacement and verification status; verification records
are compared with the current replacement source hash so stale evidence is visible. No call
relationship is inferred from address proximity or naming.

Optional Ghidra exports add function metrics and references. `tools/ghidra/ExportFunctionAnalysis.java`
scans the analyzed listing and writes two CSVs. `--edges` accepts:

| Column | Meaning |
| --- | --- |
| `caller` | Function entry address containing the call instruction. |
| `callee` | Function address for direct/indirect calls, `external:<name>` for imports, blank for unresolved calls. |
| `kind` | `direct`, `indirect`, `import`, `unresolved_direct`, or `unresolved_indirect`. |
| `reference` | Address of the call instruction. |
| `source` | Analysis method/artifact description. |
| `confidence` | Evidence label, such as `direct-reference`, `computed-reference`, or `unresolved`. |

`--metrics` uses `address,instruction_count,complexity,fixture_difficulty,data_references,boundary_confidence,analysis_complete,source`.
`complexity` is a documented static estimate (one plus Ghidra conditional-flow instructions), not a
behavioral measure. Fixture difficulty is `low`, `medium`, `high`, or `unknown`; the exporter sets it
to unknown because disassembly alone cannot establish fixture setup cost. Data references are JSON
arrays of referenced addresses and Ghidra reference types, not proof that each address is a global variable. An
`analysis_complete` value means the script completed its listing scan of that Ghidra function body;
it supports the reported static call graph and reference list, but does not certify Ghidra's
function boundaries or recovered indirect targets. Static references are recorded under
`memory_dependencies.static_references`; pointer-derived/indirect accesses remain unknown, and
full memory-dependency analysis is always marked incomplete. A completed call scan does not prove
that a function has no other memory or global-state dependencies.

Local capture metadata can be supplied with `--captures` as JSON containing a `functions` array.
Each item has an `address` and a `captures` list with `evidence_type` (`gameplay`, `synthetic`, or
`other`) and optional `capture_set`, `case_id`, `recorded_at`,
`source_sha256`, and/or a non-path `reference`. The importer rejects local filesystem paths and
capture content; it records provenance identifiers only. The repository currently has no per-
function gameplay capture provenance artifact, so those values remain unknown unless supplied.

Runtime relevance is optional and requires reviewed evidence. A `--relevance` CSV has
`address,score,source`; score is 0..100 and should cite a boot trace or other evidence. The ranking
does not guess boot relevance from a subsystem name.

Ownership snapshots are local JSON and should be refreshed from current issue/PR state. Example:

```json
{
  "snapshot_complete": true,
  "claims": [
    {"address": "0x0183ac60", "source": "issue #32", "owner": "active issue"},
    {"system": "kernel", "source": "issue #34", "owner": "contributor work"}
  ]
}
```

`no_recorded_claim` means no matching address or subsystem appeared in that supplied snapshot. The
ranked queue still tells the developer to confirm ownership before assignment. Missing or
non-comprehensive ownership evidence is marked `unknown`, yields only a conditional candidate, and
reduces confidence. A claim excludes the matching candidate. Do not commit private notes, local
paths, or executable identifiers beyond the executable SHA-256.

Scores are weighted heuristics, not probabilities. `confidence_percent` reports how many of the
seven evidence dimensions have supporting data. Each result includes per-component weight, evidence
ratio, weighted score, and a reason. Defaults are feasibility 20, dependency complexity 15, fixture
difficulty 10, analysis confidence 10, unlock potential 15, runtime relevance 15, and ownership 5.
Override any subset with `rank --weights weights.json`; missing keys keep their defaults. For
example, `{"unlock": 30, "runtime_relevance": 25}` gives extra weight to boot leverage.

## Build and query

The default database is `$XDG_CACHE_HOME/paleblood/function-catalog.sqlite3` (or
`~/.cache/paleblood/function-catalog.sqlite3`). Override it with `--state`. SQLite transactions
make a completed build visible atomically; interrupted writes roll back. Cache keys include the
executable SHA-256 (when supplied), catalog/tool version, explicit analysis version, canonical
configuration hash, function address, and hashes of all input artifacts. Raw configuration values
and source paths are not included in portable metadata. Changing any input changes the catalog
identity and per-function keys. `invalidate` explicitly drops cached state.

```sh
# Inventory only: missing execution and dependency facts remain unknown.
python3 tools/function_catalog.py build
python3 tools/function_catalog.py status
python3 tools/function_catalog.py function 0x017cfcc0
python3 tools/function_catalog.py dependencies 0x017cfcc0
python3 tools/function_catalog.py rank --limit 20
python3 tools/function_catalog.py cluster
python3 tools/function_catalog.py leaves --limit 20
python3 tools/function_catalog.py unresolved
python3 tools/function_catalog.py export /tmp/paleblood-function-catalog.json

# With fresh Ghidra analysis exports and an ownership snapshot:
python3 tools/function_catalog.py build --executable /path/to/eboot.elf \
  --edges /path/to/call_edges.csv --metrics /path/to/function_metrics.csv \
  --analysis-version 'Ghidra 12.x / ExportFunctionAnalysis 1' \
  --claims /path/to/open-work-claims.json
```

Add `--json` before the subcommand for automation. The database itself is local and resumable; JSON
export is an explicit portable snapshot.

## Example from available analysis

Paleblood source `6140c22fe5c261206f3da3f469afe3a82566202a` has 157,757 Ghidra-exported entries.
For the local executable with SHA-256
`ca8813862d7b1345a6791b7d88cc1d383ede2a6bbc944f39dd3c0e0e3ad9e285`, Ghidra 12.0.3 with
GhidraOrbis 1.0144 produced 643,402 static call/reference edges and instruction metrics for all
157,757 entries. This is a reproducible static-analysis inventory, not independent confirmation
of each function boundary or runtime behavior. The local claims snapshot was incomplete, so the
catalog marked zero candidates strictly eligible and retained the remainder as conditional until
ownership can be checked.

Address `0x017cfcc0` is named `event_flag_write`, has a 177-byte Ghidra-defined extent, 59 scanned
instructions, and an estimated complexity of 10 (conditional-flow count plus one). It remains
`edge-verified`: the recorded original-instruction differential has 14 passing fixtures, but that
does not meet the project's full `verified` promotion bar. Ghidra reports 28 known static callers
and no call sites within its body; its data-reference list is empty. Pointer-derived memory and
global-state dependencies remain unknown. This example shows how the catalog reports the evidence
and its limits together.

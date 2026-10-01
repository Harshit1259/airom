# AIROM

**The AI bill of materials that shows its work.**

AIROM is an open-source **AI Bill of Materials (AIBOM) scanner** that discovers AI
components across the software supply chain and records the evidence behind its
findings. Point it at a filesystem, git repository, container image, or Kubernetes
workload and it returns the models, prompts, datasets, embeddings, vector databases,
frameworks, and serving infrastructure your software actually uses — each entry
carrying the `file:line` it was seen at.

[![CI](https://github.com/airomhq/airom/actions/workflows/ci.yml/badge.svg)](https://github.com/airomhq/airom/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/airomhq/airom?include_prereleases)](https://github.com/airomhq/airom/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/airomhq/airom)](https://goreportcard.com/report/github.com/airomhq/airom)
[![Go Reference](https://pkg.go.dev/badge/github.com/airomhq/airom.svg)](https://pkg.go.dev/github.com/airomhq/airom)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

| | |
|---|---|
| **Who it's for** | Developers who need to know what AI is in their stack, security engineers who have to evaluate it, and platform teams standardising AI asset inventory across repositories |
| **What it discovers** | 8 AI asset categories, represented by 13 component kinds — [see the mapping](#the-8-categories-and-13-component-kinds) |
| **How you run it** | One static binary. `pip install airom && airom scan .` |
| **What you get** | CycloneDX, SPDX, SARIF, OpenVEX, native JSON, YAML, a terminal table, and a compliance view |

---

## Quick start

```bash
pip install airom
```

```bash
airom scan .
```

One static binary. No runtime, no daemon, no account, no network call unless an
overlay needs one.

More ways to install and run: **[installation](https://docs.airom.dev/installation)** ·
**[quickstart](https://docs.airom.dev/quickstart)** · **[CLI reference](docs/cli.md)**

### Common commands

```bash
airom scan .                              # a directory
airom repo https://github.com/org/app     # a git URL
airom image --input app.tar               # a container image archive
airom k8s --manifests ./deploy            # Kubernetes workloads

airom scan . -o cyclonedx=bom.json -o spdx=bom.spdx.json  # many formats, one pass
airom scan . --fix --fix-verify                          # fix the CVEs it found, one click each
airom scan . --exit-code 1 --fail-on "risk:high"         # gate a build
airom diff base.json head.json                           # what a PR changed
```

---

## A real scan

Everything below is produced by the current binary against
[`internal/e2e/testdata/fixtures/python-langchain-rag`](internal/e2e/testdata/fixtures/python-langchain-rag),
a fixture in this repository. Nothing here is illustrative.

```console
$ airom scan . -o table
```

```
┌──────────────────┬────────────────────────┬─────────┬─────────────┬───────┬────────────────────┬──────────┐
│ KIND             │ NAME                   │ VERSION │ PROVIDER    │ CONF  │ LOCATION           │ EVIDENCE │
├──────────────────┼────────────────────────┼─────────┼─────────────┼───────┼────────────────────┼──────────┤
│ embedding-model  │ text-embedding-3-large │ -       │ openai      │ 0.85  │ src/rag.py:6       │ 1 occ    │
│ framework        │ langchain              │ 0.2.16  │ langchain   │ 0.95  │ requirements.txt:2 │ 1 occ    │
│ hosted-llm       │ gpt-4.1                │ -       │ openai      │ 0.85  │ src/rag.py:15      │ 1 occ    │
│ library          │ openai                 │ 1.51.0  │ openai      │ 0.985 │ requirements.txt:3 │ 2 occ    │
│ library          │ sentence-transformers  │ 3.1.1   │ huggingface │ 0.95  │ requirements.txt:5 │ 1 occ    │
│ local-model-file │ poisoned.pt            │ -       │ local       │ 0.95  │ models/poisoned.pt │ 1 occ    │
│ local-model-file │ tiny                   │ -       │ local       │ 0.95  │ models/tiny.gguf   │ 1 occ    │
│ prompt           │ system.txt             │ -       │ -           │ 0.8   │ prompts/system.txt │ 1 occ    │
│ rag-pipeline     │ rag-pipeline           │ -       │ -           │ 0.6   │ src/rag.py:6       │ 1 occ    │
│ vector-db        │ chroma                 │ 0.5.5   │ chroma      │ 0.985 │ requirements.txt:4 │ 3 occ    │
└──────────────────┴────────────────────────┴─────────┴─────────────┴───────┴────────────────────┴──────────┘
```

Ten components across eight kinds, from five files. The four non-AI dependencies in
that `requirements.txt` — `requests`, `numpy`, `pydantic`, `python-dotenv` — are
absent, because an AIBOM is not an SBOM.

### The same finding as CycloneDX

```console
$ airom scan . -o cyclonedx=bom.json
```

One component from `bom.json`, verbatim:

```json
{
  "bom-ref": "airom:cfc27e587216febe",
  "type": "machine-learning-model",
  "name": "gpt-4.1",
  "properties": [
    { "name": "airom:confidence", "value": "0.85" },
    { "name": "airom:kind", "value": "hosted-llm" },
    { "name": "airom:model.id", "value": "gpt-4.1" },
    { "name": "airom:model.provider", "value": "openai" },
    { "name": "airom:param.max_tokens", "value": "800 @ src/rag.py:14" },
    { "name": "airom:param.temperature", "value": "0.2 @ src/rag.py:14" }
  ],
  "evidence": {
    "occurrences": [
      {
        "location": "src/rag.py",
        "line": 15,
        "additionalContext": "model=\"gpt-4.1\","
      }
    ]
  }
}
```

This is generated directly by AIROM. Evidence connects the inventory entry back to
where it was discovered. The document is CycloneDX 1.6 and validates against the
published `bom-1.6.schema.json` with no errors.

Note what travels with the component beyond its name: the detection confidence, the
exact kind (CycloneDX's `machine-learning-model` type is coarser than AIROM's
`hosted-llm`), and the generation parameters bound to the call site that set them.

---

## The evidence model

Sooner or later someone asks: *"Your AIBOM says this service uses `gpt-4.1`. Why?
Where?"*

AIROM is built so that question always has an answer. Every component carries:

| | |
|---|---|
| **Occurrences** | The `file:line` where it was seen, with the surrounding snippet and enclosing symbol. Emitted as CycloneDX `evidence.occurrences[]`. |
| **Technique** | Which detector fired, and by what method — manifest analysis, AST walk, binary header parse, filename heuristic. |
| **Confidence** | An evidence-weighted score in `[0,1]`, with the arithmetic behind it recorded rather than asserted. It is not an empirically calibrated probability, and the output says so. |
| **Identity claims** | When two sources disagree about a version, both are kept as competing CycloneDX `evidence.identity[]` entries rather than one being silently dropped. |

It is equally deliberate about what it does **not** know. A version it could not
resolve stays empty instead of being guessed at; a model outside the lifecycle
catalog carries no claim rather than a quiet "supported"; and every scan emits an
**assurance account** stating what it could not prove — files excluded, reads
truncated at the size cap, which overlays actually ran.

Full detail: **[evidence model](https://docs.airom.dev/concepts/evidence)** ·
**[confidence](https://docs.airom.dev/concepts/confidence)**

---

## What AIROM discovers

### The 8 categories and 13 component kinds

AIROM organizes its detections into **8 high-level AI asset categories, represented
by 13 component kinds**. The categories are how the inventory is described; the
kinds are what the tool emits. Every component carries exactly one kind, in the
`kind` field of native JSON and the `airom:kind` property of CycloneDX.

| High-level category | Component kinds |
|---|---|
| **Models** | `hosted-llm`, `local-model-file` |
| **Datasets** | `dataset` |
| **Prompts** | `prompt` |
| **Embeddings** | `embedding-model` |
| **Vector databases** | `vector-db` |
| **RAG pipelines** | `rag-pipeline` |
| **Frameworks & SDKs** | `framework`, `library` |
| **Infrastructure** | `infra`, `service`, `ai-config` |

The thirteenth kind, `application`, is the scan root itself rather than a discovered
AI asset: it is always present, anchors the relationship graph, and belongs to no
category. Definitions of each kind, with examples, are in
**[what an AIBOM is](https://docs.airom.dev/concepts/aibom#the-kinds-in-full)**.

### What that looks like in practice

| | |
|---|---|
| **Hosted models** | OpenAI, Anthropic, Gemini, Bedrock, Azure OpenAI, Cohere, Mistral, Groq. Model IDs and SDK call sites, including OpenAI's non-text lines (DALL·E, Sora, Whisper, moderation, computer-use) |
| **Local weights** | GGUF, safetensors, ONNX, PyTorch, SavedModel, TFLite, HDF5, TensorRT. Identified by magic bytes and header parse, and **never loaded or run** |
| **Frameworks** | LangChain, LlamaIndex, CrewAI, Agno, AutoGen, Semantic Kernel, CAMEL, MetaGPT, Letta, Crawl4AI, FastMCP, Transformers, and more |
| **Local inference & training** | vLLM, llama.cpp, GPT4All, Ollama, DeepSpeed, Unsloth |
| **Vector databases** | Chroma, Milvus, Qdrant, Pinecone, Weaviate, FAISS, Redis, pgvector. Includes SQL schemas and a server-side pgvector install |
| **Prompts & datasets** | Prompt files and templates, CSV/JSONL/Parquet signatures, `load_dataset()`, HF and Kaggle references |
| **Everything else** | Generation parameters bound to their call site, serving infrastructure, and RAG pipelines stitched into one component |

Dependencies are read from manifests, **lockfiles**, **installed metadata**, and even
**PyInstaller binaries**, so a frozen app with no source on disk still produces an
inventory.

**Languages with rule-targetable region lexers:** Python · JavaScript · TypeScript ·
Go · Java · Rust · C# · Kotlin · SQL

---

## Scan targets

| Target | Command | Notes |
|---|---|---|
| Directory tree | `airom fs ./app` or `airom scan .` | The default |
| Git repository | `airom repo <url>` | Remote URL is shallow-cloned; a local path is read as a worktree |
| Container image | `airom image --input app.tar` | An archive or OCI layout. Live registry and daemon pulls are **not implemented** |
| Kubernetes | `airom k8s --manifests ./deploy` | Offline manifest enumeration. Live-cluster scanning is **not implemented** |

`airom scan` auto-detects which of these you meant from the argument's shape.

Details: **[filesystem](https://docs.airom.dev/scanning/filesystem)** ·
**[repository](https://docs.airom.dev/scanning/repository)** ·
**[container images](https://docs.airom.dev/scanning/container-images)** ·
**[Kubernetes](https://docs.airom.dev/scanning/kubernetes)**

---

## Output formats

Eight formats, all projected from one scan. Native JSON is the lossless reference;
every other format is a pure projection of it.

| Format | Flag | What it's for |
|---|---|---|
| Native JSON | `-o json` | The lossless superset. Every other format projects from this. |
| CycloneDX 1.6 / 1.7 | `-o cyclonedx` | The ML-BOM, with `evidence.occurrences[]` and `evidence.identity[]` populated |
| SPDX 3.0.1 | `-o spdx` | A JSON-LD graph with the AI, Dataset, Software, and Security profiles |
| SARIF 2.1.0 | `-o sarif` | Code scanning alerts, for GitHub and any SARIF consumer |
| OpenVEX | `-o vex` | A VEX document over the CVE overlay |
| Compliance | `-o compliance` | NIST AI RMF and OWASP Agentic control mapping |
| YAML | `-o yaml` | Native JSON, in YAML |
| Table | `-o table` | The terminal view (default) |

A note on SPDX: it is the lossiest format AIROM emits, because SPDX 3.0.1 has no slot
for `file:line` evidence. The document says so explicitly rather than letting a reader
mistake the silence for absence.

Details: **[output formats](https://docs.airom.dev/output/formats)** ·
**[CycloneDX](https://docs.airom.dev/output/cyclonedx)** ·
**[SARIF](https://docs.airom.dev/output/sarif)** ·
**[field mapping](docs/mapping.md)**

---

## Beyond inventory

| Feature | What it does |
|---|---|
| [Risk detection](docs/risks.md) | Load-time code-execution surfaces: pickle imports, Keras Lambda layers, GGUF template gadgets, and unsafe `torch.load`. Emitted as CycloneDX `vulnerabilities[]` and SARIF. Offline. |
| [CVE overlay](docs/cve.md) | Your AI dependencies against OSV.dev, with real CVSS scores and a fail-closed gate. On by default; `--no-cve` turns it off. |
| [One-click fixes](docs/cve.md#fixing-what-it-finds) | `--fix` opens the advisory table with a **Fix** action per package and rewrites the manifest pin you click. Declared manifests only — a lockfile is reported, never forged. `--fix-verify` then dry-runs the ecosystem's resolver, so a bump that clears eight CVEs and leaves a manifest nothing can install is caught here, not in your next build. |
| [Model lifecycle](docs/eol.md) | Hosted models matched against a dated, sourced catalog of provider retirement announcements. |
| [Compliance mapping](docs/compliance.md) | NIST AI RMF and OWASP Agentic controls as CycloneDX attestations, marked met, gap, or manual, with no invented scores. |
| [VEX export](docs/cli.md) | An OpenVEX document over the CVE overlay. Only ever asserts `affected`, because a scanner has no basis for an all-clear. |
| [AIBOM diff](docs/cli.md) | The semantic delta between two scans, so AI becomes a per-PR control. |
| [Test scope](https://docs.airom.dev/concepts/test-scope) | Fixtures and test trees are recorded but kept out of the default view. |
| [Signed rule updates](https://docs.airom.dev/rules/updates) | New frameworks reach you without a new binary, over an ed25519-verified channel. |

---

## CI/CD

```yaml
- run: pip install airom
- run: airom scan . --exit-code 1 --fail-on "risk:high|cve:critical" -o sarif=airom.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: airom.sarif }
```

Findings land as GitHub Code Scanning alerts on the pull request that introduced them.

Findings are **not** failures by default: a completed scan exits `0` no matter what it
found, and `--exit-code` / `--fail-on` are the opt-in gate. Exit `2` is reserved for a
fatal error.

See **[exit codes](docs/cli.md#exit-code-contract)** ·
**[GitHub Actions](https://docs.airom.dev/ci/github-actions)** ·
**[exit code reference](https://docs.airom.dev/ci/exit-codes)**

---

## Security model

AIROM is a security tool whose parsers eat untrusted bytes, and is built accordingly:

- **No model execution, ever.** Weights are identified by magic bytes and bounded
  header parsing. Nothing is loaded, deserialized, or run. A pickle's opcode stream is
  read to enumerate its imports; it is never unpickled.
- **Fuzzed parsers.** Every binary header parser is fuzzed in CI and must return
  errors, never panic.
- **No surprise network access.** `--offline` asserts it globally. The CVE overlay is
  the only component that needs the network, and it refuses under `--offline` rather
  than reporting a quiet nothing.
- **Bounded reads.** Files are read under a size cap, and anything truncated is
  declared in the assurance account rather than silently partially scanned.
- **Signed releases.** `CGO_ENABLED=0`, reproducible, checksummed, and
  keyless-cosign-signed, with a `checksums.txt` covering every platform.
- **Signed rule updates.** The rule-update channel verifies an ed25519 signature and a
  SHA-256 tarball digest, and accepts only strictly newer bundles.

Report vulnerabilities privately via a GitHub security advisory. See
[SECURITY.md](SECURITY.md).

---

## Extending it

Model IDs churn weekly, so the fast-moving surface lives in **YAML rule packs** rather
than Go. Adding a provider is a rules PR, not a release:

```bash
airom dev new-rulepack fireworks   # scaffolds the pack and fixture stubs
airom rules lint rules/models/fireworks.yaml
```

One YAML file, two fixtures, one golden. For detections needing a real parser,
implement `FileDetector` against the stdlib-only `pkg/airom/detect` SDK.

Rules are merged by rule ID — add, override, or disable — across layers: packs
embedded in the binary, then a fetched signed bundle, then any `--rules` overlay. A
bundle that does not carry a pack therefore never removes that pack's detection. A
fourth layer, an OCI-distributed registry, is planned for v2 and not implemented.

See **[writing rules](docs/rule-schema.md)** ·
**[plugin guide](docs/plugin-guide.md)** ·
**[rule packs](https://docs.airom.dev/rules/overview)**

---

## Architecture

A single static Go binary. One streaming pass — **walk → classify → dispatch
detectors → collect** — then cross-file **project detectors**, then **assemble →
enrich → write**.

- **Detectors** are isolated and accounted for individually; one failing detector
  degrades to an `unknowns` record rather than failing the scan.
- **The assembler** merges findings by a canonical key, keeps-and-relates rather than
  overwriting, and refuses to assert a relationship it cannot substantiate.
- **Writers are pure projections** — `func(*airom.Inventory) []byte`. No writer
  invents, drops, or re-derives data, and a round-trip test turns any disagreement
  with [`docs/mapping.md`](docs/mapping.md) into a CI failure rather than docs drift.
- **Evidence is retained through detection and assembly**, so inventory entries can be
  traced back to source occurrences and carried into every output format that has a
  slot for them.

Read **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the full design and the
decision log, including the alternatives each decision rejected.

---

## Documentation

| | |
|---|---|
| **Getting started** | [installation](https://docs.airom.dev/installation) · [quickstart](https://docs.airom.dev/quickstart) |
| **Concepts** | [what an AIBOM is](https://docs.airom.dev/concepts/aibom) · [evidence](https://docs.airom.dev/concepts/evidence) · [confidence](https://docs.airom.dev/concepts/confidence) · [versions](https://docs.airom.dev/concepts/versions) |
| **Scan targets** | [filesystem](https://docs.airom.dev/scanning/filesystem) · [repository](https://docs.airom.dev/scanning/repository) · [container images](https://docs.airom.dev/scanning/container-images) · [Kubernetes](https://docs.airom.dev/scanning/kubernetes) |
| **Output formats** | [overview](https://docs.airom.dev/output/formats) · [CycloneDX](https://docs.airom.dev/output/cyclonedx) · [SARIF](https://docs.airom.dev/output/sarif) · [field mapping](docs/mapping.md) |
| **Security** | [risk detection](docs/risks.md) · [CVE overlay](docs/cve.md) · [model lifecycle](docs/eol.md) · [SECURITY.md](SECURITY.md) |
| **CI/CD** | [GitHub Actions](https://docs.airom.dev/ci/github-actions) · [exit codes](https://docs.airom.dev/ci/exit-codes) · [compliance mapping](docs/compliance.md) |
| **Rule packs** | [rule schema](docs/rule-schema.md) · [overview](https://docs.airom.dev/rules/overview) · [writing rules](https://docs.airom.dev/rules/writing-rules) · [signed updates](https://docs.airom.dev/rules/updates) |
| **Detector development** | [plugin guide](docs/plugin-guide.md) · [`pkg/airom` API](https://pkg.go.dev/github.com/airomhq/airom/pkg/airom) |
| **Reference** | [CLI](docs/cli.md) · [configuration](https://docs.airom.dev/reference/configuration) · [schemas](schemas/) |
| **Project** | [architecture](docs/ARCHITECTURE.md) · [status](docs/project-status.md) · [roadmap](docs/ROADMAP.md) · [releasing](docs/RELEASING.md) |

The documentation site and the landing page are built from
**[airomhq/airom-web](https://github.com/airomhq/airom-web)**.

---

## Project status

**v0.4.7**, early but real. The pipeline, detectors, writers, and overlays are
implemented and tested; expect rough edges.

Known gaps, each also surfaced in the affected flag's `--help`:

- Caching is not implemented (`--no-cache` is a no-op).
- Live registry and daemon image pulls are not available — use
  `airom image --input <archive>`.
- Live-cluster Kubernetes scanning is not available — use
  `airom k8s --manifests <dir>`.

The full ledger of what is complete and what is deferred is in
**[docs/project-status.md](docs/project-status.md)**.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). The fastest way to help is a rule pack.
Most providers land in under an hour.

## License

[Apache License 2.0](LICENSE). © AIROM contributors

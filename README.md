# AI-CSI - Information Security Review 3

## Review 3 reporting extension

The original Review 2 analysis pipeline, saved XGBoost model, samples, and deterministic report remain in place. Review 3 adds a server-side forensic reporting layer in `backend/forensic.py` and a report / Q&A panel in the dashboard. The sections below document the Review 2 baseline and its historical evaluation; they do not describe the new reporting layer.

After analysing evidence, select **Generate report**. The service builds a claim registry from the verified analysis snapshot. Each material claim has a source file, artifact ID, SHA-256, and (where applicable) event ID. Observed events, model detections, ATT&CK rule mappings, SHAP explanations, and evidence gaps are labelled separately. The attack story is ordered by event time. The Q&A endpoint selects only relevant registered claims and returns an explicit insufficient-evidence answer when none match. The PDF export includes the case, verified evidence inventory, detections, chronology, mappings, SHAP, confidence, limitations, conclusion, and full hash appendix.

The LLM receives a bounded list of structured claims and returns claim IDs only. The service rejects invented IDs and ignores generated prose, so model text cannot introduce a finding. If the provider is unavailable or responds incorrectly, deterministic claim selection still produces a cited report. The current case is held in memory by the local service; restarting it requires a fresh analysis. Evidence is not persisted to a database.

### LLM setup on a Mac M2 with 16 GB RAM

The default is local Ollama with `qwen2.5:3b`, keeping evidence on the machine. Install Ollama separately, run `ollama pull qwen2.5:3b`, and start its service before `npm run dev`. The browser never receives an API key. Set environment variables in the local service process only:

| Variable | Default | Purpose |
| --- | --- | --- |
| `AICSI_LLM_PROVIDER` | `ollama` | `ollama`, `openai`, `openai_compatible`, or `disabled` |
| `AICSI_LLM_MODEL` | Provider-specific | `qwen2.5:3b` for Ollama; `gpt-6-luna` for OpenAI |
| `AICSI_OLLAMA_URL` | `http://127.0.0.1:11434` | Local Ollama endpoint |
| `AICSI_LLM_BASE_URL` | unset | Explicit OpenAI-compatible `/v1` base URL |
| `AICSI_LLM_API_KEY` | unset | Server-only bearer token for compatible providers |

Sending claims to a remote OpenAI-compatible endpoint is an explicit operator choice and may disclose case details to that provider. Do not commit credentials. The `.env*` files remain ignored. The default Ollama endpoint is local.

### OpenAI API key

The dedicated `openai` provider uses OpenAI's Responses API with structured claim-ID output. It sends the bounded claim registry to OpenAI and requests `store: false`; the local service still validates every selected ID before rendering a finding. The default OpenAI model is `gpt-6-luna`, which can be changed in `backend/.env`. Create an API key in the OpenAI Platform, then put it in the ignored local `backend/.env` file as `OPENAI_API_KEY=...`. The file should have owner-only permissions (`chmod 600 backend/.env`). Restart `npm run dev` after editing. `backend/env.example` shows the expected fields without a secret. Never paste the key into the web dashboard or commit it to Git.

| OpenAI setting | Value |
| --- | --- |
| `AICSI_LLM_PROVIDER` | `openai` |
| `AICSI_LLM_MODEL` | `gpt-6-luna` (configurable) |
| `OPENAI_API_KEY` | Secret in local `backend/.env` or server environment |

Run `npm run test:backend`, `npm run lint`, `./node_modules/.bin/tsc --noEmit`, and `npm run build` to verify the implementation. The reporting tests cover valid citations, chronological order, forged LLM findings and references, offline LLM fallback, stale evidence hashes, and PDF output.

## Review 2 baseline

AI-CSI is a college-scale, evidence-centred cyber-investigation prototype. It ingests heterogeneous evidence, preserves provenance, normalizes events, extracts entities, classifies activity with a real ML pipeline, correlates observations in a NetworkX graph, reconstructs a timeline, maps behaviors to MITRE ATT&CK, calculates investigation confidence, recommends missing evidence, explains model predictions with SHAP, and produces a deterministic evidence-grounded report.

The central Review-2 contribution is the **Missing Evidence Recommendation Engine**. It treats evidence completeness as a calculated, incident-specific investigation problem rather than a static checklist.

> The Review 2 report below is deterministic. The Review 3 reporting layer above adds optional LLM-assisted claim selection and evidence-aware Q&A.

## Review-2 scope

The project implements the Review-1 pipeline at a defensible prototype scale:

```text
Evidence files
  -> SHA-256 + provenance
  -> parsers + common event schema
  -> hybrid IOC/entity extraction
  -> DistilBERT embeddings
  -> XGBoost event classification
  -> NetworkX evidence graph + correlation
  -> chronological attack timeline
  -> MITRE ATT&CK mapping
  -> evidence requirement analysis
  -> missing-evidence ranking
  -> investigation confidence
  -> TreeSHAP explanation
  -> deterministic evidence-grounded report
```

Samples load files only. No sample identifier is sent to the analysis service, and no sample directly supplies a hypothesis, timeline, confidence score, recommendation, graph, or report.

## Architecture

The existing React/Vinext dashboard remains the investigator interface. A local FastAPI service runs the genuine Python ML and graph components.

| Layer            | Implementation                                                              |
| ---------------- | --------------------------------------------------------------------------- |
| Interface        | React 19, Vinext, Tailwind CSS, existing UI primitives                      |
| Evidence intake  | Browser file API; CSV, JSON, JSONL, LOG, TXT                                |
| Integrity        | SHA-256 calculated in the browser and independently verified by the service |
| Analysis service | FastAPI + Pydantic                                                          |
| Embeddings       | Hugging Face Transformers + DistilBERT                                      |
| Classification   | Saved XGBoost three-class classifier                                        |
| Semantic NER     | Hugging Face token-classification pipeline                                  |
| Structured IOCs  | Deterministic schema parsing, regex, and validation                         |
| Graph            | NetworkX MultiDiGraph                                                       |
| ATT&CK           | Local versioned subset derived from official Enterprise ATT&CK v19.2        |
| Explainability   | SHAP TreeExplainer                                                          |
| Report           | Deterministic template over current calculated state                        |

## Open-source models and libraries

| Component               | Exact implementation                                                 | Status                              |
| ----------------------- | -------------------------------------------------------------------- | ----------------------------------- |
| DistilBERT              | `distilbert/distilbert-base-uncased`, Apache-2.0                     | Real inference                      |
| XGBoost                 | `XGBClassifier`, saved at `models/event_classifier.json`, Apache-2.0 | Real training and inference         |
| Transformer NER         | `elastic/distilbert-base-uncased-finetuned-conll03-english`          | Real semantic extraction            |
| NetworkX                | NetworkX 3.7, BSD-3-Clause                                           | Real dynamic graph                  |
| SHAP                    | TreeExplainer, MIT license                                           | Real event-level SHAP values        |
| MITRE ATT&CK            | Enterprise ATT&CK v19.2 subset, CC BY 4.0                            | Official versioned knowledge subset |
| Missing evidence engine | AI-CSI domain matrix and ranking algorithm                           | Custom logic                        |
| Confidence engine       | Review-1 weighted formula                                            | Custom logic                        |
| LLM/RAG (Review 2)      | Not implemented in the Review 2 baseline                              | Added for Review 3 as described above |

## DistilBERT implementation

`backend/ml.py` loads `distilbert/distilbert-base-uncased` once and caches embeddings by SHA-256 of the normalized event text.

- Input: event type, message, status, resource, and source type.
- Preprocessing: DistilBERT uncased tokenizer, truncation at 128 tokens.
- Output: 768-dimensional contextual embedding.
- Pooling: attention-mask mean pooling over the final hidden state.
- Use: concatenated with ten structured security features before XGBoost inference.

The first run downloads the public model. Later runs reuse the Hugging Face cache.

## XGBoost classifier

The classifier predicts `NORMAL`, `SUSPICIOUS`, or `MALICIOUS`.

Input features:

- 768 DistilBERT embedding dimensions;
- risk-keyword density;
- authentication signal;
- privilege signal;
- outbound-transfer signal;
- script-execution signal;
- malware signal;
- failure/alert status;
- IP presence;
- domain/URL presence; and
- source-risk prior.

The reproducible training script is `backend/train_model.py`. It writes:

- `models/event_classifier.json`;
- `models/metadata.json`; and
- actual evaluation results and model metadata.

### Training data and actual evaluation

The safe labelled dataset is `backend/data/training_events.csv`.

| Measurement        |                                   Actual value |
| ------------------ | ---------------------------------------------: |
| Samples            |                                             60 |
| Class distribution |       20 Normal / 20 Suspicious / 20 Malicious |
| Split              | 45 train / 15 test, stratified, random seed 42 |
| Accuracy           |                                         0.7333 |
| Macro precision    |                                         0.7937 |
| Macro recall       |                                         0.7333 |
| Macro F1           |                                         0.7107 |

Confusion matrix, class order `MALICIOUS`, `NORMAL`, `SUSPICIOUS`:

```text
[[4, 1, 0],
 [0, 5, 0],
 [2, 1, 2]]
```

These values describe one small synthetic held-out split. They demonstrate a genuine reproducible pipeline; they do not establish production generalisation.

### Review 2 group-separated evaluation (2026-10-20)

`backend/review2_experiments.py` adds a stricter comparison. It drops incomplete/exact-duplicate rows, splits by `event_type` before model fitting, and keeps event-type groups exclusive to train, validation, and test. A fixed, label-balanced candidate is chosen without using model performance. The TF-IDF vocabulary is fitted on training text only. DistilBERT is a fixed pretrained feature extractor; neither it nor XGBoost is fitted on validation/test records. Validation is diagnostic; the held-out test set is reported once.

| Model | Train / val / test | Validation accuracy / macro F1 | Test accuracy | Test macro precision | Test macro recall | Test macro F1 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| TF-IDF + Random Forest baseline | 37 / 12 / 11 | 0.4167 / 0.4148 | 0.5455 | 0.5500 | 0.5833 | 0.5450 |
| DistilBERT + XGBoost | 37 / 12 / 11 | 0.6667 / 0.6762 | 0.6364 | 0.7222 | 0.6389 | 0.6571 |

The grouped test result replaces neither the existing saved model nor its original 45/15 random-split metric. It is a more conservative, separately trained evaluation of the same model configuration. All labels are from 60 synthetic classroom examples; eleven test records are too few for strong generalisation claims. The dataset SHA-256 is `2f364c3d82cda50de852ff71004d87e540d1e3fa4bb96fd3cc8fc3601c5a6864`.

Run the comparison and security checks with:

```bash
PYTHONPATH=backend AICSI_ENABLE_NER=0 .venv/bin/python backend/review2_experiments.py --output review2_results.json
```

## Hybrid entity extraction

AI-CSI intentionally does not use Transformer NER for structured IOCs.

Deterministic extraction handles:

- IPv4 addresses;
- hashes;
- URLs and domains;
- ports;
- Event IDs;
- timestamps;
- users, hosts, processes, and parent processes already present in structured fields.

The Transformer NER model handles semantic entities in unstructured messages, such as people, organizations, locations, and miscellaneous named context. Every entity includes its extractor so the UI never claims an IOC came from NER when it came from a parser or regex.

## Common event schema

Every parser produces an event with the same conceptual fields:

```text
event_id, timestamp, source_type, source_file, artifact_id,
host, user, process, parent_process,
src_ip, dst_ip, domain, url,
event_type, status, resource, message,
raw_event, provenance_hash
```

The service retains the raw event, source file, artifact identifier, and evidence hash for traceability.

## NetworkX investigation graph

The backend creates a real `networkx.MultiDiGraph` on every analysis.

Dynamic node types include evidence artifacts, events, users, hosts, processes, IPs, domains, URLs, semantic entities, and MITRE techniques. Relationships include:

- `OBSERVED_IN` from event to evidence;
- `MENTIONS` from event to extracted entity;
- `MAPS_TO` from event to ATT&CK technique; and
- `CORRELATES_WITH` between evidence-derived events.

Correlation considers a 45-minute temporal window, shared entities, source evidence, and attack-stage compatibility. Correlation edges store their weight, time distance, shared entities, and supporting event identifiers. Clicking a graph item in the UI exposes its evidence references and provenance hash where available.

## Timeline and correlation

The timeline is a sorted view of normalized events that XGBoost classifies as Suspicious or Malicious. Each entry retains its timestamp, source evidence, entities, prediction and probability, and any ATT&CK mappings.

No timeline is selected by a sample or scenario ID.

## MITRE ATT&CK mapping

`backend/data/mitre_attack_subset.json` is a versioned local subset derived from official MITRE ATT&CK Enterprise v19.2. It contains techniques needed for the three safe demonstrations. Behavior-to-technique patterns are predefined domain knowledge; mappings appear only when current normalized events match those behaviors.

Official source: <https://attack.mitre.org/versions/v19/>

## Evidence requirement matrix

The matrix is predefined domain knowledge keyed by detected ATT&CK technique, not by sample case. Examples:

| Detected behavior              | Useful evidence                          |
| ------------------------------ | ---------------------------------------- |
| Spearphishing link             | Email headers, browser history, DNS, IDS |
| Brute force / credential abuse | Authentication logs, Sysmon, memory      |
| Valid accounts                 | Authentication logs, firewall, Sysmon    |
| PowerShell                     | Sysmon, EDR, memory                      |
| Registry persistence           | Registry, Sysmon, memory                 |
| Web C2                         | Firewall, DNS, PCAP, proxy               |
| Data staging                   | EDR, Sysmon, authentication logs         |
| Exfiltration                   | PCAP, proxy, firewall, DNS               |

Requirements from all currently detected techniques are combined. Observed, successfully parsed evidence types are then compared with those requirements.

## Dynamic evidence coverage

For each applicable evidence type, technique-specific relevance weights are summed and normalized across the current requirement set.

```text
E = sum(normalized weight of PRESENT required evidence)
```

Adding DNS before Email headers and adding Email headers before DNS therefore produce different intermediate coverage and recommendation states.

## Temporal / causal coherence

Temporal coherence is calculated from the current suspicious/malicious timeline:

```text
T = 0.20 x chronology
  + 0.35 x supported attack-stage transitions
  + 0.30 x entity continuity
  + 0.15 x correlation density
```

- Chronology checks valid ordered timestamps.
- Transition support checks same-stage or allowed ATT&CK-stage progressions.
- Entity continuity checks shared users, hosts, IPs, domains, files, or processes.
- Correlation density measures evidence-supported graph connections.

The UI exposes every factor and the formula.

## Provenance / integrity

Each artifact receives five implemented checks:

1. Server SHA-256 generated.
2. Server hash matches the browser hash.
3. At least one row parsed successfully.
4. Source metadata and evidence type are available.
5. Artifact is associated with the current case.

Each artifact score is the fraction of passed checks. `P` is their mean. A fully valid sample legitimately scores 1.0 because both browser and server independently perform the checks; selecting a sample does not assign 100% by itself.

The service now requires a 64-digit SHA-256 for every artifact and rejects a request when it is missing or does not match the evidence bytes. A matching client-supplied hash checks transfer consistency; it does not independently prove the file was authentic before intake.

## Model confidence

Every event receives genuine XGBoost class probabilities. `M` is the mean winning-class probability over Suspicious/Malicious events. If no event is non-normal, it is the mean winning-class probability over all events.

The Analysis Details view shows every event's three probabilities and the exact aggregation rule.

## Investigation Confidence Score

The Review-1 formula is preserved:

```text
C = 100 x (0.35E + 0.25M + 0.25T + 0.15P)
```

- `E`: dynamic evidence coverage;
- `M`: aggregated XGBoost probability;
- `T`: dynamic temporal/causal coherence; and
- `P`: implemented provenance checks.

The interface prints the substituted equation, factors, weights, and final score for viva explanation. Scores remain evidential-support indicators, not legal conclusions or probabilities of guilt.

## Missing Evidence Recommendation Engine

The engine follows this path:

```text
current evidence
  -> normalized events
  -> XGBoost predictions
  -> detected ATT&CK techniques
  -> evidence-derived hypothesis
  -> technique evidence requirements
  -> observed vs missing evidence
  -> calculated usefulness
  -> ranked recommendations
```

For each missing evidence type:

```text
Recommendation score = 100 x
  (0.45 x technique relevance
 + 0.25 x unsupported-stage support
 + 0.20 x normalized confidence contribution
 + 0.10 x confirm-or-refute value)
```

The UI exposes each term, relevant techniques, reason, expected coverage gain, and coverage-only confidence contribution. These values are estimates, not promises that collection will confirm the hypothesis.

## SHAP explainability

The backend runs `shap.TreeExplainer` against the real saved XGBoost classifier. Each event receives actual SHAP contributions for its predicted class.

The 768 embedding dimensions are summarized as one signed **DistilBERT contextual embedding** contribution. Structured features are shown separately. The UI keeps two concepts distinct:

- **Model explanation**: prediction, probability, and actual TreeSHAP contributions.
- **Evidence traceability**: source file, SHA-256, entities, event, and ATT&CK mapping.

## Evidence-grounded report

The report consumes only current calculated state and includes:

- case summary;
- evidence analyzed;
- evidence-derived hypothesis;
- timeline;
- MITRE techniques;
- affected entities/assets;
- confidence and factor breakdown;
- missing evidence;
- explainability summary;
- limitations and uncertainty; and
- recommended investigator actions.

It uses a deterministic template. It cannot add an event absent from the investigation state and does not call an LLM.

## Safe synthetic datasets

All files under `public/sample-data/review2/` are inert text evidence for classroom demonstrations.

1. **Phishing / Credential Compromise**: authentication, firewall, and IDS initial files; Email headers and DNS add-ons.
2. **Malware / Persistence**: EDR initial file; Sysmon and memory-indicator add-ons.
3. **Data Exfiltration**: proxy, firewall, and authentication initial files; sanitised PCAP metadata add-on.

The sample picker only reads these files. Manual uploads and sample files use the same API request and analysis function.

## Setup

Requirements:

- Node.js 22.13 or newer;
- Python 3.12;
- npm; and
- OpenMP for XGBoost on macOS.

One-time setup:

```bash
cd "/Volumes/Vaibhav/AI-CSI-Cybersecurity-Prototype"

# macOS only
brew install libomp

python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
npm install

# Reproduce the saved XGBoost model and metrics
npm run train:model
```

Run both the interface and local analysis service:

```bash
npm run dev
```

Then open <http://localhost:3000>.

The first run may download the two public Hugging Face models. Subsequent runs use the local cache.

## Exact Review-2 demonstration

1. Open AI-CSI and click **Load sample case**.
2. Select **Phishing / Credential Compromise** under **Safe synthetic sample data**.
3. Explain that only three evidence files were loaded; no investigation answer was loaded.
4. Show independent SHA-256 verification and provenance checks.
5. Show the normalized common event table.
6. Open **Analysis details** and show real XGBoost class probabilities.
7. Return to **Investigation** and show extracted deterministic and semantic entities.
8. Show the real NetworkX graph; click a node or edge for provenance.
9. Walk through the timestamp-derived timeline and ATT&CK v19.2 mappings.
10. Open **How calculated?** and substitute `E`, `M`, `T`, and `P` into the confidence formula.
11. Show the ranked missing evidence and expand **Why recommended?**.
12. Click **Add this sample evidence file** for Email headers, or manually choose `public/sample-data/review2/phishing_email_headers.json` with **Add evidence**.
13. Wait for the exact same pipeline to rerun.
14. Show the before/after banner, new timeline events, changed NetworkX graph, changed coverage/confidence, and reordered recommendations.
15. Select a classified event and show its actual TreeSHAP values separately from provenance.
16. Show the deterministic **Evidence-Grounded Forensic Report**.
17. Open **System information** and accurately disclose every real, deterministic, and excluded component.

For a contrasting intermediate state, start a new investigation, reload the same incomplete phishing evidence, and add DNS before Email headers.

## Testing

```bash
npm test
npm run lint
npm run build
```

Tests cover:

- parsing and evidence-type detection;
- deterministic IOC extraction;
- real DistilBERT embedding generation;
- real XGBoost inference and class probabilities;
- real Transformer NER;
- NetworkX graph creation;
- MITRE mapping;
- evidence coverage and provenance;
- confidence formula;
- real SHAP output;
- Email-first versus DNS-first differences;
- unrelated evidence behavior; and
- manual investigation without a sample.

## Project structure

```text
app/page.tsx                              application entry
components/evidence-driven-console.tsx   investigator UI
backend/server.py                         FastAPI service
backend/pipeline.py                       evidence-driven analysis pipeline
backend/ml.py                             DistilBERT, NER, XGBoost, SHAP runtime
backend/train_model.py                    reproducible training/evaluation
backend/data/training_events.csv          safe labelled baseline dataset
backend/data/mitre_attack_subset.json     ATT&CK v19.2 local subset
backend/test_pipeline.py                  backend and hard-coding tests
models/event_classifier.json              saved XGBoost model
models/metadata.json                      exact model/evaluation metadata
public/sample-data/review2/               safe synthetic evidence files
```

## Limitations

- The 60-event training set is intentionally small and synthetic.
- The reported metrics are from one 15-event held-out split.
- DistilBERT is used as a pretrained embedder, not fine-tuned on a large cybersecurity corpus.
- Semantic NER is general English NER; structured security IOCs rely on deterministic extraction.
- The ATT&CK file is a relevant subset, not the full Enterprise STIX collection.
- Correlation and temporal reasoning are transparent heuristics, not research-grade causal inference.
- Browser state is not a persistent case database.
- PCAP and memory examples contain safe metadata, not executable or packet payloads.
- The confidence score measures evidential support, not truth, guilt, or legal sufficiency.
- Review 3 LLM selection is limited to registered claims; it cannot write free-form forensic findings.

## Future work

- Fine-tune or calibrate the classifier on larger labelled security datasets.
- Evaluate across held-out incident families and real laboratory telemetry.
- Import the complete official ATT&CK STIX bundle automatically.
- Add persistent case storage and authenticated investigator accounts.
- Add safe binary PCAP/memory feature extraction in an isolated service.
- Measure top-3 recommendation recall and calibration error on systematically masked incidents.

## Likely viva questions

**What is the novelty?**  
The prototype identifies evidence gaps from evidence-derived techniques and ranks additional artifacts by their expected usefulness. It also recalculates the whole investigation after collection.

**Are the confidence values hard-coded?**  
No. `E`, `M`, `T`, and `P` are recomputed from current evidence. The UI shows their algorithms and the substituted equation.

**Is model confidence a hand-written score?**  
No. It aggregates actual XGBoost winning-class probabilities. Deterministic rules are not presented as model probability.

**Why combine DistilBERT and XGBoost?**  
DistilBERT captures semantic context from log text. XGBoost combines those embeddings with interpretable structured security signals and supports efficient saved-model inference and TreeSHAP.

**Why use regex if Transformer NER is available?**  
IPs, hashes, URLs, ports, Event IDs, and timestamps have strict syntax. Deterministic validators are more reliable and auditable. Transformer NER is limited to semantic entities in unstructured text.

**How is NetworkX genuine?**  
The backend creates a new MultiDiGraph from each request. Nodes and edges store supporting evidence identifiers; changing evidence changes the serialized graph.

**What is predefined?**  
Only domain knowledge: parsers, feature definitions, ATT&CK behavior mappings, evidence requirements, transition rules, and formula weights. Investigation answers are not predefined.

**Can adding unrelated evidence advance the demo?**  
No. A test adds a valid unrelated artifact and verifies that technique-driven coverage and recommendation order do not progress to a scripted state.

**Why is the accuracy not 99%?**  
The 73.33% held-out accuracy is the actual result from a deliberately small synthetic dataset. Reporting the real limitation is more defensible than inflating a college prototype result.

**Does the report use an LLM?**  
The original Review 2 text report remains deterministic. The Review 3 report can use an LLM to select cited claim IDs; the final factual text is rendered from the verified claim registry.

## Final hard-coding audit

### Previously scenario-driven or fallback behavior

- The header exposed Primary demo / Scenario 2 / Scenario 3 as direct investigation controls.
- Sample selection and analysis presentation were coupled in one client component.
- Event classification used deterministic feature points instead of a fitted model.
- Model certainty used a heuristic count formula.
- The graph was a custom in-browser node/edge structure, not NetworkX.
- Explainability showed feature-point reasons under a disclosed SHAP fallback label.
- Transformer NER was not running.

### Replaced with dynamic calculations

- New Investigation can start completely empty.
- Samples now load evidence files only through the same path as uploads.
- DistilBERT embeddings and saved XGBoost probabilities drive classification and `M`.
- NetworkX builds and serializes the graph from parsed events and entities.
- TreeSHAP produces event-level model contributions.
- Technique-driven requirement aggregation calculates `E` and recommendations.
- Timeline relationships calculate `T`.
- Independent browser/server checks calculate `P`.
- Confidence, hypothesis, timeline, graph, MITRE mappings, recommendations, before/after state, and report are recalculated after every upload.

### Predefined domain knowledge that remains

- parser aliases and evidence-type detection rules;
- deterministic IOC validators;
- structured feature definitions;
- ATT&CK v19.2 behavior patterns;
- evidence requirements and usefulness weights;
- supported attack-stage transitions;
- confidence and recommendation formula weights; and
- safe synthetic datasets and labelled training examples.

### Genuine AI/ML components

- DistilBERT contextual embedding inference;
- XGBoost model training, saved-model inference, and class probability output;
- DistilBERT token-classification NER for semantic text entities; and
- SHAP TreeExplainer.

### Deterministic components

- parsing, normalization, SHA-256, provenance checks;
- structured IOC extraction;
- ATT&CK behavior mapping;
- evidence requirements and ranking formula;
- temporal/correlation algorithm;
- confidence formula; and
- report generation.

### Future-work components

- large-scale model training and calibration;
- full ATT&CK STIX ingestion;
- production case storage, access control, and audit infrastructure;
- isolated binary forensic parsing; and
- broader retrieval over external intelligence sources and persistent case storage.

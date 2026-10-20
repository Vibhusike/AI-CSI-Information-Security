'use client';

import { useCallback, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertCircle,
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  Database,
  Download,
  FileCheck2,
  FilePlus2,
  Fingerprint,
  FlaskConical,
  Gauge,
  GitBranch,
  LoaderCircle,
  Network,
  Plus,
  ServerCog,
  ShieldCheck,
  Sparkles,
  Upload,
  X,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { sha256Text, type EvidenceType } from '@/lib/evidence-client';

type ClientArtifact = {
  id: string;
  name: string;
  type: EvidenceType;
  text: string;
  sha256: string;
  size: number;
  ingestedAt: string;
};
type Entity = {
  type: string;
  value: string;
  confidence: number;
  extractor: string;
};
type ShapItem = { feature: string; value: number };
type EventResult = {
  id: string;
  timestamp: string;
  sourceType: string;
  sourceFile: string;
  artifactId: string;
  host: string;
  user: string;
  process: string;
  parentProcess: string;
  srcIp: string;
  dstIp: string;
  domain: string;
  url: string;
  eventType: string;
  status: string;
  resource: string;
  message: string;
  provenanceHash: string;
  classification: 'NORMAL' | 'SUSPICIOUS' | 'MALICIOUS';
  classificationProbability: number;
  classProbabilities: Record<string, number>;
  entities: Entity[];
  shap: ShapItem[];
  mitre: Array<{ techniqueId: string; technique: string; tactic: string }>;
};
type Recommendation = {
  type: EvidenceType;
  label: string;
  weight: number;
  normalizedWeight: number;
  status: string;
  techniques: string[];
  reasons: string[];
  recommendationScore: number;
  estimatedCoverageGain: number;
  estimatedConfidenceGain: number;
  scoreFormula: {
    techniqueRelevance: number;
    stageSupport: number;
    confidenceContribution: number;
    confirmOrRefuteValue: number;
    formula: string;
  };
};
type Analysis = {
  caseId: string;
  analysedAt: string;
  droppedRows: number;
  artifacts: Array<
    ClientArtifact & {
      rowCount: number;
      parseError: string;
      provenanceScore: number;
      provenanceChecks: Record<string, boolean>;
    }
  >;
  events: EventResult[];
  hypothesis: {
    id: string;
    title: string;
    summary: string;
    supportingEventIds: string[];
    techniqueVotes: Record<string, number>;
  };
  mitre: Array<{
    techniqueId: string;
    technique: string;
    tactic: string;
    evidenceEventIds: string[];
    sourceFiles: string[];
  }>;
  graph: {
    engine: string;
    nodes: Array<{
      id: string;
      label: string;
      kind: string;
      evidenceIds: string[];
      provenanceHash?: string;
      [key: string]: unknown;
    }>;
    edges: Array<{
      id: string;
      source: string;
      target: string;
      relation: string;
      evidenceIds: string[];
      weight?: number;
      sharedEntities?: string[];
      [key: string]: unknown;
    }>;
  };
  correlations: Array<{
    source: string;
    target: string;
    weight: number;
    sharedEntities: string[];
    minutesApart: number;
  }>;
  coverageRequirements: Array<{
    type: EvidenceType;
    label: string;
    weight: number;
    normalizedWeight: number;
    status: 'PRESENT' | 'MISSING';
    techniques: string[];
    reasons: string[];
  }>;
  recommendations: Recommendation[];
  confidence: {
    evidenceCoverage: number;
    modelConfidence: number;
    temporalCoherence: number;
    provenanceIntegrity: number;
    overall: number;
    label: 'Low' | 'Moderate' | 'High';
    calculation: string;
    modelDetails: {
      model: string;
      input: string;
      eventsAggregated: number;
      aggregation: string;
    };
    temporalDetails: Record<string, number | string>;
    provenanceDetails: {
      artifactsPassedAllChecks: number;
      artifactCount: number;
      aggregation: string;
    };
  };
  report: {
    title: string;
    generationMethod: string;
    caseSummary: string;
    attackHypothesis: string;
    evidenceAnalyzed: Array<{ name: string; type: string; sha256: string }>;
    timeline: Array<Record<string, unknown>>;
    mitre: unknown[];
    affectedEntities: string[];
    confidence: Analysis['confidence'];
    missingEvidence: Array<{ type: string; score: number; why: string[] }>;
    explainabilitySummary: string;
    limitations: string[];
    recommendedActions: string[];
  };
  system: Record<string, { status: string; [key: string]: unknown }>;
};

type SampleFile = { url: string; name: string; type: EvidenceType };
type Sample = {
  id: string;
  title: string;
  description: string;
  initial: SampleFile[];
  optional: SampleFile[];
};

const root = '/sample-data/review2';
const samples: Sample[] = [
  {
    id: 'phishing',
    title: 'Phishing / Credential Compromise',
    description: 'Incomplete authentication, firewall, and IDS evidence.',
    initial: [
      {
        url: `${root}/phishing_endpoint_auth.csv`,
        name: 'Windows-Authentication.csv',
        type: 'endpoint_auth',
      },
      {
        url: `${root}/phishing_firewall.csv`,
        name: 'Perimeter-Firewall.csv',
        type: 'firewall',
      },
      {
        url: `${root}/phishing_ids.jsonl`,
        name: 'IDS-Alerts.jsonl',
        type: 'ids',
      },
    ],
    optional: [
      {
        url: `${root}/phishing_email_headers.json`,
        name: 'Email-Headers.json',
        type: 'email_headers',
      },
      { url: `${root}/phishing_dns.csv`, name: 'DNS-Queries.csv', type: 'dns' },
    ],
  },
  {
    id: 'malware',
    title: 'Malware / Persistence',
    description: 'Incomplete EDR evidence for a safe synthetic malware chain.',
    initial: [
      {
        url: `${root}/malware_edr.jsonl`,
        name: 'EDR-Detections.jsonl',
        type: 'edr',
      },
    ],
    optional: [
      {
        url: `${root}/malware_sysmon.csv`,
        name: 'Sysmon-Events.csv',
        type: 'sysmon',
      },
      {
        url: `${root}/malware_memory.json`,
        name: 'Memory-Indicators.json',
        type: 'memory',
      },
    ],
  },
  {
    id: 'exfil',
    title: 'Data Exfiltration',
    description: 'Incomplete proxy, firewall, and authentication evidence.',
    initial: [
      { url: `${root}/exfil_proxy.csv`, name: 'Web-Proxy.csv', type: 'proxy' },
      {
        url: `${root}/exfil_firewall.csv`,
        name: 'Egress-Firewall.csv',
        type: 'firewall',
      },
      {
        url: `${root}/exfil_auth.csv`,
        name: 'Authentication.csv',
        type: 'endpoint_auth',
      },
    ],
    optional: [
      {
        url: `${root}/exfil_pcap.json`,
        name: 'Sanitised-PCAP-Metadata.json',
        type: 'pcap',
      },
    ],
  },
];

const timeFormat = new Intl.DateTimeFormat('en-IN', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
  timeZone: 'UTC',
});
const readable = (value: string) =>
  value
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
const percent = (value: number) => `${Math.round(value * 100)}%`;
const displayValue = (value: unknown) => {
  if (value === null || value === undefined || value === '') return '—';
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  )
    return String(value);
  return JSON.stringify(value);
};
const evidenceLabel = (type: string) =>
  type
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');

function makeCaseId() {
  const bytes = new Uint16Array(1);
  crypto.getRandomValues(bytes);
  return `ACSI-${new Date().getFullYear()}-${String(bytes[0] % 10000).padStart(4, '0')}`;
}

async function sampleArtifact(
  file: SampleFile,
  caseId: string,
): Promise<ClientArtifact> {
  const response = await fetch(file.url);
  if (!response.ok) throw new Error(`Could not load ${file.name}.`);
  const text = await response.text();
  return {
    id: `${caseId}-${Date.now()}-${file.name}`,
    name: file.name,
    type: file.type,
    text,
    sha256: await sha256Text(text),
    size: new TextEncoder().encode(text).length,
    ingestedAt: new Date().toISOString(),
  };
}

function PanelTitle({
  eyebrow,
  title,
  aside,
}: {
  eyebrow: string;
  title: string;
  aside?: React.ReactNode;
}) {
  return (
    <div className="mb-5 flex items-start justify-between gap-4">
      <div>
        <p className="text-[11px] font-semibold uppercase tracking-[0.15em] text-slate-500">
          {eyebrow}
        </p>
        <h2 className="mt-1 text-lg font-semibold tracking-tight">{title}</h2>
      </div>
      {aside}
    </div>
  );
}

function Metric({
  label,
  value,
  note,
  icon: Icon,
  accent = 'emerald',
}: {
  label: string;
  value: string;
  note: string;
  icon: typeof Activity;
  accent?: 'emerald' | 'amber' | 'sky' | 'violet';
}) {
  const tone =
    accent === 'amber'
      ? 'text-amber-300 bg-amber-300/10'
      : accent === 'sky'
        ? 'text-sky-300 bg-sky-300/10'
        : accent === 'violet'
          ? 'text-violet-300 bg-violet-300/10'
          : 'text-emerald-300 bg-emerald-300/10';
  return (
    <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-4 shadow-lg shadow-black/10">
      <div className="flex items-center justify-between text-slate-400">
        <p className="text-[11px] font-semibold uppercase tracking-[0.13em]">
          {label}
        </p>
        <span className={`grid size-8 place-items-center rounded-lg ${tone}`}>
          <Icon className="size-4" />
        </span>
      </div>
      <p className="mt-3 text-3xl font-semibold tracking-tight">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{note}</p>
    </article>
  );
}

function BreakdownRow({
  label,
  value,
  weight,
  color,
}: {
  label: string;
  value: number;
  weight: string;
  color: string;
}) {
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-3 text-xs">
        <span className="text-slate-400">
          {label} <span className="text-slate-600">({weight})</span>
        </span>
        <span className="font-mono font-semibold text-slate-200">
          {value.toFixed(4)}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-white/8">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: percent(value) }}
        />
      </div>
    </div>
  );
}

function GraphView({ analysis }: { analysis: Analysis }) {
  const [selected, setSelected] = useState<{
    type: 'node' | 'edge';
    data: Record<string, unknown>;
  } | null>(null);
  const visibleNodes = analysis.graph.nodes.slice(0, 24);
  const ids = new Set(visibleNodes.map((node) => node.id));
  const edges = analysis.graph.edges
    .filter((edge) => ids.has(edge.source) && ids.has(edge.target))
    .slice(0, 42);
  const columns = ['artifact', 'event', 'entity', 'technique'] as const;
  const category = (kind: string) =>
    kind === 'artifact'
      ? 'artifact'
      : kind === 'event'
        ? 'event'
        : kind === 'technique'
          ? 'technique'
          : 'entity';
  const x: Record<(typeof columns)[number], number> = {
    artifact: 90,
    event: 300,
    entity: 520,
    technique: 735,
  };
  const positions = new Map<string, { x: number; y: number }>();
  for (const column of columns) {
    const nodes = visibleNodes.filter((node) => category(node.kind) === column);
    nodes.forEach((node, index) =>
      positions.set(node.id, {
        x: x[column],
        y: 48 + index * (252 / Math.max(1, nodes.length - 1)),
      }),
    );
  }
  const color = {
    artifact: '#38bdf8',
    event: '#6ee7b7',
    entity: '#fbbf24',
    technique: '#c084fc',
  };
  return (
    <div>
      <div className="overflow-hidden rounded-xl border border-white/8 bg-[#081311]">
        <svg
          viewBox="0 0 825 335"
          className="h-[330px] w-full"
          aria-label="NetworkX investigation graph"
        >
          <title>NetworkX investigation graph</title>
          <defs>
            <marker
              id="nx-arrow"
              markerWidth="7"
              markerHeight="7"
              refX="6"
              refY="3.5"
              orient="auto"
            >
              <polygon points="0 0, 7 3.5, 0 7" fill="#334b46" />
            </marker>
          </defs>
          {edges.map((edge) => {
            const source = positions.get(edge.source);
            const target = positions.get(edge.target);
            if (!source || !target) return null;
            return (
              <line
                key={edge.id}
                onClick={() => setSelected({ type: 'edge', data: edge })}
                className="cursor-pointer"
                x1={source.x + 45}
                y1={source.y}
                x2={target.x - 45}
                y2={target.y}
                stroke={
                  edge.relation === 'CORRELATES_WITH' ? '#4f8f7f' : '#263b37'
                }
                strokeDasharray={
                  edge.relation === 'CORRELATES_WITH' ? '5 4' : undefined
                }
                strokeWidth="1.5"
                markerEnd="url(#nx-arrow)"
              />
            );
          })}
          {visibleNodes.map((node) => {
            const point = positions.get(node.id);
            if (!point) return null;
            const kind = category(node.kind);
            const label =
              node.label.length > 19
                ? `${node.label.slice(0, 17)}…`
                : node.label;
            return (
              <g
                key={node.id}
                onClick={() => setSelected({ type: 'node', data: node })}
                className="cursor-pointer"
              >
                <rect
                  x={point.x - 47}
                  y={point.y - 14}
                  width="94"
                  height="28"
                  rx="8"
                  fill={`${color[kind]}18`}
                  stroke={`${color[kind]}80`}
                />
                <text
                  x={point.x}
                  y={point.y + 3.5}
                  fill="#dcebe7"
                  fontSize="8.5"
                  textAnchor="middle"
                >
                  {label}
                </text>
              </g>
            );
          })}
          {columns.map((kind) => (
            <text
              key={kind}
              x={x[kind]}
              y="326"
              fill={color[kind]}
              fontSize="9"
              textAnchor="middle"
            >
              {kind.toUpperCase()}
            </text>
          ))}
        </svg>
      </div>
      {selected && (
        <div className="mt-3 rounded-xl border border-white/8 bg-white/[0.025] p-3">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                Selected {selected.type} · provenance
              </p>
              <p className="mt-1 text-sm text-slate-300">
                {String(
                  selected.data.label ??
                    selected.data.relation ??
                    selected.data.id,
                )}
              </p>
            </div>
            <button
              onClick={() => setSelected(null)}
              aria-label="Close graph details"
            >
              <X className="size-4 text-slate-500" />
            </button>
          </div>
          <p className="mt-2 break-all font-mono text-[10px] leading-5 text-slate-600">
            Evidence: {JSON.stringify(selected.data.evidenceIds ?? [])}
            <br />
            {selected.data.provenanceHash
              ? `SHA-256: ${displayValue(selected.data.provenanceHash)}`
              : ''}
            {selected.data.sharedEntities
              ? `Shared: ${JSON.stringify(selected.data.sharedEntities)}`
              : ''}
          </p>
        </div>
      )}
    </div>
  );
}

function EmptyInvestigation({
  onLoadSample,
  onAdd,
}: {
  onLoadSample: () => void;
  onAdd: () => void;
}) {
  return (
    <section className="grid min-h-[480px] place-items-center rounded-2xl border border-dashed border-white/15 bg-[#0d1b19] p-8 text-center">
      <div className="max-w-md">
        <span className="mx-auto grid size-14 place-items-center rounded-2xl border border-emerald-300/20 bg-emerald-300/10 text-emerald-300">
          <FilePlus2 className="size-6" />
        </span>
        <h2 className="mt-5 text-2xl font-semibold">
          No evidence in this investigation
        </h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Add real CSV, JSON, JSONL, LOG, or TXT artifacts. Every result will be
          generated from their contents through the same local analysis
          pipeline.
        </p>
        <div className="mt-5 flex flex-wrap justify-center gap-2">
          <Button
            className="bg-emerald-300 text-emerald-950 hover:bg-emerald-200"
            onClick={onAdd}
          >
            <Upload />
            Add evidence
          </Button>
          <Button
            variant="outline"
            className="border-white/10 bg-white/[0.03] text-slate-300"
            onClick={onLoadSample}
          >
            <FlaskConical />
            Load sample case
          </Button>
        </div>
      </div>
    </section>
  );
}

function AnalysisDetails({ analysis }: { analysis: Analysis }) {
  const metrics = analysis.system.xgboost.metrics as
    | Record<string, unknown>
    | undefined;
  return (
    <div className="space-y-5">
      <section className="grid gap-5 xl:grid-cols-[.9fr_1.1fr]">
        <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
          <PanelTitle
            eyebrow="How calculated?"
            title="Investigation Confidence"
            aside={
              <Badge className="border-amber-300/20 bg-amber-300/10 text-amber-200">
                {analysis.confidence.overall}% · {analysis.confidence.label}
              </Badge>
            }
          />
          <div className="space-y-4">
            <BreakdownRow
              label="E · Evidence coverage"
              value={analysis.confidence.evidenceCoverage}
              weight="35%"
              color="bg-sky-400"
            />
            <BreakdownRow
              label="M · XGBoost model confidence"
              value={analysis.confidence.modelConfidence}
              weight="25%"
              color="bg-violet-400"
            />
            <BreakdownRow
              label="T · Temporal / causal coherence"
              value={analysis.confidence.temporalCoherence}
              weight="25%"
              color="bg-emerald-400"
            />
            <BreakdownRow
              label="P · Provenance / integrity"
              value={analysis.confidence.provenanceIntegrity}
              weight="15%"
              color="bg-amber-300"
            />
          </div>
          <pre className="mt-5 whitespace-pre-wrap rounded-xl border border-white/8 bg-[#081311] p-3 font-mono text-xs leading-6 text-slate-400">
            {analysis.confidence.calculation}
          </pre>
          <div className="mt-4 space-y-2 text-xs leading-5 text-slate-500">
            <p>
              <strong className="text-slate-300">M:</strong>{' '}
              {analysis.confidence.modelDetails.aggregation}
            </p>
            <p>
              <strong className="text-slate-300">T:</strong>{' '}
              {String(analysis.confidence.temporalDetails.formula)}
            </p>
            <p>
              <strong className="text-slate-300">P:</strong>{' '}
              {analysis.confidence.provenanceDetails.artifactsPassedAllChecks}/
              {analysis.confidence.provenanceDetails.artifactCount} artifacts
              passed all checks.{' '}
              {analysis.confidence.provenanceDetails.aggregation}
            </p>
          </div>
        </article>
        <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
          <PanelTitle
            eyebrow="Evidence requirement analysis"
            title="Expected vs observed evidence"
          />
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-white/10 hover:bg-transparent">
                  <TableHead className="text-slate-500">Evidence</TableHead>
                  <TableHead className="text-slate-500">Status</TableHead>
                  <TableHead className="text-slate-500">Weight</TableHead>
                  <TableHead className="text-slate-500">
                    Relevant techniques
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {analysis.coverageRequirements.map((item) => (
                  <TableRow key={item.type} className="border-white/8">
                    <TableCell className="font-medium">{item.label}</TableCell>
                    <TableCell>
                      <Badge
                        className={
                          item.status === 'PRESENT'
                            ? 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200'
                            : 'border-amber-300/20 bg-amber-300/10 text-amber-200'
                        }
                      >
                        {item.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {percent(item.normalizedWeight)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-slate-500">
                      {item.techniques.join(', ')}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </article>
      </section>
      <section className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
        <PanelTitle
          eyebrow="Actual model output"
          title="XGBoost event probabilities"
          aside={
            <Badge
              variant="outline"
              className="border-violet-300/20 text-violet-200"
            >
              DistilBERT 768d + 10 features
            </Badge>
          }
        />
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="border-white/10 hover:bg-transparent">
                <TableHead className="text-slate-500">Event</TableHead>
                <TableHead className="text-slate-500">Prediction</TableHead>
                <TableHead className="text-slate-500">Normal</TableHead>
                <TableHead className="text-slate-500">Suspicious</TableHead>
                <TableHead className="text-slate-500">Malicious</TableHead>
                <TableHead className="text-slate-500">Source</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {analysis.events.map((event) => (
                <TableRow key={event.id} className="border-white/8">
                  <TableCell className="font-medium">
                    {readable(event.eventType)}
                  </TableCell>
                  <TableCell>
                    <Badge
                      className={
                        event.classification === 'MALICIOUS'
                          ? 'border-red-400/20 bg-red-400/10 text-red-300'
                          : event.classification === 'SUSPICIOUS'
                            ? 'border-amber-300/20 bg-amber-300/10 text-amber-200'
                            : 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200'
                      }
                    >
                      {event.classification}{' '}
                      {(event.classificationProbability * 100).toFixed(1)}%
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {percent(event.classProbabilities.NORMAL ?? 0)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {percent(event.classProbabilities.SUSPICIOUS ?? 0)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {percent(event.classProbabilities.MALICIOUS ?? 0)}
                  </TableCell>
                  <TableCell className="text-xs text-slate-500">
                    {event.sourceFile}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>
      <section className="grid gap-5 lg:grid-cols-2">
        <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
          <PanelTitle
            eyebrow="Temporal / causal inputs"
            title="Coherence factors"
          />
          <dl className="grid grid-cols-2 gap-3">
            {Object.entries(analysis.confidence.temporalDetails)
              .filter(([, value]) => typeof value === 'number')
              .map(([label, value]) => (
                <div
                  key={label}
                  className="rounded-xl border border-white/8 bg-white/[0.025] p-3"
                >
                  <dt className="text-xs text-slate-500">{readable(label)}</dt>
                  <dd className="mt-1 font-mono text-lg font-semibold">
                    {typeof value === 'number' && value <= 1
                      ? percent(value)
                      : String(value)}
                  </dd>
                </div>
              ))}
          </dl>
        </article>
        <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
          <PanelTitle
            eyebrow="Reproducible baseline"
            title="Held-out model evaluation"
          />
          <dl className="grid grid-cols-2 gap-3 text-sm">
            {[
              ['Samples', metrics?.samples],
              [
                'Train / test',
                `${String(metrics?.train_samples)} / ${String(metrics?.test_samples)}`,
              ],
              ['Accuracy', metrics?.accuracy],
              ['Macro F1', metrics?.macro_f1],
              ['Macro precision', metrics?.macro_precision],
              ['Macro recall', metrics?.macro_recall],
            ].map(([label, value]) => (
              <div
                key={String(label)}
                className="rounded-xl border border-white/8 bg-white/[0.025] p-3"
              >
                <dt className="text-xs text-slate-500">{String(label)}</dt>
                <dd className="mt-1 font-mono text-lg font-semibold">
                  {typeof value === 'number' && value <= 1
                    ? percent(value)
                    : displayValue(value)}
                </dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-xs leading-5 text-slate-500">
            These are actual metrics from the saved 75/25 stratified split, not
            claims of production generalisation.
          </p>
        </article>
      </section>
    </div>
  );
}

function SystemView({ analysis }: { analysis: Analysis }) {
  return (
    <div className="space-y-5">
      <section className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
        <PanelTitle
          eyebrow="Open-source implementation disclosure"
          title="What actually ran"
          aside={
            <Badge
              variant="outline"
              className="border-emerald-300/20 text-emerald-200"
            >
              Runtime verified
            </Badge>
          }
        />
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="border-white/10 hover:bg-transparent">
                <TableHead className="text-slate-500">Component</TableHead>
                <TableHead className="text-slate-500">Status</TableHead>
                <TableHead className="text-slate-500">
                  Runtime details
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {Object.entries(analysis.system).map(([name, item]) => (
                <TableRow key={name} className="border-white/8">
                  <TableCell className="font-medium">
                    {readable(name)}
                  </TableCell>
                  <TableCell>
                    <Badge
                      className={
                        item.status === 'REAL' ||
                        item.status === 'CUSTOM AI-CSI LOGIC' ||
                        item.status === 'OFFICIAL SUBSET'
                          ? 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200'
                          : item.status.includes('NOT')
                            ? 'border-slate-300/10 bg-slate-300/5 text-slate-400'
                            : 'border-sky-300/20 bg-sky-300/10 text-sky-200'
                      }
                    >
                      {item.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-3xl text-xs leading-5 text-slate-500">
                    {Object.entries(item)
                      .filter(([key]) => key !== 'status' && key !== 'metrics')
                      .map(
                        ([key, value]) =>
                          `${readable(key)}: ${displayValue(value)}`,
                      )
                      .join(' · ')}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>
      <section className="grid gap-5 lg:grid-cols-2">
        <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
          <PanelTitle
            eyebrow="Architecture"
            title="Evidence-driven execution"
          />
          <ol className="space-y-2 text-sm text-slate-400">
            {[
              'Evidence files and real SHA-256 provenance',
              'Parser and common event schema',
              'Hybrid deterministic IOC + Transformer NER extraction',
              'DistilBERT contextual embeddings',
              'XGBoost classification probabilities',
              'NetworkX graph and cross-source correlation',
              'Evidence-derived timeline and MITRE ATT&CK',
              'Coverage, confidence, missing-evidence ranking',
              'Real TreeSHAP explanations',
              'Deterministic evidence-grounded report',
            ].map((step, index) => (
              <li
                key={step}
                className="flex items-center gap-3 rounded-xl border border-white/8 bg-white/[0.025] p-3"
              >
                <span className="grid size-6 shrink-0 place-items-center rounded-md bg-emerald-300/10 font-mono text-xs text-emerald-300">
                  {index + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>
        </article>
        <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
          <PanelTitle eyebrow="Scope discipline" title="Review-2 boundaries" />
          <ul className="space-y-3 text-sm leading-6 text-slate-400">
            <li className="flex gap-2">
              <CheckCircle2 className="mt-1 size-4 shrink-0 text-emerald-300" />
              Samples supply evidence files only; no sample ID enters the
              analysis service.
            </li>
            <li className="flex gap-2">
              <CheckCircle2 className="mt-1 size-4 shrink-0 text-emerald-300" />
              All investigation outputs are recalculated after every upload.
            </li>
            <li className="flex gap-2">
              <CheckCircle2 className="mt-1 size-4 shrink-0 text-emerald-300" />
              MITRE mappings and evidence requirements are predefined domain
              knowledge, not predefined answers.
            </li>
            <li className="flex gap-2">
              <AlertCircle className="mt-1 size-4 shrink-0 text-amber-300" />
              The small synthetic training set demonstrates a genuine pipeline;
              it is not production-ready or externally validated.
            </li>
            <li className="flex gap-2">
              <AlertCircle className="mt-1 size-4 shrink-0 text-amber-300" />
              LLM/RAG is intentionally not implemented for Review 2.
            </li>
          </ul>
        </article>
      </section>
    </div>
  );
}

export default function EvidenceDrivenConsole() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [caseId, setCaseId] = useState('ACSI-REVIEW2-NEW');
  const [artifacts, setArtifacts] = useState<ClientArtifact[]>([]);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [selectedEventId, setSelectedEventId] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingText, setLoadingText] = useState('');
  const [error, setError] = useState('');
  const [view, setView] = useState<'investigation' | 'details' | 'system'>(
    'investigation',
  );
  const [sampleOpen, setSampleOpen] = useState(false);
  const [sampleLabel, setSampleLabel] = useState('');
  const [availableSampleFiles, setAvailableSampleFiles] = useState<
    SampleFile[]
  >([]);
  const [feedback, setFeedback] = useState<{
    before: number;
    after: number;
    artifact: string;
  } | null>(null);

  const relevantEvents = useMemo(
    () =>
      analysis?.events.filter((event) => event.classification !== 'NORMAL') ??
      [],
    [analysis],
  );
  const selectedEvent =
    analysis?.events.find((event) => event.id === selectedEventId) ??
    relevantEvents[0] ??
    analysis?.events[0];

  const runAnalysis = useCallback(
    async (
      nextArtifacts: ClientArtifact[],
      nextCaseId: string,
      previous?: Analysis | null,
    ) => {
      if (!nextArtifacts.length) {
        setAnalysis(null);
        return;
      }
      setLoading(true);
      setLoadingText(
        'Running DistilBERT embeddings, XGBoost, NetworkX, and SHAP…',
      );
      setError('');
      try {
        const response = await fetch('http://127.0.0.1:8000/api/analyse', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            caseId: nextCaseId,
            artifacts: nextArtifacts,
          }),
        });
        const body = (await response.json()) as Analysis | { detail?: string };
        if (!response.ok)
          throw new Error(
            'detail' in body && body.detail
              ? body.detail
              : 'The analysis service rejected the evidence.',
          );
        const result = body as Analysis;
        setAnalysis(result);
        setSelectedEventId(
          result.events.find((event) => event.classification !== 'NORMAL')
            ?.id ??
            result.events[0]?.id ??
            '',
        );
        if (previous && nextArtifacts.length > previous.artifacts.length)
          setFeedback({
            before: previous.confidence.overall,
            after: result.confidence.overall,
            artifact: nextArtifacts[nextArtifacts.length - 1].name,
          });
      } catch (reason) {
        setError(
          reason instanceof Error
            ? `${reason.message} Ensure the local analysis service is running with npm run dev.`
            : 'Evidence analysis failed.',
        );
      } finally {
        setLoading(false);
        setLoadingText('');
      }
    },
    [],
  );

  function newInvestigation() {
    setCaseId(makeCaseId());
    setArtifacts([]);
    setAnalysis(null);
    setSelectedEventId('');
    setSampleLabel('');
    setAvailableSampleFiles([]);
    setFeedback(null);
    setError('');
    setView('investigation');
  }

  async function loadSample(sample: Sample) {
    const nextCaseId = makeCaseId();
    setCaseId(nextCaseId);
    setSampleOpen(false);
    setSampleLabel(sample.title);
    setAvailableSampleFiles(sample.optional);
    setFeedback(null);
    setLoading(true);
    setLoadingText('Loading safe synthetic evidence files…');
    try {
      const loaded = await Promise.all(
        sample.initial.map((file) => sampleArtifact(file, nextCaseId)),
      );
      setArtifacts(loaded);
      await runAnalysis(loaded, nextCaseId, null);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : 'The sample evidence could not be loaded.',
      );
      setLoading(false);
    }
  }

  async function addSampleArtifact(file: SampleFile) {
    if (artifacts.some((item) => item.name === file.name)) {
      setError(`${file.name} is already in this investigation.`);
      return;
    }
    setLoading(true);
    setLoadingText(`Reading and hashing ${file.name}…`);
    try {
      const loaded = await sampleArtifact(file, caseId);
      const next = [...artifacts, loaded];
      setArtifacts(next);
      await runAnalysis(next, caseId, analysis);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : 'The sample artifact could not be added.',
      );
      setLoading(false);
    }
  }

  async function handleUpload(files?: FileList | null) {
    if (!files?.length) return;
    const accepted = [...files].filter((file) =>
      /\.(csv|json|jsonl|log|txt)$/i.test(file.name),
    );
    if (accepted.length !== files.length) {
      setError('Supported evidence formats: CSV, JSON, JSONL, LOG, and TXT.');
      return;
    }
    setLoading(true);
    setLoadingText('Reading and hashing uploaded evidence…');
    setError('');
    try {
      const additions = await Promise.all(
        accepted.map(async (file) => {
          const text = await file.text();
          return {
            id: `${caseId}-${Date.now()}-${file.name}`,
            name: file.name,
            type: 'unknown' as EvidenceType,
            text,
            sha256: await sha256Text(text),
            size: file.size,
            ingestedAt: new Date().toISOString(),
          };
        }),
      );
      const next = [...artifacts, ...additions];
      setArtifacts(next);
      await runAnalysis(next, caseId, analysis);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : 'The evidence files could not be read.',
      );
      setLoading(false);
    }
  }

  function downloadReport() {
    if (!analysis) return;
    const report = analysis.report;
    const text = [
      report.title,
      `Case: ${analysis.caseId}`,
      report.generationMethod,
      '',
      'CASE SUMMARY',
      report.caseSummary,
      '',
      'ATTACK HYPOTHESIS',
      report.attackHypothesis,
      '',
      'EVIDENCE ANALYZED',
      ...report.evidenceAnalyzed.map(
        (item) => `- ${item.name} | ${item.type} | SHA-256 ${item.sha256}`,
      ),
      '',
      'TIMELINE',
      ...report.timeline.map(
        (item) =>
          `- ${String(item.timestamp)} | ${String(item.event)} | ${String(item.classification)} | ${String(item.source)}`,
      ),
      '',
      'CONFIDENCE',
      analysis.confidence.calculation,
      '',
      'MISSING EVIDENCE',
      ...report.missingEvidence.map(
        (item) =>
          `- ${item.type} | score ${item.score} | ${item.why.join(' ')}`,
      ),
      '',
      'LIMITATIONS',
      ...report.limitations.map((item) => `- ${item}`),
      '',
      'RECOMMENDED ACTIONS',
      ...report.recommendedActions.map((item) => `- ${item}`),
    ].join('\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${analysis.caseId}-forensic-report.txt`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  const openFilePicker = () => {
    if (inputRef.current) {
      inputRef.current.value = '';
      inputRef.current.click();
    }
  };
  const sampleForRecommendation = (type: EvidenceType) =>
    availableSampleFiles.find((file) => file.type === type);

  return (
    <main className="min-h-screen bg-[#07100f] text-[#e8f6ef] selection:bg-emerald-300/25">
      <header className="sticky top-0 z-30 border-b border-emerald-100/10 bg-[#091614]/95 px-5 py-3.5 backdrop-blur-xl lg:px-8">
        <div className="mx-auto flex max-w-[1500px] items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="grid size-10 place-items-center rounded-xl border border-emerald-300/20 bg-emerald-300/10 text-emerald-300">
              <Fingerprint className="size-5" />
            </span>
            <div>
              <p className="hidden text-[10px] font-semibold uppercase tracking-[0.2em] text-emerald-300/65 sm:block">
                CBS3002 · Review 2
              </p>
              <h1 className="text-base font-semibold tracking-tight sm:text-lg">
                AI-CSI Evidence Console
              </h1>
            </div>
          </div>
          <nav className="flex rounded-xl border border-white/10 bg-white/[0.025] p-1 text-xs">
            <button
              onClick={() => setView('investigation')}
              className={`rounded-lg px-3 py-2 transition ${view === 'investigation' ? 'bg-emerald-300 text-emerald-950' : 'text-slate-400 hover:text-white'}`}
            >
              Investigation
            </button>
            <button
              onClick={() => setView('details')}
              disabled={!analysis}
              className={`rounded-lg px-3 py-2 transition disabled:opacity-40 ${view === 'details' ? 'bg-emerald-300 text-emerald-950' : 'text-slate-400 hover:text-white'}`}
            >
              Analysis details
            </button>
            <button
              onClick={() => setView('system')}
              disabled={!analysis}
              className={`rounded-lg px-3 py-2 transition disabled:opacity-40 ${view === 'system' ? 'bg-emerald-300 text-emerald-950' : 'text-slate-400 hover:text-white'}`}
            >
              System information
            </button>
          </nav>
        </div>
      </header>
      <div className="mx-auto max-w-[1500px] space-y-5 px-5 py-6 lg:px-8">
        <section className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5 shadow-2xl shadow-black/20">
          <div className="flex flex-col justify-between gap-5 xl:flex-row xl:items-center">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-300">
                  Case {caseId}
                </p>
                {sampleLabel ? (
                  <Badge
                    variant="outline"
                    className="border-sky-300/20 text-sky-200"
                  >
                    <FlaskConical />
                    Safe synthetic sample data
                  </Badge>
                ) : (
                  <Badge
                    variant="outline"
                    className="border-white/10 text-slate-400"
                  >
                    Manual investigation
                  </Badge>
                )}
              </div>
              <h2 className="mt-1.5 text-2xl font-semibold tracking-tight">
                {analysis?.hypothesis.title ?? 'Evidence-driven investigation'}
              </h2>
              <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-400">
                {analysis?.hypothesis.summary ??
                  'Add evidence to begin. No hypothesis, timeline, confidence, or recommendation exists until files are analysed.'}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                className="border-white/10 bg-white/[0.03] text-slate-300"
                onClick={newInvestigation}
              >
                <Plus />
                New investigation
              </Button>
              <Dialog open={sampleOpen} onOpenChange={setSampleOpen}>
                <DialogTrigger
                  render={
                    <Button
                      variant="outline"
                      className="border-sky-300/20 bg-sky-300/[0.05] text-sky-200"
                    >
                      <FlaskConical />
                      Load sample case
                    </Button>
                  }
                />
                <DialogContent className="border-white/10 bg-[#0d1b19] text-[#e8f6ef] sm:max-w-2xl">
                  <DialogHeader>
                    <DialogTitle>
                      Load safe synthetic sample evidence
                    </DialogTitle>
                    <DialogDescription className="text-slate-400">
                      This loads evidence files only. The same backend used for
                      manual uploads derives every result.
                    </DialogDescription>
                  </DialogHeader>
                  <div className="grid gap-3">
                    {samples.map((sample) => (
                      <button
                        key={sample.id}
                        onClick={() => void loadSample(sample)}
                        className="rounded-xl border border-white/10 bg-white/[0.025] p-4 text-left transition hover:border-emerald-300/30 hover:bg-emerald-300/[0.05]"
                      >
                        <p className="font-semibold">{sample.title}</p>
                        <p className="mt-1 text-sm text-slate-400">
                          {sample.description}
                        </p>
                        <p className="mt-2 text-xs text-slate-600">
                          Loads {sample.initial.length} incomplete evidence file
                          {sample.initial.length === 1 ? '' : 's'}.
                        </p>
                      </button>
                    ))}
                  </div>
                </DialogContent>
              </Dialog>
              <input
                ref={inputRef}
                className="sr-only"
                type="file"
                multiple
                accept=".csv,.json,.jsonl,.log,.txt,text/csv,application/json,text/plain"
                onChange={(event) => void handleUpload(event.target.files)}
              />
              <Button
                className="bg-emerald-300 text-emerald-950 hover:bg-emerald-200"
                onClick={openFilePicker}
              >
                <Upload />
                Add evidence
              </Button>
            </div>
          </div>
        </section>
        {error && (
          <div
            role="alert"
            className="flex items-start gap-3 rounded-xl border border-red-400/20 bg-red-400/10 p-3 text-sm text-red-200"
          >
            <AlertCircle className="mt-0.5 size-4 shrink-0" />
            {error}
          </div>
        )}
        {feedback && analysis && (
          <div className="flex flex-col justify-between gap-3 rounded-2xl border border-emerald-300/25 bg-emerald-300/[0.08] p-4 sm:flex-row sm:items-center">
            <div className="flex items-start gap-3">
              <Sparkles className="mt-0.5 size-5 text-emerald-300" />
              <div>
                <p className="font-semibold">
                  Full evidence feedback loop completed
                </p>
                <p className="mt-0.5 text-sm text-slate-400">
                  {feedback.artifact} was hashed, parsed, embedded, classified,
                  correlated, and the investigation was recalculated.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 font-mono text-lg">
              <span className="text-slate-500">{feedback.before}%</span>
              <ArrowRight className="size-4 text-emerald-300" />
              <span className="font-bold text-emerald-300">
                {feedback.after}%
              </span>
              <Badge className="border-emerald-300/20 bg-emerald-300/10 text-emerald-200">
                {feedback.after - feedback.before >= 0 ? '+' : ''}
                {(feedback.after - feedback.before).toFixed(1)} pts
              </Badge>
            </div>
          </div>
        )}
        {loading && (
          <section className="grid min-h-[380px] place-items-center rounded-2xl border border-white/10 bg-[#0d1b19]">
            <div className="text-center text-slate-400">
              <LoaderCircle className="mx-auto mb-3 size-7 animate-spin text-emerald-300" />
              <p className="font-medium text-slate-200">
                Analysing current evidence
              </p>
              <p className="mt-1 text-sm">{loadingText}</p>
              <p className="mt-3 text-xs text-slate-600">
                First run may take longer while open-source models load.
              </p>
            </div>
          </section>
        )}
        {!loading && !analysis && (
          <EmptyInvestigation
            onAdd={openFilePicker}
            onLoadSample={() => setSampleOpen(true)}
          />
        )}
        {!loading && analysis && view === 'details' && (
          <AnalysisDetails analysis={analysis} />
        )}
        {!loading && analysis && view === 'system' && (
          <SystemView analysis={analysis} />
        )}
        {!loading && analysis && view === 'investigation' && (
          <>
            <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <Metric
                label="Investigation confidence"
                value={`${analysis.confidence.overall}%`}
                note={`${analysis.confidence.label} evidential support`}
                icon={Gauge}
                accent="amber"
              />
              <Metric
                label="Evidence coverage"
                value={percent(analysis.confidence.evidenceCoverage)}
                note={`${analysis.coverageRequirements.filter((item) => item.status === 'PRESENT').length}/${analysis.coverageRequirements.length} required sources present`}
                icon={FileCheck2}
              />
              <Metric
                label="ML-classified events"
                value={String(relevantEvents.length)}
                note={`${analysis.events.length} normalized events`}
                icon={BrainCircuit}
                accent="violet"
              />
              <Metric
                label="NetworkX graph"
                value={`${analysis.graph.nodes.length}/${analysis.graph.edges.length}`}
                note="Nodes / evidence-derived edges"
                icon={Network}
                accent="sky"
              />
            </section>
            <section className="grid gap-5 xl:grid-cols-[1.05fr_.95fr]">
              <article className="rounded-2xl border border-amber-300/15 bg-[#0d1b19] p-5">
                <PanelTitle
                  eyebrow="Core novelty"
                  title="Missing Evidence Recommendation Engine"
                  aside={
                    <Badge className="border-amber-300/20 bg-amber-300/10 text-amber-200">
                      {analysis.confidence.label.toUpperCase()}
                    </Badge>
                  }
                />
                <div className="grid gap-3">
                  <BreakdownRow
                    label="E · Evidence coverage"
                    value={analysis.confidence.evidenceCoverage}
                    weight="35%"
                    color="bg-sky-400"
                  />
                  <BreakdownRow
                    label="M · XGBoost certainty"
                    value={analysis.confidence.modelConfidence}
                    weight="25%"
                    color="bg-violet-400"
                  />
                  <BreakdownRow
                    label="T · Temporal coherence"
                    value={analysis.confidence.temporalCoherence}
                    weight="25%"
                    color="bg-emerald-400"
                  />
                  <BreakdownRow
                    label="P · Provenance integrity"
                    value={analysis.confidence.provenanceIntegrity}
                    weight="15%"
                    color="bg-amber-300"
                  />
                </div>
                <button
                  onClick={() => setView('details')}
                  className="mt-4 w-full rounded-lg border border-white/8 bg-[#081311] px-3 py-2 text-left font-mono text-[11px] text-slate-500 transition hover:border-emerald-300/20"
                >
                  {analysis.confidence.calculation}
                  <span className="ml-2 text-emerald-300">
                    How calculated? →
                  </span>
                </button>
                <div className="mt-5 space-y-2">
                  <p className="mb-3 text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                    Ranked evidence gaps
                  </p>
                  {analysis.recommendations.slice(0, 5).map((item, index) => {
                    const sampleFile = sampleForRecommendation(item.type);
                    return (
                      <div
                        key={item.type}
                        className="rounded-xl border border-white/8 bg-white/[0.025] p-3"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex min-w-0 gap-3">
                            <span className="grid size-7 shrink-0 place-items-center rounded-lg bg-amber-300/10 font-mono text-xs font-bold text-amber-300">
                              {index + 1}
                            </span>
                            <div>
                              <p className="text-sm font-medium">
                                {item.label}
                              </p>
                              <p className="mt-0.5 text-xs leading-5 text-slate-500">
                                {item.reasons[0]}
                              </p>
                              <p className="mt-1 text-[10px] text-slate-600">
                                Relevant to {item.techniques.join(', ')} ·
                                missing · potential coverage +
                                {item.estimatedCoverageGain}%
                              </p>
                            </div>
                          </div>
                          <div className="shrink-0 text-right">
                            <p className="font-mono text-sm font-semibold text-amber-300">
                              {item.recommendationScore}
                            </p>
                            <p className="text-[10px] text-slate-600">
                              calculated score
                            </p>
                          </div>
                        </div>
                        <details className="mt-2 text-xs text-slate-500">
                          <summary className="cursor-pointer text-slate-400">
                            Why recommended?
                          </summary>
                          <p className="mt-2 rounded-lg bg-black/20 p-2 leading-5">
                            {item.scoreFormula.formula}
                            <br />
                            Relevance{' '}
                            {item.scoreFormula.techniqueRelevance.toFixed(
                              2,
                            )} ·
                            stage support{' '}
                            {item.scoreFormula.stageSupport.toFixed(2)} ·
                            confidence contribution{' '}
                            {item.scoreFormula.confidenceContribution.toFixed(
                              2,
                            )}{' '}
                            · confirm/refute{' '}
                            {item.scoreFormula.confirmOrRefuteValue.toFixed(2)}
                          </p>
                        </details>
                        {sampleFile && (
                          <Button
                            size="sm"
                            variant="outline"
                            className="mt-3 w-full border-sky-300/20 bg-sky-300/[0.05] text-sky-200"
                            onClick={() => void addSampleArtifact(sampleFile)}
                          >
                            <FlaskConical />
                            Add this sample evidence file
                          </Button>
                        )}
                      </div>
                    );
                  })}
                </div>
              </article>
              <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
                <PanelTitle
                  eyebrow="Evidence intake & provenance"
                  title="Chain of custody"
                  aside={
                    <Badge
                      variant="outline"
                      className="border-emerald-300/20 text-emerald-200"
                    >
                      <ShieldCheck />
                      Server verified
                    </Badge>
                  }
                />
                <div className="space-y-2">
                  {analysis.artifacts.map((artifact) => (
                    <div
                      key={artifact.id}
                      className="rounded-xl border border-white/8 bg-white/[0.025] p-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium">
                            {artifact.name}
                          </p>
                          <p className="mt-1 text-xs text-slate-500">
                            {evidenceLabel(artifact.type)} · {artifact.rowCount}{' '}
                            parsed rows · provenance{' '}
                            {percent(artifact.provenanceScore)}
                          </p>
                        </div>
                        {artifact.provenanceScore === 1 ? (
                          <CheckCircle2 className="size-4 shrink-0 text-emerald-300" />
                        ) : (
                          <AlertCircle className="size-4 shrink-0 text-amber-300" />
                        )}
                      </div>
                      <p
                        className="mt-2 truncate rounded-md bg-black/20 px-2 py-1.5 font-mono text-[10px] text-slate-600"
                        title={artifact.sha256}
                      >
                        sha256:{artifact.sha256}
                      </p>
                      <p className="mt-2 text-[10px] text-slate-600">
                        {Object.entries(artifact.provenanceChecks)
                          .map(
                            ([key, passed]) =>
                              `${passed ? '✓' : '✕'} ${readable(key)}`,
                          )
                          .join(' · ')}
                      </p>
                    </div>
                  ))}
                </div>
              </article>
            </section>
            <section className="grid gap-5 xl:grid-cols-[1.35fr_.85fr]">
              <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
                <PanelTitle
                  eyebrow="Evidence-derived attack reconstruction"
                  title="Chronological timeline"
                  aside={
                    <Badge
                      variant="outline"
                      className="border-white/10 text-slate-400"
                    >
                      <Clock3 />
                      UTC
                    </Badge>
                  }
                />
                <ol className="max-h-[560px] space-y-1 overflow-y-auto pr-2">
                  {relevantEvents.map((event, index) => (
                    <li key={event.id}>
                      <button
                        type="button"
                        onClick={() => setSelectedEventId(event.id)}
                        className={`grid w-full grid-cols-[68px_18px_1fr_auto] gap-3 rounded-xl px-2 py-2.5 text-left transition ${selectedEvent?.id === event.id ? 'bg-emerald-300/[0.07]' : 'hover:bg-white/[0.035]'}`}
                      >
                        <time className="pt-0.5 font-mono text-[11px] text-slate-500">
                          {timeFormat.format(new Date(event.timestamp))}
                        </time>
                        <div className="flex flex-col items-center">
                          <span
                            className={`mt-0.5 size-2.5 rounded-full ${event.classification === 'MALICIOUS' ? 'bg-red-400' : 'bg-amber-300'}`}
                          />
                          {index !== relevantEvents.length - 1 && (
                            <span className="mt-1 h-full w-px bg-white/10" />
                          )}
                        </div>
                        <div className="min-w-0 pb-2">
                          <p className="truncate text-sm font-medium sm:text-base">
                            {readable(event.eventType)}
                          </p>
                          <p className="mt-1 truncate text-xs text-slate-500">
                            {event.classification}{' '}
                            {(event.classificationProbability * 100).toFixed(1)}
                            % ·{' '}
                            {event.user ||
                              event.host ||
                              event.srcIp ||
                              'unattributed'}{' '}
                            · {event.sourceFile}
                          </p>
                          <p className="mt-1 text-[10px] text-sky-300/70">
                            {event.mitre
                              .map(
                                (item) =>
                                  `${item.techniqueId} ${item.technique}`,
                              )
                              .join(' · ') || 'No ATT&CK technique mapped'}
                          </p>
                        </div>
                        <ChevronRight className="mt-0.5 size-4 text-slate-600" />
                      </button>
                    </li>
                  ))}
                </ol>
                {!relevantEvents.length && (
                  <div className="grid min-h-64 place-items-center text-center text-slate-500">
                    <div>
                      <ShieldCheck className="mx-auto mb-3 size-7 text-emerald-300" />
                      No suspicious or malicious event was predicted.
                    </div>
                  </div>
                )}
              </article>
              <aside className="rounded-2xl border border-violet-300/15 bg-[#0d1b19] p-5">
                <PanelTitle
                  eyebrow="Model explanation"
                  title="Real SHAP contributions"
                  aside={
                    <Badge className="border-violet-300/20 bg-violet-300/10 text-violet-200">
                      TreeExplainer
                    </Badge>
                  }
                />
                {selectedEvent ? (
                  <>
                    <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="font-medium">
                            {readable(selectedEvent.eventType)}
                          </p>
                          <p className="mt-1 text-xs leading-5 text-slate-500">
                            {selectedEvent.message}
                          </p>
                        </div>
                        <Badge
                          className={
                            selectedEvent.classification === 'MALICIOUS'
                              ? 'border-red-400/20 bg-red-400/10 text-red-300'
                              : selectedEvent.classification === 'SUSPICIOUS'
                                ? 'border-amber-300/20 bg-amber-300/10 text-amber-200'
                                : 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200'
                          }
                        >
                          {selectedEvent.classification}{' '}
                          {(
                            selectedEvent.classificationProbability * 100
                          ).toFixed(1)}
                          %
                        </Badge>
                      </div>
                    </div>
                    <div className="mt-4 space-y-2">
                      {selectedEvent.shap.map((item) => (
                        <div
                          key={item.feature}
                          className="rounded-xl border border-white/8 bg-white/[0.025] p-3"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <span className="text-xs text-slate-300">
                              {item.feature}
                            </span>
                            <span
                              className={`font-mono text-xs font-semibold ${item.value >= 0 ? 'text-red-300' : 'text-emerald-300'}`}
                            >
                              {item.value >= 0 ? '+' : ''}
                              {item.value.toFixed(4)}
                            </span>
                          </div>
                          <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/8">
                            <div
                              className={`h-full ${item.value >= 0 ? 'bg-red-400' : 'bg-emerald-400'}`}
                              style={{
                                width: `${Math.min(100, Math.abs(item.value) * 120)}%`,
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="mt-5 border-t border-white/8 pt-4">
                      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                        Evidence traceability
                      </p>
                      <p className="mt-2 text-xs leading-5 text-slate-400">
                        Source: {selectedEvent.sourceFile}
                        <br />
                        SHA-256:{' '}
                        <span className="break-all font-mono text-slate-600">
                          {selectedEvent.provenanceHash}
                        </span>
                      </p>
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {selectedEvent.entities.slice(0, 8).map((entity) => (
                          <Badge
                            key={`${entity.type}-${entity.value}`}
                            variant="outline"
                            className="border-white/10 text-slate-400"
                          >
                            {entity.type}: {entity.value}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </>
                ) : (
                  <p className="text-sm text-slate-500">
                    Select an event to inspect its genuine model explanation.
                  </p>
                )}
              </aside>
            </section>
            <section className="grid gap-5 xl:grid-cols-[.7fr_1.3fr]">
              <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
                <PanelTitle
                  eyebrow={`MITRE ATT&CK v${displayValue(analysis.system.mitreAttack.version)}`}
                  title="Observed technique mapping"
                />
                <div className="space-y-2">
                  {analysis.mitre.map((item) => (
                    <div
                      key={item.techniqueId}
                      className="rounded-xl border border-white/8 bg-white/[0.025] p-3"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <p className="font-mono text-xs font-semibold text-sky-300">
                            {item.techniqueId}
                          </p>
                          <p className="mt-1 text-sm font-medium">
                            {item.technique}
                          </p>
                          <p className="mt-0.5 text-xs text-slate-500">
                            {item.tactic}
                          </p>
                        </div>
                        <Badge
                          variant="outline"
                          className="border-white/10 text-slate-400"
                        >
                          {item.evidenceEventIds.length} event
                          {item.evidenceEventIds.length === 1 ? '' : 's'}
                        </Badge>
                      </div>
                      <p className="mt-2 text-[10px] text-slate-600">
                        Sources: {item.sourceFiles.join(', ')}
                      </p>
                    </div>
                  ))}
                </div>
              </article>
              <article className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
                <PanelTitle
                  eyebrow="Cross-source evidence correlation"
                  title="NetworkX investigation graph"
                  aside={
                    <Badge
                      variant="outline"
                      className="border-white/10 text-slate-400"
                    >
                      <GitBranch />
                      {analysis.graph.nodes.length} nodes ·{' '}
                      {analysis.graph.edges.length} edges
                    </Badge>
                  }
                />
                <GraphView analysis={analysis} />
                <p className="mt-3 text-xs text-slate-500">
                  Every node and edge was created from parsed events, extracted
                  entities, temporal windows, or event-level ATT&CK mappings.
                  Click a node or edge to inspect provenance.
                </p>
              </article>
            </section>
            <section className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
              <PanelTitle
                eyebrow="Normalized common event schema"
                title="Current evidence events"
                aside={
                  <Badge
                    variant="outline"
                    className="border-white/10 text-slate-400"
                  >
                    <Database />
                    {analysis.events.length} events
                  </Badge>
                }
              />
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-white/10 hover:bg-transparent">
                      <TableHead className="text-slate-500">Time</TableHead>
                      <TableHead className="text-slate-500">
                        Source type
                      </TableHead>
                      <TableHead className="text-slate-500">Event</TableHead>
                      <TableHead className="text-slate-500">
                        User / host / process
                      </TableHead>
                      <TableHead className="text-slate-500">Network</TableHead>
                      <TableHead className="text-slate-500">
                        Classification
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {analysis.events.map((event) => (
                      <TableRow key={event.id} className="border-white/8">
                        <TableCell className="font-mono text-xs text-slate-500">
                          {event.timestamp}
                        </TableCell>
                        <TableCell className="text-xs">
                          {evidenceLabel(event.sourceType)}
                        </TableCell>
                        <TableCell>
                          <p className="font-medium">
                            {readable(event.eventType)}
                          </p>
                          <p className="max-w-xs truncate text-xs text-slate-600">
                            {event.message}
                          </p>
                        </TableCell>
                        <TableCell className="text-xs text-slate-400">
                          {[event.user, event.host, event.process]
                            .filter(Boolean)
                            .join(' · ') || '—'}
                        </TableCell>
                        <TableCell className="text-xs text-slate-400">
                          {[event.srcIp, event.dstIp, event.domain]
                            .filter(Boolean)
                            .join(' → ') || '—'}
                        </TableCell>
                        <TableCell>
                          <Badge
                            className={
                              event.classification === 'MALICIOUS'
                                ? 'border-red-400/20 bg-red-400/10 text-red-300'
                                : event.classification === 'SUSPICIOUS'
                                  ? 'border-amber-300/20 bg-amber-300/10 text-amber-200'
                                  : 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200'
                            }
                          >
                            {event.classification}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </section>
            <section className="rounded-2xl border border-white/10 bg-[#0d1b19] p-5">
              <PanelTitle
                eyebrow="Deterministic · no LLM/RAG"
                title="Evidence-Grounded Forensic Report"
                aside={
                  <Button
                    variant="outline"
                    size="sm"
                    className="border-white/10 bg-white/[0.03] text-slate-300"
                    onClick={downloadReport}
                  >
                    <Download />
                    Export report
                  </Button>
                }
              />
              <p className="text-xs text-slate-500">
                {analysis.report.generationMethod}
              </p>
              <div className="mt-5 grid gap-5 lg:grid-cols-[1.1fr_.9fr]">
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                    Case summary
                  </h3>
                  <p className="mt-2 text-sm leading-7 text-slate-300">
                    {analysis.report.caseSummary}
                  </p>
                  <h3 className="mt-5 text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                    Affected entities / assets
                  </h3>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {analysis.report.affectedEntities.map((entity) => (
                      <Badge
                        key={entity}
                        variant="outline"
                        className="border-white/10 text-slate-400"
                      >
                        {entity}
                      </Badge>
                    ))}
                  </div>
                  <h3 className="mt-5 text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                    Recommended investigator actions
                  </h3>
                  <ul className="mt-3 space-y-2">
                    {analysis.report.recommendedActions.map((item) => (
                      <li
                        key={item}
                        className="flex gap-2 text-sm leading-6 text-slate-400"
                      >
                        <CircleDot className="mt-1.5 size-3 shrink-0 text-emerald-300" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="rounded-xl border border-amber-300/15 bg-amber-300/[0.04] p-4">
                  <h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-300">
                    Limitations / uncertainty
                  </h3>
                  <ul className="mt-3 space-y-2">
                    {analysis.report.limitations.map((item) => (
                      <li
                        key={item}
                        className="text-sm leading-6 text-slate-400"
                      >
                        • {item}
                      </li>
                    ))}
                  </ul>
                  <div className="mt-4 border-t border-white/8 pt-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">
                      Confidence
                    </p>
                    <p className="mt-2 font-mono text-xs leading-6 text-slate-500">
                      {analysis.confidence.calculation}
                    </p>
                  </div>
                </div>
              </div>
            </section>
          </>
        )}
        <footer className="flex flex-col justify-between gap-2 border-t border-white/8 py-4 text-xs text-slate-600 sm:flex-row">
          <span className="flex items-center gap-1.5">
            <CheckCircle2 className="size-3.5 text-emerald-400" />
            Evidence is processed by the local AI-CSI analysis service.
          </span>
          <span className="flex items-center gap-1.5">
            <ServerCog className="size-3.5" />
            Real DistilBERT · XGBoost · NetworkX · SHAP
          </span>
        </footer>
      </div>
    </main>
  );
}

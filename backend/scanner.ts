import * as fs from "node:fs/promises";
import * as crypto from "node:crypto";
import * as path from "node:path";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";

export interface FileEntry {
  fullPath: string;
  relativePath: string;
}

export interface Snapshot {
  path: string;
  hash: string;
  content: string;
  sizeBytes: number;
  truncated: boolean;
}

export interface TraceEvent {
  id: string;
  time: string;
  type: string;
  title: string;
  subtitle: string;
  label: string;
  risk: number;
  badge: string;
  riskTitle: string;
  riskText: string;
  checkpoint: string;
  command: string;
  diff: string;
  diffSummary?: FileDiff;
}

export interface FileDiff {
  path: string;
  status: "added" | "deleted" | "modified";
  beforeHash: string | null;
  afterHash: string | null;
  additions: number;
  deletions: number;
  changedFunctions: string[];
  preview: string;
}

export interface ScanOptions {
  previousSnapshots?: Snapshot[];
  source?: string;
}

const IGNORED_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SECRET_PATTERNS = [
  { name: "OpenAI-style key", pattern: /sk-[A-Za-z0-9_-]{16,}/ },
  { name: "JWT secret", pattern: /JWT_SECRET\s*=\s*['"]?[A-Za-z0-9_-]{12,}/i },
  { name: "Database URL", pattern: /DATABASE_URL\s*=\s*['"]?[A-Za-z]+:\/\/[^'"\s]+/i },
  { name: "Generic API key", pattern: /(API_KEY|TOKEN|SECRET)\s*=\s*['"]?[A-Za-z0-9_-]{12,}/i },
];

const ENTROPY_MIN_LENGTH = 24;
const ENTROPY_THRESHOLD = 4.2;
const ENTROPY_TOKEN_PATTERN = /[A-Za-z0-9_+/=.-]{24,}/g;
const SNAPSHOT_MAX_BYTES = 500_000;
const DIFF_PREVIEW_LIMIT = 16;

export async function walkFiles(rootDir: string, currentDir: string = rootDir, files: FileEntry[] = []): Promise<FileEntry[]> {
  const entries = await fs.readdir(currentDir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(currentDir, entry.name);
    const relativePath = path.relative(rootDir, fullPath).replaceAll(path.sep, "/");

    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) {
        await walkFiles(rootDir, fullPath, files);
      }
      continue;
    }

    files.push({ fullPath, relativePath });
  }

  return files;
}

export async function readTextFile(fullPath: string): Promise<string> {
  try {
    const buffer = await fs.readFile(fullPath);
    if (buffer.includes(0)) {
      return "";
    }
    return buffer.toString("utf8");
  } catch (err) {
    console.error(`Error reading ${fullPath}:`, err);
    return "";
  }
}

export function hashContent(text: string): string {
  return crypto.createHash("sha256").update(text).digest("hex");
}

export function redactSnapshotText(text: string): string {
  return text
    .replace(
      /\b([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|DATABASE_URL|PRIVATE_KEY|NONCE)[A-Z0-9_]*)\s*=\s*([^\r\n]+)/gi,
      "$1=[redacted]",
    )
    .replace(/[A-Za-z0-9_+/=.-]{32,}/g, (candidate) => {
      if (candidate.includes("://") || !isLikelyEntropySecret(candidate)) {
        return candidate;
      }
      return "[redacted-token]";
    });
}

export function createSnapshot(file: FileEntry, text: string): Snapshot {
  const content = redactSnapshotText(text);
  const isTruncated = Buffer.byteLength(content, "utf8") > SNAPSHOT_MAX_BYTES;

  return {
    path: file.relativePath,
    hash: hashContent(text),
    content: isTruncated ? content.slice(0, SNAPSHOT_MAX_BYTES) : content,
    sizeBytes: Buffer.byteLength(text, "utf8"),
    truncated: isTruncated,
  };
}

export function makeEvent(params: Partial<TraceEvent>): TraceEvent {
  return {
    id: params.id || `evt-${Math.random().toString(16).slice(2, 8)}`,
    time: params.time || "00:00",
    type: params.type || "generic",
    title: params.title || "Unknown Event",
    subtitle: params.subtitle || "",
    label: params.label || "info",
    risk: params.risk || 0,
    badge: params.badge || scoreToBadge(params.risk || 0),
    riskTitle: params.riskTitle || "",
    riskText: params.riskText || "",
    checkpoint: params.checkpoint || "",
    command: params.command || "",
    diff: params.diff || "",
    ...params,
  } as TraceEvent;
}

export function scoreToBadge(score: number): string {
  if (score >= 80) return "P1";
  if (score >= 60) return "P2";
  return "P3";
}

export function calculateShannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  value.split("").forEach((character) => {
    counts.set(character, (counts.get(character) || 0) + 1);
  });

  return Array.from(counts.values()).reduce((entropy, count) => {
    const probability = count / value.length;
    return entropy - probability * Math.log2(probability);
  }, 0);
}

function getCharacterClassCount(value: string): number {
  return [
    /[a-z]/.test(value),
    /[A-Z]/.test(value),
    /\d/.test(value),
    /[_+/=.-]/.test(value),
  ].filter(Boolean).length;
}

function getLineNumber(text: string, index: number): number {
  return text.slice(0, index).split(/\r?\n/).length;
}

export function isLikelyEntropySecret(candidate: string): boolean {
  if (candidate.length < ENTROPY_MIN_LENGTH) return false;
  if (candidate.includes("://")) return false;
  if (/^[a-z0-9.-]+$/i.test(candidate) && candidate.includes(".")) return false;
  if (/(.)\1{6,}/.test(candidate)) return false;

  const entropy = calculateShannonEntropy(candidate);
  const characterClasses = getCharacterClassCount(candidate);

  return entropy >= ENTROPY_THRESHOLD && characterClasses >= 3;
}

function findEntropySecretEvents(file: FileEntry, text: string, checkpoint: string): TraceEvent[] {
  const events: TraceEvent[] = [];
  const seen = new Set<string>();
  const isSensitiveFile = /(^|\/)\.env|secret|credential|private-key|fixture/i.test(file.relativePath);
  let match: RegExpExecArray | null;

  ENTROPY_TOKEN_PATTERN.lastIndex = 0;
  while (events.length < 3 && (match = ENTROPY_TOKEN_PATTERN.exec(text))) {
    const candidate = match[0].replace(/^[=.-]+|[=.-]+$/g, "");
    if (seen.has(candidate) || !isLikelyEntropySecret(candidate)) {
      continue;
    }

    seen.add(candidate);
    const entropy = calculateShannonEntropy(candidate);
    const risk = isSensitiveFile ? 88 : 80;
    const lineNumber = getLineNumber(text, match.index);

    events.push(
      makeEvent({
        type: "security",
        title: "High-entropy token detected",
        subtitle: `${file.relativePath}:${lineNumber}`,
        label: "security",
        risk,
        badge: scoreToBadge(risk),
        riskTitle: "Opaque secret candidate",
        riskText: `CodeTrace AI found a ${candidate.length}-character high-entropy string in ${file.relativePath}. This catches token-like secrets even when no API_KEY or SECRET keyword is present.`,
        checkpoint,
        command: `$ codetrace entropy ${file.relativePath}\nentropy: ${entropy.toFixed(2)} bits/char\nlength: ${candidate.length}\nvalue: redacted`,
        diff: `${file.relativePath}:${lineNumber}\nmatched high-entropy token\nvalue hidden from dashboard export`,
      }),
    );
  }

  return events;
}

function splitLines(text: string): string[] {
  if (!text) return [];
  return text.split(/\r?\n/);
}

export function detectFunctions(text: string): { name: string; start: number; end: number }[] {
  const functions: { name: string; start: number; end: number }[] = [];
  const lines = splitLines(text);
  const patterns = [
    /\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/,
    /^\s*(?:public|private|protected|static|async|\s)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/,
    /^\s*def\s+([A-Za-z_][\w]*)\s*\(/,
  ];

  lines.forEach((line, index) => {
    const match = patterns.map((pattern) => pattern.exec(line)).find(Boolean);
    if (match) {
      functions.push({ name: match[1], start: index + 1, end: lines.length });
    }
  });

  return functions.map((entry, index) => ({
    ...entry,
    end: functions[index + 1] ? functions[index + 1].start - 1 : lines.length,
  }));
}

export function diffLines(beforeText: string, afterText: string): { operations: any[]; addedLineNumbers: number[]; deletedLineNumbers: number[] } {
  const beforeLines = splitLines(beforeText);
  const afterLines = splitLines(afterText);

  if (beforeLines.length * afterLines.length > 250_000) {
    return approximateLineDiff(beforeLines, afterLines);
  }

  const table = Array.from({ length: beforeLines.length + 1 }, () =>
    new Int32Array(afterLines.length + 1).fill(0),
  );

  for (let i = beforeLines.length - 1; i >= 0; i -= 1) {
    for (let j = afterLines.length - 1; j >= 0; j -= 1) {
      table[i][j] =
        beforeLines[i] === afterLines[j]
          ? table[i + 1][j + 1] + 1
          : Math.max(table[i + 1][j], table[i][j + 1]);
    }
  }

  const operations = [];
  const addedLineNumbers = [];
  const deletedLineNumbers = [];
  let i = 0;
  let j = 0;

  while (i < beforeLines.length && j < afterLines.length) {
    if (beforeLines[i] === afterLines[j]) {
      i += 1;
      j += 1;
    } else if (table[i + 1][j] >= table[i][j + 1]) {
      operations.push({ type: "-", lineNumber: i + 1, text: beforeLines[i] });
      deletedLineNumbers.push(i + 1);
      i += 1;
    } else {
      operations.push({ type: "+", lineNumber: j + 1, text: afterLines[j] });
      addedLineNumbers.push(j + 1);
      j += 1;
    }
  }

  while (i < beforeLines.length) {
    operations.push({ type: "-", lineNumber: i + 1, text: beforeLines[i] });
    deletedLineNumbers.push(i + 1);
    i += 1;
  }

  while (j < afterLines.length) {
    operations.push({ type: "+", lineNumber: j + 1, text: afterLines[j] });
    addedLineNumbers.push(j + 1);
    j += 1;
  }

  return { operations, addedLineNumbers, deletedLineNumbers };
}

function approximateLineDiff(beforeLines: string[], afterLines: string[]) {
  let prefix = 0;
  while (
    prefix < beforeLines.length &&
    prefix < afterLines.length &&
    beforeLines[prefix] === afterLines[prefix]
  ) {
    prefix += 1;
  }

  let suffix = 0;
  while (
    suffix + prefix < beforeLines.length &&
    suffix + prefix < afterLines.length &&
    beforeLines[beforeLines.length - 1 - suffix] === afterLines[afterLines.length - 1 - suffix]
  ) {
    suffix += 1;
  }

  const deleted = beforeLines.slice(prefix, beforeLines.length - suffix);
  const added = afterLines.slice(prefix, afterLines.length - suffix);

  return {
    operations: [
      ...deleted.map((line, index) => ({ type: "-", lineNumber: prefix + index + 1, text: line })),
      ...added.map((line, index) => ({ type: "+", lineNumber: prefix + index + 1, text: line })),
    ],
    addedLineNumbers: added.map((_, index) => prefix + index + 1),
    deletedLineNumbers: deleted.map((_, index) => prefix + index + 1),
  };
}

function functionsForLines(functions: { name: string; start: number; end: number }[], lineNumbers: number[]): string[] {
  const changedLines = new Set(lineNumbers);

  return functions
    .filter((entry) => {
      for (let line = entry.start; line <= entry.end; line += 1) {
        if (changedLines.has(line)) return true;
      }
      return false;
    })
    .map((entry) => entry.name);
}

function buildPreview(operations: any[]): string {
  const lines = operations
    .slice(0, DIFF_PREVIEW_LIMIT)
    .map((operation) => `${operation.type} ${operation.lineNumber}: ${operation.text || "(blank)"}`);

  if (operations.length > DIFF_PREVIEW_LIMIT) {
    lines.push(`... ${operations.length - DIFF_PREVIEW_LIMIT} more changed lines`);
  }

  return lines.join("\n");
}

function buildFileDiffSummary(filePath: string, previous: Snapshot | undefined, current: Snapshot | null): FileDiff | null {
  if (!previous && !current) return null;

  const status: "added" | "deleted" | "modified" = !previous ? "added" : !current ? "deleted" : "modified";
  const beforeContent = previous?.content || "";
  const afterContent = current?.content || "";

  if (status === "modified" && previous!.hash === current!.hash) {
    return null;
  }

  const lineDiff = diffLines(beforeContent, afterContent);
  const beforeFunctions = detectFunctions(beforeContent);
  const afterFunctions = detectFunctions(afterContent);
  const changedFunctions = Array.from(
    new Set([
      ...functionsForLines(beforeFunctions, lineDiff.deletedLineNumbers),
      ...functionsForLines(afterFunctions, lineDiff.addedLineNumbers),
    ]),
  );

  if (status === "added") {
    changedFunctions.push(
      ...detectFunctions(afterContent)
        .map((entry) => entry.name)
        .filter((name) => !changedFunctions.includes(name)),
    );
  }

  if (status === "deleted") {
    changedFunctions.push(
      ...detectFunctions(beforeContent)
        .map((entry) => entry.name)
        .filter((name) => !changedFunctions.includes(name)),
    );
  }

  return {
    path: filePath,
    status,
    beforeHash: previous?.hash || null,
    afterHash: current?.hash || null,
    additions: lineDiff.addedLineNumbers.length,
    deletions: lineDiff.deletedLineNumbers.length,
    changedFunctions,
    preview: buildPreview(lineDiff.operations),
  };
}

function formatDiffSummary(diffSummary: FileDiff): string {
  const functions =
    diffSummary.changedFunctions.length > 0 ? diffSummary.changedFunctions.join(", ") : "none detected";

  return [
    diffSummary.path,
    `status: ${diffSummary.status}`,
    `lines: +${diffSummary.additions} / -${diffSummary.deletions}`,
    `functions changed: ${functions}`,
    "",
    diffSummary.preview || "No changed lines in redacted snapshot preview",
  ].join("\n");
}

function buildFileDiffs(previousSnapshots: Snapshot[], currentSnapshots: Snapshot[]): FileDiff[] {
  const previousByPath = new Map(previousSnapshots.map((snapshot) => [snapshot.path, snapshot]));
  const currentByPath = new Map(currentSnapshots.map((snapshot) => [snapshot.path, snapshot]));
  const summaries: FileDiff[] = [];

  currentByPath.forEach((current, filePath) => {
    const summary = buildFileDiffSummary(filePath, previousByPath.get(filePath), current);
    if (summary) {
      summaries.push(summary);
    }
  });

  previousByPath.forEach((previous, filePath) => {
    if (!currentByPath.has(filePath)) {
      const summary = buildFileDiffSummary(filePath, previous, null);
      if (summary) summaries.push(summary);
    }
  });

  return summaries.filter(Boolean).sort((a, b) => {
    const impactA = a.additions + a.deletions;
    const impactB = b.additions + b.deletions;
    return impactB - impactA || a.path.localeCompare(b.path);
  });
}

function riskForDiff(diffSummary: FileDiff): number {
  const filePath = diffSummary.path;
  if (/(^|\/)\.env|secret|credential|private-key/i.test(filePath)) return 86;
  if (/tests?\//i.test(filePath) && diffSummary.status === "deleted") return 84;
  if (/(auth|token|session|jwt|middleware)/i.test(filePath + diffSummary.changedFunctions.join(" "))) {
    return 78;
  }
  if (/migrations|\.sql$/i.test(filePath)) return 66;
  if (path.basename(filePath) === "package.json") return 64;
  return diffSummary.additions + diffSummary.deletions > 80 ? 58 : 46;
}

function findDiffEvents(fileDiffs: FileDiff[], checkpoint: string): TraceEvent[] {
  return fileDiffs.slice(0, 8).map((diffSummary) => {
    const risk = riskForDiff(diffSummary);
    const functions =
      diffSummary.changedFunctions.length > 0 ? diffSummary.changedFunctions.join(", ") : "none detected";

    return makeEvent({
      type: "file",
      title:
        diffSummary.status === "deleted"
          ? "File deleted since last snapshot"
          : diffSummary.status === "added"
            ? "File added since last snapshot"
            : "Structured file diff captured",
      subtitle: `${diffSummary.path} (+${diffSummary.additions}/-${diffSummary.deletions})`,
      label: "file",
      risk,
      badge: scoreToBadge(risk),
      riskTitle: "Line-level change summary",
      riskText: `CodeTrace AI compared this file with the previous SQLite snapshot. It found +${diffSummary.additions}/-${diffSummary.deletions} lines and changed functions: ${functions}.`,
      checkpoint,
      command: `$ codetrace diff ${diffSummary.path}\nstatus: ${diffSummary.status}\nlines: +${diffSummary.additions} / -${diffSummary.deletions}\nfunctions: ${functions}`,
      diff: formatDiffSummary(diffSummary),
      diffSummary,
    });
  });
}

function findSecretEvents(file: FileEntry, text: string, checkpoint: string): TraceEvent[] {
  const events: TraceEvent[] = [];
  const isSensitiveFile = /(^|\/)\.env|secret|credential|private-key/i.test(file.relativePath);

  SECRET_PATTERNS.forEach((rule) => {
    if (rule.pattern.test(text)) {
      const risk = isSensitiveFile ? 92 : 84;
      events.push(
        makeEvent({
          type: "security",
          title: `${rule.name} detected`,
          subtitle: file.relativePath,
          label: "security",
          risk,
          badge: scoreToBadge(risk),
          riskTitle: "Secret exposure risk",
          riskText: `CodeTrace AI found a ${rule.name.toLowerCase()} pattern in ${file.relativePath}. The report redacts values but keeps the file in the review list.`,
          checkpoint,
          command: `$ codetrace scan ${file.relativePath}\nblocked: secret value redacted\nrule: secret.${rule.name.toLowerCase().replaceAll(" ", "_")}`,
          diff: `${file.relativePath}\nmatched secret pattern: ${rule.name}\nvalue hidden from dashboard export`,
        }),
      );
    }
  });

  if (isSensitiveFile && events.length === 0) {
    const risk = 72;
    events.push(
      makeEvent({
        type: "security",
        title: "Sensitive config file touched",
        subtitle: file.relativePath,
        label: "security",
        risk,
        badge: scoreToBadge(risk),
        riskTitle: "Sensitive file access",
        riskText: `${file.relativePath} is a sensitive configuration file. Values should be redacted before sharing the trace.`,
        checkpoint,
        command: `$ codetrace redact ${file.relativePath}\nstatus: sensitive file marked for review`,
        diff: `${file.relativePath}\nvalues hidden from replay export`,
      }),
    );
  }

  return events;
}

function findAuthEvents(file: FileEntry, text: string, checkpoint: string): TraceEvent[] {
  const isCodeFile = /\.(cjs|mjs|js|jsx|ts|tsx|py|go|rb|php|java|cs)$/i.test(file.relativePath);
  if (!isCodeFile) {
    return [];
  }

  if (!/(auth|token|session|jwt|middleware)/i.test(file.relativePath + text)) {
    return [];
  }

  const risk = /decodeJwt|jwt\.decode|authorization|refresh/i.test(text) ? 78 : 64;
  return [
    makeEvent({
      type: "file",
      title: "Auth-sensitive code path",
      subtitle: file.relativePath,
      label: "file",
      risk,
      badge: scoreToBadge(risk),
      riskTitle: "Auth behavior needs review",
      riskText: `The scanner found authentication or token-handling logic in ${file.relativePath}. This should be linked with auth tests before merging AI-generated edits.`,
      checkpoint,
      command: `$ codetrace map ${file.relativePath}\nlinked domain: authentication\nsuggested tests: token expiry, replay, missing header`,
      diff: `review focus: ${file.relativePath}\nkeywords: auth, token, session, middleware`,
    }),
  ];
}

function findPackageEvents(file: FileEntry, text: string, checkpoint: string): TraceEvent[] {
  if (path.basename(file.relativePath) !== "package.json") {
    return [];
  }

  const events: TraceEvent[] = [];
  let parsed: any;
  try {
    parsed = JSON.parse(text);
  } catch {
    return events;
  }

  const deps = { ...parsed.dependencies, ...parsed.devDependencies };
  Object.entries(deps).forEach(([name, version]) => {
    const riskyVersion = typeof version === "string" && (/latest|\*|x/i.test(version) || version.startsWith(">"));
    const authPackage = /jwt|auth|oauth|passport|crypto/i.test(name);

    if (riskyVersion || authPackage) {
      const risk = riskyVersion ? 68 : 56;
      events.push(
        makeEvent({
          type: "package",
          title: riskyVersion ? "Loose dependency version" : "Security-sensitive dependency",
          subtitle: `${name}@${version}`,
          label: "package",
          risk,
          badge: scoreToBadge(risk),
          riskTitle: "Dependency review needed",
          riskText: `${name}@${version} affects runtime behavior. CodeTrace AI marks it so reviewers check advisories, lockfile changes, and package purpose.`,
          checkpoint,
          command: `$ codetrace deps ${file.relativePath}\npackage: ${name}\nversion: ${version}`,
          diff: `dependency: ${name}\nversion: ${version}\nreview: advisories, lockfile, license`,
        }),
      );
    }
  });

  return events;
}

async function findCommandEvents(rootDir: string, checkpoint: string): Promise<TraceEvent[]> {
  const commandLog = path.join(rootDir, "codetrace.commands.log");
  if (!existsSync(commandLog)) {
    return [];
  }

  const text = await readTextFile(commandLog);
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  return lines
    .map((line) => {
      const secretEcho = /(echo|print).*(API_KEY|TOKEN|SECRET|DATABASE_URL)/i.test(line);
      const destructive = /\brm\s+-rf\b|\bdel\b|\bRemove-Item\b/i.test(line);
      const installLatest = /npm\s+install.*(@latest|\slatest\b)/i.test(line);

      if (!secretEcho && !destructive && !installLatest) {
        return null;
      }

      const risk = secretEcho || destructive ? 91 : 66;
      return makeEvent({
        type: "terminal",
        title: secretEcho ? "Secret printed in terminal" : destructive ? "Destructive command captured" : "Latest package install",
        subtitle: line,
        label: "terminal",
        risk,
        badge: scoreToBadge(risk),
        riskTitle: secretEcho ? "Secret exposure attempt" : destructive ? "Rollback danger" : "Unpinned install risk",
        riskText: secretEcho
          ? "The command log includes an attempt to print a sensitive environment variable. The backend redacts this in reports."
          : destructive
            ? "A destructive shell command appeared in the session. CodeTrace AI links it to a rollback checkpoint."
            : "A package was installed using a moving version target. This can make AI-created changes harder to reproduce.",
        checkpoint,
        command: `$ ${line}\nblocked or flagged by CodeTrace AI\nsource: codetrace.commands.log`,
        diff: "terminal command event\nno source diff available",
      });
    })
    .filter(Boolean) as TraceEvent[];
}

function findMigrationEvents(file: FileEntry, text: string, checkpoint: string): TraceEvent[] {
  if (!/migrations|\.sql$/i.test(file.relativePath)) {
    return [];
  }

  if (!/alter table|drop table|create index|delete from/i.test(text)) {
    return [];
  }

  const risk = /drop table|delete from/i.test(text) ? 86 : 62;
  return [
    makeEvent({
      type: "terminal",
      title: "Database migration detected",
      subtitle: file.relativePath,
      label: "terminal",
      risk,
      badge: scoreToBadge(risk),
      riskTitle: "Database behavior changed",
      riskText: `The scanner found SQL schema or data changes in ${file.relativePath}. Review rollback SQL and data impact.`,
      checkpoint,
      command: `$ codetrace migration ${file.relativePath}\nstatus: migration linked to session report`,
      diff: text.split(/\r?\n/).slice(0, 6).join("\n"),
    }),
  ];
}

function assignTimes(events: TraceEvent[]): TraceEvent[] {
  return events.map((event, index) => ({
    ...event,
    id: `evt-${String(index + 1).padStart(3, "0")}`,
    time: `${String(Math.floor((4 + index * 7) / 60)).padStart(2, "0")}:${String((4 + index * 7) % 60).padStart(2, "0")}`,
  }));
}

function buildRiskExplanation(events: TraceEvent[], fileDiffs: FileDiff[], riskScore: number) {
  const factors: any[] = [];
  const addFactor = (count: number, label: string, detail: string) => {
    if (count > 0) {
      factors.push({ label, count, detail });
    }
  };

  const entropySecrets = events.filter((event) => /high-entropy token/i.test(event.title)).length;
  const keywordSecrets = events.filter((event) =>
    event.type === "security" &&
    !/high-entropy/i.test(event.title) &&
    /key|secret|database url|sensitive config|sensitive file/i.test(event.title),
  ).length;
  const riskyCommands = events.filter((event) =>
    event.type === "terminal" && /secret printed|destructive command/i.test(event.title),
  ).length;
  const authFilePaths = new Set(
    events
      .filter(
        (event) =>
          event.title === "Auth-sensitive code path" ||
          (event.diffSummary &&
            /(auth|token|jwt|middleware)/i.test(
              `${event.diffSummary.path} ${event.diffSummary.changedFunctions.join(" ")}`,
            )),
      )
      .map((event) => event.diffSummary?.path || event.subtitle),
  );
  const authFiles = authFilePaths.size;
  const packageEvents = events.filter((event) => event.type === "package").length;
  const migrations = events.filter((event) => /migration|database behavior/i.test(event.title + event.riskTitle)).length;
  const changedFiles = fileDiffs.filter((diff) => diff.status === "modified").length;
  const addedFiles = fileDiffs.filter((diff) => diff.status === "added").length;
  const removedFiles = fileDiffs.filter((diff) => diff.status === "deleted").length;

  addFactor(keywordSecrets, "secret pattern", "Regex rules matched API keys, JWT secrets, database URLs, or sensitive config access.");
  addFactor(entropySecrets, "high-entropy token", "Shannon entropy caught token-like strings without relying on variable names.");
  addFactor(riskyCommands, "risky command", "Terminal history contained destructive commands or secret-printing attempts.");
  addFactor(authFiles, "auth-sensitive file", "Auth, JWT, token, or middleware code paths need focused review.");
  addFactor(packageEvents, "dependency signal", "Dependency versions or security-sensitive packages need lockfile/advisory review.");
  addFactor(migrations, "database migration", "Schema or data migration files were touched.");
  addFactor(addedFiles, "new file snapshot", "SQLite snapshots captured files that were not present in the previous scan.");
  addFactor(changedFiles, "changed file", "SQLite snapshots found modified files since the previous scan.");
  addFactor(removedFiles, "deleted file", "SQLite snapshots found files removed since the previous scan.");

  const summaryParts = factors.map((factor) => {
    const plural = factor.count === 1 ? factor.label : `${factor.label}s`;
    return `${factor.count} ${plural}`;
  });

  return {
    summary: `Score: ${riskScore} - ${
      summaryParts.length ? summaryParts.join(", ") : "no high-risk signals detected"
    }.`,
    factors,
  };
}

function buildSummary(events: TraceEvent[], files: FileEntry[], fileDiffs: FileDiff[]) {
  const riskScore = events.length
    ? Math.round(events.reduce((sum, event) => sum + event.risk, 0) / events.length)
    : 0;

  return {
    riskScore,
    metrics: {
      files: files.length,
      commands: events.filter((event) => event.type === "terminal").length,
      blocked: events.filter((event) => event.risk >= 80).length,
      changedFiles: fileDiffs.length,
    },
  };
}

export async function scanRepository(repoPath: string, options: ScanOptions = {}) {
  const rootDir = path.resolve(repoPath);
  if (!existsSync(rootDir) || !statSync(rootDir).isDirectory()) {
    throw new Error(`Scan target is not a directory: ${repoPath}`);
  }

  const project = path.basename(rootDir);
  const createdAt = new Date().toISOString();
  const checkpoint = `safe-${project}-${createdAt.slice(0, 19).replace(/[-:T]/g, "")}`;
  const files = await walkFiles(rootDir);
  const events: TraceEvent[] = [];
  const snapshots: Snapshot[] = [];

  for (const file of files) {
    const text = await readTextFile(file.fullPath);
    if (!text) continue;

    snapshots.push(createSnapshot(file, text));
    events.push(...findSecretEvents(file, text, checkpoint));
    events.push(...findEntropySecretEvents(file, text, checkpoint));
    events.push(...findAuthEvents(file, text, checkpoint));
    events.push(...findPackageEvents(file, text, checkpoint));
    events.push(...findMigrationEvents(file, text, checkpoint));
  }

  const fileDiffs = buildFileDiffs(options.previousSnapshots || [], snapshots);
  events.push(...findDiffEvents(fileDiffs, checkpoint));
  events.push(...(await findCommandEvents(rootDir, checkpoint)));

  const timedEvents = assignTimes(events.sort((a, b) => b.risk - a.risk));
  const summary = buildSummary(timedEvents, files, fileDiffs);
  const riskExplanation = buildRiskExplanation(timedEvents, fileDiffs, summary.riskScore);

  return {
    id: `trace-${Date.now()}`,
    name: `${project}.trace`,
    project,
    projectPath: rootDir,
    source: options.source || "manual-scan",
    createdAt,
    checkpoint,
    riskScore: summary.riskScore,
    metrics: summary.metrics,
    riskExplanation,
    fileDiffs,
    snapshots,
    events: timedEvents,
    report: {
      title: "CodeTrace AI Session Report",
      summary: riskExplanation.summary,
      suggestedTests: ["auth refresh flow", "JWT expiry", "secret redaction", "dependency lockfile review"],
    },
  };
}

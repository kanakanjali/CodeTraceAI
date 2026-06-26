import * as fs from "node:fs";
import * as path from "node:path";
import Database from "better-sqlite3";
import { fileURLToPath } from "node:url";

const _dirname = typeof __dirname !== "undefined" ? __dirname : path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(_dirname, "..", "data");
const DB_FILE = path.join(DATA_DIR, "codetrace.sqlite");
const LEGACY_SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");

let db: Database.Database | null = null;

export function setDatabase(database: Database.Database | null) {
  db = database;
}

function parseJson(value: string | null, fallback: any) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

export function openDatabase(customPath?: string): Database.Database {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!db || customPath) {
    const target = customPath || DB_FILE;
    const connection = new Database(target);
    connection.pragma("foreign_keys = ON");
    connection.pragma("journal_mode = WAL");
    if (!customPath) db = connection;
    return connection;
  }

  return db;
}

export function createSchema(database: Database.Database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      project TEXT,
      project_path TEXT,
      created_at TEXT NOT NULL,
      risk_score INTEGER NOT NULL DEFAULT 0,
      metrics_json TEXT NOT NULL,
      checkpoint TEXT,
      report_json TEXT,
      session_json TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_created_at
      ON sessions (created_at DESC);

    CREATE TABLE IF NOT EXISTS file_snapshots (
      session_id TEXT NOT NULL,
      file_path TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      content_text TEXT NOT NULL,
      size_bytes INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      PRIMARY KEY (session_id, file_path),
      FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_file_snapshots_session
      ON file_snapshots (session_id);

    CREATE TABLE IF NOT EXISTS diff_summaries (
      session_id TEXT NOT NULL,
      file_path TEXT NOT NULL,
      status TEXT NOT NULL,
      before_hash TEXT,
      after_hash TEXT,
      additions INTEGER NOT NULL DEFAULT 0,
      deletions INTEGER NOT NULL DEFAULT 0,
      changed_functions_json TEXT NOT NULL,
      preview TEXT NOT NULL,
      summary_json TEXT NOT NULL,
      PRIMARY KEY (session_id, file_path),
      FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );
  `);
}

function upsertSession(database: Database.Database, session: any) {
  const createdAt = session.createdAt || new Date().toISOString();
  const normalizedSession = stripPrivateSessionFields({ ...session, createdAt });

  database
    .prepare(`
      INSERT INTO sessions (
        id,
        name,
        project,
        project_path,
        created_at,
        risk_score,
        metrics_json,
        checkpoint,
        report_json,
        session_json
      )
      VALUES (
        @id,
        @name,
        @project,
        @projectPath,
        @createdAt,
        @riskScore,
        @metricsJson,
        @checkpoint,
        @reportJson,
        @sessionJson
      )
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        project = excluded.project,
        project_path = excluded.project_path,
        created_at = excluded.created_at,
        risk_score = excluded.risk_score,
        metrics_json = excluded.metrics_json,
        checkpoint = excluded.checkpoint,
        report_json = excluded.report_json,
        session_json = excluded.session_json
    `)
    .run({
      id: normalizedSession.id,
      name: normalizedSession.name || "local-session.trace",
      project: normalizedSession.project || null,
      projectPath: normalizedSession.projectPath || null,
      createdAt,
      riskScore: normalizedSession.riskScore || 0,
      metricsJson: JSON.stringify(normalizedSession.metrics || {}),
      checkpoint: normalizedSession.checkpoint || null,
      reportJson: JSON.stringify(normalizedSession.report || {}),
      sessionJson: JSON.stringify(normalizedSession),
    });
}

function stripPrivateSessionFields(session: any) {
  const { snapshots, ...publicSession } = session;
  return publicSession;
}

function saveSnapshots(database: Database.Database, session: any) {
  const snapshots = Array.isArray(session.snapshots) ? session.snapshots : [];

  database.prepare("DELETE FROM file_snapshots WHERE session_id = ?").run(session.id);

  const insertSnapshot = database.prepare(`
    INSERT INTO file_snapshots (
      session_id,
      file_path,
      content_hash,
      content_text,
      size_bytes,
      created_at
    )
    VALUES (
      @sessionId,
      @filePath,
      @contentHash,
      @contentText,
      @sizeBytes,
      @createdAt
    )
  `);

  snapshots.forEach((snapshot: any) => {
    insertSnapshot.run({
      sessionId: session.id,
      filePath: snapshot.path,
      contentHash: snapshot.hash,
      contentText: snapshot.content,
      sizeBytes: snapshot.sizeBytes || 0,
      createdAt: session.createdAt,
    });
  });
}

function saveDiffSummaries(database: Database.Database, session: any) {
  const fileDiffs = Array.isArray(session.fileDiffs) ? session.fileDiffs : [];

  database.prepare("DELETE FROM diff_summaries WHERE session_id = ?").run(session.id);

  const insertDiff = database.prepare(`
    INSERT INTO diff_summaries (
      session_id,
      file_path,
      status,
      before_hash,
      after_hash,
      additions,
      deletions,
      changed_functions_json,
      preview,
      summary_json
    )
    VALUES (
      @sessionId,
      @filePath,
      @status,
      @beforeHash,
      @afterHash,
      @additions,
      @deletions,
      @changedFunctionsJson,
      @preview,
      @summaryJson
    )
  `);

  fileDiffs.forEach((diff: any) => {
    insertDiff.run({
      sessionId: session.id,
      filePath: diff.path,
      status: diff.status,
      beforeHash: diff.beforeHash || null,
      afterHash: diff.afterHash || null,
      additions: diff.additions || 0,
      deletions: diff.deletions || 0,
      changedFunctionsJson: JSON.stringify(diff.changedFunctions || []),
      preview: diff.preview || "",
      summaryJson: JSON.stringify(diff),
    });
  });
}

function importLegacySessions(database: Database.Database) {
  const row = database.prepare("SELECT COUNT(*) AS total FROM sessions").get() as { total: number };
  if (row.total > 0 || !fs.existsSync(LEGACY_SESSIONS_FILE)) {
    return;
  }

  const raw = fs.readFileSync(LEGACY_SESSIONS_FILE, "utf8");
  const parsed = parseJson(raw, { sessions: [] });
  if (!Array.isArray(parsed.sessions) || parsed.sessions.length === 0) {
    return;
  }

  const importSession = database.transaction((sessions: any[]) => {
    sessions.forEach((session) => {
      if (session && session.id) {
        upsertSession(database, session);
      }
    });
  });

  importSession(parsed.sessions);
}

function ensureStore(): Database.Database {
  const database = openDatabase();
  createSchema(database);
  importLegacySessions(database);
  return database;
}

function rowToSessionSummary(row: any) {
  return {
    id: row.id,
    name: row.name,
    project: row.project,
    createdAt: row.created_at,
    riskScore: row.risk_score,
    metrics: parseJson(row.metrics_json, {}),
    checkpoint: row.checkpoint,
  };
}

export function listSessions() {
  const database = ensureStore();
  return database
    .prepare(`
      SELECT
        id,
        name,
        project,
        created_at,
        risk_score,
        metrics_json,
        checkpoint
      FROM sessions
      ORDER BY datetime(created_at) DESC, id DESC
      LIMIT 25
    `)
    .all()
    .map(rowToSessionSummary);
}

export function getSession(id: string) {
  const database = ensureStore();
  const row = database
    .prepare("SELECT session_json FROM sessions WHERE id = ?")
    .get(id) as { session_json: string } | undefined;

  return row ? parseJson(row.session_json, null) : null;
}

export function getLatestSnapshots(projectPath: string) {
  const database = ensureStore();
  const row = database
    .prepare(`
      SELECT id
      FROM sessions
      WHERE project_path = ?
      ORDER BY datetime(created_at) DESC, id DESC
      LIMIT 1
    `)
    .get(projectPath) as { id: string } | undefined;

  if (!row) {
    return [];
  }

  return database
    .prepare(`
      SELECT
        file_path,
        content_hash,
        content_text,
        size_bytes
      FROM file_snapshots
      WHERE session_id = ?
    `)
    .all(row.id) as any[];
}

function pruneSessions(database: Database.Database) {
  database
    .prepare(`
      DELETE FROM sessions
      WHERE id NOT IN (
        SELECT id
        FROM sessions
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 25
      )
    `)
    .run();

  database
    .prepare(`
      DELETE FROM file_snapshots
      WHERE session_id NOT IN (SELECT id FROM sessions)
    `)
    .run();

  database
    .prepare(`
      DELETE FROM diff_summaries
      WHERE session_id NOT IN (SELECT id FROM sessions)
    `)
    .run();
}

export function saveSession(session: any) {
  const database = ensureStore();
  const createdAt = session.createdAt || new Date().toISOString();
  const normalizedSession = { ...session, createdAt };

  const persistSession = database.transaction(() => {
    upsertSession(database, normalizedSession);
    saveSnapshots(database, normalizedSession);
    saveDiffSummaries(database, normalizedSession);
    pruneSessions(database);
  });

  persistSession();
  return stripPrivateSessionFields(normalizedSession);
}

const fallbackTraceEvents = [
  {
    id: "evt-001",
    time: "00:04",
    type: "file",
    title: "Auth middleware rewritten",
    subtitle: "src/middleware/auth.ts",
    label: "file",
    risk: 76,
    badge: "P2",
    riskTitle: "Sensitive auth path",
    riskText:
      "The agent modified token validation and moved the allowlist check below request parsing.",
    checkpoint: "before-auth-middleware-rewrite",
    command: "$ codetrace watch --session cursor-auth-refactor\nrecording file mutation: src/middleware/auth.ts\ncheckpoint: before-auth-middleware-rewrite",
    diff: "- validateToken(req.headers.authorization)\n+ const user = decodeJwt(token)\n+ validateToken(token)\n\nrisk: auth order changed",
  },
  {
    id: "evt-002",
    time: "00:11",
    type: "terminal",
    title: "Environment variable printed",
    subtitle: "PowerShell command output captured",
    label: "terminal",
    risk: 91,
    badge: "P1",
    riskTitle: "Secret exposure attempt",
    riskText:
      "The session attempted to echo an environment variable while debugging an API integration.",
    checkpoint: "secret-safe-pre-debug",
    command: "$ echo $OPENAI_API_KEY\nblocked: output redacted by CodeTrace AI\nrule: terminal.secret_echo",
    diff: "no file diff\nterminal output was blocked before report export",
  },
  {
    id: "evt-003",
    time: "00:18",
    type: "package",
    title: "Dependency added",
    subtitle: "package.json changed",
    label: "package",
    risk: 58,
    badge: "P3",
    riskTitle: "New package drift",
    riskText:
      "A new transitive dependency was introduced. Review license, version, and security advisories before merging.",
    checkpoint: "before-dependency-install",
    command: "$ npm install jsonwebtoken@latest\ncaptured package lock delta: 6 packages\nrule: dependency.new_runtime_package",
    diff: '+ "jsonwebtoken": "^9.0.2"\n+ "jwa": "^2.0.0"\n+ "jws": "^4.0.0"',
  },
  {
    id: "evt-004",
    time: "00:26",
    type: "file",
    title: "Test file deleted",
    subtitle: "tests/auth-refresh.test.ts",
    label: "file",
    risk: 84,
    badge: "P1",
    riskTitle: "Coverage removed",
    riskText:
      "The agent removed a test that covered refresh-token replay behavior while editing the same auth flow.",
    checkpoint: "before-test-delete",
    command: "$ git diff --name-status\nD tests/auth-refresh.test.ts\nM src/middleware/auth.ts",
    diff: "- test('rejects replayed refresh token', async () => {\n-   expect(response.status).toBe(401)\n- })",
  },
  {
    id: "evt-005",
    time: "00:33",
    type: "security",
    title: "Config file touched",
    subtitle: "env.fixture opened by agent",
    label: "security",
    risk: 88,
    badge: "P1",
    riskTitle: "Sensitive file access",
    riskText:
      "A local environment file was opened during the session. The report will redact values and mark this checkpoint as sensitive.",
    checkpoint: "env-file-access-redacted",
    command: "$ codetrace redact env.fixture\nredacted: DATABASE_URL, JWT_SECRET, OPENAI_API_KEY\nrule: file.sensitive_config",
    diff: "env.fixture\nvalues hidden from replay export",
  },
  {
    id: "evt-006",
    time: "00:41",
    type: "terminal",
    title: "Migration generated",
    subtitle: "db/migrations/20260601_auth.sql",
    label: "terminal",
    risk: 63,
    badge: "P2",
    riskTitle: "Database behavior changed",
    riskText:
      "A migration was generated in the same session as auth edits. Review rollback SQL and data impact.",
    checkpoint: "before-auth-migration",
    command: "$ npm run db:generate\ncreated db/migrations/20260601_auth.sql\nlinked to auth.ts mutation",
    diff: "+ alter table sessions add column rotated_at timestamptz;\n+ create index sessions_user_id_idx on sessions(user_id);",
  },
  {
    id: "evt-007",
    time: "00:48",
    type: "security",
    title: "Rollback report prepared",
    subtitle: "reports/cursor-auth-refactor.md",
    label: "security",
    risk: 42,
    badge: "P3",
    riskTitle: "Report ready",
    riskText:
      "The session has a safe checkpoint, redacted command log, risky files list, and test suggestions for review.",
    checkpoint: "safe-auth-before-ai-pass",
    command: "$ codetrace report --format markdown\nwrote reports/cursor-auth-refactor.md\nrollback target: safe-auth-before-ai-pass",
    diff: "+ risky files: src/middleware/auth.ts, env.fixture\n+ suggested tests: auth refresh, JWT expiry, session rotation",
  },
];

let traceEvents = [...fallbackTraceEvents];
let activeSession = {
  name: "cursor-auth-refactor.trace",
  metrics: { files: 14, commands: 6, blocked: 2 },
  riskScore: 82,
  riskExplanation: {
    summary: "Score: 82 - secret exposure, auth-sensitive file, dependency signal.",
    factors: [
      { label: "secret pattern", count: 1 },
      { label: "auth-sensitive file", count: 1 },
      { label: "dependency signal", count: 1 },
    ],
  },
};

const timelineList = document.querySelector("#timelineList");
const eventCount = document.querySelector("#eventCount");
const riskScore = document.querySelector("#riskScore");
const sessionName = document.querySelector("#sessionName");
const filesMetric = document.querySelector("#filesMetric");
const commandsMetric = document.querySelector("#commandsMetric");
const blockedMetric = document.querySelector("#blockedMetric");
const apiMode = document.querySelector("#apiMode");
const riskMeterFill = document.querySelector("#riskMeterFill");
const riskTitle = document.querySelector("#riskTitle");
const riskText = document.querySelector("#riskText");
const riskBadge = document.querySelector("#riskBadge");
const scoreExplanation = document.querySelector("#scoreExplanation");
const riskFactorList = document.querySelector("#riskFactorList");
const checkpointName = document.querySelector("#checkpointName");
const commandOutput = document.querySelector("#commandOutput");
const diffOutput = document.querySelector("#diffOutput");
const selectedTitle = document.querySelector("#selectedTitle");
const filterButtons = document.querySelectorAll(".filter-btn");
const signalButtons = document.querySelectorAll(".signal-filter");
const scanBtn = document.querySelector("#scanBtn");
const headerScanBtn = document.querySelector("#headerScanBtn");
const simulateBtn = document.querySelector("#simulateBtn");
const exportBtn = document.querySelector("#exportBtn");
const rollbackBtn = document.querySelector("#rollbackBtn");
const pauseCanvasBtn = document.querySelector("#pauseCanvasBtn");
const canvas = document.querySelector("#traceCanvas");
const ctx = canvas.getContext("2d");

let selectedEvent = traceEvents[1];
let activeFilter = "all";
let animationPaused = false;
let tick = 0;

function renderTimeline() {
  const visibleEvents =
    activeFilter === "all"
      ? traceEvents
      : traceEvents.filter((event) => event.type === activeFilter);

  eventCount.textContent = `${visibleEvents.length} events`;
  timelineList.innerHTML = "";

  visibleEvents.forEach((event) => {
    const item = document.createElement("button");
    item.className = `timeline-item ${event.id === selectedEvent.id ? "active" : ""}`;
    item.type = "button";
    item.dataset.eventId = event.id;
    item.innerHTML = `
      <span class="event-time">${event.time}</span>
      <span class="event-body">
        <strong>${event.title}</strong>
        <span>${event.subtitle}</span>
        <span class="event-label ${event.type}">${event.label}</span>
      </span>
    `;
    item.addEventListener("click", () => selectEvent(event.id));
    timelineList.appendChild(item);
  });
}

function setTimelineFilter(filter) {
  activeFilter = filter;
  filterButtons.forEach((item) => {
    item.classList.toggle("active", item.dataset.filter === filter);
  });
  signalButtons.forEach((item) => {
    item.classList.toggle("active", item.dataset.filter === filter);
  });
  renderTimeline();
}

function selectEvent(eventId) {
  const event = traceEvents.find((entry) => entry.id === eventId);
  if (!event) return;

  selectedEvent = event;
  riskScore.textContent = activeSession.riskScore ?? event.risk;
  riskMeterFill.style.width = `${event.risk}%`;
  riskTitle.textContent = event.riskTitle;
  riskText.textContent = event.riskText;
  riskBadge.textContent = event.badge;
  checkpointName.textContent = event.checkpoint;
  commandOutput.textContent = event.command;
  diffOutput.textContent = event.diff;
  selectedTitle.textContent = event.title;
  renderTimeline();
  drawTraceGraph();
}

function showToast(message) {
  let toast = document.querySelector(".toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.className = "toast";
    document.body.appendChild(toast);
  }

  toast.textContent = message;
  toast.classList.add("visible");
  window.setTimeout(() => toast.classList.remove("visible"), 2600);
}

function formatDiffSummary(diffSummary) {
  if (!diffSummary) return "";
  const functions = diffSummary.changedFunctions?.length
    ? diffSummary.changedFunctions.join(", ")
    : "none detected";

  return [
    diffSummary.path,
    `status: ${diffSummary.status}`,
    `lines: +${diffSummary.additions} / -${diffSummary.deletions}`,
    `functions changed: ${functions}`,
    "",
    diffSummary.preview || "No changed lines in redacted snapshot preview",
  ].join("\n");
}

function normalizeEvent(event, index) {
  return {
    id: event.id || `evt-${String(index + 1).padStart(3, "0")}`,
    time: event.time || `00:${String(4 + index * 7).padStart(2, "0")}`,
    type: event.type || "file",
    title: event.title || "Recorded event",
    subtitle: event.subtitle || "No file path",
    label: event.label || event.type || "event",
    risk: Number(event.risk || 0),
    badge: event.badge || "P3",
    riskTitle: event.riskTitle || "Review needed",
    riskText: event.riskText || "CodeTrace AI marked this event for review.",
    checkpoint: event.checkpoint || activeSession.checkpoint || "local-demo-checkpoint",
    command: event.command || "$ codetrace scan\nstatus: captured",
    diff: event.diff || formatDiffSummary(event.diffSummary) || "No diff summary available",
    diffSummary: event.diffSummary,
  };
}

function renderRiskExplanation(session) {
  const explanation = session.riskExplanation || activeSession.riskExplanation || {};
  const factors = Array.isArray(explanation.factors) ? explanation.factors : [];

  scoreExplanation.textContent =
    explanation.summary || `Score: ${session.riskScore ?? activeSession.riskScore} - review recorded events.`;
  riskFactorList.innerHTML = "";

  factors.slice(0, 6).forEach((factor) => {
    const item = document.createElement("span");
    item.className = "risk-factor";
    item.textContent = `${factor.count} ${factor.label}`;
    item.title = factor.detail || factor.label;
    riskFactorList.appendChild(item);
  });
}

function updateSessionMetrics(session, modeLabel) {
  activeSession = {
    ...activeSession,
    ...session,
    metrics: {
      files: session.metrics?.files ?? activeSession.metrics.files,
      commands: session.metrics?.commands ?? activeSession.metrics.commands,
      blocked: session.metrics?.blocked ?? activeSession.metrics.blocked,
      changedFiles: session.metrics?.changedFiles ?? activeSession.metrics.changedFiles,
    },
  };

  sessionName.textContent = activeSession.name || "local-demo.trace";
  riskScore.textContent = activeSession.riskScore ?? selectedEvent.risk;
  filesMetric.textContent = activeSession.metrics.files;
  commandsMetric.textContent = activeSession.metrics.commands;
  blockedMetric.textContent = activeSession.metrics.blocked;
  apiMode.textContent = modeLabel;
  renderRiskExplanation(activeSession);
}

function applySession(session, modeLabel = "backend live") {
  const events = Array.isArray(session.events) ? session.events : [];
  traceEvents = events.length ? events.map(normalizeEvent) : [...fallbackTraceEvents];
  selectedEvent = traceEvents[0];
  activeFilter = "all";
  filterButtons.forEach((button) => button.classList.toggle("active", button.dataset.filter === "all"));
  signalButtons.forEach((button) => button.classList.remove("active"));
  updateSessionMetrics(session, modeLabel);
  selectEvent(selectedEvent.id);
}

async function requestJson(path, options) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || `Request failed with ${response.status}`);
  }

  return response.json();
}

async function loadLatestSession() {
  try {
    const payload = await requestJson("/api/sessions");
    if (!payload.sessions?.length) {
      updateSessionMetrics(activeSession, "backend ready");
      return;
    }

    const latest = payload.sessions[0];
    const detail = await requestJson(`/api/sessions/${encodeURIComponent(latest.id)}`);
    applySession(detail.session, "backend live");
  } catch {
    updateSessionMetrics(activeSession, "demo mode");
  }
}

async function scanSampleRepo() {
  scanBtn.disabled = true;
  headerScanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";
  headerScanBtn.textContent = "...";

  try {
    const payload = await requestJson("/api/scan", {
      method: "POST",
      body: JSON.stringify({ target: "sample" }),
    });
    applySession(payload.session, "backend scan");
    showToast("Backend scanned sample-repo and saved a real session.");
  } catch (error) {
    showToast(`Start the backend first: npm start. ${error.message}`);
  } finally {
    scanBtn.disabled = false;
    headerScanBtn.disabled = false;
    scanBtn.textContent = "Scan sample repo";
    headerScanBtn.textContent = "Scan";
  }
}

function drawTraceGraph() {
  const pixelRatio = window.devicePixelRatio || 1;
  const bounds = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, Math.floor(bounds.width * pixelRatio));
  canvas.height = Math.max(1, Math.floor(bounds.height * pixelRatio));
  ctx.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);

  const width = bounds.width;
  const height = bounds.height;
  const nodes = [
    { x: width * 0.14, y: height * 0.24, label: "Prompt", color: "#16a06f" },
    { x: width * 0.38, y: height * 0.18, label: "Files", color: "#157f8f" },
    { x: width * 0.62, y: height * 0.34, label: "Shell", color: "#6254a3" },
    { x: width * 0.48, y: height * 0.67, label: "Risk", color: "#e45e55" },
    { x: width * 0.78, y: height * 0.66, label: "Report", color: "#d99b28" },
  ];

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#111613";
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = "rgba(255,255,255,0.08)";
  ctx.lineWidth = 1;
  for (let x = 24; x < width; x += 42) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
  for (let y = 24; y < height; y += 42) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  const edges = [
    [0, 1],
    [1, 2],
    [1, 3],
    [2, 3],
    [3, 4],
  ];

  edges.forEach(([from, to], index) => {
    const a = nodes[from];
    const b = nodes[to];
    ctx.strokeStyle = "rgba(235, 244, 235, 0.28)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();

    const progress = ((tick * 0.014 + index * 0.18) % 1);
    const px = a.x + (b.x - a.x) * progress;
    const py = a.y + (b.y - a.y) * progress;
    ctx.fillStyle = selectedEvent.risk > 80 ? "#e45e55" : "#16a06f";
    ctx.beginPath();
    ctx.arc(px, py, 4.5, 0, Math.PI * 2);
    ctx.fill();
  });

  nodes.forEach((node) => {
    const isRiskNode = node.label === "Risk";
    const radius = isRiskNode ? 26 : 22;
    ctx.fillStyle = "rgba(255,255,255,0.1)";
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius + 8, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = node.color;
    ctx.beginPath();
    ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = "#ffffff";
    ctx.font = "700 12px Inter, system-ui, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(node.label, node.x, node.y + 4);
  });

  ctx.fillStyle = "rgba(255,255,255,0.82)";
  ctx.font = "700 13px Inter, system-ui, sans-serif";
  ctx.textAlign = "left";
  ctx.fillText(`selected: ${selectedEvent.id}`, 18, height - 22);
  ctx.fillStyle = selectedEvent.risk > 80 ? "#ffb1aa" : "#9ee8cb";
  ctx.fillText(`risk ${selectedEvent.risk}`, 140, height - 22);
}

function animate() {
  if (!animationPaused) {
    tick += 1;
    drawTraceGraph();
  }
  window.requestAnimationFrame(animate);
}

filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    setTimelineFilter(button.dataset.filter);
  });
});

signalButtons.forEach((button) => {
  button.addEventListener("click", () => {
    setTimelineFilter(button.dataset.filter);
  });
});

scanBtn.addEventListener("click", scanSampleRepo);
headerScanBtn.addEventListener("click", scanSampleRepo);

simulateBtn.addEventListener("click", () => {
  let index = traceEvents.findIndex((event) => event.id === selectedEvent.id);
  const timer = window.setInterval(() => {
    index = (index + 1) % traceEvents.length;
    selectEvent(traceEvents[index].id);
    if (index === traceEvents.length - 1) {
      window.clearInterval(timer);
      showToast("Session replay finished. Report is ready for review.");
    }
  }, 650);
});

exportBtn.addEventListener("click", () => {
  const report = [
    "CodeTrace AI Session Report",
    `Session: ${activeSession.name}`,
    `Overall risk: ${activeSession.riskScore}`,
    activeSession.riskExplanation?.summary || "",
    `Selected event: ${selectedEvent.title}`,
    `Event risk: ${selectedEvent.risk}`,
    `Checkpoint: ${selectedEvent.checkpoint}`,
    "",
    selectedEvent.riskText,
  ].join("\n");

  navigator.clipboard
    .writeText(report)
    .then(() => showToast("Report summary copied to clipboard."))
    .catch(() => showToast("Report summary prepared in the dashboard."));
});

rollbackBtn.addEventListener("click", () => {
  showToast(`Rollback prepared from checkpoint: ${selectedEvent.checkpoint}`);
});

pauseCanvasBtn.addEventListener("click", () => {
  animationPaused = !animationPaused;
  pauseCanvasBtn.textContent = animationPaused ? ">" : "||";
  pauseCanvasBtn.setAttribute(
    "aria-label",
    animationPaused ? "Resume trace animation" : "Pause trace animation",
  );
});

window.addEventListener("resize", drawTraceGraph);

renderRiskExplanation(activeSession);
selectEvent(selectedEvent.id);
loadLatestSession();
animate();

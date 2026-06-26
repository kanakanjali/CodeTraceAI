const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { URL } = require("node:url");

const { scanRepository } = require("./backend/scanner.ts");
const { getLatestSnapshots, getSession, listSessions, saveSession } = require("./backend/storage.ts");

const PORT = Number(process.env.PORT || 4173);
const ROOT_DIR = __dirname;
const SAMPLE_REPO = path.join(ROOT_DIR, "sample-repo");

// Ensure data directory exists on deployment
const DATA_DIR = path.join(ROOT_DIR, "data");
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload, null, 2));
}

function sendError(res, statusCode, message) {
  sendJson(res, statusCode, { error: message });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
  });
}

function resolveScanTarget(body) {
  if (!body || !body.target || body.target === "sample") {
    return SAMPLE_REPO;
  }

  const requested = path.resolve(ROOT_DIR, body.target);
  if (!requested.startsWith(ROOT_DIR)) {
    throw new Error("Scan target must stay inside the CodeTraceAI project folder");
  }
  return requested;
}

async function handleApi(req, res, url) {
  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(res, 200, { ok: true, service: "CodeTrace AI API" });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/sessions") {
    sendJson(res, 200, { sessions: listSessions() });
    return;
  }

  if (req.method === "GET" && url.pathname.startsWith("/api/sessions/")) {
    const id = decodeURIComponent(url.pathname.replace("/api/sessions/", ""));
    const session = getSession(id);
    if (!session) {
      sendError(res, 404, "Session not found");
      return;
    }
    sendJson(res, 200, { session });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/scan") {
    try {
      const body = await readBody(req);
      const target = resolveScanTarget(body);
      const previousSnapshots = getLatestSnapshots(target);
      const scanned = await scanRepository(target, { previousSnapshots, source: "dashboard-scan" });
      const session = saveSession(scanned);
      sendJson(res, 201, { session });
    } catch (error) {
      sendError(res, 400, error.message);
    }
    return;
  }

  sendError(res, 404, "API route not found");
}

function serveStatic(req, res, url) {
  const pathname = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const requestedPath = path.resolve(ROOT_DIR, `.${pathname}`);

  if (!requestedPath.startsWith(ROOT_DIR)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  fs.readFile(requestedPath, (error, content) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }

    const contentType = MIME_TYPES[path.extname(requestedPath)] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname.startsWith("/api/")) {
    await handleApi(req, res, url);
    return;
  }

  serveStatic(req, res, url);
});

server.listen(PORT, () => {
  console.log(`CodeTrace AI running at http://localhost:${PORT}`);
  console.log(`API health: http://localhost:${PORT}/api/health`);
});

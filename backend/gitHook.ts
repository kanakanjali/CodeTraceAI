import * as fs from "node:fs";
import * as path from "node:path";

const MANAGED_START = "# >>> CodeTrace AI snapshot hook >>>";
const MANAGED_END = "# <<< CodeTrace AI snapshot hook <<<";
const SUPPORTED_HOOKS = new Set(["post-commit", "pre-commit"]);

function shellQuote(value: string) {
  const normalized = String(value).replaceAll("\\", "/");
  return `'${normalized.replaceAll("'", "'\\''")}'`;
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function resolveGitDir(repoPath: string) {
  const gitPath = path.join(repoPath, ".git");

  if (!fs.existsSync(gitPath)) {
    throw new Error(`No .git directory found in ${repoPath}`);
  }

  const stat = fs.statSync(gitPath);
  if (stat.isDirectory()) {
    return gitPath;
  }

  const gitFile = fs.readFileSync(gitPath, "utf8").trim();
  const match = /^gitdir:\s*(.+)$/i.exec(gitFile);
  if (!match) {
    throw new Error(`Unsupported .git file format in ${repoPath}`);
  }

  return path.resolve(repoPath, match[1]);
}

function buildHookBlock(cliPath: string) {
  return [
    MANAGED_START,
    "if command -v node >/dev/null 2>&1; then",
    '  REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"',
    `  node ${shellQuote(cliPath)} scan "$REPO_ROOT" --source git-hook --quiet >/dev/null 2>&1 || true`,
    "fi",
    MANAGED_END,
  ].join("\n");
}

export function installGitHook(repoPath: string, options: { hookName?: string } = {}) {
  const hookName = options.hookName || "post-commit";
  if (!SUPPORTED_HOOKS.has(hookName)) {
    throw new Error(`Unsupported hook: ${hookName}`);
  }

  const resolvedRepo = path.resolve(repoPath);
  const gitDir = resolveGitDir(resolvedRepo);
  const hooksDir = path.join(gitDir, "hooks");
  const hookPath = path.join(hooksDir, hookName);
  const cliPath = path.resolve(__dirname, "..", "cli.js");
  const managedBlock = buildHookBlock(cliPath);

  fs.mkdirSync(hooksDir, { recursive: true });

  const existing = fs.existsSync(hookPath) ? fs.readFileSync(hookPath, "utf8") : "#!/bin/sh\n";
  const blockPattern = new RegExp(
    `\\n?${escapeRegExp(MANAGED_START)}[\\s\\S]*?${escapeRegExp(MANAGED_END)}\\n?`,
    "m",
  );
  let nextContent = existing.replace(blockPattern, "\n").trimEnd();

  if (!nextContent.startsWith("#!")) {
    nextContent = `#!/bin/sh\n${nextContent}`;
  }

  nextContent = `${nextContent}\n\n${managedBlock}\n`;
  fs.writeFileSync(hookPath, nextContent, "utf8");
  fs.chmodSync(hookPath, 0o755);

  return {
    hookName,
    hookPath,
    repoPath: resolvedRepo,
  };
}

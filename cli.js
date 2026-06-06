const path = require("node:path");
const { installGitHook } = require("./backend/gitHook.ts");
const { scanRepository } = require("./backend/scanner.ts");
const { getLatestSnapshots, saveSession } = require("./backend/storage.ts");

function printUsage() {
  console.log("Usage:");
  console.log("  node cli.js scan <folder> [--source label] [--quiet]");
  console.log("  node cli.js install-hook <folder> [--hook post-commit]");
  console.log("");
  console.log("Example:");
  console.log("  node cli.js scan sample-repo");
  console.log("  node cli.js install-hook ../my-project");
}

function readFlag(args, name, fallback = null) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  return args[index + 1] && !args[index + 1].startsWith("--") ? args[index + 1] : true;
}

function resolveTarget(target) {
  return path.resolve(process.cwd(), target);
}

async function scan(target, options = {}) {
  const targetPath = resolveTarget(target);
  const previousSnapshots = getLatestSnapshots(targetPath);
  const scanned = await scanRepository(targetPath, {
    previousSnapshots,
    source: options.source || "cli-scan",
  });
  const session = saveSession(scanned);

  if (!options.quiet) {
    console.log(`Saved session: ${session.name}`);
    console.log(`Risk score: ${session.riskScore}`);
    console.log(`Risk summary: ${session.riskExplanation.summary}`);
    console.log(`Events: ${session.events.length}`);
    console.log(`Changed files: ${session.fileDiffs.length}`);
    console.log(`Checkpoint: ${session.checkpoint}`);
  }

  return session;
}

function installHook(target, options = {}) {
  const targetPath = resolveTarget(target);
  const result = installGitHook(targetPath, { hookName: options.hookName });
  console.log(`Installed CodeTrace AI ${result.hookName} hook: ${result.hookPath}`);
  console.log("Future git commits in that repo will save a CodeTrace snapshot.");
}

async function main() {
  const [, , command, target = "sample-repo", ...args] = process.argv;

  if (command === "scan") {
    await scan(target, {
      quiet: args.includes("--quiet"),
      source: readFlag(args, "--source", "cli-scan"),
    });
    return;
  }

  if (command === "install-hook") {
    installHook(target, {
      hookName: readFlag(args, "--hook", "post-commit"),
    });
    return;
  }

  if (command === "hook" && target === "install") {
    const repo = args[0] || "sample-repo";
    installHook(repo, {
      hookName: readFlag(args.slice(1), "--hook", "post-commit"),
    });
    return;
  }

  {
    printUsage();
    process.exitCode = 1;
  }
}

main();

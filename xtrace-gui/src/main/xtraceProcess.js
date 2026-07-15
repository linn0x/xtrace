const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const DEFAULT_CHROMIUM_APP = path.join(REPO_ROOT, "chromium", "src", "out", "XTrace", "Chromium.app");
const DEFAULT_LOG_DIR = path.join(REPO_ROOT, "logs");
const DEFAULT_TAIL_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_ASSET_MAX_BYTES = 2 * 1024 * 1024;

function resolveChromiumExecutable(chromiumPath) {
  if (chromiumPath.endsWith(".app")) {
    return path.join(chromiumPath, "Contents", "MacOS", "Chromium");
  }
  return chromiumPath;
}

function timestampForFile(date = new Date()) {
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getUTCFullYear(),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate())
  ].join("") + "_" + [
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds())
  ].join("");
}

function makeTracePath(logDir, date = new Date()) {
  return path.join(logDir, `trace_${timestampForFile(date)}.ndjson`);
}

function makeProfilePath(logDir, date = new Date(), id = crypto.randomUUID()) {
  return path.join(logDir, "profiles", `profile_${timestampForFile(date)}_${id.replaceAll("-", "")}`);
}

function metadataPathForTrace(tracePath) {
  return tracePath.replace(/\.ndjson$/, ".metadata.json");
}

function buildChromiumLaunch({
  chromiumPath,
  url,
  logDir,
  categories,
  captureValues,
  maxValueBytes,
  maxBodyBytes = 0,
  maxHeaderValueBytes = 0,
  captureAssets = "summary",
  assetMaxBytes = DEFAULT_ASSET_MAX_BYTES,
  now
}) {
  const tracePath = makeTracePath(logDir, now);
  const profilePath = makeProfilePath(logDir, now);
  const executable = resolveChromiumExecutable(chromiumPath);
  const args = [
    "--xtrace-enable",
    `--xtrace-file=${tracePath}`,
    `--xtrace-categories=${categories}`,
    `--xtrace-capture-values=${captureValues}`,
    `--xtrace-max-value-bytes=${maxValueBytes}`,
    `--xtrace-capture-assets=${captureAssets}`,
    `--xtrace-asset-max-bytes=${assetMaxBytes}`,
    `--user-data-dir=${profilePath}`,
    "--no-first-run",
    "--no-default-browser-check",
    url
  ];
  if (maxBodyBytes > 0) {
    args.splice(6, 0, `--xtrace-max-body-bytes=${maxBodyBytes}`);
  }
  if (maxHeaderValueBytes > 0) {
    const headerCapIndex = maxBodyBytes > 0 ? 7 : 6;
    args.splice(
      headerCapIndex,
      0,
      `--xtrace-max-header-value-bytes=${maxHeaderValueBytes}`
    );
  }
  const env = {
    ...process.env,
    XTRACE_ENABLE: "1",
    XTRACE_FILE: tracePath,
    XTRACE_CATEGORIES: categories,
    XTRACE_CAPTURE_VALUES: captureValues,
    XTRACE_MAX_VALUE_BYTES: String(maxValueBytes),
    XTRACE_CAPTURE_ASSETS: captureAssets,
    XTRACE_ASSET_MAX_BYTES: String(assetMaxBytes)
  };
  if (maxBodyBytes > 0) {
    env.XTRACE_MAX_BODY_BYTES = String(maxBodyBytes);
  }
  if (maxHeaderValueBytes > 0) {
    env.XTRACE_MAX_HEADER_VALUE_BYTES = String(maxHeaderValueBytes);
  }
  return {executable, args, env, tracePath, profilePath};
}

function buildRunMetadata(launch, options = {}) {
  const metadata = {
    schema_version: 1,
    kind: "xtrace_run_metadata",
    trace_path: launch.tracePath,
    profile_path: launch.profilePath,
    executable: launch.executable,
    launch: {
      chromium_path: options.chromiumPath || "",
      url: options.url || "",
      log_dir: options.logDir || "",
      categories: options.categories || "",
      capture_values: options.captureValues || "",
      max_value_bytes: options.maxValueBytes ?? null,
      max_body_bytes: options.maxBodyBytes ?? null,
      max_header_value_bytes: options.maxHeaderValueBytes ?? null,
      capture_assets: options.captureAssets || "",
      asset_max_bytes: options.assetMaxBytes ?? null
    },
    recipe_source_trace_path: options.recipeSourceTracePath || "",
    rerun_recipe: options.rerunRecipe || null
  };
  if (!metadata.recipe_source_trace_path) delete metadata.recipe_source_trace_path;
  if (!metadata.rerun_recipe) delete metadata.rerun_recipe;
  return metadata;
}

function writeRunMetadata(tracePath, metadata) {
  const metadataPath = metadataPathForTrace(tracePath);
  fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2) + "\n", "utf8");
  return metadataPath;
}

function startChromiumRun(options) {
  fs.mkdirSync(options.logDir, {recursive: true});
  const launch = buildChromiumLaunch(options);
  fs.mkdirSync(path.dirname(launch.profilePath), {recursive: true});
  const metadata = buildRunMetadata(launch, options);
  const metadataPath = writeRunMetadata(launch.tracePath, metadata);
  const child = childProcess.spawn(launch.executable, launch.args, {
    env: launch.env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  return {...launch, metadataPath, child};
}

function parseNdjsonLines(buffer) {
  const events = [];
  for (const line of buffer.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      events.push(JSON.parse(trimmed));
    } catch (error) {
      events.push({schema_version: 0, api: "xtrace.parse_error", error: String(error), raw: trimmed});
    }
  }
  return events;
}

function readEventsSince(tracePath, offset = 0, options = {}) {
  if (!fs.existsSync(tracePath)) {
    return {events: [], offset};
  }
  const stat = fs.statSync(tracePath);
  if (stat.size < offset) {
    offset = 0;
  }
  if (stat.size === offset) {
    return {events: [], offset};
  }
  const fd = fs.openSync(tracePath, "r");
  try {
    const maxBytes = options.maxBytes || DEFAULT_TAIL_MAX_BYTES;
    let length = Math.min(stat.size - offset, maxBytes);
    const buffer = Buffer.alloc(length);
    fs.readSync(fd, buffer, 0, length, offset);
    let text = buffer.toString("utf8");
    let nextOffset = offset + length;

    if (nextOffset < stat.size) {
      const lastNewline = text.lastIndexOf("\n");
      if (lastNewline === -1) {
        return {events: [], offset};
      }
      text = text.slice(0, lastNewline + 1);
      nextOffset = offset + Buffer.byteLength(text);
    }

    return {events: parseNdjsonLines(text), offset: nextOffset};
  } finally {
    fs.closeSync(fd);
  }
}

function listTraceFiles(logDir) {
  if (!fs.existsSync(logDir)) return [];
  return fs.readdirSync(logDir)
    .filter((name) => name.endsWith(".ndjson"))
    .map((name) => {
      const filePath = path.join(logDir, name);
      const stat = fs.statSync(filePath);
      return {
        name,
        path: filePath,
        size: stat.size,
        modifiedMs: stat.mtimeMs
      };
    })
    .sort((a, b) => b.modifiedMs - a.modifiedMs);
}

module.exports = {
  DEFAULT_CHROMIUM_APP,
  DEFAULT_LOG_DIR,
  DEFAULT_ASSET_MAX_BYTES,
  resolveChromiumExecutable,
  timestampForFile,
  makeTracePath,
  makeProfilePath,
  metadataPathForTrace,
  buildChromiumLaunch,
  buildRunMetadata,
  writeRunMetadata,
  startChromiumRun,
  parseNdjsonLines,
  readEventsSince,
  listTraceFiles
};

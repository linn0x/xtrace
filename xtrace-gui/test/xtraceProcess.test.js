const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const childProcess = require("node:child_process");
const {
  buildChromiumLaunch,
  buildRunMetadata,
  listTraceFiles,
  metadataPathForTrace,
  parseNdjsonLines,
  readEventsSince,
  resolveChromiumExecutable,
  timestampForFile,
  writeRunMetadata
} = require("../src/main/xtraceProcess");

test("resolveChromiumExecutable handles app bundles", () => {
  assert.equal(
    resolveChromiumExecutable("/tmp/Chromium.app"),
    "/tmp/Chromium.app/Contents/MacOS/Chromium"
  );
  assert.equal(resolveChromiumExecutable("/tmp/Chromium"), "/tmp/Chromium");
});

test("buildChromiumLaunch sets sandbox-safe XTrace flags and env", () => {
  const now = new Date(Date.UTC(2026, 5, 28, 9, 1, 2));
  const launch = buildChromiumLaunch({
    chromiumPath: "/tmp/Chromium.app",
    url: "https://example.test",
    logDir: "/tmp/xtrace-logs",
    categories: "reverse",
    captureValues: "summary",
    maxValueBytes: 4096,
    maxBodyBytes: 65536,
    maxHeaderValueBytes: 2048,
    captureAssets: "full",
    assetMaxBytes: 8192,
    now
  });
  assert.equal(timestampForFile(now), "20260628_090102");
  assert.equal(launch.executable, "/tmp/Chromium.app/Contents/MacOS/Chromium");
  assert.ok(launch.args.includes("--xtrace-enable"));
  assert.ok(launch.args.includes("--xtrace-categories=reverse"));
  assert.ok(launch.args.includes("--xtrace-capture-values=summary"));
  assert.ok(launch.args.includes("--xtrace-max-value-bytes=4096"));
  assert.ok(launch.args.includes("--xtrace-max-body-bytes=65536"));
  assert.ok(launch.args.includes("--xtrace-max-header-value-bytes=2048"));
  assert.ok(launch.args.includes("--xtrace-capture-assets=full"));
  assert.ok(launch.args.includes("--xtrace-asset-max-bytes=8192"));
  assert.equal(launch.args.at(-1), "https://example.test");
  assert.equal(launch.env.XTRACE_CATEGORIES, "reverse");
  assert.equal(launch.env.XTRACE_CAPTURE_VALUES, "summary");
  assert.equal(launch.env.XTRACE_MAX_VALUE_BYTES, "4096");
  assert.equal(launch.env.XTRACE_MAX_BODY_BYTES, "65536");
  assert.equal(launch.env.XTRACE_MAX_HEADER_VALUE_BYTES, "2048");
  assert.equal(launch.env.XTRACE_CAPTURE_ASSETS, "full");
  assert.equal(launch.env.XTRACE_ASSET_MAX_BYTES, "8192");
});

test("buildRunMetadata records rerun recipe context beside trace", () => {
  const launch = {
    executable: "/tmp/Chromium.app/Contents/MacOS/Chromium",
    tracePath: "/tmp/xtrace-logs/trace_20260628_090102.ndjson",
    profilePath: "/tmp/xtrace-logs/profiles/profile_20260628_090102_abcd",
    args: ["--xtrace-enable", "--xtrace-file=/tmp/xtrace-logs/trace_20260628_090102.ndjson", "https://example.test"]
  };
  const metadata = buildRunMetadata(launch, {
    chromiumPath: "/tmp/Chromium.app",
    url: "https://example.test",
    logDir: "/tmp/xtrace-logs",
    categories: "reverse,fingerprint",
    captureValues: "full",
    maxValueBytes: 262144,
    maxBodyBytes: 65536,
    maxHeaderValueBytes: 2048,
    captureAssets: "full",
    assetMaxBytes: 2097152,
    recipeSourceTracePath: "/tmp/xtrace-logs/trace_previous.ndjson",
    rerunRecipe: {
      profile: "interactive_full_capture",
      start_url: "https://example.test",
      focus: {
        target_terms: ["X-Signature", "X-Secondary-Signature"],
        endpoints: ["https://example.test/api/feed/list"],
        gaps: ["signature_terms_not_observed"],
        hooks: ["vmp_string_decoder"]
      }
    }
  });

  assert.equal(metadataPathForTrace(launch.tracePath), "/tmp/xtrace-logs/trace_20260628_090102.metadata.json");
  assert.deepEqual(metadata, {
    schema_version: 1,
    kind: "xtrace_run_metadata",
    trace_path: "/tmp/xtrace-logs/trace_20260628_090102.ndjson",
    profile_path: "/tmp/xtrace-logs/profiles/profile_20260628_090102_abcd",
    executable: "/tmp/Chromium.app/Contents/MacOS/Chromium",
    launch: {
      chromium_path: "/tmp/Chromium.app",
      url: "https://example.test",
      log_dir: "/tmp/xtrace-logs",
      categories: "reverse,fingerprint",
      capture_values: "full",
      max_value_bytes: 262144,
      max_body_bytes: 65536,
      max_header_value_bytes: 2048,
      capture_assets: "full",
      asset_max_bytes: 2097152
    },
    recipe_source_trace_path: "/tmp/xtrace-logs/trace_previous.ndjson",
    rerun_recipe: {
      profile: "interactive_full_capture",
      start_url: "https://example.test",
      focus: {
        target_terms: ["X-Signature", "X-Secondary-Signature"],
        endpoints: ["https://example.test/api/feed/list"],
        gaps: ["signature_terms_not_observed"],
        hooks: ["vmp_string_decoder"]
      }
    }
  });
});

test("writeRunMetadata writes sidecar json next to trace", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-metadata-"));
  const tracePath = path.join(dir, "trace_demo.ndjson");
  const metadata = {schema_version: 1, kind: "xtrace_run_metadata", trace_path: tracePath};

  const metadataPath = writeRunMetadata(tracePath, metadata);

  assert.equal(metadataPath, path.join(dir, "trace_demo.metadata.json"));
  assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), metadata);
});

test("startChromiumRun writes run metadata before spawning Chromium", () => {
  const originalSpawn = childProcess.spawn;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-start-metadata-"));
  const now = new Date(Date.UTC(2026, 5, 28, 9, 1, 2));
  const spawned = [];
  childProcess.spawn = (executable, args, options) => {
    spawned.push({executable, args, options});
    return {
      stdout: {on() {}},
      stderr: {on() {}},
      on() {},
      pid: 12345
    };
  };
  try {
    const {startChromiumRun} = require("../src/main/xtraceProcess");
    const run = startChromiumRun({
      chromiumPath: "/tmp/Chromium.app",
      url: "https://example.test",
      logDir: dir,
      categories: "reverse,fingerprint",
      captureValues: "full",
      maxValueBytes: 262144,
      captureAssets: "full",
      assetMaxBytes: 2097152,
      recipeSourceTracePath: path.join(dir, "trace_previous.ndjson"),
      rerunRecipe: {profile: "interactive_full_capture", start_url: "https://example.test"},
      now
    });

    assert.equal(spawned.length, 1);
    assert.equal(run.metadataPath, path.join(dir, "trace_20260628_090102.metadata.json"));
    const metadata = JSON.parse(fs.readFileSync(run.metadataPath, "utf8"));
    assert.equal(metadata.trace_path, path.join(dir, "trace_20260628_090102.ndjson"));
    assert.equal(metadata.recipe_source_trace_path, path.join(dir, "trace_previous.ndjson"));
    assert.equal(metadata.rerun_recipe.profile, "interactive_full_capture");
  } finally {
    childProcess.spawn = originalSpawn;
  }
});

test("readEventsSince tails ndjson incrementally", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-gui-"));
  const trace = path.join(dir, "trace.ndjson");
  fs.writeFileSync(trace, "{\"api\":\"fetch\"}\n", "utf8");
  const first = readEventsSince(trace, 0);
  assert.deepEqual(first.events, [{api: "fetch"}]);
  fs.appendFileSync(trace, "{\"api\":\"Storage.setItem\"}\n", "utf8");
  const second = readEventsSince(trace, first.offset);
  assert.deepEqual(second.events, [{api: "Storage.setItem"}]);
});

test("readEventsSince caps reads at complete lines", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-gui-"));
  const trace = path.join(dir, "trace.ndjson");
  const firstLine = "{\"api\":\"fetch\"}\n";
  const secondLine = JSON.stringify({api: "Storage.setItem", value: "x".repeat(512)}) + "\n";
  fs.writeFileSync(trace, firstLine + secondLine, "utf8");

  const first = readEventsSince(trace, 0, {maxBytes: firstLine.length + 16});

  assert.deepEqual(first.events, [{api: "fetch"}]);
  assert.equal(first.offset, Buffer.byteLength(firstLine));

  const second = readEventsSince(trace, first.offset, {maxBytes: 4096});
  assert.equal(second.events.length, 1);
  assert.equal(second.events[0].api, "Storage.setItem");
});

test("listTraceFiles returns newest ndjson first", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-gui-"));
  const first = path.join(dir, "trace_a.ndjson");
  const second = path.join(dir, "trace_b.ndjson");
  fs.writeFileSync(first, "{\"api\":\"a\"}\n", "utf8");
  fs.writeFileSync(second, "{\"api\":\"b\"}\n", "utf8");
  fs.utimesSync(first, new Date(1000), new Date(1000));
  fs.utimesSync(second, new Date(2000), new Date(2000));
  const logs = listTraceFiles(dir);
  assert.equal(logs[0].name, "trace_b.ndjson");
  assert.equal(logs[1].name, "trace_a.ndjson");
});

test("parseNdjsonLines preserves malformed lines as parse events", () => {
  const events = parseNdjsonLines("{\"api\":\"fetch\"}\nnot-json\n");
  assert.equal(events[0].api, "fetch");
  assert.equal(events[1].api, "xtrace.parse_error");
});

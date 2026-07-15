const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  assetDirectoryForTrace,
  manifestPathForTrace,
  readAssetManifest
} = require("../src/main/xtraceAssets");

test("manifestPathForTrace stores assets beside trace logs", () => {
  const tracePath = "/tmp/xtrace/logs/trace_20260629_010203.ndjson";

  assert.equal(
    assetDirectoryForTrace(tracePath),
    "/tmp/xtrace/logs/assets/trace_20260629_010203"
  );
  assert.equal(
    manifestPathForTrace(tracePath),
    "/tmp/xtrace/logs/assets/trace_20260629_010203/manifest.ndjson"
  );
});

test("readAssetManifest parses manifest rows and caps reads at complete lines", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-assets-"));
  const tracePath = path.join(dir, "trace_demo.ndjson");
  const manifestPath = manifestPathForTrace(tracePath);
  fs.mkdirSync(path.dirname(manifestPath), {recursive: true});
  const first = JSON.stringify({
    asset_id: "sha1:first",
    kind: "dynamic-code",
    content_path: "assets/trace_demo/sha1_first.js",
    sha1: "sha1:first",
    size: 32,
    truncated: false,
    first_seq: 10
  }) + "\n";
  const second = JSON.stringify({
    asset_id: "sha1:second",
    kind: "external-script",
    url: "https://example.test/app.js",
    sha1: "sha1:second",
    size: 64,
    truncated: false,
    first_seq: 12
  }) + "\n";
  fs.writeFileSync(manifestPath, first + second, "utf8");

  const rows = readAssetManifest(tracePath, {maxBytes: first.length + 5});

  assert.equal(rows.length, 1);
  assert.equal(rows[0].asset_id, "sha1:first");
});

test("readAssetManifest returns parse marker rows for malformed manifest lines", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-assets-"));
  const tracePath = path.join(dir, "trace_bad.ndjson");
  const manifestPath = manifestPathForTrace(tracePath);
  fs.mkdirSync(path.dirname(manifestPath), {recursive: true});
  fs.writeFileSync(manifestPath, "{\"asset_id\":\"ok\"}\nnot-json\n", "utf8");

  const rows = readAssetManifest(tracePath);

  assert.equal(rows[0].asset_id, "ok");
  assert.equal(rows[1].asset_id, "xtrace.asset_parse_error");
});

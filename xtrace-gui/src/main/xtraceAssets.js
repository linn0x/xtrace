const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_MANIFEST_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_ASSET_CONTENT_MAX_BYTES = 2 * 1024 * 1024;

function traceBaseName(tracePath) {
  return path.basename(tracePath).replace(/\.ndjson$/i, "");
}

function assetDirectoryForTrace(tracePath) {
  return path.join(path.dirname(tracePath), "assets", traceBaseName(tracePath));
}

function manifestPathForTrace(tracePath) {
  return path.join(assetDirectoryForTrace(tracePath), "manifest.ndjson");
}

function parseManifestLines(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const row = JSON.parse(trimmed);
      rows.push(row && typeof row === "object" ? row : {
        asset_id: "xtrace.asset_parse_error",
        error: "manifest row is not an object",
        raw: trimmed
      });
    } catch (error) {
      rows.push({
        asset_id: "xtrace.asset_parse_error",
        error: String(error),
        raw: trimmed
      });
    }
  }
  return rows;
}

function readCompleteText(filePath, maxBytes) {
  const stat = fs.statSync(filePath);
  const length = Math.min(stat.size, maxBytes);
  const fd = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.alloc(length);
    fs.readSync(fd, buffer, 0, length, 0);
    let text = buffer.toString("utf8");
    if (length < stat.size) {
      const lastNewline = text.lastIndexOf("\n");
      if (lastNewline === -1) return "";
      text = text.slice(0, lastNewline + 1);
    }
    return text;
  } finally {
    fs.closeSync(fd);
  }
}

function readPrefixText(filePath, maxBytes) {
  const stat = fs.statSync(filePath);
  const length = Math.min(stat.size, maxBytes);
  const fd = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.alloc(length);
    fs.readSync(fd, buffer, 0, length, 0);
    return buffer.toString("utf8");
  } finally {
    fs.closeSync(fd);
  }
}

function readAssetManifest(tracePath, options = {}) {
  const filePath = options.manifestPath || manifestPathForTrace(tracePath);
  if (!fs.existsSync(filePath)) return [];
  const text = readCompleteText(filePath, options.maxBytes || DEFAULT_MANIFEST_MAX_BYTES);
  return parseManifestLines(text);
}

function resolveAssetContentPath(tracePath, asset) {
  if (!asset || !asset.content_path) return null;
  if (path.isAbsolute(asset.content_path)) return asset.content_path;
  return path.resolve(path.dirname(tracePath), asset.content_path);
}

function readAssetContent(tracePath, asset, options = {}) {
  const contentPath = resolveAssetContentPath(tracePath, asset);
  if (!contentPath || !fs.existsSync(contentPath)) return null;
  return readPrefixText(contentPath, options.maxBytes || DEFAULT_ASSET_CONTENT_MAX_BYTES);
}

function attachAssetContent(tracePath, assets, options = {}) {
  return assets.map((asset) => {
    if (asset.asset_id === "xtrace.asset_parse_error") return asset;
    const content = readAssetContent(tracePath, asset, options);
    return content === null ? asset : {...asset, content};
  });
}

module.exports = {
  DEFAULT_MANIFEST_MAX_BYTES,
  DEFAULT_ASSET_CONTENT_MAX_BYTES,
  assetDirectoryForTrace,
  manifestPathForTrace,
  readAssetManifest,
  resolveAssetContentPath,
  readAssetContent,
  attachAssetContent
};

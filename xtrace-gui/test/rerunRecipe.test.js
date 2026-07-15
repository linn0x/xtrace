const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const {
  applyRerunRecipeToForm,
  launchOptionsFromForm,
  recipeFromReport
} = require("../src/renderer/rerunRecipe");

function formElements(ids) {
  const elements = new Map(ids.map((id) => [id, {id, value: ""}]));
  return {
    get: (id) => elements.get(id),
    value: (id) => elements.get(id).value
  };
}

test("recipeFromReport extracts next capture rerun recipe", () => {
  const recipe = {start_url: "https://www.example.test/api/feed/list"};
  const report = {
    signature: {
      agent_evidence_pack: {
        next_capture_plan: {rerun_recipe: recipe}
      }
    }
  };

  assert.equal(recipeFromReport(report), recipe);
  assert.equal(recipeFromReport({capture_recipe: recipe}), recipe);
  assert.equal(recipeFromReport({}), null);
});

test("applyRerunRecipeToForm populates GUI launch fields from recipe", () => {
  const form = formElements([
    "chromiumPath",
    "url",
    "logDir",
    "categories",
    "captureValues",
    "captureAssets",
    "maxValueBytes",
    "assetMaxBytes"
  ]);
  const recipe = {
    start_url: "https://www.example.test/api/feed/list",
    gui_defaults: {
      url: "https://www.example.test/api/feed/list",
      categories: "reverse,fingerprint",
      captureValues: "full",
      captureAssets: "full",
      maxValueBytes: 262144
    },
    python_launcher_args: [
      "run",
      "--chromium",
      "/path/to/xtrace/chromium/src/out/XTrace/Chromium.app",
      "--url",
      "https://www.example.test/api/feed/list",
      "--log-dir",
      "/path/to/xtrace/logs",
      "--xtrace-asset-max-bytes",
      "2097152"
    ]
  };

  const applied = applyRerunRecipeToForm(recipe, form.get);

  assert.equal(applied, true);
  assert.equal(form.value("chromiumPath"), "/path/to/xtrace/chromium/src/out/XTrace/Chromium.app");
  assert.equal(form.value("url"), "https://www.example.test/api/feed/list");
  assert.equal(form.value("logDir"), "/path/to/xtrace/logs");
  assert.equal(form.value("categories"), "reverse,fingerprint");
  assert.equal(form.value("captureValues"), "full");
  assert.equal(form.value("captureAssets"), "full");
  assert.equal(form.value("maxValueBytes"), "262144");
  assert.equal(form.value("assetMaxBytes"), "2097152");
});

test("applyRerunRecipeToForm ignores missing recipe", () => {
  const form = formElements(["url"]);

  assert.equal(applyRerunRecipeToForm(null, form.get), false);
  assert.equal(form.value("url"), "");
});

test("launchOptionsFromForm builds start payload after applying recipe", () => {
  const form = formElements([
    "chromiumPath",
    "url",
    "logDir",
    "categories",
    "captureValues",
    "captureAssets",
    "maxValueBytes",
    "assetMaxBytes"
  ]);
  const recipe = {
    gui_defaults: {
      url: "https://www.example.test/api/feed/list",
      categories: "reverse,fingerprint",
      captureValues: "full",
      captureAssets: "full",
      maxValueBytes: 262144
    },
    python_launcher_args: [
      "run",
      "--chromium",
      "/path/to/xtrace/chromium/src/out/XTrace/Chromium.app",
      "--log-dir",
      "/path/to/xtrace/logs",
      "--xtrace-asset-max-bytes",
      "2097152"
    ]
  };

  applyRerunRecipeToForm(recipe, form.get);

  assert.deepEqual(launchOptionsFromForm(form.get), {
    chromiumPath: "/path/to/xtrace/chromium/src/out/XTrace/Chromium.app",
    url: "https://www.example.test/api/feed/list",
    logDir: "/path/to/xtrace/logs",
    categories: "reverse,fingerprint",
    captureValues: "full",
    maxValueBytes: 262144,
    captureAssets: "full",
    assetMaxBytes: 2097152
  });
});

test("renderer page loads rerun recipe helper before app", () => {
  const html = fs.readFileSync(
    path.join(__dirname, "../src/renderer/index.html"),
    "utf8"
  );
  const appJs = fs.readFileSync(
    path.join(__dirname, "../src/renderer/app.js"),
    "utf8"
  );

  assert.match(html, /id="applyRecipe"/);
  assert.match(html, /id="runRecipe"/);
  assert.match(html, /id="captureGateState"/);
  assert.match(html, /id="agentPackPath"/);
  assert.match(appJs, /agentPackMarkdownPath/);
  assert.match(appJs, /\$\("agentPackPath"\)\.textContent/);
  assert.ok(html.indexOf("./captureGate.js") < html.indexOf("./app.js"));
  assert.ok(html.indexOf("./rerunRecipe.js") < html.indexOf("./app.js"));
});

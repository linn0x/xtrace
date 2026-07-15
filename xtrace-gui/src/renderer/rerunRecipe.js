(function initRerunRecipe(root) {
  function recipeFromReport(report) {
    return report?.signature?.agent_evidence_pack?.next_capture_plan?.rerun_recipe ||
      report?.capture_recipe ||
      null;
  }

  function valueAfterArg(args, name) {
    const index = (args || []).indexOf(name);
    return index === -1 ? "" : args[index + 1] || "";
  }

  function setValue(getElement, id, value) {
    if (value === undefined || value === null || value === "") return;
    const element = getElement(id);
    if (element) element.value = String(value);
  }

  function applyRerunRecipeToForm(recipe, getElement) {
    if (!recipe) return false;
    const defaults = recipe.gui_defaults || {};
    const args = recipe.python_launcher_args || [];

    setValue(getElement, "chromiumPath", valueAfterArg(args, "--chromium"));
    setValue(getElement, "url", defaults.url || recipe.start_url || valueAfterArg(args, "--url"));
    setValue(getElement, "logDir", valueAfterArg(args, "--log-dir"));
    setValue(getElement, "categories", defaults.categories || valueAfterArg(args, "--xtrace-categories"));
    setValue(getElement, "captureValues", defaults.captureValues || valueAfterArg(args, "--xtrace-capture-values"));
    setValue(getElement, "captureAssets", defaults.captureAssets || valueAfterArg(args, "--xtrace-capture-assets"));
    setValue(getElement, "maxValueBytes", defaults.maxValueBytes || valueAfterArg(args, "--xtrace-max-value-bytes"));
    setValue(getElement, "assetMaxBytes", defaults.assetMaxBytes || valueAfterArg(args, "--xtrace-asset-max-bytes"));
    return true;
  }

  function numberValue(getElement, id) {
    return Number(getElement(id)?.value || 0);
  }

  function stringValue(getElement, id) {
    return getElement(id)?.value || "";
  }

  function launchOptionsFromForm(getElement) {
    return {
      chromiumPath: stringValue(getElement, "chromiumPath"),
      url: stringValue(getElement, "url"),
      logDir: stringValue(getElement, "logDir"),
      categories: stringValue(getElement, "categories"),
      captureValues: stringValue(getElement, "captureValues"),
      maxValueBytes: numberValue(getElement, "maxValueBytes"),
      captureAssets: stringValue(getElement, "captureAssets"),
      assetMaxBytes: numberValue(getElement, "assetMaxBytes")
    };
  }

  const api = {
    applyRerunRecipeToForm,
    launchOptionsFromForm,
    recipeFromReport
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.xtraceRerunRecipe = api;
  }
})(typeof window !== "undefined" ? window : null);

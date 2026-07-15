(function initCaptureGate(root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.xtraceCaptureGate = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : window, () => {
  const REJECT_RESOURCE_CLASSES = [
    "document_request",
    "static_resource",
    "telemetry_endpoint"
  ];
  const REQUIRED_RENDERER_APIS = [
    "Request.constructor",
    "fetch",
    "XMLHttpRequest.open",
    "XMLHttpRequest.send"
  ];
  const TAIL_APIS = [
    "BrowserNetwork.request",
    ...REQUIRED_RENDERER_APIS
  ];
  const STATIC_EXTENSIONS = new Set([
    ".js",
    ".mjs",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".mp4",
    ".webm"
  ]);
  const STATIC_DESTINATIONS = new Set([
    "script",
    "style",
    "image",
    "font",
    "media"
  ]);

  function firstArg(event) {
    return Array.isArray(event?.args) ? event.args[0] || {} : {};
  }

  function eventUrl(event) {
    const arg = firstArg(event);
    return arg.url || arg.href || arg.request_url || arg.request?.url || event?.url || "";
  }

  function canonicalEndpoint(url) {
    try {
      const parsed = new URL(url);
      parsed.search = "";
      parsed.hash = "";
      return parsed.toString().replace(/\/$/, parsed.pathname === "/" ? "/" : "");
    } catch {
      return String(url || "").split(/[?#]/)[0];
    }
  }

  function sameOriginApiPattern(startUrl) {
    try {
      const parsed = new URL(startUrl);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        return `${parsed.origin}/api/*`;
      }
    } catch {
      // Fall through to a generic pattern.
    }
    return "same-origin /api/*";
  }

  function pathExtension(pathname) {
    const match = String(pathname || "").toLowerCase().match(/\.[a-z0-9]+$/);
    return match ? match[0] : "";
  }

  function classifyResource(event, url) {
    const arg = firstArg(event);
    const destination = String(arg.request_destination || arg.destination || "").toLowerCase();
    let parsed = null;
    try {
      parsed = new URL(url);
    } catch {
      parsed = null;
    }
    const haystack = [
      parsed?.hostname || "",
      parsed?.pathname || "",
      parsed?.search || ""
    ].join(" ").toLowerCase();
    if (destination === "document" || arg.resource_type === "main_frame") return "document_request";
    if (STATIC_DESTINATIONS.has(destination)) return "static_resource";
    if (parsed && STATIC_EXTENSIONS.has(pathExtension(parsed.pathname))) return "static_resource";
    if (/(\/web\/resource|\/resource$)/.test(haystack)) return "static_resource";
    if (/(telemetry|analytics|monitor|collect|beacon|log|report|metrics|probe|privacy_headers)/.test(haystack)) {
      return "telemetry_endpoint";
    }
    if (parsed && parsed.pathname === "/" && event?.api === "BrowserNetwork.request") return "document_request";
    return "";
  }

  function isActionableBrowserRequest(event) {
    if (event?.category !== "network" || event?.api !== "BrowserNetwork.request") return false;
    const url = eventUrl(event);
    if (!url) return false;
    return !classifyResource(event, url);
  }

  function rejectedEndpointSummary(events = []) {
    const byClass = new Map();
    for (const event of events || []) {
      if (event?.category !== "network" || !TAIL_APIS.includes(event?.api)) continue;
      const url = eventUrl(event);
      if (!url) continue;
      const resourceClass = classifyResource(event, url);
      if (!resourceClass) continue;
      const item = byClass.get(resourceClass) || {
        resource_class: resourceClass,
        endpoints: new Set(),
        event_count: 0
      };
      item.endpoints.add(canonicalEndpoint(url));
      item.event_count += 1;
      byClass.set(resourceClass, item);
    }
    return [...byClass.values()]
      .sort((a, b) =>
        REJECT_RESOURCE_CLASSES.indexOf(a.resource_class) - REJECT_RESOURCE_CLASSES.indexOf(b.resource_class) ||
        String(a.resource_class).localeCompare(String(b.resource_class)))
      .map((item) => ({
        resource_class: item.resource_class,
        endpoint_count: item.endpoints.size,
        event_count: item.event_count,
        examples: [...item.endpoints].slice(0, 3)
      }));
  }

  function unique(values, limit = 8) {
    const output = [];
    const seen = new Set();
    for (const value of values || []) {
      if (!value || seen.has(value)) continue;
      seen.add(value);
      output.push(value);
      if (output.length >= limit) break;
    }
    return output;
  }

  function buildRealtimeCaptureGate(events = [], {startUrl = ""} = {}) {
    const matchedEndpoints = unique((events || [])
      .filter(isActionableBrowserRequest)
      .map((event) => canonicalEndpoint(eventUrl(event))));
    const rejectedSummary = rejectedEndpointSummary(events);
    const status = matchedEndpoints.length ? "passed" : "pending";
    const missing = status === "passed" ? [] : ["business_api_anchor_not_captured"];
    return {
      id: "business_api_anchor",
      status,
      observed_actionable_endpoint_count: matchedEndpoints.length,
      matched_endpoints: matchedEndpoints,
      missing,
      rejected_endpoint_summary: rejectedSummary,
      target_endpoint_patterns: matchedEndpoints.length
        ? matchedEndpoints
        : [sameOriginApiPattern(startUrl), "fetch/XMLHttpRequest non-static endpoint"],
      reject_resource_classes: REJECT_RESOURCE_CLASSES,
      tail_filters: {
        categories: ["network"],
        apis: TAIL_APIS,
        exclude_resource_classes: REJECT_RESOURCE_CLASSES
      }
    };
  }

  function formatRealtimeCaptureGate(gate) {
    const firstPattern = gate?.target_endpoint_patterns?.[0] || "same-origin /api/*";
    if (gate?.status === "passed") {
      const count = gate.observed_actionable_endpoint_count || 0;
      const endpoint = gate.matched_endpoints?.[0] || firstPattern;
      return `Gate passed · ${count} endpoint${count === 1 ? "" : "s"} · ${endpoint}`;
    }
    const rejected = (gate?.rejected_endpoint_summary || [])
      .map((item) => `${item.resource_class.replace("_request", "").replace("_resource", "").replace("_endpoint", "")}=${item.endpoint_count || 0}`)
      .join(" ");
    return [
      "Gate pending",
      "waiting for business API",
      firstPattern,
      rejected ? `rejected ${rejected}` : ""
    ].filter(Boolean).join(" · ");
  }

  return {
    buildRealtimeCaptureGate,
    formatRealtimeCaptureGate
  };
});

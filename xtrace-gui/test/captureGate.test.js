const assert = require("node:assert/strict");
const test = require("node:test");
const {
  buildRealtimeCaptureGate,
  formatRealtimeCaptureGate
} = require("../src/renderer/captureGate");

test("buildRealtimeCaptureGate stays pending for document static and telemetry traffic", () => {
  const gate = buildRealtimeCaptureGate([
    {
      category: "network",
      api: "BrowserNetwork.request",
      args: [{method: "GET", url: "https://www.example.test/", request_destination: "document"}]
    },
    {
      category: "network",
      api: "BrowserNetwork.request",
      args: [{method: "GET", url: "https://cdn.example.test/runtime-sdk.js", request_destination: "script"}]
    },
    {
      category: "network",
      api: "XMLHttpRequest.send",
      args: [{method: "POST", url: "https://telemetry.example.test/monitor_browser/collect?batch=1"}]
    }
  ], {startUrl: "https://www.example.test/"});

  assert.deepEqual(gate, {
    id: "business_api_anchor",
    status: "pending",
    observed_actionable_endpoint_count: 0,
    matched_endpoints: [],
    missing: ["business_api_anchor_not_captured"],
    rejected_endpoint_summary: [
      {
        resource_class: "document_request",
        endpoint_count: 1,
        event_count: 1,
        examples: ["https://www.example.test/"]
      },
      {
        resource_class: "static_resource",
        endpoint_count: 1,
        event_count: 1,
        examples: ["https://cdn.example.test/runtime-sdk.js"]
      },
      {
        resource_class: "telemetry_endpoint",
        endpoint_count: 1,
        event_count: 1,
        examples: ["https://telemetry.example.test/monitor_browser/collect"]
      }
    ],
    target_endpoint_patterns: [
      "https://www.example.test/api/*",
      "fetch/XMLHttpRequest non-static endpoint"
    ],
    reject_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"],
    tail_filters: {
      categories: ["network"],
      apis: [
        "BrowserNetwork.request",
        "Request.constructor",
        "fetch",
        "XMLHttpRequest.open",
        "XMLHttpRequest.send"
      ],
      exclude_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"]
    }
  });
  assert.equal(
    formatRealtimeCaptureGate(gate),
    "Gate pending · waiting for business API · https://www.example.test/api/* · rejected document=1 static=1 telemetry=1"
  );
});

test("buildRealtimeCaptureGate passes when tail sees an actionable browser API request", () => {
  const gate = buildRealtimeCaptureGate([
    {
      category: "network",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/feed/list?cursor=1"}]
    },
    {
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://www.example.test/api/feed/list?cursor=1",
        is_fetch_like_api: true
      }]
    }
  ], {startUrl: "https://www.example.test/"});

  assert.deepEqual(gate, {
    id: "business_api_anchor",
    status: "passed",
    observed_actionable_endpoint_count: 1,
    matched_endpoints: ["https://www.example.test/api/feed/list"],
    missing: [],
    rejected_endpoint_summary: [],
    target_endpoint_patterns: ["https://www.example.test/api/feed/list"],
    reject_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"],
    tail_filters: {
      categories: ["network"],
      apis: [
        "BrowserNetwork.request",
        "Request.constructor",
        "fetch",
        "XMLHttpRequest.open",
        "XMLHttpRequest.send"
      ],
      exclude_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"]
    }
  });
  assert.equal(
    formatRealtimeCaptureGate(gate),
    "Gate passed · 1 endpoint · https://www.example.test/api/feed/list"
  );
});

test("buildRealtimeCaptureGate keeps probe privacy and generic resource endpoints pending", () => {
  const gate = buildRealtimeCaptureGate([
    {
      category: "network",
      api: "BrowserNetwork.request",
      args: [{method: "GET", url: "https://www.example.test/cdn-sw-probe"}]
    },
    {
      category: "network",
      api: "BrowserNetwork.request",
      args: [{method: "GET", url: "https://www.example.test/pns/privacy_headers"}]
    },
    {
      category: "network",
      api: "BrowserNetwork.request",
      args: [{method: "GET", url: "https://static.example.test/web/resource"}]
    }
  ], {startUrl: "https://www.example.test/"});

  assert.equal(gate.status, "pending");
  assert.equal(gate.observed_actionable_endpoint_count, 0);
  assert.deepEqual(gate.matched_endpoints, []);
  assert.deepEqual(gate.missing, ["business_api_anchor_not_captured"]);
  assert.deepEqual(gate.rejected_endpoint_summary, [
    {
      resource_class: "static_resource",
      endpoint_count: 1,
      event_count: 1,
      examples: ["https://static.example.test/web/resource"]
    },
    {
      resource_class: "telemetry_endpoint",
      endpoint_count: 2,
      event_count: 2,
      examples: [
        "https://www.example.test/cdn-sw-probe",
        "https://www.example.test/pns/privacy_headers"
      ]
    }
  ]);
  assert.deepEqual(gate.target_endpoint_patterns, [
    "https://www.example.test/api/*",
    "fetch/XMLHttpRequest non-static endpoint"
  ]);
  assert.equal(
    formatRealtimeCaptureGate(gate),
    "Gate pending · waiting for business API · https://www.example.test/api/* · rejected static=1 telemetry=2"
  );
});

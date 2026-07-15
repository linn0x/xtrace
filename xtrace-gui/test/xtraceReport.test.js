const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  analyzeJavaScriptSource,
  reportDirectoryForTrace,
  buildLocalReport,
  buildReportForTrace,
  renderMarkdownReport,
  buildAgentInputPack,
  buildAgentAnalysis,
  renderAgentInputPackMarkdown,
  renderAgentAnalysisMarkdown,
  readTraceEvents,
  readTargetedTraceEvents,
  writeLocalReport,
  generateReportForTrace,
  __testHooks
} = require("../src/main/xtraceReport");

// Recipe defaults resolve relative to the repo root, same as the source module.
const REPO_ROOT = path.resolve(__dirname, "..", "..");
const EXPECTED_CHROMIUM_APP = path.join(REPO_ROOT, "chromium", "src", "out", "XTrace", "Chromium.app");
const EXPECTED_LOG_DIR = path.join(REPO_ROOT, "logs");

test("analyzeJavaScriptSource flags common obfuscation and anti-debug signals", () => {
  const source = `
    var _0xabc = ["\\x68\\x69", "\\u0064\\u0065\\u0062\\u0075\\u0067"];
    while (!![]) { switch (_0xabc[0x1]) { case "debug": debugger; break; default: break; } break; }
    window[_0xabc[0]] = Function("return eval")();
  `;

  const analysis = analyzeJavaScriptSource(source);

  assert.ok(analysis.score >= 5);
  assert.ok(analysis.signals.includes("hex_or_unicode_escape_density"));
  assert.ok(analysis.signals.includes("bracket_property_access"));
  assert.ok(analysis.signals.includes("control_flow_flattening"));
  assert.ok(analysis.signals.includes("anti_debug"));
});

test("analyzeJavaScriptSource flags VMP interpreter signals", () => {
  const source = `
    const bytecode = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33];
    const handlers = [
      function(vm) { vm.reg[bytecode[vm.pc++]] = String.fromCharCode(bytecode[vm.pc++]); },
      function(vm) { return handlers[bytecode[vm.pc++]].call(null, vm); }
    ];
    function run() {
      const vm = {pc: 0, reg: []};
      while (vm.pc < bytecode.length) {
        switch (bytecode[vm.pc++]) { case 1: handlers[0](vm); break; default: Reflect.apply(handlers[1], null, [vm]); }
      }
    }
  `;

  const analysis = analyzeJavaScriptSource(source);

  assert.ok(analysis.score >= 6);
  assert.ok(analysis.signals.includes("vmp_bytecode_array"));
  assert.ok(analysis.signals.includes("vmp_handler_table"));
  assert.ok(analysis.signals.includes("vmp_dispatch_loop"));
  assert.ok(analysis.signals.includes("vmp_dynamic_dispatch"));
  assert.ok(analysis.signals.includes("vmp_string_decode_refs"));
});

test("analyzeJavaScriptSource flags minified VMP bytecode cursor helpers", () => {
  const source = `
    var H=[
      function(n){var t=I(n),r=I(n),i=I(n),o=C(n);D(n,r,M(n,i)+M(n,t));n.A=o},
      function(n){var t=I(n),r=I(n);D(n,I(n),M(n,r)[M(n,t)])},
      function(n){var t=I(n),r=C(n);D(n,I(n),-M(n,t));n.A=r}
    ];
    while(n.A < Z.length){ H[Z[n.A++]](n) }
  `;

  const analysis = analyzeJavaScriptSource(source);

  assert.ok(analysis.signals.includes("vmp_handler_table"));
  assert.ok(analysis.signals.includes("vmp_bytecode_cursor"));
  assert.ok(analysis.signals.includes("vmp_dispatch_loop"));
});

test("analyzeJavaScriptSource flags compact VMP handler access windows", () => {
  const source = `
    for (; offset + 4 <= bytes.byteLength; offset += 4) {
      vm.offset = offset;
      const word = Reflect.apply(handlers[0], null, [vm]);
      Function.prototype.call.call(handlers[1], null, vm, word);
      Function.prototype.apply.call(function applyProbe(state, value) {
        return handlers[state.opcode & 3](state, value);
      }, null, [vm, word]);
      vm.reg[vm.pc++] = word ^ vm.reg[state.idx++];
    }
  `;

  const analysis = analyzeJavaScriptSource(source);

  assert.ok(analysis.score >= 5);
  assert.ok(analysis.signals.includes("vmp_handler_table"));
  assert.ok(analysis.signals.includes("vmp_dispatch_loop"));
  assert.ok(analysis.signals.includes("vmp_dynamic_dispatch"));
  assert.ok(analysis.signals.includes("vmp_register_state"));
});

test("buildLocalReport summarizes events, fingerprints, and asset findings", () => {
  const assets = [
    {
      asset_id: "sha1:dynamic",
      kind: "dynamic-code",
      content: "eval(\"navigator.webdriver\"); debugger;",
      sha1: "sha1:dynamic",
      size: 38,
      truncated: false,
      first_seq: 2
    }
  ];
  const events = [
    {category: "reverse", api: "eval", asset_id: "sha1:dynamic"},
    {category: "fingerprint", api: "Navigator.webdriver"},
    {category: "fingerprint", api: "CanvasRenderingContext2D.getImageData"}
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_demo.ndjson", events, assets});

  assert.equal(report.trace.event_count, 3);
  assert.equal(report.reverse.dynamic_execution_count, 1);
  assert.deepEqual(report.fingerprint.apis.sort(), [
    "CanvasRenderingContext2D.getImageData",
    "Navigator.webdriver"
  ]);
  assert.equal(report.assets.length, 1);
  assert.equal(report.assets[0].asset_id, "sha1:dynamic");
  assert.ok(report.assets[0].signals.includes("anti_debug"));
});

test("buildLocalReport summarizes VMP runtime events and assets", () => {
  const assets = [
    {
      asset_id: "sha1:vmp",
      kind: "script",
      content: `
        const p = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33];
        const A = [function(n){ return String.fromCharCode(p[n.i++]); }, function(n){ return A[p[n.i++]].apply(null, [n]); }];
        while (n.i < p.length) { switch (p[n.i++]) { case 1: A[0](n); break; } }
      `,
      sha1: "sha1:vmp",
      size: 300,
      truncated: false,
      first_seq: 10
    }
  ];
  const events = [
    {seq: 1, category: "reverse", api: "ArrayBuffer.constructor", args: [{byte_length: 16}]},
    {seq: 2, category: "reverse", api: "DataView.getUint8", args: [{byte_offset: 1, little_endian: null, result: 18}]},
    {seq: 3, category: "reverse", api: "DataView.getUint16", args: [{byte_offset: 2, little_endian: true, result: 4660}]},
    {seq: 4, category: "reverse", api: "DataView.getUint32", args: [{byte_offset: 4, little_endian: true, result: 305419896}]},
    {seq: 5, category: "reverse", api: "DataView.getInt32", args: [{byte_offset: 4, little_endian: true, result: -1234}]},
    {seq: 6, category: "reverse", api: "DataView.setUint8", args: [{byte_offset: 1, value: 18, little_endian: null}]},
    {seq: 7, category: "reverse", api: "DataView.setUint16", args: [{byte_offset: 2, value: 4660, little_endian: true}]},
    {seq: 8, category: "reverse", api: "DataView.setUint32", args: [{byte_offset: 4, value: 305419896, little_endian: true}]},
    {seq: 9, category: "reverse", api: "DataView.setInt32", args: [{byte_offset: 4, value: -1234, little_endian: true}]},
    {seq: 10, category: "reverse", api: "Math.imul", args: [{x: 120, y: 2654435761, result: -392329960}]},
    {seq: 11, category: "reverse", api: "String.prototype.charCodeAt", args: [{position: 0, result: 120}]},
    {seq: 12, category: "reverse", api: "String.fromCharCode", args: [{argc: 3, first_code: 88, result_preview: "Xtr"}]},
    {seq: 13, category: "reverse", api: "String.fromCodePoint", args: [{argc: 1, first_code: 9731, result_preview: "codepoint"}]},
    {seq: 14, category: "reverse", api: "Number.prototype.toString", args: [{number: 57582, radix: 16, result_preview: "e0ee", result_ref: "string:length:4"}]},
    {seq: 15, category: "reverse", api: "BigInt.prototype.toString", args: [{shape: "bigint_to_string", radix: 16, result_preview: "1234", result_ref: "string:length:4"}]},
    {category: "reverse", api: "SubtleCrypto.digest"},
    {category: "reverse", api: "atob"},
    {category: "reverse", api: "TextDecoder.decode"},
    {category: "reverse", api: "TextEncoder.encode"}
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp.ndjson", events, assets});

  assert.equal(report.vmp.runtime_event_count, 19);
  assert.deepEqual(report.vmp.apis, [
    {api: "ArrayBuffer.constructor", count: 1},
    {api: "atob", count: 1},
    {api: "BigInt.prototype.toString", count: 1},
    {api: "DataView.getInt32", count: 1},
    {api: "DataView.getUint16", count: 1},
    {api: "DataView.getUint32", count: 1},
    {api: "DataView.getUint8", count: 1},
    {api: "DataView.setInt32", count: 1},
    {api: "DataView.setUint16", count: 1},
    {api: "DataView.setUint32", count: 1},
    {api: "DataView.setUint8", count: 1},
    {api: "Math.imul", count: 1},
    {api: "Number.prototype.toString", count: 1},
    {api: "String.fromCharCode", count: 1},
    {api: "String.fromCodePoint", count: 1},
    {api: "String.prototype.charCodeAt", count: 1},
    {api: "SubtleCrypto.digest", count: 1},
    {api: "TextDecoder.decode", count: 1},
    {api: "TextEncoder.encode", count: 1},
  ]);
  assert.deepEqual(report.vmp.samples["DataView.getUint32"], [
    {seq: 4, args: [{byte_offset: 4, little_endian: true, result: 305419896}]}
  ]);
  assert.deepEqual(report.vmp.samples["Math.imul"], [
    {seq: 10, args: [{x: 120, y: 2654435761, result: -392329960}]}
  ]);
  assert.deepEqual(report.vmp.samples["Number.prototype.toString"], [
    {seq: 14, args: [{number: 57582, radix: 16, result_preview: "e0ee", result_ref: "string:length:4"}]}
  ]);
  assert.deepEqual(report.vmp.samples["BigInt.prototype.toString"], [
    {seq: 15, args: [{shape: "bigint_to_string", radix: 16, result_preview: "1234", result_ref: "string:length:4"}]}
  ]);
  assert.deepEqual(report.vmp.samples["String.fromCharCode"], [
    {seq: 12, args: [{argc: 3, first_code: 88, result_preview: "Xtr"}]}
  ]);
  assert.equal(report.vmp.assets.length, 1);
  assert.ok(report.vmp.assets[0].signals.includes("vmp_bytecode_array"));
  assert.match(renderMarkdownReport(report), /VMP Signals/);
});

test("buildLocalReport creates VMP hook analysis points and hotspots", () => {
  const assetUrl = "https://cdn.example.test/vmp.js";
  const stack = [{function: "runVm", url: assetUrl, line: 42, column: 9}];
  const events = [
    {seq: 100, category: "reverse", api: "String.fromCharCode", args: [{argc: 1, first_code: 88, result_preview: "X"}], stack},
    {seq: 101, category: "reverse", api: "String.prototype.charCodeAt", args: [{position: 0, result: 88}], stack},
    {seq: 102, category: "reverse", api: "DataView.getUint32", args: [{byte_offset: 12, little_endian: true, result: 305419896}], stack},
    {seq: 103, category: "reverse", api: "Math.imul", args: [{x: 305419896, y: 2654435761, result: -391880660}], stack},
    {seq: 104, category: "reverse", api: "TextEncoder.encode", args: [{input_length: 18}], stack},
    {seq: 105, category: "reverse", api: "SubtleCrypto.digest", args: [{algorithm: "SHA-256"}], stack}
  ];
  const assets = [
    {
      asset_id: "sha1:vmp-runtime",
      kind: "script",
      url: assetUrl,
      content_path: "assets/trace_demo/vmp.js",
      content: `
        const p=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30];
        const A=[function(vm){return String.fromCharCode(p[vm.i++]);},function(vm){return A[p[vm.i++]].apply(null,[vm]);}];
        while(vm.i<p.length){switch(p[vm.i++]){case 1:A[0](vm);break;}}
      `
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp_points.ndjson", events, assets});

  assert.deepEqual(report.vmp.families, [
    {family: "string_decode", count: 2},
    {family: "byte_buffer", count: 1},
    {family: "hash_crypto", count: 1},
    {family: "int_arithmetic", count: 1},
    {family: "text_codec", count: 1}
  ]);
  assert.deepEqual(report.vmp.hotspots.map((hotspot) => ({
    stack_url: hotspot.stack_url,
    asset_id: hotspot.asset_id,
    count: hotspot.count,
    families: hotspot.families
  })), [{
    stack_url: assetUrl,
    asset_id: "sha1:vmp-runtime",
    count: 6,
    families: ["byte_buffer", "hash_crypto", "int_arithmetic", "string_decode", "text_codec"]
  }]);
  assert.deepEqual(report.vmp.analysis_points.map((point) => point.type), [
    "vmp_string_decoder",
    "vmp_bytecode_or_register_access",
    "vmp_hash_or_signature_pipeline",
    "vmp_runtime_cluster",
    "vmp_obfuscated_asset"
  ]);
  assert.equal(report.vmp.analysis_points[0].seq_start, 100);
  assert.equal(report.vmp.analysis_points[0].seq_end, 101);
  assert.match(renderMarkdownReport(report), /VMP Analysis Points/);
  assert.match(renderMarkdownReport(report), /vmp_hash_or_signature_pipeline/);
});

test("buildLocalReport emits VMP execution profiles with hook analysis points", () => {
  const assetUrl = "https://cdn.example.test/vmp-profile.js";
  const runStack = [{function: "runVm", url: assetUrl, line: 42, column: 9}];
  const helperStack = [{function: "helperVm", url: assetUrl, line: 88, column: 3}];
  const events = [
    {seq: 10, category: "reverse", api: "DataView.getUint8", args: [{byte_offset: 0, result: 31}], stack: runStack},
    {seq: 11, category: "reverse", api: "Bitwise.xor", args: [{left: 31, right: 7, result: 24}], stack: runStack},
    {seq: 12, category: "reverse", api: "Shift.unsignedRight", args: [{left: -1, right: 8, result: 16777215}], stack: runStack},
    {seq: 13, category: "reverse", api: "Reflect.apply", args: [{argc: 2}], stack: runStack},
    {seq: 14, category: "reverse", api: "Proxy.get", args: [{key: "opcode", result: 1}], stack: runStack},
    {seq: 15, category: "reverse", api: "String.fromCharCode", args: [{argc: 1, first_code: 88, result_preview: "X"}], stack: runStack},
    {seq: 16, category: "reverse", api: "TextEncoder.encode", args: [{input_length: 32}], stack: runStack},
    {seq: 17, category: "reverse", api: "SubtleCrypto.digest", args: [{algorithm: "SHA-256"}], stack: runStack},
    {seq: 30, category: "reverse", api: "DataView.getUint8", args: [{byte_offset: 1, result: 9}], stack: helperStack}
  ];
  const assets = [{
    asset_id: "sha1:vmp-profile",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/vmp-profile.js",
    content: "function runVm(vm){ return vm; }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp_profile.ndjson", events, assets});

  assert.deepEqual(report.vmp.execution_profiles.map((profile) => ({
    function: profile.function,
    stack_url: profile.stack_url,
    asset_id: profile.asset_id,
    confidence: profile.confidence,
    event_count: profile.event_count,
    seq_start: profile.seq_start,
    seq_end: profile.seq_end,
    families: profile.families,
    hook_points: profile.hook_points.map((point) => ({
      type: point.type,
      event_count: point.event_count,
      families: point.families,
      apis: point.apis
    }))
  })), [
    {
      function: "runVm",
      stack_url: assetUrl,
      asset_id: "sha1:vmp-profile",
      confidence: "high",
      event_count: 8,
      seq_start: 10,
      seq_end: 17,
      families: [
        "byte_buffer",
        "dynamic_dispatch",
        "hash_crypto",
        "int_bitwise",
        "proxy_trap",
        "string_decode",
        "text_codec"
      ],
      hook_points: [
        {
          type: "bytecode_or_register_access",
          event_count: 1,
          families: ["byte_buffer"],
          apis: [{api: "DataView.getUint8", count: 1}]
        },
        {
          type: "integer_mixing",
          event_count: 2,
          families: ["int_bitwise"],
          apis: [
            {api: "Bitwise.xor", count: 1},
            {api: "Shift.unsignedRight", count: 1}
          ]
        },
        {
          type: "handler_dispatch",
          event_count: 2,
          families: ["dynamic_dispatch", "proxy_trap"],
          apis: [
            {api: "Proxy.get", count: 1},
            {api: "Reflect.apply", count: 1}
          ]
        },
        {
          type: "string_material",
          event_count: 2,
          families: ["string_decode", "text_codec"],
          apis: [
            {api: "String.fromCharCode", count: 1},
            {api: "TextEncoder.encode", count: 1}
          ]
        },
        {
          type: "hash_material",
          event_count: 1,
          families: ["hash_crypto"],
          apis: [{api: "SubtleCrypto.digest", count: 1}]
        }
      ]
    },
    {
      function: "helperVm",
      stack_url: assetUrl,
      asset_id: "sha1:vmp-profile",
      confidence: "low",
      event_count: 1,
      seq_start: 30,
      seq_end: 30,
      families: ["byte_buffer"],
      hook_points: [{
        type: "bytecode_or_register_access",
        event_count: 1,
        families: ["byte_buffer"],
        apis: [{api: "DataView.getUint8", count: 1}]
      }]
    }
  ]);
  assert.match(renderMarkdownReport(report), /VMP Execution Profiles/);
  assert.match(renderMarkdownReport(report), /runVm@https:\/\/cdn\.example\.test\/vmp-profile\.js confidence=high events=8/);
  assert.match(renderMarkdownReport(report), /hooks=bytecode_or_register_access,integer_mixing,handler_dispatch,string_material,hash_material/);
});

test("buildLocalReport groups deeper VMP table, dispatch, typed array, and bitwise hooks", () => {
  const assetUrl = "https://cdn.example.test/vmp-deep.js";
  const stack = [{function: "vmDispatch", url: assetUrl, line: 7, column: 3}];
  const events = [
    {seq: 200, category: "reverse", api: "URL.constructor", args: [{url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 201, category: "reverse", api: "TypedArray.at", args: [{kind: "Uint8Array", index: 4, result: 99}], stack},
    {seq: 202, category: "reverse", api: "TypedArray.slice", args: [{kind: "Uint8Array", start: 0, end: 8, result_length: 8}], stack},
    {seq: 203, category: "reverse", api: "Array.prototype.push", args: [{argc: 1, length_before: 4, length_after: 5}], stack},
    {seq: 204, category: "reverse", api: "Array.prototype.join", args: [{length: 5, separator_length: 1, result_length: 18}], stack},
    {
      seq: 205,
      category: "reverse",
      api: "Reflect.apply",
      args: [{
        target_function: "readWord",
        target_type: "function",
        this_type: "null",
        arg_count: 1,
        arguments_list_type: "array",
        subject_id: 41,
        target_id: 42,
        this_id: null,
        arguments_list_id: 43
      }],
      stack
    },
    {seq: 206, category: "reverse", api: "Function.prototype.call", args: [{argc: 2}], stack},
    {seq: 207, category: "reverse", api: "Function.prototype.apply", args: [{argc: 2, has_arguments_list: true}], stack},
    {seq: 208, category: "reverse", api: "Function.prototype.call.call", args: [{argc: 3}], stack},
    {seq: 209, category: "reverse", api: "Function.prototype.apply.call", args: [{argc: 3, has_arguments_list: true}], stack},
    {seq: 210, category: "reverse", api: "Object.keys", args: [{result_length: 12}], stack},
    {seq: 211, category: "reverse", api: "Object.getOwnPropertyNames", args: [{result_length: 12}], stack},
    {seq: 212, category: "reverse", api: "Reflect.ownKeys", args: [{result_length: 13}], stack},
    {seq: 213, category: "reverse", api: "Reflect.getOwnPropertyDescriptor", args: [{key: "xor", result_present: true}], stack},
    {seq: 214, category: "reverse", api: "Reflect.get", args: [{key: "xor", result: null}], stack},
    {seq: 215, category: "reverse", api: "Reflect.has", args: [{key: "xor", result: true}], stack},
    {seq: 216, category: "reverse", api: "Map.prototype.set", args: [{key: "xor", value: 3}], stack},
    {seq: 217, category: "reverse", api: "Map.prototype.get", args: [{key: "xor", result: 3}], stack},
    {seq: 218, category: "reverse", api: "Map.prototype.has", args: [{key: "xor", result: true}], stack},
    {seq: 219, category: "reverse", api: "Map.prototype.delete", args: [{key: "old", result: false}], stack},
    {seq: 220, category: "reverse", api: "Set.prototype.add", args: [{key: "xor", result: true}], stack},
    {seq: 221, category: "reverse", api: "Set.prototype.has", args: [{key: "xor", result: true}], stack},
    {seq: 222, category: "reverse", api: "Set.prototype.delete", args: [{key: "old", result: false}], stack},
    {seq: 223, category: "reverse", api: "Proxy.get", args: [{key: "handler", result: null}], stack},
    {seq: 224, category: "reverse", api: "Proxy.set", args: [{key: "pc", value: 12, result: true}], stack},
    {seq: 225, category: "reverse", api: "Proxy.has", args: [{key: "opcode", result: true}], stack},
    {seq: 226, category: "reverse", api: "Proxy.ownKeys", args: [{result_length: 4}], stack},
    {seq: 227, category: "reverse", api: "Proxy.getOwnPropertyDescriptor", args: [{key: "opcode", result_present: true}], stack},
    {seq: 228, category: "reverse", api: "Proxy.defineProperty", args: [{key: "scratch", result: true}], stack},
    {seq: 229, category: "reverse", api: "Proxy.deleteProperty", args: [{key: "scratch", result: true}], stack},
    {seq: 230, category: "reverse", api: "Bitwise.and", args: [{left: 4660, right: 22136, result: 4112}], stack},
    {seq: 231, category: "reverse", api: "Bitwise.or", args: [{left: 4660, right: 22136, result: 26796}], stack},
    {seq: 232, category: "reverse", api: "Bitwise.xor", args: [{left: 4660, right: 22136, result: 22684}], stack},
    {seq: 233, category: "reverse", api: "Bitwise.not", args: [{value: 22136, result: -22137}], stack},
    {seq: 234, category: "reverse", api: "Shift.left", args: [{left: 4660, right: 2, result: 18640}], stack},
    {seq: 235, category: "reverse", api: "Shift.right", args: [{left: -1024, right: 3, result: -128}], stack},
    {seq: 236, category: "reverse", api: "Shift.unsignedRight", args: [{left: -1, right: 8, result: 16777215}], stack},
    {
      seq: 237,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&X-Signature=secret-signature&X-Secondary-Signature=secret-secondary-signature"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_deep_vmp.ndjson", events, assets: []});
  const [flow] = report.signature.agent_brief.flows;

  assert.deepEqual(report.vmp.families, [
    {family: "dynamic_dispatch", count: 11},
    {family: "collection_table", count: 7},
    {family: "int_bitwise", count: 7},
    {family: "proxy_trap", count: 7},
    {family: "array_table", count: 2},
    {family: "typed_array", count: 2}
  ]);
  assert.equal(report.vmp.apis.find((item) => item.api === "Function.prototype.call.call").count, 1);
  assert.equal(report.vmp.apis.find((item) => item.api === "Function.prototype.apply.call").count, 1);
  assert.deepEqual(
    Object.fromEntries(report.vmp.apis.filter((item) => item.api.startsWith("Bitwise.") || item.api.startsWith("Shift.")).map((item) => [item.api, item.count])),
    {
      "Bitwise.and": 1,
      "Bitwise.not": 1,
      "Bitwise.or": 1,
      "Bitwise.xor": 1,
      "Shift.left": 1,
      "Shift.right": 1,
      "Shift.unsignedRight": 1
    }
  );
  assert.deepEqual(report.vmp.samples["Bitwise.not"], [
    {seq: 233, args: [{value: 22136, result: -22137}]}
  ]);
  assert.deepEqual(report.vmp.samples["Map.prototype.get"], [
    {seq: 217, args: [{key: "xor", result: 3}]}
  ]);
  assert.deepEqual(report.vmp.samples["Proxy.has"], [
    {seq: 225, args: [{key: "opcode", result: true}]}
  ]);
  assert.deepEqual(report.vmp.samples["Proxy.ownKeys"], [
    {seq: 226, args: [{result_length: 4}]}
  ]);
  assert.deepEqual(report.vmp.analysis_points.map((point) => point.type), [
    "vmp_bytecode_or_register_access",
    "vmp_array_table",
    "vmp_dynamic_dispatch",
    "vmp_collection_table",
    "vmp_proxy_trap",
    "vmp_int_bitwise_pipeline",
    "vmp_runtime_cluster"
  ]);
  const dispatchPoint = report.vmp.analysis_points.find((point) => point.type === "vmp_dynamic_dispatch");
  assert.deepEqual(dispatchPoint.sample_events[0].dispatch, {
    target_function: "readWord",
    target_type: "function",
    this_type: "null",
    arg_count: 1,
    arguments_list_type: "array",
    subject_id: 41,
    target_id: 42,
    this_id: null,
    arguments_list_id: 43
  });
  assert.deepEqual(flow.phases.map((phase) => phase.phase), [
    "unsigned_url",
    "vmp_bytecode_or_register_access",
    "vmp_array_table",
    "vmp_dynamic_dispatch",
    "vmp_collection_table",
    "vmp_proxy_trap",
    "vmp_int_bitwise_pipeline",
    "signed_request"
  ]);
  assert.deepEqual(flow.vmp_analysis_points.map((point) => point.type), [
    "vmp_bytecode_or_register_access",
    "vmp_array_table",
    "vmp_dynamic_dispatch",
    "vmp_collection_table",
    "vmp_proxy_trap",
    "vmp_int_bitwise_pipeline",
    "vmp_runtime_cluster"
  ]);
  assert.match(renderMarkdownReport(report), /vmp_int_bitwise_pipeline/);
});

test("buildLocalReport handles large VMP hook sets without stack overflow", () => {
  const events = Array.from({length: 150000}, (_, index) => ({
    seq: index + 1,
    category: "reverse",
    api: "String.prototype.charCodeAt",
    args: [{position: 0, result: 88}],
    stack: [{function: "vm", url: "https://cdn.example.test/vmp.js", line: 1, column: 1}]
  }));

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_large_vmp.ndjson", events, assets: []});

  assert.equal(report.vmp.runtime_event_count, 150000);
  assert.equal(report.vmp.analysis_points[0].seq_start, 1);
  assert.equal(report.vmp.analysis_points[0].seq_end, 150000);
});

test("buildLocalReport preserves raw signature flow token values", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const events = [
    {
      seq: 10,
      category: "reverse",
      api: "URL.constructor",
      args: [{url: "https://www.example.test/api/list?count=6"}],
      stack: [{function: "A", url: assetUrl, line: 1, column: 100}]
    },
    {
      seq: 11,
      category: "reverse",
      api: "Request.constructor",
      args: [{
        url: "https://www.example.test/api/list?count=6&X-Signature=secret-signature&X-Secondary-Signature=secret-secondary-signature"
      }],
      stack: [{function: "signRequest", url: assetUrl, line: 1, column: 120}]
    }
  ];
  const assets = [
    {
      asset_id: "sha1:runtime-sdk",
      kind: "script",
      url: assetUrl,
      content_path: "assets/trace_demo/sha1_runtime-sdk.js",
      content: `
        const p=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27];
        const A=[function(n){return String.fromCharCode(p[n.i++]);},function(n){return A[p[n.i++]].apply(null,[n]);}];
        while(n.i<p.length){switch(p[n.i++]){case 1:A[0](n);break;}}
      `
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_signature.ndjson", events, assets});

  assert.equal(report.signature.event_count, 1);
  assert.deepEqual(report.signature.terms, ["X-Signature", "X-Secondary-Signature"]);
  assert.deepEqual(report.signature.api_counts, [{api: "Request.constructor", count: 1}]);
  assert.equal(report.signature.first_events[0].seq, 11);
  assert.equal(report.signature.first_events[0].previous_event.seq, 10);
  assert.deepEqual(report.signature.first_events[0].context.previous.map((event) => event.seq), [10]);
  assert.deepEqual(report.signature.first_events[0].context.next, []);
  assert.equal(report.signature.first_events[0].stack[0].asset_id, "sha1:runtime-sdk");
  assert.equal(report.signature.involved_assets[0].asset_id, "sha1:runtime-sdk");
  assert.ok(report.signature.involved_assets[0].signals.includes("vmp_bytecode_array"));
  assert.match(JSON.stringify(report.signature), /secret-signature/);
  assert.match(JSON.stringify(report.signature), /secret-secondary-signature/);
  assert.doesNotMatch(JSON.stringify(report.signature), /<redacted>/);
  assert.match(renderMarkdownReport(report), /Signature Flow/);
});

test("buildLocalReport identifies signature parameter transitions and preceding VMP hooks", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const events = [
    {
      seq: 10,
      category: "reverse",
      api: "URL.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&device_id=abc"}],
      stack: [{function: "buildUrl", url: assetUrl, line: 10, column: 4}]
    },
    {
      seq: 11,
      category: "reverse",
      api: "String.fromCharCode",
      args: [{argc: 6, first_code: 88, result_preview: "X-Signature"}],
      stack: [{function: "decodeName", url: assetUrl, line: 18, column: 6}]
    },
    {
      seq: 12,
      category: "reverse",
      api: "URLSearchParams.set",
      args: [{name: "X-Signature", value: "secret-signature"}],
      stack: [{function: "appendSignature", url: assetUrl, line: 19, column: 6}]
    },
    {
      seq: 13,
      category: "reverse",
      api: "URLSearchParams.sort",
      args: [{before_serialized: "device_id=abc&count=6&X-Signature=secret-signature", serialized: "X-Signature=secret-signature&count=6&device_id=abc"}],
      stack: [{function: "canonicalize", url: assetUrl, line: 20, column: 8}]
    },
    {
      seq: 14,
      category: "reverse",
      api: "URLSearchParams.toString",
      args: [{serialized: "X-Signature=secret-signature&count=6&device_id=abc"}],
      stack: [{function: "canonicalize", url: assetUrl, line: 21, column: 8}]
    },
    {
      seq: 15,
      category: "reverse",
      api: "URL.href.get",
      args: [{href: "https://www.example.test/api/list?count=6&device_id=abc&X-Signature=secret-signature"}],
      stack: [{function: "canonicalize", url: assetUrl, line: 22, column: 8}]
    },
    {
      seq: 16,
      category: "reverse",
      api: "TextEncoder.encode",
      args: [{input_preview: "count=6&device_id=abc"}],
      stack: [{function: "encodePayload", url: assetUrl, line: 23, column: 8}]
    },
    {
      seq: 17,
      category: "reverse",
      api: "Request.constructor",
      args: [{
        url: "https://www.example.test/api/list?count=6&device_id=abc&sessionToken=secret-token&X-Signature=secret-signature&X-Secondary-Signature=secret-secondary-signature"
      }],
      stack: [{function: "signRequest", url: assetUrl, line: 30, column: 12}]
    }
  ];
  const assets = [
    {
      asset_id: "sha1:runtime-sdk",
      kind: "script",
      url: assetUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: `
        const p=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27];
        const A=[function(n){return String.fromCharCode(p[n.i++]);},function(n){return A[p[n.i++]].apply(null,[n]);}];
        while(n.i<p.length){switch(p[n.i++]){case 1:A[0](n);break;}}
      `
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_signature.ndjson", events, assets});
  const [flow] = report.signature.flows;

  assert.equal(flow.unsigned_event.seq, 10);
  assert.equal(flow.signed_event.seq, 17);
  assert.equal(flow.endpoint, "https://www.example.test/api/list");
  assert.deepEqual(flow.unchanged_params, ["count", "device_id"]);
  assert.deepEqual(flow.added_params.map((item) => item.name), ["X-Signature", "X-Secondary-Signature", "sessionToken"]);
  assert.deepEqual(flow.preceding_vmp_events.map((event) => event.seq), [11, 13, 14, 16]);
  assert.equal(flow.preceding_vmp_events[0].stack[0].asset_id, "sha1:runtime-sdk");
  assert.deepEqual(flow.timeline.map((event) => `${event.role}:${event.api}@${event.seq}`), [
    "unsigned_url:URL.constructor@10",
    "vmp:String.fromCharCode@11",
    "url_mutation:URLSearchParams.set@12",
    "vmp:URLSearchParams.sort@13",
    "vmp:URLSearchParams.toString@14",
    "url_mutation:URL.href.get@15",
    "vmp:TextEncoder.encode@16",
    "signed_request:Request.constructor@17"
  ]);
  assert.equal(flow.timeline[2].args[0].value, "secret-signature");
  assert.equal(flow.assets[0].asset_id, "sha1:runtime-sdk");
  assert.match(JSON.stringify(flow), /secret-token/);
  assert.match(JSON.stringify(flow), /secret-signature/);
  assert.match(JSON.stringify(flow), /secret-secondary-signature/);
  assert.doesNotMatch(JSON.stringify(flow), /<redacted>/);
  assert.match(renderMarkdownReport(report), /Signature Transitions/);
  assert.match(renderMarkdownReport(report), /timeline=unsigned_url:URL\.constructor@10,vmp:String\.fromCharCode@11,url_mutation:URLSearchParams\.set@12,vmp:URLSearchParams\.sort@13,vmp:URLSearchParams\.toString@14,url_mutation:URL\.href\.get@15/);
});

test("buildLocalReport matches distant unsigned URL candidates", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const events = [
    {
      seq: 100,
      category: "reverse",
      api: "URL.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&device_id=abc&app_id=1000"}],
      stack: [{function: "buildUnsignedUrl", url: assetUrl, line: 10, column: 4}]
    }
  ];
  for (let i = 0; i < 300; i += 1) {
    events.push({
      seq: 101 + i,
      category: "reverse",
      api: "String.prototype.charCodeAt",
      args: [{position: 0, result: 88}],
      stack: [{function: "vmLoop", url: assetUrl, line: 20, column: 2}]
    });
  }
  events.push({
    seq: 500,
    category: "reverse",
    api: "Request.constructor",
    args: [{
      url: "https://www.example.test/api/list?count=6&device_id=abc&app_id=1000&sessionToken=secret-token&X-Signature=secret-signature&X-Secondary-Signature=secret-secondary-signature"
    }],
    stack: [{function: "signRequest", url: assetUrl, line: 40, column: 12}]
  });

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_distant_unsigned.ndjson", events, assets: []});
  const [flow] = report.signature.flows;

  assert.equal(flow.match, "unsigned_to_signed");
  assert.equal(flow.unsigned_event.seq, 100);
  assert.equal(flow.signed_event.seq, 500);
  assert.deepEqual(flow.unchanged_params, ["app_id", "count", "device_id"]);
  assert.deepEqual(report.signature.agent_brief.flows[0].gaps, []);
});

test("buildLocalReport emits an agent-readable signature brief", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "sign", url: assetUrl, line: 10, column: 2}];
  const events = [
    {seq: 30, category: "reverse", api: "URL.constructor", args: [{url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 31, category: "reverse", api: "String.fromCharCode", args: [{argc: 7, first_code: 88, result_preview: "X-Signature"}], stack},
    {seq: 32, category: "reverse", api: "DataView.getUint32", args: [{byte_offset: 4, little_endian: true, result: 195936478}], stack},
    {seq: 33, category: "reverse", api: "TextEncoder.encode", args: [{input_length: 18}], stack},
    {seq: 34, category: "reverse", api: "SubtleCrypto.digest", args: [{algorithm: "SHA-256"}], stack},
    {seq: 35, category: "reverse", api: "URLSearchParams.set", args: [{name: "X-Signature", value: "secret-signature"}], stack},
    {
      seq: 36,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&X-Signature=secret-signature&X-Secondary-Signature=secret-secondary-signature"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_agent_brief.ndjson", events, assets: []});
  const brief = report.signature.agent_brief;
  const [flow] = brief.flows;

  assert.equal(brief.version, 1);
  assert.deepEqual(brief.target_terms, ["X-Signature", "X-Secondary-Signature"]);
  assert.deepEqual(brief.summary, {
    flow_count: 1,
    unsigned_to_signed_count: 1,
    signed_only_count: 0,
    signature_event_count: 1
  });
  assert.equal(flow.match, "unsigned_to_signed");
  assert.equal(flow.evidence_level, "high");
  assert.deepEqual(flow.signature_params, ["X-Signature", "X-Secondary-Signature"]);
  assert.deepEqual(flow.gaps, []);
  assert.deepEqual(flow.phases.map((phase) => phase.phase), [
    "unsigned_url",
    "vmp_string_decode",
    "vmp_bytecode_or_register_access",
    "vmp_hash_or_signature_pipeline",
    "url_signature_mutation",
    "signed_request"
  ]);
  assert.deepEqual(flow.phases[1].apis, ["String.fromCharCode"]);
  assert.deepEqual(flow.phases[2].families, ["byte_buffer"]);
  assert.deepEqual(flow.phases[3].apis, ["SubtleCrypto.digest", "TextEncoder.encode"]);
  assert.deepEqual(flow.vmp_analysis_points.map((point) => point.type), [
    "vmp_string_decoder",
    "vmp_bytecode_or_register_access",
    "vmp_hash_or_signature_pipeline",
    "vmp_runtime_cluster"
  ]);
  assert.deepEqual(flow.vmp_analysis_points[0].apis, [{api: "String.fromCharCode", count: 1}]);
  assert.deepEqual(flow.vmp_analysis_points[2].families, ["hash_crypto", "text_codec"]);
  assert.deepEqual(flow.vmp_analysis_points[3].seq_start, 31);
  assert.deepEqual(flow.vmp_analysis_points[3].seq_end, 34);
  assert.match(renderMarkdownReport(report), /Agent Signature Brief/);
  assert.match(renderMarkdownReport(report), /vmp_points=vmp_string_decoder@31\.\.31/);
});

test("buildLocalReport emits raw agent evidence packs for signature flows", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "sign", url: assetUrl, line: 3, column: 2}];
  const events = [
    {seq: 70, category: "reverse", api: "URL.constructor", args: [{url: "https://www.example.test/api/list?count=6&device_id=abc"}], stack},
    {seq: 71, category: "reverse", api: "String.fromCharCode", args: [{argc: 7, first_code: 88, result_preview: "X-Signature"}], stack},
    {seq: 72, category: "reverse", api: "DataView.getUint32", args: [{byte_offset: 4, little_endian: true, result: 195936478}], stack},
    {seq: 73, category: "reverse", api: "Bitwise.xor", args: [{left: 195936478, right: 305419896, result: 42424242}], stack},
    {seq: 74, category: "reverse", api: "URLSearchParams.set", args: [{name: "X-Signature", value: "secret-signature"}], stack},
    {
      seq: 75,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&device_id=abc&sessionToken=secret-token&X-Signature=secret-signature&X-Secondary-Signature=secret-secondary-signature"}],
      stack
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: `
      const raw = "X-Signature=secret-signature&sessionToken=secret-token";
      const p=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27];
      const A=[function(n){return String.fromCharCode(p[n.i++]);},function(n){return A[p[n.i++]].apply(null,[n]);}];
      while(n.i<p.length){switch(p[n.i++]){case 1:A[0](n);break;}}
    `
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_agent_pack.ndjson", events, assets});
  const pack = report.signature.agent_evidence_pack;
  const [flow] = pack.flows;

  assert.equal(pack.version, 1);
  assert.deepEqual(pack.redaction, {
    sensitive_terms: ["X-Signature", "X-Secondary-Signature", "token"],
    values_redacted: false
  });
  assert.equal(flow.id, "signature_flow_1");
  assert.equal(flow.endpoint, "https://www.example.test/api/list");
  assert.equal(flow.evidence_level, "high");
  assert.deepEqual(flow.coverage, {
    unsigned_url: true,
    signature_mutation: true,
    signed_request: true,
    vmp_runtime: true,
    vmp_string_decode: true,
    vmp_bytecode_or_register_access: true,
    vmp_int_bitwise_pipeline: true,
    vmp_hash_or_signature_pipeline: false,
    vmp_anti_debug_timing_gate: false,
    vmp_source_integrity_probe: false,
    vmp_stack_trace_probe: false,
    vmp_exception_control_flow: false,
    vmp_string_transform: false,
    vmp_regexp_probe: false,
    vmp_url_encoding_boundary: false,
    assets: true
  });
  assert.deepEqual(flow.seq_range, {start: 70, end: 75});
  assert.deepEqual(flow.event_windows.map((window) => window.phase), [
    "unsigned_url",
    "vmp_string_decode",
    "vmp_bytecode_or_register_access",
    "vmp_int_bitwise_pipeline",
    "url_signature_mutation",
    "signed_request"
  ]);
  assert.deepEqual({
    seq: flow.event_windows[1].events[0].seq,
    api: flow.event_windows[1].events[0].api,
    role: flow.event_windows[1].events[0].role,
    relation: flow.event_windows[1].events[0].relation,
    family: flow.event_windows[1].events[0].family,
    stack_url: flow.event_windows[1].events[0].stack_url,
    asset_id: flow.event_windows[1].events[0].asset_id
  }, {
    seq: 71,
    api: "String.fromCharCode",
    role: "vmp",
    relation: "between_unsigned_signed",
    family: "string_decode",
    stack_url: assetUrl,
    asset_id: "sha1:runtime-sdk"
  });
  assert.equal(flow.event_windows.find((window) => window.phase === "url_signature_mutation").events[0].args[0].value, "secret-signature");
  const sourceContext = flow.event_windows[1].source_contexts[0];
  assert.equal(sourceContext.asset_id, "sha1:runtime-sdk");
  assert.equal(sourceContext.url, assetUrl);
  assert.equal(sourceContext.line_start, 1);
  assert.equal(sourceContext.line_end, 5);
  assert.match(sourceContext.preview, /String\.fromCharCode/);
  assert.match(sourceContext.preview, /X-Signature=secret-signature/);
  assert.match(sourceContext.preview, /secret-token/);
  assert.deepEqual(flow.graph.nodes.map((node) => ({
    id: node.id,
    phase: node.phase,
    seq_start: node.seq_start,
    seq_end: node.seq_end,
    source_context_refs: node.source_context_refs
  })), [
    {id: "n1", phase: "unsigned_url", seq_start: 70, seq_end: 70, source_context_refs: ["unsigned_url:0"]},
    {id: "n2", phase: "vmp_string_decode", seq_start: 71, seq_end: 71, source_context_refs: ["vmp_string_decode:0"]},
    {id: "n3", phase: "vmp_bytecode_or_register_access", seq_start: 72, seq_end: 72, source_context_refs: ["vmp_bytecode_or_register_access:0"]},
    {id: "n4", phase: "vmp_int_bitwise_pipeline", seq_start: 73, seq_end: 73, source_context_refs: ["vmp_int_bitwise_pipeline:0"]},
    {id: "n5", phase: "url_signature_mutation", seq_start: 74, seq_end: 74, source_context_refs: ["url_signature_mutation:0"]},
    {id: "n6", phase: "signed_request", seq_start: 75, seq_end: 75, source_context_refs: ["signed_request:0"]}
  ]);
  assert.deepEqual(flow.graph.edges, [
    {from: "n1", to: "n2", relation: "observed_before", seq_gap: 1},
    {from: "n2", to: "n3", relation: "observed_before", seq_gap: 1},
    {from: "n3", to: "n4", relation: "observed_before", seq_gap: 1},
    {from: "n4", to: "n5", relation: "observed_before", seq_gap: 1},
    {from: "n5", to: "n6", relation: "observed_before", seq_gap: 1}
  ]);
  assert.deepEqual(flow.stack_clusters, [{
    function: "sign",
    stack_url: assetUrl,
    asset_id: "sha1:runtime-sdk",
    event_count: 6,
    seq_start: 70,
    seq_end: 75,
    phases: [
      "unsigned_url",
      "vmp_string_decode",
      "vmp_bytecode_or_register_access",
      "vmp_int_bitwise_pipeline",
      "url_signature_mutation",
      "signed_request"
    ],
    apis: [
      {api: "Bitwise.xor", count: 1},
      {api: "DataView.getUint32", count: 1},
      {api: "Request.constructor", count: 1},
      {api: "String.fromCharCode", count: 1},
      {api: "URL.constructor", count: 1},
      {api: "URLSearchParams.set", count: 1}
    ],
    source_context_refs: [
      "unsigned_url:0",
      "vmp_string_decode:0",
      "vmp_bytecode_or_register_access:0",
      "vmp_int_bitwise_pipeline:0",
      "url_signature_mutation:0",
      "signed_request:0"
    ]
  }]);
  assert.equal(flow.assets[0].asset_id, "sha1:runtime-sdk");
  assert.equal(flow.assets[0].url, assetUrl);
  assert.equal(flow.assets[0].content_path, "assets/trace_demo/runtime-sdk.js");
  assert.ok(flow.assets[0].score >= 7);
  for (const signal of [
    "vmp_bytecode_array",
    "vmp_handler_table",
    "vmp_dispatch_loop",
    "vmp_dynamic_dispatch",
    "vmp_string_decode_refs"
  ]) {
    assert.ok(flow.assets[0].signals.includes(signal));
  }
  assert.ok(flow.next_questions.includes("hash_or_signature_pipeline_not_observed"));
  assert.deepEqual(flow.capture_recommendations, [{
    id: "capture_hash_or_signature_pipeline",
    priority: "high",
    reason: "JSON serialization, encoding, WebCrypto digest/sign/importKey, or integer arithmetic evidence is missing for this signature flow",
    suggested_hooks: [
      "JSON.stringify",
      "JSON.parse",
      "TextEncoder.encode",
      "TextEncoder.encodeInto",
      "TextDecoder.decode",
      "SubtleCrypto.digest",
      "SubtleCrypto.importKey",
      "SubtleCrypto.sign",
      "Math.imul"
    ],
    related_existing_evidence: [
      "vmp_string_decode",
      "vmp_bytecode_or_register_access",
      "vmp_int_bitwise_pipeline",
      "url_signature_mutation",
      "asset_source_context"
    ]
  }]);
  assert.match(JSON.stringify(pack), /secret-token/);
  assert.match(JSON.stringify(pack), /secret-signature/);
  assert.match(JSON.stringify(pack), /secret-secondary-signature/);
  assert.doesNotMatch(JSON.stringify(pack), /<redacted>/);
  assert.match(renderMarkdownReport(report), /Agent Evidence Pack/);
  assert.match(renderMarkdownReport(report), /graph=unsigned_url->vmp_string_decode->vmp_bytecode_or_register_access/);
  assert.match(renderMarkdownReport(report), /stacks=sign@https:\/\/cdn\.example\.test\/runtime-sdk\.js:6/);
  assert.match(renderMarkdownReport(report), /recommend=capture_hash_or_signature_pipeline:high/);
});

test("buildLocalReport aggregates global stack clusters across signature flows", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "A", url: assetUrl, line: 3, column: 2}];
  const events = [
    {seq: 100, category: "reverse", api: "URL.constructor", args: [{url: "https://www.example.test/api/list?count=1"}], stack},
    {seq: 101, category: "reverse", api: "TextEncoder.encode", args: [{input_length: 24}], stack},
    {
      seq: 102,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=1&X-Signature=secret-one&X-Secondary-Signature=secret-two"}],
      stack
    },
    {seq: 200, category: "reverse", api: "URL.constructor", args: [{url: "https://www.example.test/api/detail?item=2"}], stack},
    {seq: 201, category: "reverse", api: "TextEncoder.encode", args: [{input_length: 25}], stack},
    {
      seq: 202,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/detail?item=2&X-Signature=secret-three&X-Secondary-Signature=secret-four"}],
      stack
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: `
      const raw = "X-Secondary-Signature=secret-four";
      function A(vm){ return TextEncoder.prototype.encode.call(new TextEncoder(), vm.qs); }
      function sign(url){ return A({qs:url}); }
    `
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_global_clusters.ndjson", events, assets});
  const pack = report.signature.agent_evidence_pack;

  assert.equal(pack.flows.length, 2);
  assert.deepEqual(pack.global_stack_clusters, [{
    function: "A",
    stack_url: assetUrl,
    asset_id: "sha1:runtime-sdk",
    flow_count: 2,
    event_count: 6,
    seq_start: 100,
    seq_end: 202,
    endpoints: [
      "https://www.example.test/api/detail",
      "https://www.example.test/api/list"
    ],
    phases: [
      "signed_request",
      "unsigned_url",
      "vmp_hash_or_signature_pipeline"
    ],
    apis: [
      {api: "Request.constructor", count: 2},
      {api: "TextEncoder.encode", count: 2},
      {api: "URL.constructor", count: 2}
    ],
    sample_flow_ids: ["signature_flow_1", "signature_flow_2"],
    source_context_refs: [
      {flow_id: "signature_flow_1", refs: ["unsigned_url:0", "vmp_hash_or_signature_pipeline:0", "signed_request:0"]},
      {flow_id: "signature_flow_2", refs: ["vmp_hash_or_signature_pipeline:0", "unsigned_url:0", "signed_request:0"]}
    ]
  }]);
  assert.deepEqual(pack.pipeline_patterns, [{
    pattern: "unsigned_url -> vmp_hash_or_signature_pipeline -> signed_request",
    flow_count: 2,
    event_count: 6,
    endpoints: [
      "https://www.example.test/api/detail",
      "https://www.example.test/api/list"
    ],
    sample_flow_ids: ["signature_flow_1", "signature_flow_2"],
    coverage: {
      unsigned_url: true,
      signature_mutation: false,
      signed_request: true,
      vmp_runtime: true,
      vmp_string_decode: false,
      vmp_bytecode_or_register_access: false,
      vmp_int_bitwise_pipeline: false,
      vmp_hash_or_signature_pipeline: true,
      vmp_anti_debug_timing_gate: false,
      vmp_source_integrity_probe: false,
      vmp_stack_trace_probe: false,
      vmp_exception_control_flow: false,
      vmp_string_transform: false,
      vmp_regexp_probe: false,
      vmp_url_encoding_boundary: false,
      assets: true
    },
    top_stack_clusters: [{
      function: "A",
      stack_url: assetUrl,
      asset_id: "sha1:runtime-sdk",
      flow_count: 2,
      event_count: 6
    }]
  }]);
  assert.match(renderMarkdownReport(report), /Global Signature Stack Clusters/);
  assert.match(renderMarkdownReport(report), /A@https:\/\/cdn\.example\.test\/runtime-sdk\.js flows=2 events=6/);
  assert.match(renderMarkdownReport(report), /Pipeline Patterns/);
  assert.match(renderMarkdownReport(report), /unsigned_url -> vmp_hash_or_signature_pipeline -> signed_request flows=2 events=6/);
});

test("buildLocalReport aggregates global VMP hook analysis points across signature flows", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stackA = [{function: "vmA", url: assetUrl, line: 4, column: 2}];
  const stackB = [{function: "vmB", url: assetUrl, line: 8, column: 2}];
  const events = [
    {seq: 10, category: "reverse", api: "URL.constructor", args: [{url: "https://www.example.test/api/list?count=1"}], stack: stackA},
    {seq: 11, category: "reverse", api: "String.fromCharCode", args: [{argc: 7, first_code: 88, result_preview: "X-Signature"}], stack: stackA},
    {seq: 12, category: "reverse", api: "DataView.getUint32", args: [{byte_offset: 4, little_endian: true, result: 195936478}], stack: stackA},
    {seq: 13, category: "reverse", api: "Reflect.apply", args: [{argc: 2}], stack: stackA},
    {seq: 14, category: "reverse", api: "Proxy.get", args: [{key: "opcode", result: 1}], stack: stackA},
    {
      seq: 15,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=1&X-Signature=secret-one&X-Secondary-Signature=secret-two"}],
      stack: stackA
    },
    {seq: 20, category: "reverse", api: "URL.constructor", args: [{url: "https://www.example.test/api/detail?item=2"}], stack: stackB},
    {seq: 21, category: "reverse", api: "TextEncoder.encode", args: [{input_length: 25}], stack: stackB},
    {seq: 22, category: "reverse", api: "SubtleCrypto.digest", args: [{algorithm: "SHA-256"}], stack: stackB},
    {seq: 23, category: "reverse", api: "Bitwise.xor", args: [{left: 1, right: 2, result: 3}], stack: stackB},
    {
      seq: 24,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/detail?item=2&X-Signature=secret-three&X-Secondary-Signature=secret-four"}],
      stack: stackB
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_global_vmp_hooks.ndjson", events, assets: []});
  const hooks = report.signature.agent_evidence_pack.vmp_hook_analysis;

  assert.equal(hooks.total_flows, 2);
  assert.deepEqual(hooks.observed_point_types, [
    "vmp_string_decoder",
    "vmp_bytecode_or_register_access",
    "vmp_dynamic_dispatch",
    "vmp_proxy_trap",
    "vmp_hash_or_signature_pipeline",
    "vmp_int_bitwise_pipeline",
    "vmp_runtime_cluster"
  ]);
  assert.deepEqual(hooks.missing_point_types, [
    "vmp_array_table",
    "vmp_collection_table",
    "vmp_json_serialization",
    "vmp_anti_debug_timing_gate",
    "vmp_source_integrity_probe",
    "vmp_stack_trace_probe",
    "vmp_exception_control_flow",
    "vmp_string_transform",
    "vmp_regexp_probe",
    "vmp_url_encoding_boundary"
  ]);
  assert.deepEqual(hooks.points.map((point) => ({
    type: point.type,
    flow_count: point.flow_count,
    event_count: point.event_count,
    seq_start: point.seq_start,
    seq_end: point.seq_end,
    families: point.families,
    sample_flow_ids: point.sample_flow_ids
  })), [
    {
      type: "vmp_runtime_cluster",
      flow_count: 2,
      event_count: 7,
      seq_start: 11,
      seq_end: 23,
      families: [
        "byte_buffer",
        "dynamic_dispatch",
        "hash_crypto",
        "int_bitwise",
        "proxy_trap",
        "string_decode",
        "text_codec"
      ],
      sample_flow_ids: ["signature_flow_1", "signature_flow_2"]
    },
    {
      type: "vmp_hash_or_signature_pipeline",
      flow_count: 1,
      event_count: 2,
      seq_start: 21,
      seq_end: 22,
      families: ["hash_crypto", "text_codec"],
      sample_flow_ids: ["signature_flow_2"]
    },
    {
      type: "vmp_bytecode_or_register_access",
      flow_count: 1,
      event_count: 1,
      seq_start: 12,
      seq_end: 12,
      families: ["byte_buffer"],
      sample_flow_ids: ["signature_flow_1"]
    },
    {
      type: "vmp_dynamic_dispatch",
      flow_count: 1,
      event_count: 1,
      seq_start: 13,
      seq_end: 13,
      families: ["dynamic_dispatch"],
      sample_flow_ids: ["signature_flow_1"]
    },
    {
      type: "vmp_int_bitwise_pipeline",
      flow_count: 1,
      event_count: 1,
      seq_start: 23,
      seq_end: 23,
      families: ["int_bitwise"],
      sample_flow_ids: ["signature_flow_2"]
    },
    {
      type: "vmp_proxy_trap",
      flow_count: 1,
      event_count: 1,
      seq_start: 14,
      seq_end: 14,
      families: ["proxy_trap"],
      sample_flow_ids: ["signature_flow_1"]
    },
    {
      type: "vmp_string_decoder",
      flow_count: 1,
      event_count: 1,
      seq_start: 11,
      seq_end: 11,
      families: ["string_decode"],
      sample_flow_ids: ["signature_flow_1"]
    }
  ]);
  assert.deepEqual(hooks.coverage_by_type.vmp_hash_or_signature_pipeline, {
    observed_flows: 1,
    missing_flows: 1,
    coverage_ratio: 0.5,
    event_count: 2,
    global_event_count: 2,
    global_apis: [
      {api: "SubtleCrypto.digest", count: 1},
      {api: "TextEncoder.encode", count: 1}
    ]
  });
  assert.deepEqual(hooks.hook_gaps.map((gap) => ({
    type: gap.type,
    missing_flow_count: gap.missing_flow_count,
    priority: gap.priority
  })), [
    {type: "vmp_array_table", missing_flow_count: 2, priority: "medium"},
    {type: "vmp_collection_table", missing_flow_count: 2, priority: "medium"},
    {type: "vmp_json_serialization", missing_flow_count: 2, priority: "high"},
    {type: "vmp_anti_debug_timing_gate", missing_flow_count: 2, priority: "high"},
    {type: "vmp_source_integrity_probe", missing_flow_count: 2, priority: "high"},
    {type: "vmp_stack_trace_probe", missing_flow_count: 2, priority: "high"},
    {type: "vmp_exception_control_flow", missing_flow_count: 2, priority: "high"},
    {type: "vmp_string_transform", missing_flow_count: 2, priority: "medium"},
    {type: "vmp_regexp_probe", missing_flow_count: 2, priority: "medium"},
    {type: "vmp_url_encoding_boundary", missing_flow_count: 2, priority: "high"},
    {type: "vmp_string_decoder", missing_flow_count: 1, priority: "medium"},
    {type: "vmp_bytecode_or_register_access", missing_flow_count: 1, priority: "medium"},
    {type: "vmp_dynamic_dispatch", missing_flow_count: 1, priority: "medium"},
    {type: "vmp_proxy_trap", missing_flow_count: 1, priority: "medium"},
    {type: "vmp_hash_or_signature_pipeline", missing_flow_count: 1, priority: "high"},
    {type: "vmp_int_bitwise_pipeline", missing_flow_count: 1, priority: "medium"}
  ]);
  assert.deepEqual(
    hooks.hook_analysis_points.find((point) => point.type === "vmp_hash_or_signature_pipeline"),
    {
      type: "vmp_hash_or_signature_pipeline",
      status: "partial",
      priority: "high",
      analysis_goal: "trace JSON serialization, encoding, WebCrypto digest/sign/importKey, and arithmetic material used by request signing",
      families: ["json_serialization", "text_codec", "hash_crypto", "int_arithmetic"],
      observed_flows: 1,
      missing_flows: 1,
      coverage_ratio: 0.5,
      observed_event_count: 2,
      global_event_count: 2,
      observed_apis: [
        {api: "SubtleCrypto.digest", count: 1},
        {api: "TextEncoder.encode", count: 1}
      ],
      global_apis: [
        {api: "SubtleCrypto.digest", count: 1},
        {api: "TextEncoder.encode", count: 1}
      ],
      suggested_hooks: [
        "JSON.stringify",
        "JSON.parse",
        "TextEncoder.encode",
        "TextEncoder.encodeInto",
        "TextDecoder.decode",
        "SubtleCrypto.digest",
        "SubtleCrypto.importKey",
        "SubtleCrypto.sign",
        "Math.imul"
      ],
      reason: "JSON serialization, encoding, WebCrypto digest/sign/importKey, or integer arithmetic hooks are missing in one or more signature flows",
      next_action: "improve_flow_linking"
    }
  );
  assert.equal(
    hooks.hook_analysis_points.find((point) => point.type === "vmp_collection_table").status,
    "missing"
  );
  assert.ok(hooks.hook_gaps.find((gap) => gap.type === "vmp_dynamic_dispatch").suggested_hooks.includes("Reflect.apply"));
  assert.match(renderMarkdownReport(report), /Global VMP Hook Analysis/);
  assert.match(renderMarkdownReport(report), /Global VMP Hook Analysis Points/);
  assert.match(renderMarkdownReport(report), /hook_point vmp_hash_or_signature_pipeline status=partial next=improve_flow_linking/);
  assert.match(renderMarkdownReport(report), /vmp_runtime_cluster flows=2 events=7/);
  assert.match(renderMarkdownReport(report), /VMP Hook Gaps/);
});

test("buildLocalReport reports candidate entrypoints when signature terms are absent", () => {
  const assetUrl = "https://cdn.example.test/secsdk.js";
  const stack = [{function: "ne", url: assetUrl, line: 7, column: 11979}];
  const events = [
    {seq: 10, category: "reverse", api: "Bitwise.and", args: [{left: 13, right: 3, result: 1}], stack},
    {seq: 11, category: "reverse", api: "Shift.left", args: [{left: 1, right: 3, result: 8}], stack},
    {seq: 12, category: "reverse", api: "TextEncoder.encode", args: [{input_length: 32}], stack}
  ];
  const assets = [{
    asset_id: "sha1:secsdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/secsdk.js",
    content: `
      var table = ["\\x61","\\x62","\\x63","\\x64","\\x65"];
      function ne(vm){ while (vm.pc < vm.code.length) { switch(vm.code[vm.pc++]) { case 1: return handlers[vm.code[vm.pc++]].call(null, vm); } } }
      var handlers = [function(vm){ return String.fromCharCode(vm.code[vm.pc++]); }, function(vm){ return Reflect.apply(handlers[0], null, [vm]); }];
    `
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_absent_signature.ndjson", events, assets});
  const absent = report.signature.agent_evidence_pack.signature_absent;

  assert.equal(report.signature.event_count, 0);
  assert.equal(absent.reason, "signature_terms_not_observed");
  assert.equal(absent.vmp_runtime_event_count, 3);
  assert.deepEqual(absent.candidate_entrypoints.map((entry) => ({
    stack_url: entry.stack_url,
    function: entry.function,
    event_count: entry.event_count,
    seq_start: entry.seq_start,
    seq_end: entry.seq_end,
    families: entry.families
  })), [{
    stack_url: assetUrl,
    function: "ne",
    event_count: 3,
    seq_start: 10,
    seq_end: 12,
    families: ["int_bitwise", "text_codec"]
  }]);
  assert.deepEqual(absent.candidate_assets.map((asset) => asset.asset_id), ["sha1:secsdk"]);
  assert.deepEqual(absent.capture_recommendations.map((item) => item.id), [
    "trigger_signed_request_paths",
    "rerun_with_interactive_profile",
    "inspect_candidate_entrypoints"
  ]);
  assert.doesNotMatch(JSON.stringify(absent), /X-Signature=.*secret|X-Secondary-Signature=.*secret/);
  assert.match(renderMarkdownReport(report), /Signature Capture Gap/);
  assert.match(renderMarkdownReport(report), /candidate_entry=ne@https:\/\/cdn\.example\.test\/secsdk\.js events=3 seq=10\.\.12 families=int_bitwise,text_codec/);
});

test("buildLocalReport links signature-absent network anchors by trace index", () => {
  const assetUrl = "https://cdn.example.test/secsdk.js";
  const stack = [{function: "vmSign", url: assetUrl, line: 9, column: 3}];
  const events = [
    {
      _trace_index: 10,
      seq: 2,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://www.example.test/api/list?count=1",
        is_fetch_like_api: true
      }],
      origin: "https://www.example.test"
    },
    {
      _trace_index: 8,
      seq: 9001,
      category: "reverse",
      api: "TextEncoder.encode",
      args: [{input_length: 32}],
      origin: "https://www.example.test",
      stack
    },
    {
      _trace_index: 12,
      seq: 9002,
      category: "reverse",
      api: "Bitwise.xor",
      args: [{left: 1, right: 2, result: 3}],
      origin: "https://www.example.test",
      stack
    }
  ];
  const assets = [{
    asset_id: "sha1:secsdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/secsdk.js",
    content: "function vmSign(input){ return input ^ 3; }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_absent_network.ndjson", events, assets});
  const absent = report.signature.agent_evidence_pack.signature_absent;

  assert.deepEqual(absent.network_anchors.map(({
    evidence_score,
    ranking_signals,
    candidate_signature_pipeline,
    request_context,
    vmp_analysis_points,
    ...anchor
  }) => anchor), [{
    trace_index: 10,
    seq: 2,
    api: "BrowserNetwork.request",
    method: "GET",
    endpoint: "https://www.example.test/api/list",
    host: "www.example.test",
    path: "/api/list",
    is_fetch_like_api: true,
    nearby_vmp_candidates: [
      {
        trace_index: 8,
        seq: 9001,
        api: "TextEncoder.encode",
        family: "text_codec",
        relation: "before_request",
        trace_distance: 2,
        function: "vmSign",
        stack_url: assetUrl,
        asset_id: "sha1:secsdk"
      },
      {
        trace_index: 12,
        seq: 9002,
        api: "Bitwise.xor",
        family: "int_bitwise",
        relation: "after_request",
        trace_distance: 2,
        function: "vmSign",
        stack_url: assetUrl,
        asset_id: "sha1:secsdk"
      }
    ]
  }]);
  assert.ok(absent.network_anchors[0].evidence_score > 0);
  assert.deepEqual(absent.network_anchors[0].ranking_signals, [
    "browser_fetch_like_request",
    "application_endpoint",
    "query_params_present",
    "nearby_vmp:text_codec",
    "nearby_vmp:int_bitwise"
  ]);
  assert.deepEqual(
    absent.network_anchors[0].candidate_signature_pipeline.stages.find((stage) => stage.stage === "signed_request").runtime_apis,
    ["BrowserNetwork.request"]
  );
  assert.match(renderMarkdownReport(report), /network_anchor=GET https:\/\/www\.example\.test\/api\/list trace=10 seq=2/);
  assert.match(renderMarkdownReport(report), /nearby_vmp=TextEncoder\.encode@9001:before_request:2,Bitwise\.xor@9002:after_request:2/);
});

test("buildLocalReport ranks signature-absent network anchors by VMP evidence", () => {
  const assetUrl = "https://cdn.example.test/secsdk.js";
  const stack = [{function: "signBeforeSend", url: assetUrl, line: 12, column: 4}];
  const events = [
    {
      _trace_index: 1,
      seq: 1,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{method: "GET", url: "https://www.example.test/"}],
      origin: "https://www.example.test"
    },
    {
      _trace_index: 45,
      seq: 45,
      category: "network",
      api: "XMLHttpRequest.send",
      args: [{method: "POST", url: "https://telemetry.example.test/monitor_browser/collect?batch=1"}],
      origin: "https://www.example.test"
    },
    {
      _trace_index: 48,
      seq: 48,
      category: "reverse",
      api: "TextEncoder.encode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 49,
      seq: 49,
      category: "reverse",
      api: "SubtleCrypto.digest",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 50,
      seq: 50,
      category: "reverse",
      api: "btoa",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 52,
      seq: 52,
      category: "network",
      api: "XMLHttpRequest.send",
      args: [{method: "POST", url: "https://www.example.test/api/feed/list?cursor=1"}],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:secsdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/secsdk.js",
    score: 9,
    signals: ["vmp_interpreter"],
    content: `
      var table = ["\\x61","\\x62","\\x63","\\x64","\\x65"];
      function signBeforeSend(vm){ while (vm.pc < vm.code.length) { switch(vm.code[vm.pc++]) { case 1: return handlers[vm.code[vm.pc++]].call(null, vm); } } }
      var handlers = [function(vm){ return btoa(String.fromCharCode(vm.code[vm.pc++])); }];
    `
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_ranked_absent.ndjson", events, assets});
  const anchors = report.signature.agent_evidence_pack.signature_absent.network_anchors;

  assert.equal(anchors[0].api, "XMLHttpRequest.send");
  assert.equal(anchors[0].method, "POST");
  assert.equal(anchors[0].endpoint, "https://www.example.test/api/feed/list");
  assert.ok(anchors[0].evidence_score > anchors[1].evidence_score);
  assert.deepEqual(anchors[0].ranking_signals, [
    "script_request_api",
    "state_changing_method",
    "application_endpoint",
    "query_params_present",
    "nearby_vmp:text_codec",
    "nearby_vmp:hash_crypto",
    "nearby_vmp:base64",
    "nearby_obfuscated_asset"
  ]);
  const telemetryAnchor = anchors.find((anchor) => anchor.endpoint === "https://telemetry.example.test/monitor_browser/collect");
  assert.ok(telemetryAnchor);
  assert.ok(telemetryAnchor.evidence_score < anchors[0].evidence_score);
  assert.ok(telemetryAnchor.ranking_signals.includes("deprioritized:telemetry_endpoint"));
  assert.match(renderMarkdownReport(report), /network_anchor=POST https:\/\/www\.example\.test\/api\/feed\/list trace=52 seq=52 score=\d+ signals=script_request_api,state_changing_method,application_endpoint,query_params_present,nearby_vmp:text_codec,nearby_vmp:hash_crypto,nearby_vmp:base64,nearby_obfuscated_asset/);
});

test("buildLocalReport deprioritizes static resource network anchors", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "vmLoad",
    url: assetUrl,
    line: 1,
    column: 2,
    asset_id: "sha1:runtime-sdk",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {
      _trace_index: 18,
      seq: 18,
      category: "reverse",
      api: "TextEncoder.encode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 19,
      seq: 19,
      category: "reverse",
      api: "SubtleCrypto.digest",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 20,
      seq: 20,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://cdn.example.test/assets/runtime-sdk.js",
        is_fetch_like_api: true
      }],
      origin: "https://www.example.test"
    },
    {
      _trace_index: 21,
      seq: 21,
      category: "reverse",
      api: "btoa",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 100,
      seq: 100,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://www.example.test/api/feed/list?cursor=1",
        is_fetch_like_api: true
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    score: 12,
    signals: ["vmp_interpreter"],
    content: "function vmLoad(input){ return btoa(String(input)); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_static_anchor_noise.ndjson", events, assets});
  const anchors = report.signature.agent_evidence_pack.signature_absent.network_anchors;
  const staticAnchor = anchors.find((anchor) => anchor.endpoint === "https://cdn.example.test/assets/runtime-sdk.js");
  const staticChain = report.signature.agent_evidence_pack.signature_absent.candidate_trace_chains
    .find((chain) => chain.endpoint === "https://cdn.example.test/assets/runtime-sdk.js");
  const staticFlow = report.signature.agent_evidence_pack.signature_material_flows
    .find((flow) => flow.endpoint === "https://cdn.example.test/assets/runtime-sdk.js");
  const staticReviewPath = report.signature.agent_evidence_pack.agent_review_package.entries
    .flatMap((entry) => entry.generation_paths || [])
    .find((path) => path.endpoint === "https://cdn.example.test/assets/runtime-sdk.js");

  assert.equal(anchors[0].endpoint, "https://www.example.test/api/feed/list");
  assert.ok(staticAnchor);
  assert.equal(staticAnchor.resource_class, "static_resource");
  assert.equal(staticChain.resource_class, "static_resource");
  assert.equal(staticFlow.resource_class, "static_resource");
  assert.ok(staticReviewPath.warnings.includes("network_anchor_static_resource"));
  assert.ok(staticAnchor.evidence_score < anchors[0].evidence_score);
  assert.ok(staticAnchor.ranking_signals.includes("deprioritized:static_resource_request"));
  assert.match(renderMarkdownReport(report), /network_anchor=GET https:\/\/www\.example\.test\/api\/feed\/list/);
});

test("buildLocalReport deprioritizes document and telemetry network anchors", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "vmProbe", url: assetUrl, line: 8, column: 2}];
  const events = [
    {
      _trace_index: 8,
      seq: 8,
      category: "reverse",
      api: "TextEncoder.encode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 9,
      seq: 9,
      category: "reverse",
      api: "SubtleCrypto.digest",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 10,
      seq: 10,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://www.example.test/",
        is_fetch_like_api: true,
        request_destination: "document"
      }],
      origin: "https://www.example.test"
    },
    {
      _trace_index: 20,
      seq: 20,
      category: "network",
      api: "XMLHttpRequest.send",
      args: [{
        method: "POST",
        url: "https://telemetry.example.test/monitor_browser/collect?batch=1"
      }],
      origin: "https://www.example.test",
      stack
    },
    {
      _trace_index: 80,
      seq: 80,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://www.example.test/api/feed/list?cursor=1",
        is_fetch_like_api: true
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    score: 9,
    signals: ["vmp_interpreter"],
    content: "function vmProbe(input){ return input; }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_document_telemetry_noise.ndjson", events, assets});
  const anchors = report.signature.agent_evidence_pack.signature_absent.network_anchors;
  const documentAnchor = anchors.find((anchor) => anchor.endpoint === "https://www.example.test/");
  const telemetryAnchor = anchors.find((anchor) => anchor.endpoint === "https://telemetry.example.test/monitor_browser/collect");

  assert.equal(anchors[0].endpoint, "https://www.example.test/api/feed/list");
  assert.ok(documentAnchor);
  assert.ok(telemetryAnchor);
  assert.equal(documentAnchor.resource_class, "document_request");
  assert.equal(telemetryAnchor.resource_class, "telemetry_endpoint");
  assert.equal(
    report.signature.agent_evidence_pack.signature_absent.candidate_trace_chains
      .find((chain) => chain.endpoint === "https://www.example.test/").resource_class,
    "document_request"
  );
  assert.equal(
    report.signature.agent_evidence_pack.signature_absent.candidate_trace_chains
      .find((chain) => chain.endpoint === "https://telemetry.example.test/monitor_browser/collect").resource_class,
    "telemetry_endpoint"
  );
  assert.ok(documentAnchor.ranking_signals.includes("deprioritized:document_request"));
  assert.ok(telemetryAnchor.ranking_signals.includes("deprioritized:telemetry_endpoint"));
  assert.ok(documentAnchor.evidence_score < anchors[0].evidence_score);
  assert.ok(telemetryAnchor.evidence_score < anchors[0].evidence_score);
});

test("buildLocalReport reports a capture gap when only low-value network anchors are present", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "vmProbe",
    url: assetUrl,
    line: 1,
    column: 2,
    asset_id: "sha1:runtime-sdk",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {
      _trace_index: 8,
      seq: 8,
      category: "reverse",
      api: "TextEncoder.encode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 10,
      seq: 10,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://www.example.test/",
        is_fetch_like_api: true,
        request_destination: "document"
      }],
      origin: "https://www.example.test"
    },
    {
      _trace_index: 20,
      seq: 20,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://cdn.example.test/assets/runtime-sdk.js",
        is_fetch_like_api: true
      }],
      origin: "https://www.example.test"
    },
    {
      _trace_index: 30,
      seq: 30,
      category: "network",
      api: "XMLHttpRequest.send",
      args: [{
        method: "POST",
        url: "https://telemetry.example.test/monitor_browser/collect?batch=1"
      }],
      origin: "https://www.example.test",
      stack
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    score: 9,
    signals: ["vmp_interpreter"],
    content: "function vmProbe(input){ return new TextEncoder().encode(String(input)); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_only_low_value_anchors.ndjson", events, assets});
  const plan = report.signature.agent_evidence_pack.next_capture_plan;

  assert.equal(plan.actionable_endpoint_count, 0);
  assert.deepEqual(plan.focus_endpoints, []);
  assert.deepEqual(plan.business_api_capture_status, {
    status: "missing",
    priority: "high",
    actionable_endpoint_count: 0,
    missing_evidence: ["business_api_anchor_not_captured"],
    avoid_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"]
  });
  assert.deepEqual(plan.capture_gate, {
    id: "business_api_anchor",
    status: "pending",
    priority: "high",
    required_event: "BrowserNetwork.request",
    required_renderer_apis: [
      "Request.constructor",
      "fetch",
      "XMLHttpRequest.open",
      "XMLHttpRequest.send"
    ],
    target_endpoint_patterns: [
      "https://www.example.test/api/*",
      "fetch/XMLHttpRequest non-static endpoint"
    ],
    reject_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"],
    observed_actionable_endpoint_count: 0,
    matched_endpoints: [],
    missing: ["business_api_anchor_not_captured"],
    remaining_analysis_gaps: ["business_api_anchor_not_captured"],
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
    },
    stop_when: "observed_actionable_endpoint_count > 0"
  });
  assert.deepEqual(plan.capture_checklist, [
    {
      id: "load_start_url",
      status: "observed",
      priority: "medium",
      evidence: ["https://www.example.test/"],
      next_action: "keep_start_url"
    },
    {
      id: "confirm_core_sdk_asset",
      status: "observed",
      priority: "high",
      evidence: [`sha1:runtime-sdk@${assetUrl}`],
      next_action: "review_core_asset_windows"
    },
    {
      id: "trigger_business_api_anchor",
      status: "pending",
      priority: "high",
      evidence: [],
      target_endpoint_patterns: [
        "https://www.example.test/api/*",
        "fetch/XMLHttpRequest non-static endpoint"
      ],
      rejected_endpoint_summary: [
        "document_request:1",
        "static_resource:1",
        "telemetry_endpoint:1"
      ],
      next_action: "perform_normal_in_page_actions_until_fetch_or_xhr_api_request"
    }
  ]);
  assert.deepEqual(plan.low_value_endpoint_summary, [
    {
      resource_class: "document_request",
      endpoint_count: 1,
      flow_count: 1,
      examples: ["https://www.example.test/"]
    },
    {
      resource_class: "static_resource",
      endpoint_count: 1,
      flow_count: 1,
      examples: ["https://cdn.example.test/assets/runtime-sdk.js"]
    },
    {
      resource_class: "telemetry_endpoint",
      endpoint_count: 1,
      flow_count: 1,
      examples: ["https://telemetry.example.test/monitor_browser/collect"]
    }
  ]);
  assert.deepEqual(plan.focus_assets, [{
    asset_id: "sha1:runtime-sdk",
    stack_url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    score: 1,
    signals: ["vmp_string_decode_refs"],
    flow_count: 3,
    readiness_statuses: ["candidate"],
    asset_focus: "core_signature_asset",
    asset_role: "security_sdk_signature_generator"
  }]);
  assert.equal(plan.gap_summary[0].gap, "business_api_anchor_not_captured");
  assert.deepEqual(plan.capture_attempt_quality, {
    status: "core_sdk_observed_without_business_api",
    readiness: "not_ready_for_signature_generation_analysis",
    reason: "core SDK/runtime evidence is present, but captured request anchors are only document, static resource, or telemetry traffic",
    actionable_endpoint_count: 0,
    core_asset_count: 1,
    low_value_endpoint_classes: ["document_request", "static_resource", "telemetry_endpoint"],
    low_value_endpoint_count: 3,
    missing_evidence: [
      "business_api_anchor_not_captured",
      "signature_terms_not_observed",
      "unsigned_input_not_observed",
      "mix_or_hash_not_observed",
      "signature_mutation_not_observed",
      "data_links_not_observed"
    ],
    next_action: "perform_normal_in_page_actions_until_business_api_request"
  });
  assert.deepEqual(plan.action_items[0], {
    id: "capture_business_api_anchor",
    priority: "high",
    flow_count: 3,
    gaps: ["business_api_anchor_not_captured"],
    reason: "trigger and capture a fetch/XHR business API request rather than document, telemetry, or static resource traffic"
  });
  assert.equal(plan.rerun_recipe.start_url, "https://www.example.test/");
  assert.deepEqual(plan.rerun_recipe.focus.endpoints, []);
  assert.deepEqual(plan.rerun_recipe.focus.assets, [`sha1:runtime-sdk@${assetUrl}`]);
  assert.deepEqual(plan.business_api_capture_plan, {
    status: "needs_business_api_anchor",
    priority: "high",
    start_url: "https://www.example.test/",
    reason: "current candidate anchors are document, telemetry, or static resource requests; trigger normal application XHR/fetch traffic",
    avoid_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"],
    core_assets: [`sha1:runtime-sdk@${assetUrl}`],
    target_endpoint_hints: [
      {
        kind: "same_origin_api",
        pattern: "https://www.example.test/api/*",
        reason: "prefer same-origin application API traffic over document, telemetry, or static script requests"
      },
      {
        kind: "interactive_fetch_or_xhr",
        pattern: "fetch/XMLHttpRequest non-static endpoint",
        reason: "renderer request construction is needed to link URL/SearchParams mutation to the final request"
      }
    ],
    normal_user_actions: [
      "load the start URL with full reverse/fingerprint capture enabled",
      "perform normal in-page actions that request feed, search, detail, or pagination data",
      "wait until a non-static fetch/XHR BrowserNetwork.request appears"
    ],
    success_criteria: [
      "observed endpoint is not document_request, static_resource, or telemetry_endpoint",
      "BrowserNetwork.request is correlated to Request.constructor, fetch, or XMLHttpRequest",
      "URLSearchParams, URL, headers, or body events are close enough to the request to build a material flow"
    ],
    required_evidence: [
      "BrowserNetwork.request",
      "Request.constructor or fetch/XMLHttpRequest.open/send",
      "URLSearchParams.set/append/toString or URL.href/search mutation",
      "core SDK runtime events near the request"
    ]
  });
  assert.match(renderMarkdownReport(report), /gap=business_api_anchor_not_captured flows=3 priority=high next=capture_business_api_anchor/);
  assert.match(renderMarkdownReport(report), /capture_check item=trigger_business_api_anchor status=pending priority=high next=perform_normal_in_page_actions_until_fetch_or_xhr_api_request evidence=none targets=https:\/\/www\.example\.test\/api\/\*,fetch\/XMLHttpRequest non-static endpoint rejected=document_request:1,static_resource:1,telemetry_endpoint:1/);
  assert.match(renderMarkdownReport(report), /low_value_endpoint class=document_request endpoints=1 flows=1 examples=https:\/\/www\.example\.test\//);
  assert.match(renderMarkdownReport(report), /low_value_endpoint class=telemetry_endpoint endpoints=1 flows=1 examples=https:\/\/telemetry\.example\.test\/monitor_browser\/collect/);
  assert.match(renderMarkdownReport(report), /capture_gate id=business_api_anchor status=pending actionable=0 missing=business_api_anchor_not_captured patterns=https:\/\/www\.example\.test\/api\/\*,fetch\/XMLHttpRequest non-static endpoint/);
  assert.match(renderMarkdownReport(report), /capture_attempt_quality status=core_sdk_observed_without_business_api readiness=not_ready_for_signature_generation_analysis actionable=0 core_assets=1 low_value_classes=document_request,static_resource,telemetry_endpoint missing=business_api_anchor_not_captured,signature_terms_not_observed,unsigned_input_not_observed,mix_or_hash_not_observed,signature_mutation_not_observed,data_links_not_observed next=perform_normal_in_page_actions_until_business_api_request/);
  assert.match(renderMarkdownReport(report), /business_api_capture_status status=missing endpoints=0 missing=business_api_anchor_not_captured/);
  assert.match(renderMarkdownReport(report), /business_api_capture status=needs_business_api_anchor start_url=https:\/\/www\.example\.test\/ avoid=document_request,static_resource,telemetry_endpoint core_assets=sha1:runtime-sdk@https:\/\/cdn\.example\.test\/runtime-sdk\.js/);
  assert.match(renderMarkdownReport(report), /asset=sha1:runtime-sdk stack=https:\/\/cdn\.example\.test\/runtime-sdk\.js flows=3 statuses=candidate retrieval=none path=assets\/trace_demo\/runtime-sdk\.js score=1 signals=vmp_string_decode_refs focus=core_signature_asset role=security_sdk_signature_generator/);
});

test("buildLocalReport keeps runtime-sdk endpoint as core security SDK focus asset", () => {
  const loaderUrl = "https://cdn.example.test/loader.js";
  const sdkUrl = "https://cdn.example.test/runtime-sdk/1.0.0/runtime-sdk.js";
  const stack = [{function: "loadSecuritySdk", url: loaderUrl, line: 12, column: 7}];
  const events = [
    {
      _trace_index: 8,
      seq: 8,
      category: "reverse",
      api: "TextEncoder.encode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 20,
      seq: 20,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: sdkUrl,
        is_fetch_like_api: true,
        request_destination: "script"
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:loader",
    kind: "script",
    url: loaderUrl,
    content_path: "assets/trace_demo/loader.js",
    score: 3,
    signals: ["script_loader"],
    content: "function loadSecuritySdk(){ return new TextEncoder().encode('seed'); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_runtime-sdk_endpoint.ndjson", events, assets});
  const plan = report.signature.agent_evidence_pack.next_capture_plan;

  assert.equal(plan.actionable_endpoint_count, 0);
  assert.deepEqual(plan.focus_assets[0], {
    asset_id: "",
    stack_url: sdkUrl,
    flow_count: 1,
    readiness_statuses: ["candidate"],
    asset_focus: "core_signature_asset",
    asset_role: "security_sdk_signature_generator"
  });
  assert.deepEqual(plan.rerun_recipe.focus.assets.slice(0, 1), [sdkUrl]);
  assert.match(renderMarkdownReport(report), /asset=none stack=https:\/\/cdn\.example\.test\/runtime-sdk\/1\.0\.0\/runtime-sdk\.js flows=1 statuses=candidate retrieval=none path=none score=none signals=none focus=core_signature_asset role=security_sdk_signature_generator/);
});

test("buildLocalReport gives generic business API capture actions", () => {
  const wafUrl = "https://cdn.example.test/security/waf-runtime.js";
  const stack = [{
    function: "calc",
    url: wafUrl,
    line: 2,
    column: 22,
    asset_id: "sha1:waf",
    asset_path: "assets/trace_demo/waf-aiso/dd9808.js"
  }];
  const events = [
    {_trace_index: 8, seq: 8, category: "reverse", api: "TextEncoder.encode", stack, origin: "https://www.example.test"},
    {
      _trace_index: 10,
      seq: 2,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{method: "GET", url: "https://www.example.test/", request_destination: "document", is_fetch_like_api: true}],
      origin: "https://www.example.test"
    },
    {
      _trace_index: 30,
      seq: 30,
      category: "network",
      api: "XMLHttpRequest.send",
      args: [{method: "POST", url: "https://telemetry.example.test/monitor_browser/collect/batch/"}],
      origin: "https://www.example.test",
      stack
    }
  ];
  const assets = [{
    asset_id: "sha1:waf",
    kind: "script",
    url: wafUrl,
    content_path: "assets/trace_demo/security/waf-runtime.js",
    content: "function calc(input){ const bytes=new TextEncoder().encode(input); return SHA256.digest(bytes); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_generic_business_api_plan.ndjson", events, assets});
  const nextPlan = report.signature.agent_evidence_pack.next_capture_plan;
  const plan = nextPlan.business_api_capture_plan;

  assert.equal(plan.start_url, "https://www.example.test/");
  assert.deepEqual(plan.target_endpoint_hints.map((hint) => hint.pattern), [
    "https://www.example.test/api/*",
    "fetch/XMLHttpRequest non-static endpoint"
  ]);
  assert.deepEqual(plan.normal_user_actions, [
    "load the start URL with full reverse/fingerprint capture enabled",
    "perform normal in-page actions that request feed, search, detail, or pagination data",
    "wait until a non-static fetch/XHR BrowserNetwork.request appears"
  ]);
  assert.deepEqual(nextPlan.capture_gate.target_endpoint_patterns, [
    "https://www.example.test/api/*",
    "fetch/XMLHttpRequest non-static endpoint"
  ]);
  assert.match(renderMarkdownReport(report), /action=perform normal in-page actions that request feed, search, detail, or pagination data/);
  assert.match(renderMarkdownReport(report), /success=BrowserNetwork\.request is correlated to Request\.constructor, fetch, or XMLHttpRequest/);
});

test("buildLocalReport uses the referrer as next capture start when only static SDK requests are anchored", () => {
  const pageUrl = "https://www.example.test/";
  const loaderUrl = "https://cdn.example.test/security/loader/index.js";
  const staticUrl = "https://cdn.example.test/app/static/js/async/10524.a27a87b5.js";
  const stack = [{function: "loader", url: loaderUrl, line: 2, column: 40, asset_id: "sha1:loader"}];
  const events = [
    {
      _trace_index: 10,
      seq: 10,
      category: "reverse",
      api: "JSON.stringify",
      stack,
      frame_url: pageUrl,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 11,
      seq: 11,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: staticUrl,
        request_destination: "script",
        is_fetch_like_api: true,
        referrer: pageUrl
      }],
      frame_url: pageUrl,
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:loader",
    kind: "script",
    url: loaderUrl,
    content_path: "assets/trace_demo/index.js",
    content: "function loader(){ return JSON.stringify({sdk: true}); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_static_only.ndjson", events, assets});
  const nextPlan = report.signature.agent_evidence_pack.next_capture_plan;

  assert.equal(nextPlan.rerun_recipe.start_url, pageUrl);
  assert.deepEqual(nextPlan.capture_gate.target_endpoint_patterns, [
    "https://www.example.test/api/*",
    "fetch/XMLHttpRequest non-static endpoint"
  ]);
  assert.equal(nextPlan.business_api_capture_plan.start_url, pageUrl);
  assert.match(renderMarkdownReport(report), /business_api_capture status=needs_business_api_anchor start_url=https:\/\/www\.example\.test\//);
});

test("buildLocalReport excludes browser internals from business API core assets", () => {
  const sdkUrl = "https://cdn.example.test/runtime-sdk/1.0.0/runtime-sdk.js";
  const chromeStack = [{function: "send", url: "chrome://resources/mojo/mojo/public/js/bindings.js", line: 1, column: 1}];
  const events = [
    {_trace_index: 8, seq: 8, category: "reverse", api: "DataView.getUint32", stack: chromeStack, origin: "https://www.example.test"},
    {_trace_index: 9, seq: 9, category: "network", api: "BrowserNetwork.request", args: [{method: "GET", url: "https://www.example.test/", is_fetch_like_api: true, request_destination: "document"}], origin: "https://www.example.test"},
    {_trace_index: 10, seq: 10, category: "network", api: "BrowserNetwork.request", args: [{method: "GET", url: sdkUrl, is_fetch_like_api: true, request_destination: "script"}], origin: "https://www.example.test"}
  ];
  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_business_core_assets.ndjson", events, assets: []});
  const businessPlan = report.signature.agent_evidence_pack.next_capture_plan.business_api_capture_plan;
  const focusAssetLabels = report.signature.agent_evidence_pack.next_capture_plan.focus_assets
    .map((asset) => asset.stack_url || asset.asset_id);

  assert.deepEqual(businessPlan.core_assets, [sdkUrl]);
  assert.doesNotMatch(JSON.stringify(businessPlan.core_assets), /chrome:\/\/resources/);
  assert.doesNotMatch(JSON.stringify(focusAssetLabels), /chrome:\/\/resources/);
});

test("buildLocalReport emits candidate pipeline for signature-absent network anchors", () => {
  const assetUrl = "https://cdn.example.test/secsdk.js";
  const stack = [{function: "signBeforeSend", url: assetUrl, line: 12, column: 4}];
  const events = [
    {
      _trace_index: 8,
      seq: 8,
      category: "reverse",
      api: "TextEncoder.encode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 9,
      seq: 9,
      category: "reverse",
      api: "SubtleCrypto.digest",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 10,
      seq: 10,
      category: "reverse",
      api: "btoa",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 11,
      seq: 11,
      category: "network",
      api: "XMLHttpRequest.send",
      args: [{method: "POST", url: "https://www.example.test/api/item/list?cursor=1"}],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:secsdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/secsdk.js",
    content: "async function signBeforeSend(input){ const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input)); return btoa(String(d)); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_absent_pipeline.ndjson", events, assets});
  const anchor = report.signature.agent_evidence_pack.signature_absent.network_anchors[0];

  assert.equal(anchor.endpoint, "https://www.example.test/api/item/list");
  assert.equal(anchor.candidate_signature_pipeline.confidence, "high");
  assert.deepEqual(report.signature.agent_evidence_pack.next_capture_plan.business_api_capture_status, {
    status: "captured",
    priority: "high",
    actionable_endpoint_count: 1,
    endpoints: [{
      endpoint: "https://www.example.test/api/item/list",
      flow_count: 1,
      readiness_statuses: ["candidate"],
      evidence_gaps: [
        "signature_terms_not_observed",
        "unsigned_input_not_observed",
        "signature_mutation_not_observed",
        "source_context_not_available",
        "data_links_not_observed"
      ]
    }],
    success_criteria_met: [
      "observed endpoint is not document_request, static_resource, or telemetry_endpoint"
    ],
    missing_evidence: [
      "signature_terms_not_observed",
      "unsigned_input_not_observed",
      "signature_mutation_not_observed",
      "source_context_not_available",
      "data_links_not_observed"
    ],
    next_actions: [
      "capture_signature_terms_or_mutation",
      "capture_unsigned_request_construction",
      "capture_url_search_params_mutation_or_header_set",
      "capture_or_retrieve_script_asset",
      "capture_object_ids_for_data_links"
    ]
  });
  assert.deepEqual(report.signature.agent_evidence_pack.next_capture_plan.capture_gate, {
    id: "business_api_anchor",
    status: "passed",
    priority: "high",
    required_event: "BrowserNetwork.request",
    required_renderer_apis: [
      "Request.constructor",
      "fetch",
      "XMLHttpRequest.open",
      "XMLHttpRequest.send"
    ],
    target_endpoint_patterns: ["https://www.example.test/api/item/list"],
    reject_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"],
    observed_actionable_endpoint_count: 1,
    matched_endpoints: ["https://www.example.test/api/item/list"],
    missing: [],
    remaining_analysis_gaps: [
      "signature_terms_not_observed",
      "unsigned_input_not_observed",
      "signature_mutation_not_observed",
      "source_context_not_available",
      "data_links_not_observed"
    ],
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
    },
    stop_when: "observed_actionable_endpoint_count > 0"
  });
  assert.deepEqual(anchor.candidate_signature_pipeline.stages.map((stage) => ({
    stage: stage.stage,
    runtime_apis: stage.runtime_apis
  })), [
    {stage: "text_or_string_decode", runtime_apis: ["TextEncoder.encode", "btoa"]},
    {stage: "hash_or_digest", runtime_apis: ["SubtleCrypto.digest"]},
    {stage: "signed_request", runtime_apis: ["XMLHttpRequest.send"]}
  ]);
  assert.match(renderMarkdownReport(report), /capture_gate id=business_api_anchor status=passed actionable=1 missing=none patterns=https:\/\/www\.example\.test\/api\/item\/list/);
  assert.match(renderMarkdownReport(report), /business_api_capture_status status=captured endpoints=1 missing=signature_terms_not_observed,unsigned_input_not_observed,signature_mutation_not_observed,source_context_not_available,data_links_not_observed/);
  assert.match(renderMarkdownReport(report), /anchor_pipeline=text_or_string_decode\[TextEncoder\.encode,btoa\]->hash_or_digest\[SubtleCrypto\.digest\]->signed_request\[XMLHttpRequest\.send\] confidence=high/);
});

test("buildLocalReport adds VMP hook analysis points to signature-absent network anchors", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "vmDispatch", url: assetUrl, line: 22, column: 4}];
  const events = [
    {
      _trace_index: 30,
      seq: 300,
      category: "reverse",
      api: "String.fromCharCode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 31,
      seq: 301,
      category: "reverse",
      api: "DataView.getUint8",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 32,
      seq: 302,
      category: "reverse",
      api: "Bitwise.xor",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 34,
      seq: 304,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1",
        is_fetch_like_api: true,
        has_request_body: true,
        upload_body: {element_count: 1, total_bytes: 64, in_memory_bytes: 64}
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: "function vmDispatch(vm){ return String.fromCharCode(vm.dv.getUint8(vm.pc++)) ^ vm.k; }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_absent_anchor_vmp_points.ndjson", events, assets});
  const anchor = report.signature.agent_evidence_pack.signature_absent.network_anchors
    .find((item) => item.api === "BrowserNetwork.request");

  assert.ok(anchor);
  assert.deepEqual(anchor.vmp_analysis_points.map((point) => ({
    type: point.type,
    seq_start: point.seq_start,
    seq_end: point.seq_end,
    families: point.families,
    apis: point.apis.map((item) => item.api),
    stack_urls: point.stack_urls.map((item) => item.stack_url)
  })), [
    {
      type: "vmp_string_decoder",
      seq_start: 300,
      seq_end: 300,
      families: ["string_decode"],
      apis: ["String.fromCharCode"],
      stack_urls: [assetUrl]
    },
    {
      type: "vmp_bytecode_or_register_access",
      seq_start: 301,
      seq_end: 301,
      families: ["byte_buffer"],
      apis: ["DataView.getUint8"],
      stack_urls: [assetUrl]
    },
    {
      type: "vmp_int_bitwise_pipeline",
      seq_start: 302,
      seq_end: 302,
      families: ["int_bitwise"],
      apis: ["Bitwise.xor"],
      stack_urls: [assetUrl]
    },
    {
      type: "vmp_runtime_cluster",
      seq_start: 300,
      seq_end: 302,
      families: ["byte_buffer", "int_bitwise", "string_decode"],
      apis: ["Bitwise.xor", "DataView.getUint8", "String.fromCharCode"],
      stack_urls: [assetUrl]
    }
  ]);
  assert.match(renderMarkdownReport(report), /vmp_points=vmp_string_decoder@300\.\.300,vmp_bytecode_or_register_access@301\.\.301,vmp_int_bitwise_pipeline@302\.\.302,vmp_runtime_cluster@300\.\.302/);
});

test("buildLocalReport emits agent-readable candidate trace chains when signature terms are absent", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "sendByVm",
    url: assetUrl,
    line: 4,
    column: 27,
    asset_id: "sha1:runtime-sdk",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {
      _trace_index: 40,
      seq: 400,
      category: "network",
      api: "Request.constructor",
      args: [{method: "POST", url: "https://www.example.test/api/feed/list?cursor=1"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 41,
      seq: 401,
      category: "reverse",
      api: "TextEncoder.encode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 42,
      seq: 402,
      category: "reverse",
      api: "SubtleCrypto.digest",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 43,
      seq: 403,
      category: "reverse",
      api: "Bitwise.xor",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 45,
      seq: 10,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1",
        request_initiator: "https://www.example.test",
        is_fetch_like_api: true,
        has_request_body: true,
        upload_body: {element_count: 1, total_bytes: 96, in_memory_bytes: 96}
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: [
      "async function sendByVm(input) {",
      "  const material = input.url + input.seed;",
      "  const data = new TextEncoder().encode(material);",
      "  const digest = await crypto.subtle.digest('SHA-256', data);",
      "  const mixed = (digest.byteLength ^ 2654435761) >>> 0;",
      "  return fetch('/api/feed/list', {method:'POST', body: mixed});",
      "}"
    ].join("\n")
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_absent_candidate_chains.ndjson", events, assets});
  const pack = report.signature.agent_evidence_pack;
  const absent = pack.signature_absent;
  const chain = absent.candidate_trace_chains[0];

  assert.equal(chain.id, "absent_candidate_chain_1");
  assert.equal(chain.endpoint, "https://www.example.test/api/feed/list");
  assert.equal(chain.confidence, "high");
  assert.deepEqual(chain.hook_points.map((point) => point.type), [
    "vmp_hash_or_signature_pipeline",
    "vmp_int_bitwise_pipeline",
    "vmp_runtime_cluster"
  ]);
  assert.deepEqual(chain.steps.map((step) => ({
    phase: step.phase,
    api: step.api,
    seq: step.seq,
    relation: step.relation,
    trace_distance: step.trace_distance
  })), [
    {phase: "request_construction", api: "Request.constructor", seq: 400, relation: "before_browser_request", trace_distance: 5},
    {phase: "vmp_hash_or_signature_pipeline", api: "TextEncoder.encode", seq: 401, relation: "before_request", trace_distance: 4},
    {phase: "vmp_hash_or_signature_pipeline", api: "SubtleCrypto.digest", seq: 402, relation: "before_request", trace_distance: 3},
    {phase: "vmp_int_bitwise_pipeline", api: "Bitwise.xor", seq: 403, relation: "before_request", trace_distance: 2},
    {phase: "signed_request", api: "BrowserNetwork.request", seq: 10, relation: "anchor", trace_distance: 0}
  ]);
  assert.deepEqual(chain.request_context, {
    request_initiator: "https://www.example.test",
    referrer: "",
    upload: {element_count: 1, total_bytes: 96, in_memory_bytes: 96},
    renderer_link: "Request.constructor@400:before_browser_request:5",
    capture_gaps: []
  });
  assert.deepEqual(report.signature.agent_evidence_pack.signature_material_flows.map((flow) => ({
    id: flow.id,
    flow_id: flow.flow_id,
    endpoint: flow.endpoint,
    confidence: flow.confidence,
    evidence_status: flow.evidence_status,
    function: flow.function,
    stack_url: flow.stack_url,
    asset_id: flow.asset_id,
    seq_start: flow.seq_start,
    seq_end: flow.seq_end,
    target_params: flow.target_params,
    stage_count: flow.stage_count,
    stages: flow.stages.map((stage) => ({
      stage: stage.stage,
      runtime_apis: stage.runtime_apis,
      object_refs: stage.object_refs
    })),
    data_links: flow.data_links
  })), [{
    id: "material_flow_1",
    flow_id: "absent_candidate_chain_1",
    endpoint: "https://www.example.test/api/feed/list",
    confidence: "high",
    evidence_status: "signature_absent_candidate",
    function: "sendByVm",
    stack_url: assetUrl,
    asset_id: "sha1:runtime-sdk",
    seq_start: 10,
    seq_end: 403,
    target_params: ["X-Signature", "X-Secondary-Signature"],
    stage_count: 6,
    stages: [
      {stage: "request_construction", runtime_apis: ["Request.constructor"], object_refs: []},
      {stage: "request_body", runtime_apis: ["BrowserNetwork.request"], object_refs: []},
      {stage: "text_or_string_decode", runtime_apis: ["TextEncoder.encode"], object_refs: []},
      {stage: "integer_mixing", runtime_apis: ["Bitwise.xor"], object_refs: []},
      {stage: "hash_or_digest", runtime_apis: ["SubtleCrypto.digest"], object_refs: []},
      {stage: "signed_request", runtime_apis: ["BrowserNetwork.request"], object_refs: []}
    ],
    data_links: []
  }]);
  const [absentMaterialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  assert.deepEqual(absentMaterialFlow.analysis_readiness, {
    status: "candidate",
    observed_stages: [
      "request_construction",
      "request_body",
      "text_or_string_decode",
      "integer_mixing",
      "hash_or_digest",
      "signed_request"
    ],
    missing_stages: [
      "signature_mutation"
    ],
    evidence_gaps: [
      "signature_terms_not_observed",
      "signature_mutation_not_observed"
    ],
    next_actions: [
      "capture_signature_terms_or_mutation",
      "capture_url_search_params_mutation_or_header_set"
    ]
  });
  assert.deepEqual(absentMaterialFlow.source_context_refs, ["sha1:runtime-sdk:2-6"]);
  assert.equal(absentMaterialFlow.source_contexts.length, 1);
  assert.match(absentMaterialFlow.source_contexts[0].preview, /TextEncoder/);
  assert.match(absentMaterialFlow.source_contexts[0].preview, /crypto\.subtle\.digest/);
  assert.deepEqual(absentMaterialFlow.vmp_hook_points.map((point) => ({
    type: point.type,
    status: point.status,
    observed_apis: point.observed_apis
  })).filter((point) => point.status === "observed"), [
    {
      type: "vmp_hash_or_signature_pipeline",
      status: "observed",
      observed_apis: ["TextEncoder.encode", "SubtleCrypto.digest"]
    },
    {
      type: "vmp_int_bitwise_pipeline",
      status: "observed",
      observed_apis: ["Bitwise.xor"]
    }
  ]);
  assert.deepEqual({
    priority: pack.next_capture_plan.priority,
    target_terms: pack.next_capture_plan.target_terms,
    recommended_flags: pack.next_capture_plan.recommended_flags
  }, {
    priority: "high",
    target_terms: ["X-Signature", "X-Secondary-Signature"],
    recommended_flags: [
      "--xtrace-categories=reverse,fingerprint",
      "--xtrace-capture-values=full",
      "--xtrace-capture-assets=full",
      "--xtrace-max-value-bytes=262144"
    ]
  });
  assert.deepEqual(pack.next_capture_plan.gap_summary.map((gap) => ({
    gap: gap.gap,
    flow_count: gap.flow_count,
    priority: gap.priority,
    next_actions: gap.next_actions
  })), [
    {
      gap: "signature_terms_not_observed",
      flow_count: 1,
      priority: "high",
      next_actions: ["capture_signature_terms_or_mutation"]
    },
    {
      gap: "signature_mutation_not_observed",
      flow_count: 1,
      priority: "high",
      next_actions: ["capture_url_search_params_mutation_or_header_set"]
    }
  ]);
  assert.deepEqual(pack.next_capture_plan.hook_focus.slice(0, 3).map((hook) => ({
    type: hook.type,
    missing_flow_count: hook.missing_flow_count,
    priority: hook.priority,
    next_action: hook.next_action
  })), [
    {
      type: "vmp_string_decoder",
      missing_flow_count: 1,
      priority: "medium",
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_bytecode_or_register_access",
      missing_flow_count: 1,
      priority: "medium",
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_array_table",
      missing_flow_count: 1,
      priority: "medium",
      next_action: "add_or_link_hooks"
    }
  ]);
  assert.deepEqual(pack.next_capture_plan.focus_endpoints, [{
    endpoint: "https://www.example.test/api/feed/list",
    flow_count: 1,
    readiness_statuses: ["candidate"],
    evidence_gaps: [
      "signature_terms_not_observed",
      "signature_mutation_not_observed"
    ]
  }]);
  assert.deepEqual(pack.next_capture_plan.focus_assets, [{
    asset_id: "sha1:runtime-sdk",
    stack_url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    score: 1,
    signals: ["vmp_string_decode_refs"],
    flow_count: 1,
    readiness_statuses: ["candidate"],
    asset_focus: "core_signature_asset",
    asset_role: "security_sdk_signature_generator"
  }]);
  assert.deepEqual(pack.next_capture_plan.rerun_recipe, {
    profile: "interactive_full_capture",
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
      EXPECTED_CHROMIUM_APP,
      "--url",
      "https://www.example.test/api/feed/list",
      "--log-dir",
      EXPECTED_LOG_DIR,
      "--xtrace-categories",
      "reverse,fingerprint",
      "--xtrace-capture-values",
      "full",
      "--xtrace-capture-assets",
      "full",
      "--xtrace-max-value-bytes",
      "262144",
      "--xtrace-asset-max-bytes",
      "2097152"
    ],
    env: {
      XTRACE_CATEGORIES: "reverse,fingerprint",
      XTRACE_CAPTURE_VALUES: "full",
      XTRACE_CAPTURE_ASSETS: "full",
      XTRACE_MAX_VALUE_BYTES: "262144",
      XTRACE_ASSET_MAX_BYTES: "2097152"
    },
    focus: {
      target_terms: ["X-Signature", "X-Secondary-Signature"],
      endpoints: ["https://www.example.test/api/feed/list"],
      assets: ["sha1:runtime-sdk@https://cdn.example.test/runtime-sdk.js"],
      gaps: [
        "signature_terms_not_observed",
        "signature_mutation_not_observed"
      ],
      hooks: [
        "vmp_string_decoder",
        "vmp_bytecode_or_register_access",
        "vmp_array_table"
      ]
    }
  });
  assert.match(renderMarkdownReport(report), /candidate_chain=absent_candidate_chain_1 confidence=high endpoint=https:\/\/www\.example\.test\/api\/feed\/list steps=request_construction\[Request\.constructor@400\]->vmp_hash_or_signature_pipeline\[TextEncoder\.encode@401,SubtleCrypto\.digest@402\]->vmp_int_bitwise_pipeline\[Bitwise\.xor@403\]->signed_request\[BrowserNetwork\.request@10\]/);
  assert.match(renderMarkdownReport(report), /Next Capture Plan/);
  assert.match(renderMarkdownReport(report), /rerun_recipe start_url=https:\/\/www\.example\.test\/api\/feed\/list profile=interactive_full_capture/);
  assert.ok(renderMarkdownReport(report).includes(`launcher_args=run --chromium ${EXPECTED_CHROMIUM_APP} --url https://www.example.test/api/feed/list`));
  assert.match(renderMarkdownReport(report), /gap=signature_terms_not_observed flows=1 priority=high next=capture_signature_terms_or_mutation/);
  assert.match(renderMarkdownReport(report), /material_flow_1 flow=absent_candidate_chain_1 confidence=high status=signature_absent_candidate readiness=candidate gaps=signature_terms_not_observed,signature_mutation_not_observed/);
});

test("buildLocalReport infers initiator from nearby VMP stack when renderer request link is missing", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "vmDispatch", url: assetUrl, line: 77, column: 13}];
  const events = [
    {
      _trace_index: 70,
      seq: 700,
      category: "reverse",
      api: "String.fromCharCode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 71,
      seq: 701,
      category: "reverse",
      api: "DataView.getUint32",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 72,
      seq: 702,
      category: "reverse",
      api: "Array.prototype.join",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 75,
      seq: 15,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1",
        request_initiator: "https://www.example.test",
        is_fetch_like_api: true,
        has_request_body: true,
        upload_body: {element_count: 1, total_bytes: 128, in_memory_bytes: 128}
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: "function vmDispatch(vm){ return String.fromCharCode(vm.dv.getUint32(vm.pc++)); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_absent_inferred_initiator.ndjson", events, assets});
  const absent = report.signature.agent_evidence_pack.signature_absent;
  const anchor = absent.network_anchors.find((item) => item.api === "BrowserNetwork.request");
  const chain = absent.candidate_trace_chains[0];

  assert.deepEqual(anchor.request_context.inferred_initiator, {
    relation: "nearby_vmp_stack",
    confidence: "medium",
    function: "vmDispatch",
    stack_url: assetUrl,
    asset_id: "sha1:runtime-sdk",
    event_count: 3,
    seq_start: 700,
    seq_end: 702,
    trace_distance_min: 3,
    trace_distance_max: 5,
    families: ["array_table", "byte_buffer", "string_decode"],
    apis: [
      {api: "Array.prototype.join", count: 1},
      {api: "DataView.getUint32", count: 1},
      {api: "String.fromCharCode", count: 1}
    ]
  });
  assert.deepEqual(chain.inferred_initiator, anchor.request_context.inferred_initiator);
  assert.deepEqual(chain.request_context.capture_gaps, ["renderer_stack_missing"]);
  assert.match(renderMarkdownReport(report), /inferred_initiator=vmDispatch@https:\/\/cdn\.example\.test\/runtime-sdk\.js:medium:events3/);
});

test("buildLocalReport emits request context and capture gaps for signature-absent anchors", () => {
  const assetUrl = "https://cdn.example.test/secsdk.js";
  const stack = [{function: "preparePayload", url: assetUrl, line: 8, column: 2}];
  const events = [
    {
      _trace_index: 18,
      seq: 18,
      category: "reverse",
      api: "btoa",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 20,
      seq: 2,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1",
        request_initiator: "https://www.example.test",
        referrer: "https://www.example.test/home",
        originated_from_service_worker: true,
        has_user_gesture: false,
        is_fetch_like_api: true,
        headers: [
          {name: "content-type", value: "application/json"},
          {name: "cookie", redacted: true, value_length: 20}
        ]
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:secsdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/secsdk.js",
    content: "function preparePayload(input){ return btoa(input); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_absent_request_context.ndjson", events, assets});
  const anchor = report.signature.agent_evidence_pack.signature_absent.network_anchors[0];

  assert.deepEqual(anchor.request_context, {
    request_initiator: "https://www.example.test",
    referrer: "https://www.example.test/home",
    originated_from_service_worker: true,
    has_user_gesture: false,
    header_names: ["content-type", "cookie"],
    sensitive_header_names: ["cookie"],
    capture_gaps: [
      "request_body_not_captured",
      "service_worker_source_context_needed",
      "renderer_stack_missing"
    ]
  });
  assert.match(renderMarkdownReport(report), /request_context=initiator=https:\/\/www\.example\.test sw=true user_gesture=false headers=content-type,cookie upload=none gaps=request_body_not_captured,service_worker_source_context_needed,renderer_stack_missing/);
});

test("buildLocalReport preserves upload metadata for signature-absent anchors", () => {
  const assetUrl = "https://cdn.example.test/secsdk.js";
  const stack = [{function: "preparePayload", url: assetUrl, line: 8, column: 2}];
  const events = [
    {
      _trace_index: 18,
      seq: 18,
      category: "reverse",
      api: "btoa",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 20,
      seq: 2,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1",
        request_initiator: "https://www.example.test",
        referrer: "https://www.example.test/home",
        has_request_body: true,
        upload_body: {
          element_count: 1,
          total_bytes: 128,
          in_memory_bytes: 128,
          has_file: false,
          has_blob: false,
          has_data_pipe: false,
          has_chunked_data_pipe: false,
          preview_sha256: "0123456789abcdef",
          preview_size: 128,
          truncated: false
        },
        headers: [{name: "content-type", value: "application/json"}]
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:secsdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/secsdk.js",
    content: "function preparePayload(input){ return btoa(input); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_absent_upload_metadata.ndjson", events, assets});
  const anchor = report.signature.agent_evidence_pack.signature_absent.network_anchors[0];

  assert.deepEqual(anchor.request_context.upload_body, {
    element_count: 1,
    total_bytes: 128,
    in_memory_bytes: 128,
    has_file: false,
    has_blob: false,
    has_data_pipe: false,
    has_chunked_data_pipe: false,
    preview_sha256: "0123456789abcdef",
    preview_size: 128,
    truncated: false
  });
  assert.ok(!anchor.request_context.capture_gaps.includes("request_body_not_captured"));
  assert.match(renderMarkdownReport(report), /upload=elements:1 bytes:128 memory:128/);
});

test("buildLocalReport links browser network anchors to renderer request stacks", () => {
  const assetUrl = "https://cdn.example.test/secsdk.js";
  const stack = [{function: "sendSignedRequest", url: assetUrl, line: 18, column: 6}];
  const events = [
    {
      _trace_index: 12,
      seq: 1200,
      category: "network",
      api: "Request.constructor",
      args: [{method: "POST", url: "https://www.example.test/api/feed/list?cursor=1"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 14,
      seq: 1202,
      category: "reverse",
      api: "btoa",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 18,
      seq: 3,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1",
        request_initiator: "https://www.example.test",
        is_fetch_like_api: true,
        has_request_body: true,
        upload_body: {element_count: 1, total_bytes: 32, in_memory_bytes: 32}
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:secsdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/secsdk.js",
    content: "function sendSignedRequest(input){ return fetch('/api/feed/list', {method: 'POST', body: btoa(input)}); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_renderer_request_link.ndjson", events, assets});
  const anchor = report.signature.agent_evidence_pack.signature_absent.network_anchors
    .find((item) => item.api === "BrowserNetwork.request");

  assert.ok(anchor);
  assert.deepEqual(anchor.request_context.renderer_request_link, {
    trace_index: 12,
    seq: 1200,
    api: "Request.constructor",
    method: "POST",
    endpoint: "https://www.example.test/api/feed/list",
    relation: "before_browser_request",
    trace_distance: 6,
    function: "sendSignedRequest",
    stack_url: assetUrl,
    asset_id: "sha1:secsdk",
    confidence: "high"
  });
  assert.ok(!anchor.request_context.capture_gaps.includes("renderer_stack_missing"));
  assert.match(renderMarkdownReport(report), /renderer_link=Request\.constructor@1200:before_browser_request:6:sendSignedRequest/);
});

test("buildLocalReport prefers explicit request URL over initiator URL for browser network anchors", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "preparePayload", url: assetUrl, line: 8, column: 2}];
  const events = [
    {
      _trace_index: 10,
      seq: 10,
      category: "reverse",
      api: "btoa",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 12,
      seq: 2,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        request_initiator: "https://www.example.test",
        referrer: "https://www.example.test/home",
        url: "https://api.example.test/feed/list?cursor=1",
        is_fetch_like_api: true
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: "function preparePayload(input){ return btoa(input); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_browser_url_priority.ndjson", events, assets});
  const anchor = report.signature.agent_evidence_pack.signature_absent.network_anchors[0];

  assert.equal(anchor.endpoint, "https://api.example.test/feed/list");
  assert.equal(anchor.host, "api.example.test");
  assert.equal(anchor.path, "/feed/list");
});

test("buildLocalReport exposes top-level VMP hook coverage gaps", () => {
  const events = [
    {seq: 10, category: "reverse", api: "DataView.getUint8", args: [{byte_offset: 0, result: 31}]},
    {seq: 11, category: "reverse", api: "Bitwise.xor", args: [{left: 31, right: 7, result: 24}]},
    {seq: 12, category: "reverse", api: "Math.imul", args: [{x: 24, y: 2654435761, result: -392329960}]}
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp_hook_coverage.ndjson", events, assets: []});

  assert.deepEqual(report.vmp.hook_coverage.observed_point_types, [
    "vmp_bytecode_or_register_access",
    "vmp_hash_or_signature_pipeline",
    "vmp_int_bitwise_pipeline"
  ]);
  assert.ok(report.vmp.hook_coverage.missing_point_types.includes("vmp_dynamic_dispatch"));
  assert.ok(report.vmp.hook_coverage.missing_point_types.includes("vmp_string_decoder"));
  assert.deepEqual(report.vmp.hook_coverage.coverage_by_type.vmp_bytecode_or_register_access, {
    observed: true,
    event_count: 1,
    families: ["byte_buffer"],
    apis: [{api: "DataView.getUint8", count: 1}]
  });
  assert.deepEqual(
    report.vmp.hook_coverage.hook_gaps.find((gap) => gap.type === "vmp_dynamic_dispatch"),
    {
      type: "vmp_dynamic_dispatch",
      priority: "medium",
      reason: "dynamic dispatch hooks are missing in the VMP runtime trace",
      suggested_hooks: [
        "Reflect.apply",
        "Function.prototype.call",
        "Function.prototype.apply",
        "Object.keys",
        "Reflect.ownKeys"
      ],
      event_count: 0
    }
  );
  const bytecodeHookPoint = report.vmp.hook_analysis_points.find((point) =>
    point.type === "vmp_bytecode_or_register_access");
  assert.deepEqual(bytecodeHookPoint, {
    type: "vmp_bytecode_or_register_access",
    status: "observed",
    priority: "medium",
    analysis_goal: "trace VM bytecode/register reads and typed-array register movement",
    families: ["byte_buffer", "typed_array"],
    observed_event_count: 1,
    observed_apis: [{api: "DataView.getUint8", count: 1}],
    suggested_hooks: [
      "ArrayBuffer.constructor",
      "DataView.getUint8",
      "DataView.getUint16",
      "DataView.getUint32",
      "TypedArray.at",
      "TypedArray.slice"
    ],
    reason: "ArrayBuffer/DataView/TypedArray byte reads or writes often used as VM bytecode/register access",
    next_action: "review_observed_events"
  });
  const dispatchHookPoint = report.vmp.hook_analysis_points.find((point) =>
    point.type === "vmp_dynamic_dispatch");
  assert.deepEqual(dispatchHookPoint, {
    type: "vmp_dynamic_dispatch",
    status: "missing",
    priority: "medium",
    analysis_goal: "trace VM handler dispatch and indirect function invocation",
    families: ["dynamic_dispatch"],
    observed_event_count: 0,
    observed_apis: [],
    suggested_hooks: [
      "Reflect.apply",
      "Function.prototype.call",
      "Function.prototype.apply",
      "Object.keys",
      "Reflect.ownKeys"
    ],
    reason: "dynamic dispatch hooks are missing in the VMP runtime trace",
    next_action: "add_or_enable_hooks"
  });
  assert.match(renderMarkdownReport(report), /VMP Hook Coverage/);
  assert.match(renderMarkdownReport(report), /VMP Hook Analysis Points/);
  assert.match(renderMarkdownReport(report), /hook_point vmp_dynamic_dispatch status=missing next=add_or_enable_hooks/);
  assert.match(renderMarkdownReport(report), /missing=vmp_string_decoder/);
});

test("buildLocalReport exposes VMP anti-debug and timing gate hook points", () => {
  const stack = [{function: "guardVm", url: "https://cdn.example.test/vmp-guard.js", line: 9, column: 5}];
  const events = [
    {seq: 30, category: "reverse", api: "Date.now", args: [{result: 1780000000000}], stack},
    {seq: 31, category: "reverse", api: "Performance.now", args: [{result: 1234.5}], stack},
    {seq: 32, category: "reverse", api: "console.debug", args: [{argc: 1}], stack}
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp_guard.ndjson", events, assets: []});

  assert.deepEqual(report.vmp.hook_coverage.coverage_by_type.vmp_anti_debug_timing_gate, {
    observed: true,
    event_count: 3,
    families: ["anti_debug_timing"],
    apis: [
      {api: "console.debug", count: 1},
      {api: "Date.now", count: 1},
      {api: "Performance.now", count: 1}
    ]
  });
  const hookPoint = report.vmp.hook_analysis_points.find((point) =>
    point.type === "vmp_anti_debug_timing_gate");
  assert.deepEqual(hookPoint, {
    type: "vmp_anti_debug_timing_gate",
    status: "observed",
    priority: "high",
    analysis_goal: "trace VMP anti-debug checks, timing gates, and console probes",
    families: ["anti_debug_timing"],
    observed_event_count: 3,
    observed_apis: [
      {api: "console.debug", count: 1},
      {api: "Date.now", count: 1},
      {api: "Performance.now", count: 1}
    ],
    suggested_hooks: [
      "Performance.now",
      "Date.now",
      "console.debug",
      "console.clear",
      "debugger.statement"
    ],
    reason: "timing and console/debugger probes often gate VMP execution or detect analysis",
    next_action: "review_observed_events"
  });
  assert.match(renderMarkdownReport(report), /hook_point vmp_anti_debug_timing_gate status=observed next=review_observed_events/);
});

test("buildLocalReport exposes VMP source integrity probe hook points", () => {
  const stack = [{function: "probeSource", url: "https://cdn.example.test/vmp-source.js", line: 14, column: 9}];
  const events = [
    {
      seq: 40,
      category: "reverse",
      api: "Function.prototype.toString",
      args: [{receiver_type: "function", result_length: 96, native_like: false}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp_source_probe.ndjson", events, assets: []});

  assert.deepEqual(report.vmp.hook_coverage.coverage_by_type.vmp_source_integrity_probe, {
    observed: true,
    event_count: 1,
    families: ["source_probe"],
    apis: [{api: "Function.prototype.toString", count: 1}]
  });
  const hookPoint = report.vmp.hook_analysis_points.find((point) =>
    point.type === "vmp_source_integrity_probe");
  assert.deepEqual(hookPoint, {
    type: "vmp_source_integrity_probe",
    status: "observed",
    priority: "high",
    analysis_goal: "trace source/native-code probes used for anti-hook and VMP integrity checks",
    families: ["source_probe"],
    observed_event_count: 1,
    observed_apis: [{api: "Function.prototype.toString", count: 1}],
    suggested_hooks: ["Function.prototype.toString"],
    reason: "source and native-code probes often detect JS hooks or guard VMP execution paths",
    next_action: "review_observed_events"
  });
  assert.match(renderMarkdownReport(report), /hook_point vmp_source_integrity_probe status=observed next=review_observed_events/);
});

test("buildLocalReport exposes VMP stack trace probe hook points", () => {
  const stack = [{function: "probeStack", url: "https://cdn.example.test/vmp-stack.js", line: 22, column: 11}];
  const events = [
    {
      seq: 50,
      category: "reverse",
      api: "Error.captureStackTrace",
      args: [{target_is_object: true, has_constructor_opt: false}],
      stack
    },
    {
      seq: 51,
      category: "reverse",
      api: "Error.stack.get",
      args: [{stack_source: "error_stack_data", has_formatted_stack: false}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp_stack_probe.ndjson", events, assets: []});

  assert.deepEqual(report.vmp.hook_coverage.coverage_by_type.vmp_stack_trace_probe, {
    observed: true,
    event_count: 2,
    families: ["stack_probe"],
    apis: [
      {api: "Error.captureStackTrace", count: 1},
      {api: "Error.stack.get", count: 1}
    ]
  });
  const hookPoint = report.vmp.hook_analysis_points.find((point) =>
    point.type === "vmp_stack_trace_probe");
  assert.deepEqual(hookPoint, {
    type: "vmp_stack_trace_probe",
    status: "observed",
    priority: "high",
    analysis_goal: "trace Error stack capture/read probes used for stack-shape checks and guarded VMP paths",
    families: ["stack_probe"],
    observed_event_count: 2,
    observed_apis: [
      {api: "Error.captureStackTrace", count: 1},
      {api: "Error.stack.get", count: 1}
    ],
    suggested_hooks: ["Error.captureStackTrace", "Error.stack.get"],
    reason: "stack trace probes often detect call-stack shape, debugger state, or guarded VM execution paths",
    next_action: "review_observed_events"
  });
  assert.match(renderMarkdownReport(report), /hook_point vmp_stack_trace_probe status=observed next=review_observed_events/);
});

test("buildLocalReport exposes VMP exception control-flow hook points", () => {
  const stack = [{function: "guardedVmPath", url: "https://cdn.example.test/vmp-exception.js", line: 31, column: 7}];
  const events = [
    {
      seq: 60,
      category: "reverse",
      api: "Error.constructor",
      args: [{has_message: true, has_options: false}],
      stack
    },
    {
      seq: 61,
      category: "reverse",
      api: "Exception.throw",
      args: [{
        exception_type: "js_error",
        catch_prediction: "caught_by_javascript",
        catchable_by_javascript: true,
        is_stack_overflow: false
      }],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp_exception_probe.ndjson", events, assets: []});

  assert.deepEqual(report.vmp.hook_coverage.coverage_by_type.vmp_exception_control_flow, {
    observed: true,
    event_count: 2,
    families: ["exception_probe"],
    apis: [
      {api: "Error.constructor", count: 1},
      {api: "Exception.throw", count: 1}
    ]
  });
  const hookPoint = report.vmp.hook_analysis_points.find((point) =>
    point.type === "vmp_exception_control_flow");
  assert.deepEqual(hookPoint, {
    type: "vmp_exception_control_flow",
    status: "observed",
    priority: "high",
    analysis_goal: "trace thrown exceptions and Error construction used for guarded VMP control flow",
    families: ["exception_probe"],
    observed_event_count: 2,
    observed_apis: [
      {api: "Error.constructor", count: 1},
      {api: "Exception.throw", count: 1}
    ],
    suggested_hooks: ["Error.constructor", "Exception.throw"],
    reason: "exception probes often mark VM branch gates, opaque predicates, or anti-debug control flow",
    next_action: "review_observed_events"
  });
  assert.match(renderMarkdownReport(report), /hook_point vmp_exception_control_flow status=observed next=review_observed_events/);
});

test("buildLocalReport exposes VMP string transform and regexp probe hook points", () => {
  const stack = [{function: "normalizeSignatureMaterial", url: "https://cdn.example.test/vmp-strings.js", line: 44, column: 13}];
  const events = [
    {
      seq: 70,
      category: "reverse",
      api: "String.prototype.slice",
      args: [{subject_length: 32, start: 0, end: 7, result_preview: "X-Signature", result_length: 7}],
      stack
    },
    {
      seq: 71,
      category: "reverse",
      api: "String.prototype.indexOf",
      args: [{subject_length: 32, search_length: 8, position: 0, result: 12}],
      stack
    },
    {
      seq: 72,
      category: "reverse",
      api: "StringAdd",
      args: [{left_ref: "string:length:12", right_ref: "string:length:8", result_ref: "string:length:20", result_length: 20}],
      stack
    },
    {
      seq: 73,
      category: "reverse",
      api: "StringAdd.constant_lhs",
      args: [{left_ref: "string:length:8", right_ref: "string:length:10", result_ref: "string:length:18", result_length: 18}],
      stack
    },
    {
      seq: 74,
      category: "reverse",
      api: "RegExp.prototype.test",
      args: [{input_length: 32, matched: true}],
      stack
    },
    {
      seq: 75,
      category: "reverse",
      api: "RegExp.prototype.exec",
      args: [{input_length: 32, matched: true}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp_string_regexp.ndjson", events, assets: []});

  assert.deepEqual(report.vmp.hook_coverage.coverage_by_type.vmp_string_transform, {
    observed: true,
    event_count: 4,
    families: ["string_transform"],
    apis: [
      {api: "String.prototype.indexOf", count: 1},
      {api: "String.prototype.slice", count: 1},
      {api: "StringAdd", count: 1},
      {api: "StringAdd.constant_lhs", count: 1}
    ]
  });
  assert.deepEqual(report.vmp.hook_coverage.coverage_by_type.vmp_regexp_probe, {
    observed: true,
    event_count: 2,
    families: ["regexp_probe"],
    apis: [
      {api: "RegExp.prototype.exec", count: 1},
      {api: "RegExp.prototype.test", count: 1}
    ]
  });
  assert.deepEqual(report.vmp.hook_analysis_points.find((point) =>
    point.type === "vmp_string_transform"), {
    type: "vmp_string_transform",
    status: "observed",
    priority: "medium",
    analysis_goal: "trace string slicing, searching, and normalization around VM material",
    families: ["string_transform"],
    observed_event_count: 4,
    observed_apis: [
      {api: "String.prototype.indexOf", count: 1},
      {api: "String.prototype.slice", count: 1},
      {api: "StringAdd", count: 1},
      {api: "StringAdd.constant_lhs", count: 1}
    ],
    suggested_hooks: [
      "StringAdd",
      "StringAdd.constant_lhs",
      "StringAdd.constant_rhs",
      "String.prototype.slice",
      "String.prototype.substring",
      "String.prototype.indexOf",
      "String.prototype.includes"
    ],
    reason: "string transform hooks often mark parameter extraction, canonicalization, and VM token assembly",
    next_action: "review_observed_events"
  });
  assert.deepEqual(report.vmp.hook_analysis_points.find((point) =>
    point.type === "vmp_regexp_probe"), {
    type: "vmp_regexp_probe",
    status: "observed",
    priority: "medium",
    analysis_goal: "trace regular-expression probes used to parse or classify VM/request material",
    families: ["regexp_probe"],
    observed_event_count: 2,
    observed_apis: [
      {api: "RegExp.prototype.exec", count: 1},
      {api: "RegExp.prototype.test", count: 1}
    ],
    suggested_hooks: [
      "RegExp.prototype.test",
      "RegExp.prototype.exec"
    ],
    reason: "regular-expression probes often mark token extraction, branch tests, or request-material parsing",
    next_action: "review_observed_events"
  });
  assert.match(renderMarkdownReport(report), /hook_point vmp_string_transform status=observed next=review_observed_events/);
  assert.match(renderMarkdownReport(report), /hook_point vmp_regexp_probe status=observed next=review_observed_events/);
});

test("buildLocalReport exposes VMP URL encoding boundary hook points", () => {
  const stack = [{function: "canonicalizeRequestMaterial", url: "https://cdn.example.test/vmp-url.js", line: 18, column: 21}];
  const events = [
    {
      seq: 80,
      category: "reverse",
      api: "encodeURIComponent",
      args: [{input_length: 21, result_length: 31, result_preview: "q%3Dvideo%2520id%26page%3D1"}],
      stack
    },
    {
      seq: 81,
      category: "reverse",
      api: "decodeURIComponent",
      args: [{input_length: 31, result_length: 21, result_preview: "q=video%20id&page=1"}],
      stack
    },
    {
      seq: 82,
      category: "reverse",
      api: "URLSearchParams.toString",
      args: [{search_params_id: 12, size: 2, serialized: "q=video+id&page=1"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_vmp_url_encoding.ndjson", events, assets: []});

  assert.deepEqual(report.vmp.hook_coverage.coverage_by_type.vmp_url_encoding_boundary, {
    observed: true,
    event_count: 3,
    families: ["url_encoding"],
    apis: [
      {api: "decodeURIComponent", count: 1},
      {api: "encodeURIComponent", count: 1},
      {api: "URLSearchParams.toString", count: 1}
    ]
  });
  assert.deepEqual(report.vmp.hook_analysis_points.find((point) =>
    point.type === "vmp_url_encoding_boundary"), {
    type: "vmp_url_encoding_boundary",
    status: "observed",
    priority: "high",
    analysis_goal: "trace URL and query-string encoding boundaries before request material enters signing or VM mixing",
    families: ["url_encoding"],
    observed_event_count: 3,
    observed_apis: [
      {api: "decodeURIComponent", count: 1},
      {api: "encodeURIComponent", count: 1},
      {api: "URLSearchParams.toString", count: 1}
    ],
    suggested_hooks: [
      "encodeURIComponent",
      "decodeURIComponent",
      "encodeURI",
      "decodeURI",
      "URLSearchParams.toString"
    ],
    reason: "URL encoding hooks often mark request canonicalization before signature or VMP integer mixing",
    next_action: "review_observed_events"
  });
  assert.match(renderMarkdownReport(report), /hook_point vmp_url_encoding_boundary status=observed next=review_observed_events/);
});

test("buildLocalReport links browser network anchors by network correlation key", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "sendSignedRequest", url: assetUrl, line: 18, column: 6}];
  const events = [
    {
      _trace_index: 100,
      seq: 3100,
      category: "network",
      api: "Request.constructor",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1",
        network_correlation_key: "sha1:network-key"
      }],
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 7600,
      seq: 7600,
      category: "reverse",
      api: "TextEncoder.encode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 9000,
      seq: 22,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1",
        request_initiator: "https://www.example.test",
        is_fetch_like_api: true,
        has_request_body: true,
        network_correlation_key: "sha1:network-key",
        upload_body: {element_count: 1, total_bytes: 48, in_memory_bytes: 48}
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: "function sendSignedRequest(input){ return fetch('/api/feed/list', {method:'POST'}); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_network_correlation.ndjson", events, assets});
  const anchor = report.signature.agent_evidence_pack.signature_absent.network_anchors
    .find((item) => item.api === "BrowserNetwork.request");
  const chain = report.signature.agent_evidence_pack.signature_absent.candidate_trace_chains
    .find((item) => item.anchor_api === "BrowserNetwork.request");

  assert.ok(anchor);
  assert.deepEqual(anchor.request_context.renderer_request_link, {
    trace_index: 100,
    seq: 3100,
    api: "Request.constructor",
    method: "POST",
    endpoint: "https://www.example.test/api/feed/list",
    relation: "before_browser_request",
    trace_distance: 8900,
    function: "sendSignedRequest",
    stack_url: assetUrl,
    asset_id: "sha1:runtime-sdk",
    confidence: "high",
    match: "network_correlation_key"
  });
  assert.equal(anchor.network_correlation_key, "sha1:network-key");
  assert.ok(!anchor.request_context.capture_gaps.includes("renderer_stack_missing"));
  assert.equal(chain.request_context.renderer_link, "Request.constructor@3100:before_browser_request:8900");
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  assert.deepEqual(materialFlow.renderer_request_link, {
    trace_index: 100,
    seq: 3100,
    api: "Request.constructor",
    method: "POST",
    endpoint: "https://www.example.test/api/feed/list",
    relation: "before_browser_request",
    trace_distance: 8900,
    function: "sendSignedRequest",
    stack_url: assetUrl,
    asset_id: "sha1:runtime-sdk",
    confidence: "high",
    match: "network_correlation_key"
  });
  assert.deepEqual(materialFlow.data_links, [
    {
      from: "request_construction",
      to: "request_body",
      refs: ["network_request:sha1:network-key"]
    },
    {
      from: "request_construction",
      to: "signed_request",
      refs: ["network_request:sha1:network-key"]
    },
    {
      from: "request_body",
      to: "signed_request",
      refs: ["network_request:sha1:network-key"]
    }
  ]);
});

test("buildLocalReport emits inferred request links when object refs are absent", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "sendSignedRequest", url: assetUrl, line: 18, column: 6}];
  const events = [
    {
      _trace_index: 8450,
      seq: 8450,
      category: "network",
      api: "Request.constructor",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1"
      }],
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 8700,
      seq: 8700,
      category: "reverse",
      api: "TextEncoder.encode",
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 9000,
      seq: 9000,
      category: "network",
      api: "BrowserNetwork.request",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1",
        request_initiator: "https://www.example.test",
        is_fetch_like_api: true,
        has_request_body: true
      }],
      origin: "https://www.example.test"
    }
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: "function sendSignedRequest(input){ return fetch('/api/feed/list', {method:'POST'}); }"
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_inferred_request_link.ndjson", events, assets});
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.deepEqual(materialFlow.data_links, []);
  assert.deepEqual(materialFlow.inferred_data_links, [
    {
      from: "request_construction",
      to: "signed_request",
      confidence: "high",
      basis: [
        "renderer_request_link",
        "endpoint_method_trace_window",
        "before_browser_request"
      ],
      refs: ["renderer_request:Request.constructor:8450"]
    }
  ]);
  assert.ok(!materialFlow.analysis_readiness.evidence_gaps.includes("data_links_not_observed"));
});

test("buildLocalReport infers VMP material links from same source context when object refs are absent", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "signVm", url: assetUrl, line: 4, column: 10}];
  const events = [
    {
      seq: 10,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url: "https://www.example.test/api/list?count=6"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 11,
      category: "reverse",
      phase: "call",
      api: "DataView.getUint32",
      args: [{byte_offset: 4}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 12,
      category: "reverse",
      phase: "call",
      api: "Math.imul",
      args: [{x: 123, y: 2654435761}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 13,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}],
      stack,
      origin: "https://www.example.test"
    }
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_inferred_vmp_material_links.ndjson",
    events,
    assets: [{
      asset_id: "sha1:runtime-sdk",
      kind: "external-script",
      url: assetUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: "function signVm(input) { const view = new DataView(input); const x = Math.imul(view.getUint32(4, true) ^ 123, 2654435761); return fetch('/api/list?X-Signature=' + x); }"
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.deepEqual(materialFlow.data_links, []);
  assert.deepEqual(materialFlow.inferred_data_links, [
    {
      from: "input_url",
      to: "byte_buffer",
      confidence: "medium",
      basis: ["same_source_context", "ordered_runtime_window"],
      refs: ["source:sha1:runtime-sdk:1-1", "seq:10-11"]
    },
    {
      from: "byte_buffer",
      to: "integer_mixing",
      confidence: "medium",
      basis: ["same_source_context", "ordered_runtime_window"],
      refs: ["source:sha1:runtime-sdk:1-1", "seq:11-12"]
    },
    {
      from: "integer_mixing",
      to: "signed_request",
      confidence: "medium",
      basis: ["same_source_context", "ordered_runtime_window"],
      refs: ["source:sha1:runtime-sdk:1-1", "seq:12-13"]
    }
  ]);
  assert.ok(!materialFlow.analysis_readiness.evidence_gaps.includes("data_links_not_observed"));
});

test("buildLocalReport infers weaker VMP links from overlapping runtime windows", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "vmLoop", url: assetUrl, line: 3, column: 12}];
  const events = [
    {
      seq: 10,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url: "https://www.example.test/api/list?count=6"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 10,
      category: "reverse",
      phase: "call",
      api: "TextEncoder.encode",
      args: [{input_length: 48}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 11,
      category: "reverse",
      phase: "call",
      api: "DataView.getUint32",
      args: [{byte_offset: 4}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 12,
      category: "reverse",
      phase: "call",
      api: "TextEncoder.encode",
      args: [{input_length: 16}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 13,
      category: "reverse",
      phase: "call",
      api: "Math.imul",
      args: [{x: 123, y: 2654435761}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 14,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}],
      stack,
      origin: "https://www.example.test"
    }
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_inferred_vmp_overlap_links.ndjson",
    events,
    assets: [{
      asset_id: "sha1:runtime-sdk",
      kind: "external-script",
      url: assetUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function vmLoop(input) {",
        "  const view = new DataView(new TextEncoder().encode(input).buffer);",
        "  const x = Math.imul(view.getUint32(4, true) ^ 123, 2654435761);",
        "  return fetch('/api/list?X-Signature=' + x);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.deepEqual(materialFlow.inferred_data_links, [
    {
      from: "byte_buffer",
      to: "text_or_string_decode",
      confidence: "low",
      basis: ["same_source_context", "overlapping_runtime_window"],
      refs: ["source:sha1:runtime-sdk:1-5", "seq:11-12"]
    },
    {
      from: "text_or_string_decode",
      to: "integer_mixing",
      confidence: "medium",
      basis: ["same_source_context", "ordered_runtime_window"],
      refs: ["source:sha1:runtime-sdk:1-5", "seq:12-13"]
    },
    {
      from: "integer_mixing",
      to: "signed_request",
      confidence: "medium",
      basis: ["same_source_context", "ordered_runtime_window"],
      refs: ["source:sha1:runtime-sdk:1-5", "seq:13-14"]
    }
  ]);
});

test("buildLocalReport infers URL shape links when signed URL is reconstructed with a new object id", () => {
  const unsignedUrl = "https://www.example.test/api/list?count=6";
  const signedUrl = `${unsignedUrl}&X-Signature=secret-one&X-Secondary-Signature=secret-two`;
  const shapeRef = `url_shape:${crypto.createHash("sha1").update(JSON.stringify({
    endpoint: "https://www.example.test/api/list",
    query_keys: ["X-Signature", "X-Secondary-Signature", "count"]
  })).digest("hex")}`;
  const events = [
    {
      seq: 10,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 11, url: unsignedUrl, href: unsignedUrl}],
      origin: "https://www.example.test"
    },
    {
      seq: 20,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 12, url: signedUrl, href: signedUrl}],
      origin: "https://www.example.test"
    },
    {
      seq: 21,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 13, url: signedUrl, href: signedUrl}],
      origin: "https://www.example.test"
    }
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_url_shape_links.ndjson",
    events,
    assets: []
  });

  const materialFlow = report.signature.agent_evidence_pack.signature_material_flows
    .find((flow) => (flow.stages || []).some((stage) => stage.stage === "signature_mutation"));

  assert.ok(materialFlow);
  assert.deepEqual(materialFlow.inferred_data_links, [{
    from: "signature_mutation",
    to: "signed_request",
    confidence: "medium",
    basis: ["shared_url_shape", "target_signature_params"],
    refs: [shapeRef, "target_params:X-Signature|X-Secondary-Signature"]
  }]);
});

test("buildLocalReport exposes raw signature attachment events for URLSearchParams mutations", () => {
  const stack = [{function: "attachSignature", url: "https://cdn.example.test/runtime-sdk.js", line: 8, column: 4}];
  const events = [
    {
      seq: 10,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 11, search_params_id: 21, url: "https://www.example.test/api/list?count=6"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 11,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.set",
      args: [{url_object_id: 11, search_params_id: 21, name: "X-Signature", value: "secret-one"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 12,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.append",
      args: [{url_object_id: 11, search_params_id: 21, name: "X-Secondary-Signature", value: "secret-two"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 13,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{url_object_id: 11, search_params_id: 21, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one&X-Secondary-Signature=secret-two"}],
      stack,
      origin: "https://www.example.test"
    }
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_signature_attachment_events.ndjson",
    events,
    assets: []
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.deepEqual(materialFlow.signature_attachment_events, [
    {
      seq: 11,
      api: "URLSearchParams.set",
      phase: "url_signature_mutation",
      action: "set",
      target_params: ["X-Signature"],
      object_refs: ["url_object:11", "search_params:21"],
      value_refs: ["string:length:10"]
    },
    {
      seq: 12,
      api: "URLSearchParams.append",
      phase: "url_signature_mutation",
      action: "append",
      target_params: ["X-Secondary-Signature"],
      object_refs: ["url_object:11", "search_params:21"],
      value_refs: ["string:length:10"]
    }
  ]);
  assert.match(renderMarkdownReport(report), /attachments=URLSearchParams\.set@11:set:X-Signature:url_object:11\|search_params:21/);
});

test("buildLocalReport builds an agent-readable parameter attachment graph", () => {
  const stack = [{function: "attachSignature", url: "https://cdn.example.test/runtime-sdk.js", line: 8, column: 4}];
  const events = [
    {
      seq: 10,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 11, search_params_id: 21, url: "https://www.example.test/api/list?count=6"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 11,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.set",
      args: [{url_object_id: 11, search_params_id: 21, name: "X-Signature", value: "secret-one"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 12,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.append",
      args: [{url_object_id: 11, search_params_id: 21, name: "X-Secondary-Signature", value: "secret-two"}],
      stack,
      origin: "https://www.example.test"
    },
    {
      seq: 13,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{url_object_id: 11, search_params_id: 21, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one&X-Secondary-Signature=secret-two"}],
      stack,
      origin: "https://www.example.test"
    }
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_parameter_attachment_graph.ndjson",
    events,
    assets: []
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const graph = materialFlow.parameter_attachment_graph;

  assert.deepEqual(graph.target_params, ["X-Signature", "X-Secondary-Signature"]);
  assert.deepEqual(graph.nodes.map((node) => ({id: node.id, kind: node.kind})), [
    {id: "param:X-Signature", kind: "target_param"},
    {id: "param:X-Secondary-Signature", kind: "target_param"},
    {id: "attach:11", kind: "attachment_event"},
    {id: "attach:12", kind: "attachment_event"},
    {id: "ref:url_object:11", kind: "object_ref"},
    {id: "ref:search_params:21", kind: "object_ref"},
    {id: "value:string:length:10", kind: "value_ref"},
    {id: "stage:signature_mutation", kind: "stage"},
    {id: "stage:signed_request", kind: "stage"}
  ]);
  assert.deepEqual(graph.edges.map((edge) => ({
    from: edge.from,
    to: edge.to,
    relation: edge.relation,
    evidence: edge.evidence
  })), [
    {from: "param:X-Signature", to: "attach:11", relation: "attached_by", evidence: "URLSearchParams.set@11"},
    {from: "attach:11", to: "ref:url_object:11", relation: "writes_object", evidence: "URLSearchParams.set@11"},
    {from: "attach:11", to: "ref:search_params:21", relation: "writes_object", evidence: "URLSearchParams.set@11"},
    {from: "attach:11", to: "value:string:length:10", relation: "observes_value_shape", evidence: "URLSearchParams.set@11"},
    {from: "param:X-Secondary-Signature", to: "attach:12", relation: "attached_by", evidence: "URLSearchParams.append@12"},
    {from: "attach:12", to: "ref:url_object:11", relation: "writes_object", evidence: "URLSearchParams.append@12"},
    {from: "attach:12", to: "ref:search_params:21", relation: "writes_object", evidence: "URLSearchParams.append@12"},
    {from: "attach:12", to: "value:string:length:10", relation: "observes_value_shape", evidence: "URLSearchParams.append@12"},
    {from: "ref:url_object:11", to: "stage:signature_mutation", relation: "observed_in_stage", evidence: "attachment"},
    {from: "ref:search_params:21", to: "stage:signature_mutation", relation: "observed_in_stage", evidence: "attachment"},
    {from: "ref:url_object:11", to: "stage:signed_request", relation: "flows_to_stage", evidence: "data_link"},
    {from: "ref:search_params:21", to: "stage:signed_request", relation: "flows_to_stage", evidence: "data_link"}
  ]);
  assert.match(renderMarkdownReport(report), /attachment_graph=param:X-Signature->attach:11:attached_by/);
});

test("buildLocalReport emits agent-readable material flow generation steps", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 4,
    column: 14,
    asset_id: "sha1:steps",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 11, category: "reverse", phase: "call", api: "String.fromCharCode", args: [{argc: 7, first_code: 88, result_preview: "X-Signature"}], stack},
    {seq: 12, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 21, array_buffer_id: 20, byte_offset: 4}], stack},
    {seq: 13, category: "reverse", phase: "call", api: "Math.imul", args: [{data_view_id: 21, mix_state_id: 30, x: 123, y: 2654435761}], stack},
    {seq: 14, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 15, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_generation_steps.ndjson",
    events,
    assets: [{
      asset_id: "sha1:steps",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signVm(input) {",
        "  const p = String.fromCharCode(88,45,66,111,103,117,115);",
        "  const view = new DataView(input);",
        "  const mixed = Math.imul(view.getUint32(4, true) ^ 123, 2654435761) >>> 0;",
        "  url.searchParams.set(p, mixed);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.deepEqual(materialFlow.generation_steps.map((step) => ({
    id: step.id,
    order: step.order,
    stage: step.stage,
    role: step.role,
    seq_start: step.seq_start,
    seq_end: step.seq_end,
    runtime_apis: step.runtime_apis,
    target_params: step.target_params,
    evidence: step.evidence,
    attachment_events: step.attachment_events
  })), [
    {
      id: "step_1",
      order: 1,
      stage: "input_url",
      role: "input",
      seq_start: 10,
      seq_end: 10,
      runtime_apis: ["URL.constructor"],
      target_params: [],
      evidence: ["runtime_api", "source_context", "object_ref", "value_ref"],
      attachment_events: []
    },
    {
      id: "step_2",
      order: 2,
      stage: "byte_buffer",
      role: "material_read",
      seq_start: 12,
      seq_end: 12,
      runtime_apis: ["DataView.getUint32"],
      target_params: [],
      evidence: ["runtime_api", "source_context", "object_ref", "value_ref"],
      attachment_events: []
    },
    {
      id: "step_3",
      order: 3,
      stage: "text_or_string_decode",
      role: "string_material",
      seq_start: 11,
      seq_end: 11,
      runtime_apis: ["String.fromCharCode"],
      target_params: [],
      evidence: ["runtime_api", "source_context", "value_ref"],
      attachment_events: []
    },
    {
      id: "step_4",
      order: 4,
      stage: "integer_mixing",
      role: "transform",
      seq_start: 13,
      seq_end: 13,
      runtime_apis: ["Math.imul"],
      target_params: [],
      evidence: ["runtime_api", "source_context", "object_ref", "value_ref", "source_operator", "source_constant"],
      attachment_events: []
    },
    {
      id: "step_5",
      order: 5,
      stage: "signature_mutation",
      role: "parameter_attachment",
      seq_start: 14,
      seq_end: 14,
      runtime_apis: ["URLSearchParams.set"],
      target_params: ["X-Signature"],
      evidence: ["runtime_api", "source_context", "object_ref", "value_ref", "attachment_event"],
      attachment_events: [{
        seq: 14,
        api: "URLSearchParams.set",
        action: "set",
        target_params: ["X-Signature"],
        object_refs: ["url_object:11", "search_params:12"],
        value_refs: ["string:length:10", "target_params:X-Signature"]
      }]
    },
    {
      id: "step_6",
      order: 6,
      stage: "signed_request",
      role: "network_emit",
      seq_start: 15,
      seq_end: 15,
      runtime_apis: ["Request.constructor"],
      target_params: ["X-Signature"],
      evidence: ["runtime_api", "source_context", "object_ref", "value_ref"],
      attachment_events: []
    }
  ]);
  assert.match(
    renderMarkdownReport(report),
    /generation_steps=input_url\[URL\.constructor@10 src=sha1:steps:2-6 d=5\]->byte_buffer\[DataView\.getUint32@12 src=sha1:steps:2-6 d=3\]->text_or_string_decode\[String\.fromCharCode@11 src=sha1:steps:2-6 d=4\]->integer_mixing\[Math\.imul@13 src=sha1:steps:2-6 d=2\]->signature_mutation\[URLSearchParams\.set@14 params=X-Signature src=sha1:steps:2-6 d=1\]->signed_request\[Request\.constructor@15 params=X-Signature src=sha1:steps:2-6 d=0\]/
  );
});

test("buildLocalReport consumes V8 scalar refs for VMP generation edges", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 3,
    column: 18,
    asset_id: "sha1:vmp-ref-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 30, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 41, search_params_id: 42, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 31, category: "reverse", phase: "call", api: "String.fromCharCode", args: [{argc: 1, first_code: 88, result_preview: "X", result_ref: "number:88.000000"}], stack},
    {seq: 32, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left: 88, left_ref: "number:88.000000", right: 23, right_ref: "number:23.000000", result: 79, result_ref: "number:79.000000"}], stack},
    {seq: 33, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 41, search_params_id: 42, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 34, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 41, search_params_id: 42, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_scalar_refs.ndjson",
    events,
    assets: [{
      asset_id: "sha1:vmp-ref-source",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signVm(url) {",
        "  const p = String.fromCharCode(88);",
        "  const mixed = p.charCodeAt(0) ^ 23;",
        "  url.searchParams.set('X-Signature', mixed);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const textStep = materialFlow.generation_steps.find((step) => step.stage === "text_or_string_decode");
  const mixStep = materialFlow.generation_steps.find((step) => step.stage === "integer_mixing");
  const agentPack = buildAgentInputPack(report);
  const agentPackMarkdown = renderAgentInputPackMarkdown(agentPack);
  const packParameter = agentPack.parameters.find((entry) => entry.param === "X-Signature");
  assert.ok(packParameter);
  const packLogicTrace = packParameter.agent_generation_summary.logic_hypothesis.agent_logic_trace;
  const packMixingStep = packLogicTrace.steps.find((step) => step.phase === "mixing_or_hash");
  assert.ok(packMixingStep);
  assert.ok((packMixingStep.source_operators || []).includes("^"));
  assert.match(agentPackMarkdown, /logic_step=\d+:mixing_or_hash[^\n]*ops=\^/);

  const agentAnalysis = buildAgentAnalysis(agentPack);
  const parameter = agentAnalysis.parameters.find((entry) => entry.param === "X-Signature");
  const edge = parameter.generation_edges.find((item) =>
    item.from_stage === "text_or_string_decode" && item.to_stage === "integer_mixing"
  );

  assert.ok(textStep.value_refs.includes("number:88.000000"));
  assert.ok(mixStep.value_refs.includes("number:88.000000"));
  assert.ok(mixStep.value_refs.includes("number:79.000000"));
  assert.equal(edge.from_order, textStep.order);
  assert.equal(edge.to_order, mixStep.order);
  assert.ok(["shared_value_ref", "inferred_data_link"].includes(edge.relation));
  assert.ok(["high", "medium"].includes(edge.confidence));
  assert.ok(edge.evidence.includes("shared_value_ref"));
});

test("buildLocalReport derives semantic refs from string codec runtime fields", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 3,
    column: 18,
    asset_id: "sha1:string-codec-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 50, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 51, search_params_id: 52, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 51, category: "reverse", phase: "call", api: "String.fromCharCode", args: [{argc: 1, first_code: 88, result_preview: "X"}], stack},
    {seq: 52, category: "reverse", phase: "call", api: "String.prototype.charCodeAt", args: [{position: 0, result: 88}], stack},
    {seq: 53, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left: 88, left_ref: "number:88.000000", right: 23, right_ref: "number:23.000000", result: 79, result_ref: "number:79.000000"}], stack},
    {seq: 54, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 51, search_params_id: 52, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 55, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 51, search_params_id: 52, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_string_codec_semantic_refs.ndjson",
    events,
    assets: [{
      asset_id: "sha1:string-codec-source",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signVm(url) {",
        "  const p = String.fromCharCode(88);",
        "  const mixed = p.charCodeAt(0) ^ 23;",
        "  url.searchParams.set('X-Signature', mixed);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const textStep = materialFlow.generation_steps.find((step) => step.stage === "text_or_string_decode");
  const mixStep = materialFlow.generation_steps.find((step) => step.stage === "integer_mixing");
  const agentAnalysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = agentAnalysis.parameters.find((entry) => entry.param === "X-Signature");
  const edge = parameter.generation_edges.find((item) =>
    item.from_stage === "text_or_string_decode" && item.to_stage === "integer_mixing"
  );

  assert.ok(textStep.value_refs.includes("number:88.000000"));
  assert.ok(textStep.value_refs.includes("string:length:1"));
  assert.ok(mixStep.value_refs.includes("number:88.000000"));
  assert.ok(["shared_value_ref", "inferred_data_link"].includes(edge.relation));
});

test("buildLocalReport derives semantic refs from encoding boundary runtime fields", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 3,
    column: 18,
    asset_id: "sha1:encoding-boundary-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 60, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 61, search_params_id: 62, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 61, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 24, result_byte_length: 24}], stack},
    {seq: 62, category: "reverse", phase: "call", api: "TextDecoder.decode", args: [{input_byte_length: 24, result_length: 24}], stack},
    {seq: 63, category: "reverse", phase: "call", api: "btoa", args: [{input_length: 24, result_length: 32}], stack},
    {seq: 64, category: "reverse", phase: "call", api: "encodeURIComponent", args: [{input_length: 32, result_length: 40}], stack},
    {seq: 65, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 61, search_params_id: 62, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 66, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 61, search_params_id: 62, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_encoding_boundary_semantic_refs.ndjson",
    events,
    assets: [{
      asset_id: "sha1:encoding-boundary-source",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signVm(url) {",
        "  const bytes = new TextEncoder().encode(url.href);",
        "  const material = new TextDecoder().decode(bytes);",
        "  const encoded = encodeURIComponent(btoa(material));",
        "  url.searchParams.set('X-Signature', encoded);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const textStep = materialFlow.generation_steps.find((step) => step.stage === "text_or_string_decode");
  const encodingStep = materialFlow.generation_steps.find((step) => step.stage === "url_encoding");
  const agentAnalysis = buildAgentAnalysis(buildAgentInputPack(report));

  assert.ok(textStep.value_refs.includes("string:length:24"));
  assert.ok(textStep.value_refs.includes("byte:length:24"));
  assert.ok(textStep.value_refs.includes("base64:length:32"));
  assert.ok(encodingStep.value_refs.includes("string:length:32"));
  assert.ok(encodingStep.value_refs.includes("url_encoded:length:40"));
});

test("buildLocalReport derives semantic refs from byte buffer runtime fields", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 3,
    column: 18,
    asset_id: "sha1:byte-buffer-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 70, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 71, search_params_id: 72, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 71, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 81, array_buffer_id: 82, byte_offset: 4, little_endian: true, result: 305419896}], stack},
    {seq: 72, category: "reverse", phase: "call", api: "TypedArray.at", args: [{typed_array_id: 91, array_buffer_id: 82, kind: "Uint8Array", index: 0, result: 88}], stack},
    {seq: 73, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: "number:305419896.000000", y_ref: "number:88.000000", result_ref: "number:195936478.000000"}], stack},
    {seq: 74, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 71, search_params_id: 72, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 75, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 71, search_params_id: 72, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_byte_buffer_semantic_refs.ndjson",
    events,
    assets: [{
      asset_id: "sha1:byte-buffer-source",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signVm(input) {",
        "  const view = new DataView(input.buffer);",
        "  const x = view.getUint32(4, true);",
        "  const y = input.at(0);",
        "  const mixed = Math.imul(x, y);",
        "  url.searchParams.set('X-Signature', mixed);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const byteStep = materialFlow.generation_steps.find((step) => step.stage === "byte_buffer");
  const mixStep = materialFlow.generation_steps.find((step) => step.stage === "integer_mixing");
  const agentAnalysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = agentAnalysis.parameters.find((entry) => entry.param === "X-Signature");
  const edge = parameter.generation_edges.find((item) =>
    item.from_stage === "byte_buffer" && item.to_stage === "integer_mixing"
  );

  assert.ok(byteStep.value_refs.includes("number:305419896.000000"));
  assert.ok(byteStep.value_refs.includes("number:88.000000"));
  assert.ok(byteStep.value_refs.includes("byte_offset:4"));
  assert.ok(byteStep.value_refs.includes("typed_array_index:0"));
  assert.ok(mixStep.value_refs.includes("number:305419896.000000"));
  assert.ok(mixStep.value_refs.includes("number:88.000000"));
  assert.equal(edge.relation, "shared_value_ref");
  assert.equal(edge.confidence, "high");
  assert.ok(edge.refs.includes("number:305419896.000000"));
  assert.ok(edge.refs.includes("number:88.000000"));
});

test("buildLocalReport derives semantic refs from array table runtime fields", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 3,
    column: 18,
    asset_id: "sha1:array-table-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 80, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 81, search_params_id: 82, url: "https://www.example.test/api/list?count=6"}], stack},
    ...Array.from({length: 5}, (_, index) => ({
      seq: 80.1 + index,
      category: "reverse",
      phase: "call",
      api: "Function.prototype.call",
      args: [{
        target_id: 900 + index,
        arguments_list_id: 910 + index,
        state_object_id: 920 + index,
        register_ref: `register:${920 + index}/${910 + index}`,
        handler_arg_ref: `handler_arg:${900 + index}/number:${index}.000000`,
        handler_return_ref: `handler_return:${900 + index}/${910 + index}`,
        arg_count: 2
      }],
      stack
    })),
    {seq: 81, category: "reverse", phase: "call", api: "Array.prototype.push", args: [{argc: 1, first_arg_ref: "number:88.000000", length_before: 4, length_after: 5}], stack},
    {seq: 82, category: "reverse", phase: "call", api: "Array.prototype.join", args: [{length: 5, separator_length: 1, result_length: 9}], stack},
    {seq: 83, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: "number:88.000000", y_ref: "number:16777619.000000", result_ref: "number:1472430472.000000"}], stack},
    {seq: 84, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 81, search_params_id: 82, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 85, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 81, search_params_id: 82, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_array_table_semantic_refs.ndjson",
    events,
    assets: [{
      asset_id: "sha1:array-table-source",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signVm(url) {",
        "  const table = [];",
        "  table.push(88);",
        "  const material = table.join('|');",
        "  const mixed = Math.imul(table[0], 16777619);",
        "  url.searchParams.set('X-Signature', mixed);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const dispatchStep = materialFlow.generation_steps.find((step) => step.stage === "dynamic_dispatch");
  const mixStep = materialFlow.generation_steps.find((step) => step.stage === "integer_mixing");
  const agentAnalysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = agentAnalysis.parameters.find((entry) => entry.param === "X-Signature");
  const hookRefs = new Map(parameter.candidate_generation_summary.vmp_hook_ref_summary.map((item) => [item.type, item]));
  const edge = parameter.generation_edges.find((item) =>
    item.from_stage === "dynamic_dispatch" && item.to_stage === "integer_mixing"
  );

  assert.ok(dispatchStep.value_refs.some((ref) => ref.startsWith("register:")));
  assert.ok(mixStep.value_refs.includes("number:88.000000"));
  assert.ok(["shared_value_ref", "inferred_data_link"].includes(edge.relation));
  assert.ok(hookRefs.get("vmp_array_table").apis.includes("Array.prototype.push"));
  assert.ok(hookRefs.get("vmp_array_table").apis.includes("Array.prototype.join"));
  assert.ok(hookRefs.get("vmp_array_table").value_refs.includes("number:88.000000"));
  assert.ok(hookRefs.get("vmp_array_table").value_refs.includes("array:length:5"));
  assert.ok(hookRefs.get("vmp_array_table").value_refs.includes("string:length:9"));
  assert.ok(hookRefs.get("vmp_hash_or_signature_pipeline").value_refs.includes("number:1472430472.000000"));
});

test("buildLocalReport emits VMP scalar ref chains for agent review", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 4, column: 10}];
  const events = [
    {seq: 40, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left_ref: "number:1.000000", right_ref: "number:2.000000", result_ref: "number:3.000000"}], stack},
    {seq: 41, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: "number:3.000000", y_ref: "number:17.000000", result_ref: "number:51.000000"}], stack},
    {seq: 42, category: "reverse", phase: "call", api: "Shift.unsignedRight", args: [{left_ref: "number:51.000000", right_ref: "number:0.000000", result_ref: "number:51.000000"}], stack},
    {seq: 43, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{name: "X-Signature", value: "secret-one"}], stack},
    {seq: 44, category: "network", phase: "call", api: "Request.constructor", args: [{url: "https://www.example.test/api/list?X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_scalar_chain.ndjson",
    events,
    assets: []
  });
  const pack = buildAgentInputPack(report);
  const [chain] = report.signature.agent_evidence_pack.vmp_scalar_ref_chains;

  assert.equal(report.signature.agent_evidence_pack.vmp_scalar_ref_chains.length, 1);
  assert.deepEqual(chain.steps.map((step) => ({
    seq: step.seq,
    api: step.api,
    input_refs: step.input_refs,
    result_ref: step.result_ref
  })), [
    {
      seq: 40,
      api: "Bitwise.xor",
      input_refs: ["number:1.000000", "number:2.000000"],
      result_ref: "number:3.000000"
    },
    {
      seq: 41,
      api: "Math.imul",
      input_refs: ["number:3.000000", "number:17.000000"],
      result_ref: "number:51.000000"
    },
    {
      seq: 42,
      api: "Shift.unsignedRight",
      input_refs: ["number:51.000000", "number:0.000000"],
      result_ref: "number:51.000000"
    }
  ]);
  assert.deepEqual(pack.vmp_scalar_ref_chains, report.signature.agent_evidence_pack.vmp_scalar_ref_chains);
});

test("buildLocalReport ignores low-information VMP scalar refs", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 4, column: 10}];
  const events = [
    {seq: 50, category: "reverse", phase: "call", api: "Bitwise.and", args: [{left_ref: "other", right_ref: "other", result_ref: "other"}], stack},
    {seq: 51, category: "reverse", phase: "call", api: "Shift.right", args: [{left_ref: "other", right_ref: "other", result_ref: "other"}], stack},
    {seq: 52, category: "reverse", phase: "call", api: "Bitwise.or", args: [{left_ref: "other", right_ref: "other", result_ref: "other"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_low_info_refs.ndjson",
    events,
    assets: []
  });
  const pack = buildAgentInputPack(report);

  assert.deepEqual(report.signature.agent_evidence_pack.vmp_scalar_ref_chains, []);
  assert.deepEqual(pack.vmp_scalar_ref_chains, []);
});

test("buildLocalReport ranks signature-like VMP scalar chains and keeps source refs", () => {
  const lowInfoStack = [{function: "bitset", url: "https://cdn.example.test/chunk.js", line: 3, column: 1, asset_id: "sha1:chunk"}];
  const webmStack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 9, column: 14, asset_id: "sha1:runtime-sdk"}];
  const events = [
    {seq: 60, category: "reverse", phase: "call", api: "Bitwise.or", args: [{left_ref: "number:1.000000", right_ref: "number:2.000000", result_ref: "number:3.000000"}], stack: lowInfoStack},
    {seq: 61, category: "reverse", phase: "call", api: "Bitwise.and", args: [{left_ref: "number:3.000000", right_ref: "number:1.000000", result_ref: "number:1.000000"}], stack: lowInfoStack},
    {seq: 62, category: "reverse", phase: "call", api: "Shift.left", args: [{left_ref: "number:1.000000", right_ref: "number:1.000000", result_ref: "number:2.000000"}], stack: lowInfoStack},
    {seq: 63, category: "reverse", phase: "call", api: "Bitwise.or", args: [{left_ref: "number:2.000000", right_ref: "number:1.000000", result_ref: "number:3.000000"}], stack: lowInfoStack},
    {seq: 70, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left_ref: "number:2166136261.000000", right_ref: "number:1937072687.000000", result_ref: "number:-227934230.000000"}], stack: webmStack},
    {seq: 71, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: "number:-227934230.000000", y_ref: "number:16777619.000000", result_ref: "number:-2032280226.000000"}], stack: webmStack},
    {seq: 72, category: "reverse", phase: "call", api: "Shift.unsignedRight", args: [{left_ref: "number:-2032280226.000000", right_ref: "number:0.000000", result_ref: "number:2262687070.000000"}], stack: webmStack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_scalar_ranking.ndjson",
    events,
    assets: []
  });
  const [chain] = report.signature.agent_evidence_pack.vmp_scalar_ref_chains;
  const pack = buildAgentInputPack(report);

  assert.deepEqual(chain.apis, ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"]);
  assert.ok(chain.quality_score > 0);
  assert.ok(chain.quality_reasons.includes("multiply_xor_unsigned_shift"));
  assert.deepEqual(chain.source_context_refs, ["sha1:runtime-sdk:9-9"]);
  assert.equal(chain.source_contexts[0].function, "signVm");
  assert.deepEqual(pack.vmp_scalar_ref_chains[0].source_context_refs, ["sha1:runtime-sdk:9-9"]);
  assert.match(
    renderMarkdownReport(report),
    /vmp_scalar_chain_1 relation=scalar_ref_flow score=\d+ reasons=.*multiply_xor_unsigned_shift.*sources=sha1:runtime-sdk:9-9/
  );
});

test("buildLocalReport does not rank zero-carried scalar loops above signature chains", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 9, column: 14, asset_id: "sha1:runtime-sdk"}];
  const events = [];
  for (let index = 0; index < 320; index += 1) {
    events.push({
      seq: 600 + index,
      category: "reverse",
      phase: "call",
      api: "Bitwise.xor",
      args: [{
        left_ref: "number:0.000000",
        right_ref: "number:0.000000",
        result_ref: "number:0.000000"
      }],
      stack
    });
  }
  events.push(
    {seq: 1000, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left_ref: "number:2166136261.000000", right_ref: "number:1937072687.000000", result_ref: "number:-227934230.000000"}], stack},
    {seq: 1001, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: "number:-227934230.000000", y_ref: "number:16777619.000000", result_ref: "number:-2032280226.000000"}], stack},
    {seq: 1002, category: "reverse", phase: "call", api: "Shift.unsignedRight", args: [{left_ref: "number:-2032280226.000000", right_ref: "number:0.000000", result_ref: "number:2262687070.000000"}], stack}
  );

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_zero_carried_loop.ndjson",
    events,
    assets: []
  });
  const [chain] = report.signature.agent_evidence_pack.vmp_scalar_ref_chains;

  assert.deepEqual(chain.apis, ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"]);
  assert.ok(chain.quality_reasons.includes("multiply_xor_unsigned_shift"));
  assert.deepEqual(chain.steps.map((step) => step.seq), [1000, 1001, 1002]);
});

test("buildLocalReport links VMP scalar chains into signature material flows", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 9, column: 14, asset_id: "sha1:runtime-sdk"}];
  const events = [
    {seq: 80, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 81, search_params_id: 82, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 81, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left_ref: "number:88.000000", right_ref: "number:23.000000", result_ref: "number:79.000000"}], stack},
    {seq: 82, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: "number:79.000000", y_ref: "number:16777619.000000", result_ref: "number:1325431901.000000"}], stack},
    {seq: 83, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 81, search_params_id: 82, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 84, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 81, search_params_id: 82, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack},
    {seq: 90, category: "reverse", phase: "call", api: "Bitwise.or", args: [{left_ref: "number:0.000000", right_ref: "number:1.000000", result_ref: "number:1.000000"}], stack},
    {seq: 91, category: "reverse", phase: "call", api: "Shift.left", args: [{left_ref: "number:1.000000", right_ref: "number:1.000000", result_ref: "number:2.000000"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_scalar_material_link.ndjson",
    events,
    assets: []
  });
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const [link] = materialFlow.vmp_scalar_chain_links;
  const pack = buildAgentInputPack(report);
  const agentPackMarkdown = renderAgentInputPackMarkdown(pack);
  const parameter = pack.parameters.find((entry) => entry.param === "X-Signature");
  const agentAnalysis = buildAgentAnalysis(pack);
  const agentParameter = agentAnalysis.parameters.find((entry) => entry.param === "X-Signature");

  assert.equal(link.chain_id, "vmp_scalar_chain_1");
  assert.equal(link.stage, "integer_mixing");
  assert.equal(link.relation, "shared_value_ref");
  assert.equal(link.confidence, "high");
  assert.deepEqual(link.apis, ["Bitwise.xor", "Math.imul"]);
  assert.ok(link.shared_refs.includes("number:79.000000"));
  assert.ok(link.quality_score > 0);
  assert.ok(link.source_context_refs.includes("sha1:runtime-sdk:9-9"));
  assert.deepEqual(link.operation_trace, [
    {
      seq: 81,
      trace_index: 1,
      api: "Bitwise.xor",
      input_refs: ["number:88.000000", "number:23.000000"],
      result_ref: "number:79.000000",
      source_context_refs: ["sha1:runtime-sdk:9-9"]
    },
    {
      seq: 82,
      trace_index: 2,
      api: "Math.imul",
      input_refs: ["number:79.000000", "number:16777619.000000"],
      result_ref: "number:1325431901.000000",
      source_context_refs: ["sha1:runtime-sdk:9-9"]
    }
  ]);
  assert.deepEqual(materialFlow.vmp_scalar_chain_links.map((item) => item.chain_id), ["vmp_scalar_chain_1"]);
  assert.equal(parameter.vmp_scalar_chain_links[0].chain_id, "vmp_scalar_chain_1");
  assert.equal(parameter.vmp_scalar_chain_links[0].stage, "integer_mixing");
  assert.deepEqual(parameter.vmp_scalar_chain_links[0].operation_trace, link.operation_trace);
  assert.equal(agentParameter.vmp_scalar_chain_links[0].chain_id, "vmp_scalar_chain_1");
  assert.deepEqual(agentParameter.vmp_scalar_chain_links[0].operation_trace, link.operation_trace);
  assert.match(renderMarkdownReport(report), /scalar_chains=vmp_scalar_chain_1:integer_mixing:shared_value_ref\[high\]/);
  assert.match(
    agentPackMarkdown,
    /scalar_chains=vmp_scalar_chain_1:integer_mixing:shared_value_ref\[high\] ops=81:Bitwise\.xor\(number:88\.000000\|number:23\.000000->number:79\.000000\)->82:Math\.imul\(number:79\.000000\|number:16777619\.000000->number:1325431901\.000000\)/
  );
});

test("buildLocalReport keeps single-step VMP register output chains for material flows", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 9, column: 14, asset_id: "sha1:runtime-sdk"}];
  const events = [
    {seq: 80, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 81, search_params_id: 82, url: "https://www.example.test/api/list?count=6"}], stack},
    {
      seq: 81,
      category: "reverse",
      phase: "call",
      api: "Bitwise.and",
      args: [{
        left_ref: "number:11.000000",
        left_source_ref: "handler_arg:299081/number:11.000000",
        left_register_ref: "register:string:length:200/number:11.000000",
        right_ref: "number:255.000000",
        result_ref: "number:11.000000",
        result_source_ref: "handler_arg:299081/number:11.000000",
        result_register_ref: "register:string:length:200/number:11.000000"
      }],
      stack
    },
    {seq: 82, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 81, search_params_id: 82, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 83, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 81, search_params_id: 82, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_single_step_register_output.ndjson",
    events,
    assets: []
  });
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const [link] = materialFlow.vmp_scalar_chain_links;

  assert.equal(link.stage, "integer_mixing");
  assert.equal(link.relation, "shared_value_ref");
  assert.ok(link.shared_refs.includes("register:string:length:200/number:11.000000"));
  assert.ok(link.shared_refs.includes("handler_arg:299081/number:11.000000"));
  assert.deepEqual(link.operation_trace, [{
    seq: 81,
    trace_index: 1,
    api: "Bitwise.and",
    input_refs: [
      "number:11.000000",
      "handler_arg:299081/number:11.000000",
      "register:string:length:200/number:11.000000",
      "number:255.000000"
    ],
    result_ref: "number:11.000000",
    output_refs: [
      "number:11.000000",
      "handler_arg:299081/number:11.000000",
      "register:string:length:200/number:11.000000"
    ],
    source_context_refs: ["sha1:runtime-sdk:9-9"]
  }]);
});

test("buildLocalReport links structured VMP outputs retained at the end of long chains", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 9, column: 14, asset_id: "sha1:runtime-sdk"}];
  const events = [
    {seq: 200, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 201, search_params_id: 202, url: "https://www.example.test/api/list?count=6"}], stack}
  ];
  let previousRef = "number:1000.000000";
  for (let index = 0; index < 22; index += 1) {
    const resultRef = `number:${1001 + index}.000000`;
    events.push({
      seq: 210 + index,
      category: "reverse",
      phase: "call",
      api: index % 2 ? "Bitwise.xor" : "Bitwise.or",
      args: [{
        left_ref: previousRef,
        right_ref: `number:${300 + index}.000000`,
        result_ref: resultRef
      }],
      stack
    });
    previousRef = resultRef;
  }
  events.push(
    {
      seq: 240,
      category: "reverse",
      phase: "call",
      api: "Bitwise.and",
      args: [{
        left_ref: previousRef,
        left_source_ref: "handler_arg:299081/number:11.000000",
        left_register_ref: "register:string:length:200/number:11.000000",
        right_ref: "number:255.000000",
        result_ref: "number:11.000000",
        result_source_ref: "handler_arg:299081/number:11.000000",
        result_register_ref: "register:string:length:200/number:11.000000"
      }],
      stack
    },
    {seq: 241, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 201, search_params_id: 202, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 242, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 201, search_params_id: 202, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  );

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_long_chain_structured_tail.ndjson",
    events,
    assets: []
  });
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const [link] = materialFlow.vmp_scalar_chain_links;

  assert.ok(link.shared_refs.includes("register:string:length:200/number:11.000000"));
  assert.ok(link.shared_refs.includes("handler_arg:299081/number:11.000000"));
  assert.ok(link.operation_trace.some((step) =>
    (step.output_refs || []).includes("register:string:length:200/number:11.000000")
  ));
});

test("buildLocalReport links flow-local VMP register chains beyond global top sixteen", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 9, column: 14, asset_id: "sha1:runtime-sdk"}];
  const events = [];
  for (let index = 0; index < 20; index += 1) {
    const base = 1000000 + index * 10000;
    const seq = 10 + index * 3;
    events.push(
      {seq, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left_ref: `number:${base}.000000`, right_ref: `number:${base + 7}.000000`, result_ref: `number:${base + 13}.000000`}], stack},
      {seq: seq + 1, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: `number:${base + 13}.000000`, y_ref: "number:16777619.000000", result_ref: `number:${base + 29}.000000`}], stack},
      {seq: seq + 2, category: "reverse", phase: "call", api: "Shift.unsignedRight", args: [{left_ref: `number:${base + 29}.000000`, right_ref: "number:0.000000", result_ref: `number:${base + 29}.000000`}], stack}
    );
  }
  events.push(
    {seq: 1000, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 301, search_params_id: 302, url: "https://www.example.test/api/list?count=6"}], stack},
    {
      seq: 1001,
      category: "reverse",
      phase: "call",
      api: "Bitwise.and",
      args: [{
        left_ref: "number:11.000000",
        left_source_ref: "handler_arg:299081/number:11.000000",
        left_register_ref: "register:string:length:200/number:11.000000",
        right_ref: "number:255.000000",
        result_ref: "number:11.000000",
        result_source_ref: "handler_arg:299081/number:11.000000",
        result_register_ref: "register:string:length:200/number:11.000000"
      }],
      stack
    },
    {seq: 1002, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 301, search_params_id: 302, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 1003, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 301, search_params_id: 302, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  );

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_flow_local_chain_beyond_top16.ndjson",
    events,
    assets: []
  });
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const link = (materialFlow.vmp_scalar_chain_links || []).find((item) =>
    (item.shared_refs || []).includes("register:string:length:200/number:11.000000")
  );

  assert.ok(link);
  assert.equal(materialFlow.vmp_scalar_chain_links[0], link);
  assert.ok(link.shared_refs.includes("register:string:length:200/number:11.000000"));
  assert.ok(link.operation_trace.some((step) => step.seq === 1001));
});

test("buildLocalReport deduplicates equivalent VMP scalar chain links in material flows", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 9, column: 14, asset_id: "sha1:runtime-sdk"}];
  const events = [
    {seq: 80, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 81, search_params_id: 82, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 81, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left_ref: "number:88.000000", right_ref: "number:23.000000", result_ref: "number:79.000000"}], stack},
    {seq: 82, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: "number:79.000000", y_ref: "number:16777619.000000", result_ref: "number:1325431901.000000"}], stack},
    {seq: 83, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left_ref: "number:88.000000", right_ref: "number:23.000000", result_ref: "number:79.000000"}], stack},
    {seq: 84, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: "number:79.000000", y_ref: "number:16777619.000000", result_ref: "number:1325431901.000000"}], stack},
    {seq: 85, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 81, search_params_id: 82, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 86, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 81, search_params_id: 82, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_scalar_duplicate_link.ndjson",
    events,
    assets: []
  });
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const pack = buildAgentInputPack(report);
  const parameter = pack.parameters.find((entry) => entry.param === "X-Signature");

  assert.equal(report.signature.agent_evidence_pack.vmp_scalar_ref_chains.length, 2);
  assert.deepEqual(materialFlow.vmp_scalar_chain_links.map((link) => link.chain_id), ["vmp_scalar_chain_1"]);
  assert.deepEqual(parameter.vmp_scalar_chain_links.map((link) => link.chain_id), ["vmp_scalar_chain_1"]);
});

test("buildLocalReport does not link weak low-constant scalar chains to material flows", () => {
  const stack = [{function: "bitset", url: "https://cdn.example.test/runtime-sdk.js", line: 12, column: 4, asset_id: "sha1:runtime-sdk"}];
  const events = [
    {seq: 100, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 101, search_params_id: 102, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 101, category: "reverse", phase: "call", api: "Bitwise.or", args: [{left_ref: "number:0.000000", right_ref: "number:1.000000", result_ref: "number:1.000000"}], stack},
    {seq: 102, category: "reverse", phase: "call", api: "Shift.left", args: [{left_ref: "number:1.000000", right_ref: "number:1.000000", result_ref: "number:2.000000"}], stack},
    {seq: 103, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 101, search_params_id: 102, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 104, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 101, search_params_id: 102, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_vmp_scalar_weak_link.ndjson",
    events,
    assets: []
  });
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const pack = buildAgentInputPack(report);
  const parameter = pack.parameters.find((entry) => entry.param === "X-Signature");

  assert.ok(report.signature.agent_evidence_pack.vmp_scalar_ref_chains.length >= 1);
  assert.deepEqual(materialFlow.vmp_scalar_chain_links || [], []);
  assert.deepEqual(parameter.vmp_scalar_chain_links || [], []);
});

test("buildLocalReport links generation steps to source locations and signed-request distance", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 4,
    column: 14,
    asset_id: "sha1:step-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 20, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 21, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 24}], stack},
    {seq: 22, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{mix_state_id: 40, left: 1, right: 2, result: 3}], stack},
    {seq: 23, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 31, search_params_id: 32, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 24, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_generation_step_sources.ndjson",
    events,
    assets: [{
      asset_id: "sha1:step-source",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function helper(x) { return x; }",
        "function signVm(input) {",
        "  const data = new TextEncoder().encode(input.url);",
        "  const mixed = data.length ^ 123;",
        "  url.searchParams.set('X-Signature', mixed);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const [inputStep, textStep, mixStep, attachStep, requestStep] = materialFlow.generation_steps;

  assert.deepEqual(materialFlow.generation_steps.map((step) => ({
    stage: step.stage,
    relation_to_signed_request: step.relation_to_signed_request,
    seq_distance_to_signed_request: step.seq_distance_to_signed_request,
    source_locations: step.source_locations.map((location) => ({
      ref: location.ref,
      asset_id: location.asset_id,
      url: location.url,
      content_path: location.content_path,
      line_start: location.line_start,
      line_end: location.line_end
    }))
  })), [
    {
      stage: "input_url",
      relation_to_signed_request: "before_signed_request",
      seq_distance_to_signed_request: 4,
      source_locations: [{
        ref: "sha1:step-source:2-6",
        asset_id: "sha1:step-source",
        url: scriptUrl,
        content_path: "assets/trace_demo/runtime-sdk.js",
        line_start: 2,
        line_end: 6
      }]
    },
    {
      stage: "text_or_string_decode",
      relation_to_signed_request: "before_signed_request",
      seq_distance_to_signed_request: 3,
      source_locations: [{
        ref: "sha1:step-source:2-6",
        asset_id: "sha1:step-source",
        url: scriptUrl,
        content_path: "assets/trace_demo/runtime-sdk.js",
        line_start: 2,
        line_end: 6
      }]
    },
    {
      stage: "integer_mixing",
      relation_to_signed_request: "before_signed_request",
      seq_distance_to_signed_request: 2,
      source_locations: [{
        ref: "sha1:step-source:2-6",
        asset_id: "sha1:step-source",
        url: scriptUrl,
        content_path: "assets/trace_demo/runtime-sdk.js",
        line_start: 2,
        line_end: 6
      }]
    },
    {
      stage: "signature_mutation",
      relation_to_signed_request: "before_signed_request",
      seq_distance_to_signed_request: 1,
      source_locations: [{
        ref: "sha1:step-source:2-6",
        asset_id: "sha1:step-source",
        url: scriptUrl,
        content_path: "assets/trace_demo/runtime-sdk.js",
        line_start: 2,
        line_end: 6
      }]
    },
    {
      stage: "signed_request",
      relation_to_signed_request: "signed_request",
      seq_distance_to_signed_request: 0,
      source_locations: [{
        ref: "sha1:step-source:2-6",
        asset_id: "sha1:step-source",
        url: scriptUrl,
        content_path: "assets/trace_demo/runtime-sdk.js",
        line_start: 2,
        line_end: 6
      }]
    }
  ]);
  assert.equal(inputStep.source_locations[0].function, "signVm");
  assert.deepEqual(textStep.source_locations[0].signals, ["int_bitwise", "text_codec", "url_signature"]);
  assert.ok(textStep.source_locations[0].calls.includes("TextEncoder"));
  assert.ok(mixStep.source_locations[0].operators.includes("^"));
  assert.deepEqual(attachStep.attachment_events[0].target_params, ["X-Signature"]);
  assert.equal(requestStep.role, "network_emit");
  assert.match(renderMarkdownReport(report), /generation_steps=input_url\[URL\.constructor@20 src=sha1:step-source:2-6 d=4\]->text_or_string_decode\[TextEncoder\.encode@21 src=sha1:step-source:2-6 d=3\]->integer_mixing\[Bitwise\.xor@22 src=sha1:step-source:2-6 d=2\]->signature_mutation\[URLSearchParams\.set@23 params=X-Signature src=sha1:step-source:2-6 d=1\]->signed_request\[Request\.constructor@24 params=X-Signature src=sha1:step-source:2-6 d=0\]/);
});

test("buildLocalReport uses trace index for generation-step request distance when seq is process-local", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signAcrossProcesses",
    url: scriptUrl,
    line: 3,
    column: 4,
    asset_id: "sha1:trace-distance",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {_trace_index: 100, seq: 9001, category: "reverse", phase: "call", api: "URL.constructor", args: [{url: "https://www.example.test/api/list?count=6"}], stack},
    {_trace_index: 101, seq: 9002, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 24}], stack},
    {_trace_index: 102, seq: 7, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_generation_step_trace_distance.ndjson",
    events,
    assets: [{
      asset_id: "sha1:trace-distance",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signAcrossProcesses(input) {",
        "  const data = new TextEncoder().encode(input.url);",
        "  return data;",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const textStep = materialFlow.generation_steps.find((step) => step.stage === "text_or_string_decode");
  const requestStep = materialFlow.generation_steps.find((step) => step.stage === "signed_request");
  const [reviewEntry] = report.signature.agent_evidence_pack.agent_review_package.entries;
  const [generationPath] = reviewEntry.generation_paths;
  const reviewTextStep = generationPath.steps.find((step) => step.stage === "text_or_string_decode");

  assert.deepEqual({
    relation: textStep.relation_to_signed_request,
    distance_basis: textStep.distance_basis,
    trace_distance: textStep.trace_distance_to_signed_request,
    seq_distance: textStep.seq_distance_to_signed_request,
    trace_start: textStep.trace_start,
    trace_end: textStep.trace_end
  }, {
    relation: "before_signed_request",
    distance_basis: "trace_index",
    trace_distance: 1,
    seq_distance: null,
    trace_start: 101,
    trace_end: 101
  });
  assert.deepEqual({
    relation: requestStep.relation_to_signed_request,
    distance_basis: requestStep.distance_basis,
    trace_distance: requestStep.trace_distance_to_signed_request,
    trace_start: requestStep.trace_start,
    trace_end: requestStep.trace_end
  }, {
    relation: "signed_request",
    distance_basis: "trace_index",
    trace_distance: 0,
    trace_start: 102,
    trace_end: 102
  });
  assert.deepEqual({
    relation: reviewTextStep.relation_to_signed_request,
    distance_basis: reviewTextStep.distance_basis,
    distance: reviewTextStep.distance_to_signed_request,
    trace_start: reviewTextStep.trace_start,
    trace_end: reviewTextStep.trace_end
  }, {
    relation: "before_signed_request",
    distance_basis: "trace_index",
    distance: 1,
    trace_start: 101,
    trace_end: 101
  });
  assert.match(renderMarkdownReport(report), /text_or_string_decode\[TextEncoder\.encode@9002 src=sha1:trace-distance:1-4 d=1\]/);
});

test("buildLocalReport labels agent review paths when runtime steps occur after signed request", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "afterSign",
    url: scriptUrl,
    line: 2,
    column: 2,
    asset_id: "sha1:after",
    asset_path: "assets/trace_demo/after.js"
  }];
  const events = [
    {_trace_index: 100, seq: 7, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: "https://www.example.test/api/list?X-Signature=secret-one"}], stack},
    {_trace_index: 101, seq: 9001, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 24}], stack},
    {_trace_index: 102, seq: 9002, category: "reverse", phase: "call", api: "Bitwise.and", args: [{left_type: "number"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_generation_path_after_request.ndjson",
    events,
    assets: [{
      asset_id: "sha1:after",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/after.js",
      content: [
        "function afterSign() {",
        "  new TextEncoder().encode(location.href);",
        "  return 1 & 2;",
        "}"
      ].join("\n")
    }]
  });

  const [entry] = report.signature.agent_evidence_pack.agent_review_package.entries;
  const [path] = entry.generation_paths;

  assert.equal(path.causality, "post_request_activity");
  assert.deepEqual(path.warnings, ["runtime_steps_after_signed_request"]);
  assert.deepEqual({
    pre_request_step_count: path.pre_request_step_count,
    post_request_step_count: path.post_request_step_count,
    unknown_relation_step_count: path.unknown_relation_step_count
  }, {
    pre_request_step_count: 0,
    post_request_step_count: 2,
    unknown_relation_step_count: 0
  });
  assert.match(renderMarkdownReport(report), /paths=generation_path_1:post_request_activity:text_or_string_decode\[TextEncoder\.encode@9001\]->integer_mixing\[Bitwise\.and@9002\]->signed_request\[BrowserNetwork\.request@7\]/);
});

test("buildLocalReport prioritizes pre-request review entries over post-request activity", () => {
  const preUrl = "https://cdn.example.test/pre.js";
  const postUrl = "https://cdn.example.test/post.js";
  const preStack = [{
    function: "preSign",
    url: preUrl,
    line: 3,
    column: 4,
    asset_id: "sha1:pre",
    asset_path: "assets/trace_demo/pre.js"
  }];
  const postStack = [{
    function: "afterSign",
    url: postUrl,
    line: 2,
    column: 2,
    asset_id: "sha1:post",
    asset_path: "assets/trace_demo/post.js"
  }];
  const events = [
    {_trace_index: 100, seq: 1, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: "https://www.example.test/api/after-a?X-Signature=secret-after-a"}], stack: postStack},
    {_trace_index: 101, seq: 9001, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 24}], stack: postStack},
    {_trace_index: 102, seq: 9002, category: "reverse", phase: "call", api: "Bitwise.and", args: [{left_type: "number"}], stack: postStack},
    {_trace_index: 110, seq: 2, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: "https://www.example.test/api/after-b?X-Signature=secret-after-b"}], stack: postStack},
    {_trace_index: 111, seq: 9011, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 26}], stack: postStack},
    {_trace_index: 112, seq: 9012, category: "reverse", phase: "call", api: "Bitwise.and", args: [{left_type: "number"}], stack: postStack},
    {_trace_index: 200, seq: 20, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/pre?count=6"}], stack: preStack},
    {_trace_index: 201, seq: 21, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 28}], stack: preStack},
    {_trace_index: 202, seq: 22, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{mix_state_id: 40, left: 1, right: 2, result: 3}], stack: preStack},
    {_trace_index: 203, seq: 23, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 31, search_params_id: 32, name: "X-Signature", value: "secret-pre"}], stack: preStack},
    {_trace_index: 204, seq: 24, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/pre?count=6&X-Signature=secret-pre"}], stack: preStack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_review_causality_priority.ndjson",
    events,
    assets: [
      {
        asset_id: "sha1:pre",
        kind: "external-script",
        url: preUrl,
        content_path: "assets/trace_demo/pre.js",
        content: [
          "function preSign(input) {",
          "  const url = new URL(input.url);",
          "  const data = new TextEncoder().encode(url.href);",
          "  const mixed = data.length ^ 123;",
          "  url.searchParams.set('X-Signature', mixed);",
          "  return new Request(url.href);",
          "}"
        ].join("\n")
      },
      {
        asset_id: "sha1:post",
        kind: "external-script",
        url: postUrl,
        content_path: "assets/trace_demo/post.js",
        content: [
          "function afterSign() {",
          "  new TextEncoder().encode(location.href);",
          "  return 1 & 2;",
          "}"
        ].join("\n")
      }
    ]
  });

  const reviewPackage = report.signature.agent_evidence_pack.agent_review_package;

  assert.deepEqual(reviewPackage.causality_summary, {
    pre_request_chain: 1,
    mixed_pre_post_request: 0,
    signed_or_unknown: 0,
    post_request_activity: 1,
    prioritized_entry_count: 1,
    deprioritized_entry_count: 1
  });
  assert.equal(reviewPackage.entries[0].function, "preSign");
  assert.equal(reviewPackage.entries[0].causality, "pre_request_chain");
  assert.equal(reviewPackage.entries[0].review_priority, "high");
  assert.equal(reviewPackage.entries[1].function, "afterSign");
  assert.equal(reviewPackage.entries[1].causality, "post_request_activity");
  assert.equal(reviewPackage.entries[1].review_priority, "low");
  assert.ok(reviewPackage.entries[1].warnings.includes("runtime_steps_after_signed_request"));
  assert.match(renderMarkdownReport(report), /causality_summary pre_request_chain=1 mixed_pre_post_request=0 signed_or_unknown=0 post_request_activity=1 prioritized=1 deprioritized=1/);
  assert.match(renderMarkdownReport(report), /review_entry_1 candidate=source_candidate_\d+ causality=pre_request_chain priority=high function=preSign/);
});

test("buildLocalReport links observed browser signed requests to renderer request by correlation key", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "sendSignedRequest",
    url: assetUrl,
    line: 4,
    column: 10,
    asset_id: "sha1:runtime-sdk",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {
      _trace_index: 100,
      seq: 1000,
      category: "reverse",
      phase: "call",
      api: "TextEncoder.encode",
      args: [{input_length: 24}],
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 101,
      seq: 1001,
      category: "reverse",
      phase: "call",
      api: "Bitwise.xor",
      args: [{mix_state_id: 40, left: 1, right: 2, result: 3}],
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 102,
      seq: 1002,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{
        method: "GET",
        url: "https://www.example.test/api/list?count=6&X-Signature=secret-one",
        network_correlation_key: "sha1:observed-key"
      }],
      stack,
      origin: "https://www.example.test"
    },
    {
      _trace_index: 103,
      seq: 8,
      category: "network",
      phase: "call",
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://www.example.test/api/list?count=6&X-Signature=secret-one",
        network_correlation_key: "sha1:observed-key",
        is_fetch_like_api: true
      }],
      origin: "https://www.example.test"
    }
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_observed_browser_renderer_correlation.ndjson",
    events,
    assets: [{
      asset_id: "sha1:runtime-sdk",
      kind: "external-script",
      url: assetUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function sendSignedRequest(input) {",
        "  const data = new TextEncoder().encode(input.url);",
        "  const mixed = data.length ^ 123;",
        "  return new Request('/api/list?X-Signature=' + mixed);",
        "}"
      ].join("\n")
    }]
  });

  const materialFlow = report.signature.agent_evidence_pack.signature_material_flows
    .find((flow) => (flow.stages || []).some((stage) => (stage.runtime_apis || []).includes("BrowserNetwork.request")));
  const reviewPackage = report.signature.agent_evidence_pack.agent_review_package;
  const [entry] = reviewPackage.entries;
  const path = entry.generation_paths.find((item) => item.flow_id === materialFlow.id);

  assert.ok(materialFlow);
  assert.equal(materialFlow.match, "signed_only");
  assert.deepEqual(materialFlow.data_links, [
    {
      from: "request_construction",
      to: "signed_request",
      refs: ["network_request:sha1:observed-key"]
    }
  ]);
  assert.deepEqual(materialFlow.renderer_request_link, {
    trace_index: 102,
    seq: 1002,
    api: "Request.constructor",
    method: "GET",
    endpoint: "https://www.example.test/api/list",
    relation: "before_browser_request",
    trace_distance: 1,
    function: "sendSignedRequest",
    stack_url: assetUrl,
    asset_id: "sha1:runtime-sdk",
    confidence: "high",
    match: "network_correlation_key"
  });
  assert.equal(entry.causality, "pre_request_chain");
  assert.equal(entry.review_priority, "high");
  assert.equal(path.causality, "pre_request_chain");
  assert.deepEqual(path.steps.map((step) => ({
    stage: step.stage,
    runtime_apis: step.runtime_apis,
    relation: step.relation_to_signed_request,
    distance: step.distance_to_signed_request
  })), [
    {
      stage: "text_or_string_decode",
      runtime_apis: ["TextEncoder.encode"],
      relation: "before_signed_request",
      distance: 3
    },
    {
      stage: "integer_mixing",
      runtime_apis: ["Bitwise.xor"],
      relation: "before_signed_request",
      distance: 2
    },
    {
      stage: "request_construction",
      runtime_apis: ["Request.constructor"],
      relation: "before_signed_request",
      distance: 1
    },
    {
      stage: "signed_request",
      runtime_apis: ["BrowserNetwork.request"],
      relation: "signed_request",
      distance: 0
    }
  ]);
  assert.match(renderMarkdownReport(report), /data_links=request_construction->signed_request:network_request:sha1:observed-key/);
});

test("buildLocalReport ranks signature source candidates from generation step source locations", () => {
  const signUrl = "https://cdn.example.test/runtime-sdk.js";
  const helperUrl = "https://cdn.example.test/helper.js";
  const signStack = [{
    function: "signVm",
    url: signUrl,
    line: 4,
    column: 14,
    asset_id: "sha1:sign-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const helperStack = [{
    function: "helperSign",
    url: helperUrl,
    line: 3,
    column: 8,
    asset_id: "sha1:helper-source",
    asset_path: "assets/trace_demo/helper.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}], stack: signStack},
    {seq: 11, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 24}], stack: signStack},
    {seq: 12, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{mix_state_id: 30, left: 1, right: 2, result: 3}], stack: signStack},
    {seq: 13, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-one"}], stack: signStack},
    {seq: 14, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack: signStack},
    {seq: 30, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 21, search_params_id: 22, url: "https://www.example.test/api/detail?id=1"}], stack: signStack},
    {seq: 31, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 28}], stack: signStack},
    {seq: 32, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 21, search_params_id: 22, url: "https://www.example.test/api/detail?id=1&X-Signature=secret-two"}], stack: signStack},
    {seq: 50, category: "reverse", phase: "call", api: "URL.constructor", args: [{url: "https://www.example.test/api/minor?x=1"}], stack: helperStack},
    {seq: 51, category: "reverse", phase: "call", api: "String.fromCharCode", args: [{argc: 7, first_code: 88, result_preview: "X-Signature"}], stack: helperStack},
    {seq: 52, category: "network", phase: "call", api: "Request.constructor", args: [{url: "https://www.example.test/api/minor?x=1&X-Signature=secret-three"}], stack: helperStack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_source_candidates.ndjson",
    events,
    assets: [
      {
        asset_id: "sha1:sign-source",
        kind: "external-script",
        url: signUrl,
        content_path: "assets/trace_demo/runtime-sdk.js",
        content: [
          "function helper(x) { return x; }",
          "function signVm(input) {",
          "  const data = new TextEncoder().encode(input.url);",
          "  const mixed = data.length ^ 123;",
          "  url.searchParams.set('X-Signature', mixed);",
          "  return new Request(url.href);",
          "}"
        ].join("\n")
      },
      {
        asset_id: "sha1:helper-source",
        kind: "external-script",
        url: helperUrl,
        content_path: "assets/trace_demo/helper.js",
        content: [
          "function helperSign(input) {",
          "  const name = String.fromCharCode(88,45,66,111,103,117,115);",
          "  return name;",
          "}"
        ].join("\n")
      }
    ]
  });

  const candidates = report.signature.agent_evidence_pack.signature_source_candidates;

  assert.deepEqual(candidates.map((candidate) => ({
    id: candidate.id,
    rank: candidate.rank,
    function: candidate.function,
    asset_id: candidate.asset_id,
    url: candidate.url,
    content_path: candidate.content_path,
    source_refs: candidate.source_refs,
    flow_count: candidate.flow_count,
    step_count: candidate.step_count,
    target_params: candidate.target_params,
    endpoints: candidate.endpoints,
    stages: candidate.stages,
    runtime_apis: candidate.runtime_apis,
    signals: candidate.signals,
    operators: candidate.operators,
    min_distance_to_signed_request: candidate.min_distance_to_signed_request,
    distance_basis: candidate.distance_basis,
    priority_reasons: candidate.priority_reasons
  })), [
    {
      id: "source_candidate_1",
      rank: 1,
      function: "signVm",
      asset_id: "sha1:sign-source",
      url: signUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      source_refs: ["sha1:sign-source:2-6"],
      flow_count: 2,
      step_count: 9,
      target_params: ["X-Signature"],
      endpoints: [
        "https://www.example.test/api/detail",
        "https://www.example.test/api/list"
      ],
      stages: [
        "input_url",
        "text_or_string_decode",
        "integer_mixing",
        "signature_mutation",
        "signed_request"
      ],
      runtime_apis: [
        "Bitwise.xor",
        "Request.constructor",
        "TextEncoder.encode",
        "URL.constructor",
        "URLSearchParams.set"
      ],
      signals: ["int_bitwise", "text_codec", "url_signature"],
      operators: ["^"],
      min_distance_to_signed_request: 0,
      distance_basis: "seq",
      priority_reasons: [
        "multiple_flows",
        "target_param_seen",
        "parameter_attachment",
        "source_signals",
        "near_signed_request"
      ]
    },
    {
      id: "source_candidate_2",
      rank: 2,
      function: "helperSign",
      asset_id: "sha1:helper-source",
      url: helperUrl,
      content_path: "assets/trace_demo/helper.js",
      source_refs: ["sha1:helper-source:1-4"],
      flow_count: 1,
      step_count: 3,
      target_params: ["X-Signature"],
      endpoints: ["https://www.example.test/api/minor"],
      stages: [
        "input_url",
        "text_or_string_decode",
        "signed_request"
      ],
      runtime_apis: [
        "Request.constructor",
        "String.fromCharCode",
        "URL.constructor"
      ],
      signals: ["text_codec"],
      operators: [],
      min_distance_to_signed_request: 0,
      distance_basis: "seq",
      priority_reasons: [
        "target_param_seen",
        "source_signals",
        "near_signed_request"
      ]
    }
  ]);
  assert.ok(candidates[0].evidence_score > candidates[1].evidence_score);
  assert.match(renderMarkdownReport(report), /Signature Source Candidates/);
  assert.match(renderMarkdownReport(report), /source_candidate_1 function=signVm asset=sha1:sign-source refs=sha1:sign-source:2-6 flows=2 steps=9 score=\d+ relevance=business_api_candidate classes=none params=X-Signature stages=input_url,text_or_string_decode,integer_mixing,signature_mutation,signed_request apis=Bitwise\.xor,Request\.constructor,TextEncoder\.encode,URL\.constructor,URLSearchParams\.set signals=int_bitwise,text_codec,url_signature reasons=multiple_flows,target_param_seen,parameter_attachment,source_signals,near_signed_request/);
});

test("buildLocalReport deprioritizes telemetry source candidates below business API candidates", () => {
  const businessUrl = "https://www.example.test/runtime-sdk-business.js";
  const telemetryUrl = "https://www.example.test/runtime-sdk-telemetry.js";
  const businessStack = [{
    function: "signBusiness",
    url: businessUrl,
    line: 4,
    column: 14,
    asset_id: "sha1:business-source",
    asset_path: "assets/trace_demo/runtime-sdk-business.js"
  }];
  const telemetryStack = [{
    function: "signTelemetry",
    url: telemetryUrl,
    line: 4,
    column: 14,
    asset_id: "sha1:telemetry-source",
    asset_path: "assets/trace_demo/runtime-sdk-telemetry.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://telemetry.example.test/monitor_browser/collect/batch/?batch=1"}], stack: telemetryStack},
    {seq: 11, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 64}], stack: telemetryStack},
    {seq: 12, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{mix_state_id: 30, left: 1, right: 2, result: 3}], stack: telemetryStack},
    {seq: 13, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-telemetry-one"}], stack: telemetryStack},
    {seq: 14, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://telemetry.example.test/monitor_browser/collect/batch/?batch=1&X-Signature=secret-telemetry-one"}], stack: telemetryStack},
    {seq: 20, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 21, search_params_id: 22, url: "https://telemetry.example.test/monitor_browser/collect/batch/?batch=2"}], stack: telemetryStack},
    {seq: 21, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 64}], stack: telemetryStack},
    {seq: 22, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{mix_state_id: 31, left: 2, right: 3, result: 1}], stack: telemetryStack},
    {seq: 23, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 21, search_params_id: 22, name: "X-Signature", value: "secret-telemetry-two"}], stack: telemetryStack},
    {seq: 24, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 21, search_params_id: 22, url: "https://telemetry.example.test/monitor_browser/collect/batch/?batch=2&X-Signature=secret-telemetry-two"}], stack: telemetryStack},
    {seq: 100, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list/?cursor=1"}], stack: businessStack},
    {seq: 101, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 42}], stack: businessStack},
    {seq: 102, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{mix_state_id: 40, left: 4, right: 5, result: 1}], stack: businessStack},
    {seq: 103, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 31, search_params_id: 32, name: "X-Signature", value: "secret-business"}], stack: businessStack},
    {seq: 104, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list/?cursor=1&X-Signature=secret-business"}], stack: businessStack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_example_telemetry_deprioritize.ndjson",
    events,
    assets: [
      {
        asset_id: "sha1:business-source",
        kind: "external-script",
        url: businessUrl,
        content_path: "assets/trace_demo/runtime-sdk-business.js",
        content: [
          "function signBusiness(url) {",
          "  const data = new TextEncoder().encode(url.href);",
          "  const mixed = data.length ^ 123;",
          "  url.searchParams.set('X-Signature', mixed);",
          "  return new Request(url.href);",
          "}"
        ].join("\n")
      },
      {
        asset_id: "sha1:telemetry-source",
        kind: "external-script",
        url: telemetryUrl,
        content_path: "assets/trace_demo/runtime-sdk-telemetry.js",
        content: [
          "function signTelemetry(url) {",
          "  const data = new TextEncoder().encode(url.href);",
          "  const mixed = data.length ^ 456;",
          "  url.searchParams.set('X-Signature', mixed);",
          "  return new Request(url.href);",
          "}"
        ].join("\n")
      }
    ]
  });

  const materialFlows = report.signature.agent_evidence_pack.signature_material_flows;
  const telemetryFlow = materialFlows.find((flow) => flow.endpoint === "https://telemetry.example.test/monitor_browser/collect/batch/");
  const businessFlow = materialFlows.find((flow) => flow.endpoint === "https://www.example.test/api/feed/list/");
  assert.equal(telemetryFlow.resource_class, "telemetry_endpoint");
  assert.equal(telemetryFlow.business_relevance, "low_value_telemetry");
  assert.equal(businessFlow.business_relevance, "business_api_candidate");

  const candidates = report.signature.agent_evidence_pack.signature_source_candidates;
  const telemetryCandidate = candidates.find((candidate) => candidate.function === "signTelemetry");
  assert.equal(candidates[0].function, "signBusiness");
  assert.equal(candidates[0].business_relevance, "business_api_candidate");
  assert.deepEqual(candidates[0].resource_classes, []);
  assert.ok(telemetryCandidate);
  assert.equal(telemetryCandidate.business_relevance, "low_value_telemetry");
  assert.deepEqual(telemetryCandidate.resource_classes, ["telemetry_endpoint"]);
  assert.ok(telemetryCandidate.priority_reasons.includes("deprioritized_telemetry_endpoint"));
  assert.ok(telemetryCandidate.evidence_score < candidates[0].evidence_score);
  assert.match(renderMarkdownReport(report), /source_candidate_1 function=signBusiness/);
  assert.match(renderMarkdownReport(report), /source_candidate_2 function=signTelemetry .*relevance=low_value_telemetry .*reasons=.*deprioritized_telemetry_endpoint/);
});

test("buildLocalReport surfaces business API runtime hints from truncated URL canonicalization", () => {
  const sdkUrl = "https://cdn.example.test/security/security-runtime.js";
  const appUrl = "https://www.example.test/app/feed-prefetch.js";
  const stack = [
    {function: "decodeUrl", url: sdkUrl, line: 1, column: 12629, asset_id: "sha1:security-runtime"},
    {function: "fetchData", url: appUrl, line: 2, column: 72756, asset_id: "sha1:feed"}
  ];
  const truncatedBusinessUrl = "https://www.example.test/api/records/list/?client_time=1&app_id=1000&app_name=demo_web&sessionToken=secret-token";
  const events = [
    {
      seq: 629407,
      category: "reverse",
      phase: "call",
      api: "decodeURIComponent",
      args: [{
        input_preview: truncatedBusinessUrl,
        input_length: 1530,
        input_truncated: true,
        result_preview: truncatedBusinessUrl,
        result_length: 1392,
        result_truncated: true
      }],
      stack
    },
    {
      seq: 629424,
      category: "reverse",
      phase: "call",
      api: "String.prototype.substring",
      args: [{input_preview: "sessionToken", result_preview: "sessionToken"}],
      stack
    }
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_business_runtime_hint.ndjson",
    events,
    assets: [
      {
        asset_id: "sha1:security-runtime",
        kind: "external-script",
        url: sdkUrl,
        content_path: "assets/trace_demo/security-runtime.js",
        content: "function decodeUrl(url) { return decodeURIComponent(url); }"
      },
      {
        asset_id: "sha1:feed",
        kind: "external-script",
        url: appUrl,
        content_path: "assets/trace_demo/feed-prefetch.js",
        content: "function fetchData(url) { return fetch(url); }"
      }
    ]
  });

  const hints = report.signature.agent_evidence_pack.business_api_runtime_hints;
  assert.equal(hints.length, 1);
  const [hint] = hints;
  assert.equal(hint.endpoint, "https://www.example.test/api/records/list/");
  assert.equal(hint.api, "decodeURIComponent");
  assert.equal(hint.seq, 629407);
  assert.equal(hint.business_relevance, "business_api_candidate");
  assert.equal(hint.value_status, "truncated_preview");
  assert.ok(hint.query_keys.includes("sessionToken"));
  assert.deepEqual(hint.evidence_gaps, ["full_url_value_truncated", "query_keys_incomplete"]);
  assert.deepEqual(hint.next_actions, ["capture_full_url_value", "capture_network_anchor_for_endpoint"]);
  assert.deepEqual(hint.source_roles, ["core_signature_asset", "application_caller"]);
  assert.ok(hint.source_stack_urls.includes(sdkUrl));
  assert.ok(hint.source_stack_urls.includes(appUrl));
  assert.doesNotMatch(JSON.stringify(hint), /<redacted>|client_time=1|app_id=1000/);
  assert.match(
    renderMarkdownReport(report),
    /business_api_runtime_hint endpoint=https:\/\/www\.example\.test\/api\/records\/list\/ api=decodeURIComponent seq=629407 relevance=business_api_candidate status=truncated_preview query_keys=sessionToken,client_time,app_id,app_name roles=core_signature_asset,application_caller gaps=full_url_value_truncated,query_keys_incomplete next=capture_full_url_value,capture_network_anchor_for_endpoint/
  );
});

test("buildLocalReport prefers full URI codec values over truncated URL previews", () => {
  const sdkUrl = "https://cdn.example.test/obj/generic_web_runtime/runtime-sdk/1.0.0.374/runtime-sdk.js";
  const stack = [{function: "decodeUrl", url: sdkUrl, line: 1, column: 12629, asset_id: "sha1:runtime-sdk"}];
  const previewUrl = "https://www.example.test/api/records/list/?client_time=1&app_id=1000&app_name=demo_web";
  const fullUrl = [
    previewUrl,
    "app_language=en",
    "browser_language=en-US",
    "browser_name=Mozilla",
    "browser_online=true",
    "browser_platform=MacIntel",
    "device_id=demo-device",
    "sessionToken=secret-token",
    "X-Signature=secret-signature"
  ].join("&");

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_example_full_uri_hint.ndjson",
    events: [{
      seq: 629500,
      category: "reverse",
      phase: "call",
      api: "decodeURIComponent",
      args: [{
        input_preview: previewUrl,
        input_length: fullUrl.length,
        input_truncated: false,
        input_preview_truncated: true,
        input: fullUrl,
        result_preview: previewUrl,
        result_length: fullUrl.length,
        result_truncated: false,
        result_preview_truncated: true,
        result: fullUrl
      }],
      stack
    }],
    assets: [{
      asset_id: "sha1:runtime-sdk",
      kind: "external-script",
      url: sdkUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: "function decodeUrl(url) { return decodeURIComponent(url); }"
    }]
  });

  const [hint] = report.signature.agent_evidence_pack.business_api_runtime_hints;
  assert.equal(hint.endpoint, "https://www.example.test/api/records/list/");
  assert.equal(hint.value_status, "full_value");
  assert.ok(hint.query_keys.includes("browser_platform"));
  assert.ok(hint.query_keys.includes("sessionToken"));
  assert.ok(hint.query_keys.includes("X-Signature"));
  assert.deepEqual(hint.evidence_gaps, []);
  assert.deepEqual(hint.next_actions, ["capture_network_anchor_for_endpoint"]);
});

test("buildLocalReport preserves signature query keys from long full URL runtime hints", () => {
  const fillerQuery = Array.from({length: 80}, (_, index) => `k${index}=v${index}`).join("&");
  const fullUrl = `https://www.example.test/api/records/list/?${fillerQuery}&sessionToken=secret-token&X-Signature=secret-signature`;
  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_example_long_full_uri_hint.ndjson",
    events: [{
      seq: 629501,
      category: "reverse",
      phase: "call",
      api: "decodeURIComponent",
      args: [{
        input_preview: fullUrl.slice(0, 128),
        input_preview_truncated: true,
        input: fullUrl,
        input_length: fullUrl.length,
        input_truncated: false,
        result_preview: fullUrl.slice(0, 128),
        result_preview_truncated: true,
        result: fullUrl,
        result_length: fullUrl.length,
        result_truncated: false
      }],
      stack: [{function: "decodeUrl", url: "https://cdn.example.test/runtime-sdk.js", line: 1, column: 1}]
    }],
    assets: []
  });

  const [hint] = report.signature.agent_evidence_pack.business_api_runtime_hints;
  assert.equal(hint.value_status, "full_value");
  assert.ok(hint.query_keys.includes("X-Signature"));
  assert.ok(hint.query_keys.includes("sessionToken"));
  assert.equal(hint.query_keys[0], "X-Signature");
  assert.equal(hint.query_keys[1], "sessionToken");
});

test("buildLocalReport emits agent review package for ranked signature source candidates", () => {
  const signUrl = "https://cdn.example.test/runtime-sdk.js";
  const helperUrl = "https://cdn.example.test/helper.js";
  const signStack = [{
    function: "signVm",
    url: signUrl,
    line: 4,
    column: 14,
    asset_id: "sha1:sign-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const helperStack = [{
    function: "helperSign",
    url: helperUrl,
    line: 3,
    column: 8,
    asset_id: "sha1:helper-source",
    asset_path: "assets/trace_demo/helper.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}], stack: signStack},
    {seq: 11, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 24}], stack: signStack},
    {seq: 12, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{mix_state_id: 30, left: 1, right: 2, result: 3}], stack: signStack},
    {seq: 13, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-one"}], stack: signStack},
    {seq: 14, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack: signStack},
    {seq: 30, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 21, search_params_id: 22, url: "https://www.example.test/api/detail?id=1"}], stack: signStack},
    {seq: 31, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 28}], stack: signStack},
    {seq: 32, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 21, search_params_id: 22, url: "https://www.example.test/api/detail?id=1&X-Signature=secret-two"}], stack: signStack},
    {seq: 50, category: "reverse", phase: "call", api: "URL.constructor", args: [{url: "https://www.example.test/api/minor?x=1"}], stack: helperStack},
    {seq: 51, category: "reverse", phase: "call", api: "String.fromCharCode", args: [{argc: 7, first_code: 88, result_preview: "X-Signature"}], stack: helperStack},
    {seq: 52, category: "network", phase: "call", api: "Request.constructor", args: [{url: "https://www.example.test/api/minor?x=1&X-Signature=secret-three"}], stack: helperStack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_agent_review_package.ndjson",
    events,
    assets: [
      {
        asset_id: "sha1:sign-source",
        kind: "external-script",
        url: signUrl,
        content_path: "assets/trace_demo/runtime-sdk.js",
        content: [
          "function helper(x) { return x; }",
          "function signVm(input) {",
          "  const data = new TextEncoder().encode(input.url);",
          "  const mixed = data.length ^ 123;",
          "  url.searchParams.set('X-Signature', mixed);",
          "  return new Request(url.href);",
          "}"
        ].join("\n")
      },
      {
        asset_id: "sha1:helper-source",
        kind: "external-script",
        url: helperUrl,
        content_path: "assets/trace_demo/helper.js",
        content: [
          "function helperSign(input) {",
          "  const name = String.fromCharCode(88,45,66,111,103,117,115);",
          "  return name;",
          "}"
        ].join("\n")
      }
    ]
  });

  const reviewPackage = report.signature.agent_evidence_pack.agent_review_package;
  const parameterBrief = report.signature.agent_evidence_pack.parameter_generation_brief;
  const [topEntry] = reviewPackage.entries;

  assert.equal(reviewPackage.version, 1);
  assert.equal(reviewPackage.purpose, "agent_source_review_package");
  assert.equal(reviewPackage.entry_count, 2);
  assert.deepEqual({
    id: topEntry.id,
    source_candidate_id: topEntry.source_candidate_id,
    rank: topEntry.rank,
    function: topEntry.function,
    asset_id: topEntry.asset_id,
    url: topEntry.url,
    content_path: topEntry.content_path,
    source_refs: topEntry.source_refs,
    line_ranges: topEntry.line_ranges,
    flow_ids: topEntry.flow_ids,
    flow_count: topEntry.flow_count,
    step_count: topEntry.step_count,
    target_params: topEntry.target_params,
    endpoints: topEntry.endpoints,
    stages: topEntry.stages,
    runtime_apis: topEntry.runtime_apis,
    signals: topEntry.signals,
    operators: topEntry.operators,
    min_distance_to_signed_request: topEntry.min_distance_to_signed_request,
    distance_basis: topEntry.distance_basis,
    review_reasons: topEntry.review_reasons,
    next_questions: topEntry.next_questions
  }, {
    id: "review_entry_1",
    source_candidate_id: "source_candidate_1",
    rank: 1,
    function: "signVm",
    asset_id: "sha1:sign-source",
    url: signUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    source_refs: ["sha1:sign-source:2-6"],
    line_ranges: [{
      ref: "sha1:sign-source:2-6",
      content_path: "assets/trace_demo/runtime-sdk.js",
      line_start: 2,
      line_end: 6,
      preview: "function signVm(input) { const data = new TextEncoder().encode(input.url); const mixed = data.length ^ 123; url.searchParams.set('X-Signature', mixed); return new Request(url.href);"
    }],
    flow_ids: ["material_flow_1", "material_flow_2"],
    flow_count: 2,
    step_count: 9,
    target_params: ["X-Signature"],
    endpoints: [
      "https://www.example.test/api/detail",
      "https://www.example.test/api/list"
    ],
    stages: [
      "input_url",
      "text_or_string_decode",
      "integer_mixing",
      "signature_mutation",
      "signed_request"
    ],
    runtime_apis: [
      "Bitwise.xor",
      "Request.constructor",
      "TextEncoder.encode",
      "URL.constructor",
      "URLSearchParams.set"
    ],
    signals: ["int_bitwise", "text_codec", "url_signature"],
    operators: ["^"],
    min_distance_to_signed_request: 0,
    distance_basis: "seq",
    review_reasons: [
      "multiple_flows",
      "target_param_seen",
      "parameter_attachment",
      "source_signals",
      "near_signed_request"
    ],
    next_questions: [
      "which_inputs_feed_this_source_window",
      "which_runtime_step_attaches_target_params",
      "which_request_endpoint_uses_this_candidate"
    ]
  });
  assert.ok(topEntry.evidence_score > 0);
  assert.ok(topEntry.calls.includes("TextEncoder"));
  assert.ok(topEntry.calls.includes("encode"));
  assert.ok(topEntry.calls.includes("url.searchParams.set"));
  assert.deepEqual(topEntry.generation_paths.map((path) => ({
    id: path.id,
    flow_id: path.flow_id,
    endpoint: path.endpoint,
    target_params: path.target_params,
    step_count: path.step_count,
    stage_summary: path.stage_summary,
    steps: path.steps.map((step) => ({
      stage: step.stage,
      role: step.role,
      seq_start: step.seq_start,
      runtime_apis: step.runtime_apis,
      target_params: step.target_params,
      source_refs: step.source_refs,
      source_calls: step.source_calls,
      source_signals: step.source_signals,
      source_operators: step.source_operators,
      source_constants: step.source_constants,
      relation_to_signed_request: step.relation_to_signed_request,
      distance_to_signed_request: step.distance_to_signed_request
    }))
  })), [
    {
      id: "generation_path_1",
      flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/list",
      target_params: ["X-Signature"],
      step_count: 5,
      stage_summary: "input_url[URL.constructor@10]->text_or_string_decode[TextEncoder.encode@11]->integer_mixing[Bitwise.xor@12]->signature_mutation[URLSearchParams.set@13]->signed_request[Request.constructor@14]",
      steps: [
        {
          stage: "input_url",
          role: "input",
          seq_start: 10,
          runtime_apis: ["URL.constructor"],
          target_params: [],
          source_refs: ["sha1:sign-source:2-6"],
          source_calls: [],
          source_signals: [],
          source_operators: [],
          source_constants: [],
          relation_to_signed_request: "before_signed_request",
          distance_to_signed_request: 4
        },
        {
          stage: "text_or_string_decode",
          role: "string_material",
          seq_start: 11,
          runtime_apis: ["TextEncoder.encode"],
          target_params: [],
          source_refs: ["sha1:sign-source:2-6"],
          source_calls: ["TextEncoder"],
          source_signals: ["text_codec"],
          source_operators: [],
          source_constants: [],
          relation_to_signed_request: "before_signed_request",
          distance_to_signed_request: 3
        },
        {
          stage: "integer_mixing",
          role: "transform",
          seq_start: 12,
          runtime_apis: ["Bitwise.xor"],
          target_params: [],
          source_refs: ["sha1:sign-source:2-6"],
          source_calls: [],
          source_signals: ["int_bitwise"],
          source_operators: ["^"],
          source_constants: ["123"],
          relation_to_signed_request: "before_signed_request",
          distance_to_signed_request: 2
        },
        {
          stage: "signature_mutation",
          role: "parameter_attachment",
          seq_start: 13,
          runtime_apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          source_refs: ["sha1:sign-source:2-6"],
          source_calls: [],
          source_signals: ["text_codec", "int_bitwise", "url_signature"],
          source_operators: [],
          source_constants: [],
          relation_to_signed_request: "before_signed_request",
          distance_to_signed_request: 1
        },
        {
          stage: "signed_request",
          role: "network_emit",
          seq_start: 14,
          runtime_apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          source_refs: ["sha1:sign-source:2-6"],
          source_calls: [],
          source_signals: ["text_codec", "int_bitwise", "url_signature"],
          source_operators: [],
          source_constants: [],
          relation_to_signed_request: "signed_request",
          distance_to_signed_request: 0
        }
      ]
    },
    {
      id: "generation_path_2",
      flow_id: "material_flow_2",
      endpoint: "https://www.example.test/api/detail",
      target_params: ["X-Signature"],
      step_count: 3,
      stage_summary: "input_url[URL.constructor@30]->text_or_string_decode[TextEncoder.encode@31]->signed_request[Request.constructor@32]",
      steps: [
        {
          stage: "input_url",
          role: "input",
          seq_start: 30,
          runtime_apis: ["URL.constructor"],
          target_params: [],
          source_refs: ["sha1:sign-source:2-6"],
          source_calls: [],
          source_signals: [],
          source_operators: [],
          source_constants: [],
          relation_to_signed_request: "before_signed_request",
          distance_to_signed_request: 2
        },
        {
          stage: "text_or_string_decode",
          role: "string_material",
          seq_start: 31,
          runtime_apis: ["TextEncoder.encode"],
          target_params: [],
          source_refs: ["sha1:sign-source:2-6"],
          source_calls: ["TextEncoder"],
          source_signals: ["text_codec"],
          source_operators: [],
          source_constants: [],
          relation_to_signed_request: "before_signed_request",
          distance_to_signed_request: 1
        },
        {
          stage: "signed_request",
          role: "network_emit",
          seq_start: 32,
          runtime_apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          source_refs: ["sha1:sign-source:2-6"],
          source_calls: [],
          source_signals: ["text_codec", "int_bitwise", "url_signature"],
          source_operators: [],
          source_constants: [],
          relation_to_signed_request: "signed_request",
          distance_to_signed_request: 0
        }
      ]
    }
  ]);
  assert.equal(parameterBrief.version, 1);
  assert.equal(parameterBrief.purpose, "agent_parameter_generation_brief");
  assert.equal(parameterBrief.parameter_count, 1);
  assert.deepEqual(parameterBrief.redaction, {
    values_redacted: false,
    output: "raw_values_preserved"
  });
  assert.deepEqual(parameterBrief.parameters.map((entry) => ({
    param: entry.param,
    status: entry.status,
    best_flow_id: entry.best_flow_id,
    endpoint: entry.endpoint,
    confidence: entry.confidence,
    evidence_status: entry.evidence_status,
    readiness: entry.readiness,
    flow_ids: entry.flow_ids,
    source_candidate_ids: entry.source_candidate_ids,
    review_entry_ids: entry.review_entry_ids,
    source_refs: entry.source_refs,
    stage_chain: entry.stage_chain,
    evidence_gaps: entry.evidence_gaps,
    next_questions: entry.next_questions,
    trace: entry.generation_trace.map((step) => ({
      order: step.order,
      stage: step.stage,
      role: step.role,
      seq_start: step.seq_start,
      seq_end: step.seq_end,
      apis: step.apis,
      target_params: step.target_params,
      param_relation: step.param_relation,
      relation: step.relation,
      distance: step.distance_to_signed_request,
      source_refs: step.source_refs,
      source_calls: step.source_calls,
      source_signals: step.source_signals,
      source_operators: step.source_operators,
      source_constants: step.source_constants
    }))
  })), [{
    param: "X-Signature",
    status: "attachment_observed",
    best_flow_id: "material_flow_1",
    endpoint: "https://www.example.test/api/list",
    confidence: "high",
    evidence_status: "observed_only",
    readiness: "strong",
    flow_ids: ["material_flow_1", "material_flow_2", "material_flow_3"],
    source_candidate_ids: ["source_candidate_1", "source_candidate_2"],
    review_entry_ids: ["review_entry_1", "review_entry_2"],
    source_refs: ["sha1:sign-source:2-6", "sha1:helper-source:1-4"],
    stage_chain: [
      "input_url",
      "text_or_string_decode",
      "integer_mixing",
      "signature_mutation",
      "signed_request"
    ],
    evidence_gaps: [],
    next_questions: [
      "which_inputs_feed_this_source_window",
      "which_runtime_step_attaches_target_params",
      "which_request_endpoint_uses_this_candidate",
      "where_are_target_params_attached"
    ],
    trace: [
      {
        order: 1,
        stage: "input_url",
        role: "input",
        seq_start: 10,
        seq_end: 10,
        apis: ["URL.constructor"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance: 4,
        source_refs: ["sha1:sign-source:2-6"],
        source_calls: [],
        source_signals: [],
        source_operators: [],
        source_constants: []
      },
      {
        order: 2,
        stage: "text_or_string_decode",
        role: "material",
        seq_start: 11,
        seq_end: 11,
        apis: ["TextEncoder.encode"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance: 3,
        source_refs: ["sha1:sign-source:2-6"],
        source_calls: ["TextEncoder"],
        source_signals: ["text_codec"],
        source_operators: [],
        source_constants: []
      },
      {
        order: 3,
        stage: "integer_mixing",
        role: "transform",
        seq_start: 12,
        seq_end: 12,
        apis: ["Bitwise.xor"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance: 2,
        source_refs: ["sha1:sign-source:2-6"],
        source_calls: [],
        source_signals: ["int_bitwise"],
        source_operators: ["^"],
        source_constants: ["123"]
      },
      {
        order: 4,
        stage: "signature_mutation",
        role: "parameter_attachment",
        seq_start: 13,
        seq_end: 13,
        apis: ["URLSearchParams.set"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "before_signed_request",
        distance: 1,
        source_refs: ["sha1:sign-source:2-6"],
        source_calls: [],
        source_signals: ["text_codec", "int_bitwise", "url_signature"],
        source_operators: [],
        source_constants: []
      },
      {
        order: 5,
        stage: "signed_request",
        role: "network_emit",
        seq_start: 14,
        seq_end: 14,
        apis: ["Request.constructor"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "signed_request",
        distance: 0,
        source_refs: ["sha1:sign-source:2-6"],
        source_calls: [],
        source_signals: ["text_codec", "int_bitwise", "url_signature"],
        source_operators: [],
        source_constants: []
      }
    ]
  }]);
  assert.match(renderMarkdownReport(report), /Parameter Generation Brief/);
  assert.match(
    renderMarkdownReport(report),
    /parameter X-Signature status=attachment_observed flow=material_flow_1 endpoint=https:\/\/www\.example\.test\/api\/list readiness=strong agent_generation=[^\n]* trace=input_url\[URL\.constructor d=4 target=X-Signature relation=flow_target\]->text_or_string_decode\[TextEncoder\.encode d=3 target=X-Signature relation=flow_target\]->integer_mixing\[Bitwise\.xor d=2 target=X-Signature relation=flow_target\]->signature_mutation\[URLSearchParams\.set d=1 target=X-Signature relation=direct_observed\]->signed_request\[Request\.constructor d=0 target=X-Signature relation=direct_observed\] ref_lineage=[^\n]* ref_events=[^\n]* sources=sha1:sign-source:2-6,sha1:helper-source:1-4 candidates=source_candidate_1,source_candidate_2 reviews=review_entry_1,review_entry_2/
  );
  assert.match(renderMarkdownReport(report), /Agent Review Package/);
  assert.match(
    renderMarkdownReport(report),
    /review_entry_1 candidate=source_candidate_1 causality=pre_request_chain priority=high function=signVm path=assets\/trace_demo\/runtime-sdk\.js lines=2-6 endpoints=https:\/\/www\.example\.test\/api\/detail,https:\/\/www\.example\.test\/api\/list params=X-Signature stages=input_url,text_or_string_decode,integer_mixing,signature_mutation,signed_request apis=Bitwise\.xor,Request\.constructor,TextEncoder\.encode,URL\.constructor,URLSearchParams\.set signals=int_bitwise,text_codec,url_signature paths=.* next=which_inputs_feed_this_source_window,which_runtime_step_attaches_target_params,which_request_endpoint_uses_this_candidate/
  );
  assert.match(
    renderMarkdownReport(report),
    /paths=generation_path_1:pre_request_chain:input_url\[URL\.constructor@10\]->text_or_string_decode\[TextEncoder\.encode@11\]->integer_mixing\[Bitwise\.xor@12\]->signature_mutation\[URLSearchParams\.set@13\]->signed_request\[Request\.constructor@14\]/
  );
});

test("buildLocalReport keeps best parameter flow id in compact parameter brief", () => {
  const stack = [{
    function: "signVm",
    url: "https://cdn.example.test/runtime-sdk.js",
    line: 1,
    column: 1,
    asset_id: "sha1:sign-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [];
  for (let index = 1; index <= 9; index += 1) {
    events.push({
      seq: index * 10,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{
        url: `https://www.example.test/api/item/${index}?X-Signature=secret-${index}`
      }],
      stack
    });
  }
  events.push(
    {
      seq: 100,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 100, search_params_id: 101, url: "https://www.example.test/api/item/best?cursor=1"}],
      stack
    },
    {
      seq: 101,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.set",
      args: [{url_object_id: 100, search_params_id: 101, name: "X-Signature", value: "secret-best"}],
      stack
    },
    {
      seq: 102,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{
        url_object_id: 100,
        search_params_id: 101,
        url: "https://www.example.test/api/item/best?cursor=1&X-Signature=secret-best"
      }],
      stack
    }
  );

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_parameter_brief_best_flow.ndjson",
    events,
    assets: []
  });
  const brief = report.signature.agent_evidence_pack.parameter_generation_brief;
  const entry = brief.parameters.find((item) => item.param === "X-Signature");

  assert.equal(entry.status, "attachment_observed");
  assert.ok(entry.best_flow_id);
  assert.ok(entry.flow_ids.includes(entry.best_flow_id), JSON.stringify(entry.flow_ids));
});

test("buildLocalReport deprioritizes browser-internal source candidates", () => {
  const pageUrl = "https://cdn.example.test/runtime-sdk.js";
  const internalUrl = "chrome://resources/mojo/mojo/public/js/bindings.js";
  const pageStack = [{
    function: "signVm",
    url: pageUrl,
    line: 3,
    column: 8,
    asset_id: "sha1:page-source",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const internalStack = [{
    function: "mojo.internal.setUint64",
    url: internalUrl,
    line: 2,
    column: 4,
    asset_id: "sha1:internal-source",
    asset_path: "assets/trace_demo/bindings.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url: "https://www.example.test/api/list?count=6"}], stack: pageStack},
    {seq: 11, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 24}], stack: pageStack},
    {seq: 12, category: "network", phase: "call", api: "Request.constructor", args: [{url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack: pageStack},
    {seq: 19, category: "reverse", phase: "call", api: "URL.constructor", args: [{url: "https://www.example.test/api/detail?id=1"}], stack: internalStack},
    {seq: 20, category: "reverse", phase: "call", api: "DataView.setUint32", args: [{value: 1}], stack: internalStack},
    {seq: 21, category: "reverse", phase: "call", api: "Bitwise.and", args: [{left: 1, right: 2, result: 0}], stack: internalStack},
    {seq: 22, category: "network", phase: "call", api: "Request.constructor", args: [{url: "https://www.example.test/api/detail?id=1&X-Signature=secret-two"}], stack: internalStack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_internal_source_candidates.ndjson",
    events,
    assets: [
      {
        asset_id: "sha1:page-source",
        kind: "external-script",
        url: pageUrl,
        content_path: "assets/trace_demo/runtime-sdk.js",
        content: [
          "function signVm(input) {",
          "  const data = new TextEncoder().encode(input.url);",
          "  return data;",
          "}"
        ].join("\n")
      },
      {
        asset_id: "sha1:internal-source",
        kind: "external-script",
        url: internalUrl,
        content_path: "assets/trace_demo/bindings.js",
        content: [
          "function setUint64(value) {",
          "  dataView.setUint32(0, value & 0xffffffff);",
          "  return value;",
          "}"
        ].join("\n")
      }
    ]
  });

  const candidates = report.signature.agent_evidence_pack.signature_source_candidates;
  const internal = candidates.find((candidate) => candidate.function === "mojo.internal.setUint64");

  assert.equal(candidates[0].function, "signVm");
  assert.ok(internal);
  assert.ok(internal.priority_reasons.includes("deprioritized_internal_runtime"));
  assert.ok(candidates[0].evidence_score > internal.evidence_score);
});

test("buildLocalReport distinguishes captured-unlinked VMP gaps from missing hooks", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const otherAssetUrl = "https://cdn.example.test/other.js";
  const otherStack = [{
    function: "decodeUnrelated",
    url: otherAssetUrl,
    line: 3,
    column: 1,
    asset_id: "sha1:other",
    asset_path: "assets/trace_demo/other.js"
  }];
  const events = [
    {
      seq: 0,
      category: "reverse",
      api: "localStorage.getItem",
      args: [{key: "seed"}],
      origin: "https://www.example.test",
      stack: otherStack
    },
    {
      seq: 1,
      category: "reverse",
      api: "atob",
      args: [{input_length: 12, result_length: 8}],
      origin: "https://www.example.test",
      stack: otherStack
    },
    {
      seq: 2,
      category: "reverse",
      api: "document.cookie.get",
      args: [{value: "sessionToken=secret-token"}],
      origin: "https://www.example.test",
      stack: otherStack
    },
    {
      seq: 10,
      category: "reverse",
      api: "URL.constructor",
      args: [{url: "https://www.example.test/api/list?count=1"}],
      origin: "https://www.example.test",
      stack: [{function: "sign", url: assetUrl, line: 10, column: 2}]
    },
    {
      seq: 11,
      category: "reverse",
      api: "TextEncoder.encode",
      args: [{input_length: 25}],
      origin: "https://www.example.test",
      stack: [{function: "sign", url: assetUrl, line: 11, column: 2}]
    },
    {
      seq: 12,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=1&X-Signature=secret-one&X-Secondary-Signature=secret-two"}],
      origin: "https://www.example.test",
      stack: [{function: "sign", url: assetUrl, line: 12, column: 2}]
    }
  ];
  const assets = [{
    asset_id: "sha1:other",
    kind: "script",
    url: otherAssetUrl,
    content_path: "assets/trace_demo/other.js",
    content: `
      const raw = "X-Signature=secret-one&sessionToken=secret-token";
      function decodeUnrelated() {
        return atob(raw);
      }
    `
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_unlinked_vmp_hooks.ndjson", events, assets});
  const pack = report.signature.agent_evidence_pack;
  const hooks = pack.vmp_hook_analysis;
  const [flow] = pack.flows;

  assert.deepEqual(hooks.coverage_by_type.vmp_string_decoder, {
    observed_flows: 0,
    missing_flows: 1,
    coverage_ratio: 0,
    event_count: 0,
    global_event_count: 1,
    global_apis: [{api: "atob", count: 1}]
  });
  assert.deepEqual(hooks.coverage_by_type.vmp_bytecode_or_register_access, {
    observed_flows: 0,
    missing_flows: 1,
    coverage_ratio: 0,
    event_count: 0,
    global_event_count: 0,
    global_apis: []
  });
  const stringGap = hooks.hook_gaps.find((gap) => gap.type === "vmp_string_decoder");
  assert.equal(stringGap.linking_candidates.length, 1);
  assert.deepEqual({
    seq: stringGap.linking_candidates[0].seq,
    api: stringGap.linking_candidates[0].api,
    family: stringGap.linking_candidates[0].family,
    function: stringGap.linking_candidates[0].function,
    stack_url: stringGap.linking_candidates[0].stack_url,
    origin: stringGap.linking_candidates[0].origin,
    nearest_flows: stringGap.linking_candidates[0].nearest_flows
  }, {
    seq: 1,
    api: "atob",
    family: "base64",
    function: "decodeUnrelated",
    stack_url: otherAssetUrl,
    origin: "https://www.example.test",
    nearest_flows: [{
      flow_id: "signature_flow_1",
      endpoint: "https://www.example.test/api/list",
      relation: "same_origin_nearby",
      seq_distance: 9,
      seq_range: {start: 10, end: 12}
    }]
  });
  assert.deepEqual(stringGap.linking_candidates[0].context_window.events.map((event) => ({
    seq: event.seq,
    api: event.api,
    window_role: event.window_role,
    args: event.args
  })), [
    {seq: 0, api: "localStorage.getItem", window_role: "nearby", args: [{key: "seed"}]},
    {seq: 1, api: "atob", window_role: "candidate", args: [{input_length: 12, result_length: 8}]},
    {seq: 2, api: "document.cookie.get", window_role: "nearby", args: [{value: "sessionToken=secret-token"}]},
    {seq: 10, api: "URL.constructor", window_role: "nearby", args: [{url: "https://www.example.test/api/list?count=1"}]}
  ]);
  assert.equal(stringGap.linking_candidates[0].context_window.seq_start, 0);
  assert.equal(stringGap.linking_candidates[0].context_window.seq_end, 10);
  assert.equal(stringGap.linking_candidates[0].context_window.source_contexts[0].asset_id, "sha1:other");
  assert.match(stringGap.linking_candidates[0].context_window.source_contexts[0].preview, /X-Signature=secret-one/);
  assert.match(stringGap.linking_candidates[0].context_window.source_contexts[0].preview, /sessionToken=secret-token/);
  assert.deepEqual(
    hooks.hook_gaps.map((gap) => ({
      type: gap.type,
      gap_source: gap.gap_source,
      recommended_next_step: gap.recommended_next_step,
      global_event_count: gap.global_event_count
    })),
    [
      {
        type: "vmp_string_decoder",
        gap_source: "captured_outside_signature_flow",
        recommended_next_step: "improve_flow_linking",
        global_event_count: 1
      },
      {
        type: "vmp_bytecode_or_register_access",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_array_table",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_dynamic_dispatch",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_collection_table",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_proxy_trap",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_json_serialization",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_int_bitwise_pipeline",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_anti_debug_timing_gate",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_source_integrity_probe",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_stack_trace_probe",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_exception_control_flow",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_string_transform",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_regexp_probe",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      },
      {
        type: "vmp_url_encoding_boundary",
        gap_source: "not_captured_in_trace",
        recommended_next_step: "add_or_enable_hooks",
        global_event_count: 0
      }
    ]
  );
  assert.match(renderMarkdownReport(report), /vmp_string_decoder missing_flows=1 priority=medium source=captured_outside_signature_flow/);
  assert.match(renderMarkdownReport(report), /candidates=atob@1->signature_flow_1:same_origin_nearby:9/);
  assert.match(renderMarkdownReport(report), /candidate_window=atob@1 events=localStorage\.getItem@0:nearby,atob@1:candidate,document\.cookie\.get@2:nearby,URL\.constructor@10:nearby/);
  assert.match(renderMarkdownReport(report), /flow_vmp_candidates=vmp_string_decoder\[atob@1:same_origin_nearby:9\]/);
  assert.deepEqual(flow.vmp_linking_candidates.map((group) => ({
    type: group.type,
    gap_source: group.gap_source,
    recommended_next_step: group.recommended_next_step,
    candidate_count: group.candidate_count,
    candidates: group.candidates.map((candidate) => ({
      seq: candidate.seq,
      api: candidate.api,
      family: candidate.family,
      relation: candidate.relation,
      seq_distance: candidate.seq_distance,
      context_apis: candidate.context_window.events.map((event) => `${event.api}@${event.seq}:${event.window_role}`)
    }))
  })), [{
    type: "vmp_string_decoder",
    gap_source: "captured_outside_signature_flow",
    recommended_next_step: "improve_flow_linking",
    candidate_count: 1,
    candidates: [{
      seq: 1,
      api: "atob",
      family: "base64",
      relation: "same_origin_nearby",
      seq_distance: 9,
      context_apis: [
        "localStorage.getItem@0:nearby",
        "atob@1:candidate",
        "document.cookie.get@2:nearby",
        "URL.constructor@10:nearby"
      ]
    }]
  }]);
});

test("buildLocalReport promotes strong unlinked VMP candidates into candidate phases", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: assetUrl,
    line: 5,
    column: 2,
    asset_id: "sha1:runtime-sdk",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", api: "URL.constructor", args: [{url: "https://www.example.test/api/list?count=1"}], stack},
    {seq: 5, category: "reverse", api: "DataView.getUint32", args: [{byte_offset: 4, little_endian: true, result: 195936478}], stack},
    ...Array.from({length: 60}, (_, index) => ({
      seq: 20 + index,
      category: "reverse",
      api: "String.fromCharCode",
      args: [{argc: 1, first_code: 88 + index, result_preview: "X"}],
      stack
    })),
    {
      seq: 90,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=1&X-Signature=secret-one&X-Secondary-Signature=secret-two"}],
      stack
    }
  ];

  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: assetUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: [
      "const seed = 1;",
      "function helper() { return seed; }",
      "function signVm(input) {",
      "  const raw = \"X-Signature=secret-one&X-Secondary-Signature=secret-two\";",
      "  return DataView.prototype.getUint32.call(input, 4, true);",
      "}",
      "window.signVm = signVm;"
    ].join("\n")
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_candidate_phases.ndjson", events, assets});
  const [flow] = report.signature.agent_evidence_pack.flows;

  assert.deepEqual(flow.coverage.vmp_bytecode_or_register_access, false);
  assert.deepEqual(flow.vmp_candidate_phases.map((phase) => ({
    type: phase.type,
    phase: phase.phase,
    evidence_status: phase.evidence_status,
    confidence: phase.confidence,
    relation: phase.relation,
    seq_start: phase.seq_start,
    seq_end: phase.seq_end,
    candidate_count: phase.candidate_count,
    apis: phase.apis,
    sample_candidates: phase.sample_candidates.map((candidate) => ({
      seq: candidate.seq,
      api: candidate.api,
      family: candidate.family,
      relation: candidate.relation,
      seq_distance: candidate.seq_distance,
      confidence: candidate.confidence
    }))
  })), [{
    type: "vmp_bytecode_or_register_access",
    phase: "candidate_vmp_bytecode_or_register_access",
    evidence_status: "candidate_not_main_chain",
    confidence: "high",
    relation: "same_stack_nearby",
    seq_start: 5,
    seq_end: 5,
    candidate_count: 1,
    apis: [{api: "DataView.getUint32", count: 1}],
    sample_candidates: [{
      seq: 5,
      api: "DataView.getUint32",
      family: "byte_buffer",
      relation: "same_stack_nearby",
      seq_distance: 0,
      confidence: "high"
    }]
  }]);
  assert.deepEqual(flow.candidate_graph.nodes, [{
    id: "c1",
    phase: "candidate_vmp_bytecode_or_register_access",
    type: "vmp_bytecode_or_register_access",
    evidence_status: "candidate_not_main_chain",
    confidence: "high",
    seq_start: 5,
    seq_end: 5,
    candidate_count: 1,
    apis: [{api: "DataView.getUint32", count: 1}]
  }]);
  assert.deepEqual(flow.candidate_graph.edges, [
    {from: "n1", to: "c1", relation: "candidate_after", seq_gap: 4},
    {from: "c1", to: "n2", relation: "candidate_before", seq_gap: 29}
  ]);
  assert.deepEqual(flow.suspected_signature_subflows.map((subflow) => ({
    id: subflow.id,
    evidence_status: subflow.evidence_status,
    confidence: subflow.confidence,
    function: subflow.function,
    stack_url: subflow.stack_url,
    asset_id: subflow.asset_id,
    seq_start: subflow.seq_start,
    seq_end: subflow.seq_end,
    phases: subflow.phases,
    observed_apis: subflow.observed_apis,
    candidate_apis: subflow.candidate_apis,
    candidate_phase_count: subflow.candidate_phase_count,
    source_context_refs: subflow.source_context_refs,
    source_contexts: subflow.source_contexts
  })), [{
    id: "candidate_subflow_1",
    evidence_status: "mixed_observed_and_candidate",
    confidence: "high",
    function: "signVm",
    stack_url: assetUrl,
    asset_id: "sha1:runtime-sdk",
    seq_start: 1,
    seq_end: 90,
    phases: [
      "unsigned_url",
      "candidate_vmp_bytecode_or_register_access",
      "vmp_string_decode",
      "signed_request"
    ],
    observed_apis: [
      {api: "String.fromCharCode", count: 46},
      {api: "Request.constructor", count: 1},
      {api: "URL.constructor", count: 1}
    ],
    candidate_apis: [{api: "DataView.getUint32", count: 1}],
    candidate_phase_count: 1,
    source_context_refs: ["sha1:runtime-sdk:3-7"],
    source_contexts: [{
      asset_id: "sha1:runtime-sdk",
      url: assetUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      line_start: 3,
      line_end: 7,
      preview: [
        "function signVm(input) {",
        "  const raw = \"X-Signature=secret-one&X-Secondary-Signature=secret-two\";",
        "  return DataView.prototype.getUint32.call(input, 4, true);",
        "}",
        "window.signVm = signVm;"
      ].join("\n"),
      analysis: {
        signals: ["byte_buffer", "url_signature", "prototype_call"],
        calls: ["DataView.prototype.getUint32.call"],
        properties: [
          "DataView.prototype.getUint32.call",
          "window.signVm"
        ],
        operators: [],
        numeric_literals: [],
        string_literals: ["\"X-Signature=secret-one&X-Secondary-Signature=secret-two\""]
      }
    }]
  }]);
  assert.match(renderMarkdownReport(report), /candidate_phases=candidate_vmp_bytecode_or_register_access:high@5\.\.5/);
  assert.match(renderMarkdownReport(report), /candidate_graph=n1->c1:candidate_after:4,c1->n2:candidate_before:29/);
  assert.match(renderMarkdownReport(report), /suspected_subflows=signVm@https:\/\/cdn\.example\.test\/runtime-sdk\.js:high:unsigned_url>candidate_vmp_bytecode_or_register_access>vmp_string_decode>signed_request/);
  assert.match(renderMarkdownReport(report), /subflow_sources=sha1:runtime-sdk:3-7/);
});

test("buildLocalReport keeps a signed-only VMP timeline when no unsigned URL is visible", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const events = [
    {
      seq: 20,
      category: "reverse",
      api: "String.fromCodePoint",
      args: [{argc: 7, first_code: 88, result_preview: "X-Signature"}],
      stack: [{function: "decodeParam", url: assetUrl, line: 12, column: 4}]
    },
    {
      seq: 21,
      category: "reverse",
      api: "DataView.getUint32",
      args: [{byte_offset: 4, little_endian: true, result: 195936478}],
      stack: [{function: "readRegister", url: assetUrl, line: 20, column: 8}]
    },
    {
      seq: 22,
      category: "reverse",
      api: "Request.constructor",
      args: [{
        url: "https://www.example.test/api/list?count=6&sessionToken=secret-token&X-Signature=secret-signature"
      }],
      stack: [{function: "signRequest", url: assetUrl, line: 40, column: 12}]
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_signed_only.ndjson", events, assets: []});
  const [flow] = report.signature.flows;

  assert.equal(flow.match, "signed_only");
  assert.equal(flow.unsigned_event, null);
  assert.equal(flow.signed_event.seq, 22);
  assert.deepEqual(flow.added_params.map((item) => item.name), ["X-Signature", "sessionToken"]);
  assert.deepEqual(flow.preceding_vmp_events.map((event) => event.seq), [20, 21]);
  assert.deepEqual(flow.timeline.map((event) => `${event.role}:${event.api}@${event.seq}`), [
    "vmp:String.fromCodePoint@20",
    "vmp:DataView.getUint32@21",
    "signed_request:Request.constructor@22"
  ]);
  assert.equal(report.signature.agent_brief.flows[0].evidence_level, "medium");
  assert.deepEqual(report.signature.agent_brief.flows[0].gaps, ["unsigned_url_not_observed"]);
  assert.deepEqual(report.signature.agent_brief.flows[0].inferred_unsigned_param_names, ["count"]);
  assert.match(renderMarkdownReport(report), /unsigned_seq=none signed_seq=22/);
});

test("buildLocalReport exposes signature URL mutation evidence for agents", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "appendSignature", url: assetUrl, line: 20, column: 8}];
  const events = [
    {
      seq: 50,
      category: "reverse",
      api: "String.fromCharCode",
      args: [{argc: 7, first_code: 88, result_preview: "X-Signature"}],
      stack
    },
    {
      seq: 51,
      category: "reverse",
      api: "URLSearchParams.set",
      args: [{name: "X-Signature", value: "secret-signature"}],
      stack
    },
    {
      seq: 52,
      category: "reverse",
      api: "URLSearchParams.append",
      args: [{name: "X-Secondary-Signature", value: "secret-secondary-signature"}],
      stack
    },
    {
      seq: 53,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&X-Signature=secret-signature&X-Secondary-Signature=secret-secondary-signature"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_signature_mutations.ndjson", events, assets: []});
  const [flow] = report.signature.agent_brief.flows;

  assert.deepEqual(flow.signature_mutations, [
    {seq: 51, api: "URLSearchParams.set", param: "X-Signature", action: "set"},
    {seq: 52, api: "URLSearchParams.append", param: "X-Secondary-Signature", action: "append"}
  ]);
  assert.ok(flow.phases.some((phase) => phase.phase === "url_signature_mutation"));
  assert.match(renderMarkdownReport(report), /mutations=URLSearchParams\.set@51:X-Signature,URLSearchParams\.append@52:X-Secondary-Signature/);
});

test("buildLocalReport summarizes object links for URL and searchParams events", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "appendSignature", url: assetUrl, line: 20, column: 8}];
  const events = [
    {
      seq: 60,
      category: "reverse",
      api: "URL.constructor",
      args: [{url_object_id: 7, url: "https://www.example.test/api/list?count=6"}],
      stack
    },
    {
      seq: 61,
      category: "reverse",
      api: "URLSearchParams.set",
      args: [{url_object_id: 7, search_params_id: 3, name: "X-Signature", value: "secret-signature"}],
      stack
    },
    {
      seq: 62,
      category: "reverse",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&X-Signature=secret-signature"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_object_links.ndjson", events, assets: []});
  const [flow] = report.signature.agent_brief.flows;

  assert.deepEqual(flow.object_links, [
    {type: "url_object", id: 7, seqs: [60, 61], apis: ["URL.constructor", "URLSearchParams.set"]},
    {type: "search_params", id: 3, seqs: [61], apis: ["URLSearchParams.set"]}
  ]);
  assert.match(renderMarkdownReport(report), /objects=url_object:7@60,61;search_params:3@61/);
});

test("buildLocalReport keeps signed request anchor in dense VMP timelines", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const events = Array.from({length: 80}, (_, index) => ({
    seq: index + 1,
    category: "reverse",
    api: "String.prototype.charCodeAt",
    args: [{position: 0, result: 88}],
    stack: [{function: "vm", url: assetUrl, line: 10, column: 2}]
  }));
  events.push({
    seq: 81,
    category: "reverse",
    api: "Request.constructor",
    args: [{url: "https://www.example.test/api/list?count=6&X-Signature=secret-signature"}],
    stack: [{function: "signRequest", url: assetUrl, line: 40, column: 8}]
  });

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_dense_timeline.ndjson", events, assets: []});
  const [flow] = report.signature.flows;

  assert.equal(flow.timeline.length, 48);
  assert.ok(flow.timeline.some((event) => event.role === "signed_request" && event.seq === 81));
  assert.equal(flow.timeline.at(-1).role, "signed_request");
  assert.equal(flow.timeline.at(-1).seq, 81);
});

test("buildLocalReport relates earlier VMP hooks by signature stack overlap", () => {
  const assetUrl = "https://cdn.example.test/runtime-sdk.js";
  const events = [
    {
      seq: 7,
      category: "reverse",
      api: "DataView.getUint32",
      args: [{byte_offset: 8, little_endian: true, result: 195936478}],
      stack: [{function: "decodeRegister", url: assetUrl, line: 18, column: 4}]
    },
    {
      seq: 10,
      category: "reverse",
      api: "URL.constructor",
      args: [{url: "https://www.example.test/api/list?count=6&device_id=abc"}],
      stack: [{function: "buildUrl", url: assetUrl, line: 40, column: 4}]
    },
    {
      seq: 12,
      category: "reverse",
      api: "Request.constructor",
      args: [{
        url: "https://www.example.test/api/list?count=6&device_id=abc&X-Signature=secret-signature&X-Secondary-Signature=secret-secondary-signature"
      }],
      stack: [{function: "signRequest", url: assetUrl, line: 60, column: 8}]
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_signature_stack.ndjson", events, assets: []});
  const [flow] = report.signature.flows;

  assert.deepEqual(flow.preceding_vmp_events.map((event) => event.seq), [7]);
  assert.equal(flow.preceding_vmp_events[0].relation, "signed_stack");
  assert.match(renderMarkdownReport(report), /DataView\.getUint32@7:signed_stack/);
});

test("writeLocalReport writes report and compact agent pack beside logs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-report-"));
  const tracePath = path.join(dir, "trace_demo.ndjson");
  const stack = [{
    function: "sign",
    url: "https://cdn.example.test/runtime-sdk.js",
    line: 2,
    column: 1,
    asset_id: "sha1:f",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", api: "URL.constructor", args: [{url_object_id: 1, search_params_id: 2, url: "https://www.example.test/api/feed?cursor=1"}], stack},
    {seq: 2, category: "reverse", api: "URLSearchParams.set", args: [{url_object_id: 1, search_params_id: 2, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 3, category: "network", api: "Request.constructor", args: [{url_object_id: 1, search_params_id: 2, url: "https://www.example.test/api/feed?cursor=1&X-Signature=secret-one"}], stack}
  ];
  const assets = [{
    asset_id: "sha1:f",
    kind: "external-script",
    url: "https://cdn.example.test/runtime-sdk.js",
    content_path: "assets/trace_demo/runtime-sdk.js",
    content: "function sign(url) { url.searchParams.set('X-Signature', 'redacted'); }"
  }];

  const result = writeLocalReport({tracePath, events, assets});

  assert.equal(reportDirectoryForTrace(tracePath), path.join(dir, "reports", "trace_demo"));
  assert.ok(fs.existsSync(result.jsonPath));
  assert.ok(fs.existsSync(result.markdownPath));
  assert.ok(fs.existsSync(result.agentPackJsonPath));
  assert.ok(fs.existsSync(result.agentPackMarkdownPath));
  assert.ok(fs.existsSync(result.agentAnalysisJsonPath));
  assert.ok(fs.existsSync(result.agentAnalysisMarkdownPath));
  assert.match(renderMarkdownReport(result.report), /XTrace Local Report/);
  assert.equal(result.agentPack.version, 1);
  assert.equal(result.agentPack.purpose, "codex_agent_signature_analysis_input");
  assert.deepEqual(result.agentPack.redaction, {
    values_redacted: false,
    output: "raw_values_preserved"
  });
  assert.equal(result.agentPack.trace.path, tracePath);
  assert.deepEqual(result.agentPack.source_ref_index, [{
    ref: "sha1:f:1-1",
    asset_id: "sha1:f",
    url: "https://cdn.example.test/runtime-sdk.js",
    content_path: "assets/trace_demo/runtime-sdk.js",
    line_start: 1,
    line_end: 1,
    preview: "function sign(url) { url.searchParams.set('X-Signature', 'redacted'); }",
    source_candidate_ids: ["source_candidate_1"],
    review_entry_ids: ["review_entry_1"],
    target_params: ["X-Signature"],
    stages: [
      "input_url",
      "signature_mutation",
      "signed_request"
    ],
    signals: ["url_signature"],
    calls: ["url.searchParams.set"]
  }]);
  assert.deepEqual({
    profile: result.agentPack.capture_recipe.profile,
    start_url: result.agentPack.capture_recipe.start_url,
    gui_defaults: result.agentPack.capture_recipe.gui_defaults,
    tail_filters: result.agentPack.capture_recipe.tail_filters,
    stop_when: result.agentPack.capture_recipe.stop_when,
    target_endpoint_patterns: result.agentPack.capture_recipe.target_endpoint_patterns,
    noise_reduction: result.agentPack.capture_recipe.noise_reduction
  }, {
    profile: "interactive_full_capture",
    start_url: "https://www.example.test/api/feed",
    gui_defaults: {
      url: "https://www.example.test/api/feed",
      categories: "reverse,fingerprint",
      captureValues: "full",
      captureAssets: "full",
      maxValueBytes: 262144
    },
    tail_filters: {
      categories: ["network"],
      apis: [
        "BrowserNetwork.request",
        "Request.constructor",
        "fetch",
        "XMLHttpRequest.open",
        "XMLHttpRequest.send"
      ],
      exclude_resource_classes: [
        "document_request",
        "static_resource",
        "telemetry_endpoint"
      ]
    },
    stop_when: "observed_actionable_endpoint_count > 0",
    target_endpoint_patterns: ["https://www.example.test/api/feed"],
    noise_reduction: {
      prefer_targeted_rerun: true,
      avoid_resource_classes: [
        "document_request",
        "static_resource",
        "telemetry_endpoint"
      ],
      keep_capture_values: "full",
      keep_capture_assets: "full"
    }
  });
  assert.ok(result.agentPack.capture_recipe.python_launcher_args.includes("--xtrace-capture-values"));
  assert.equal(result.agentAnalysis.version, 1);
  assert.equal(result.agentAnalysis.purpose, "codex_agent_signature_analysis");
  assert.deepEqual(result.report.agent_analysis, result.agentAnalysis);
  assert.deepEqual(result.agentAnalysis.parameters.map((entry) => ({
    param: entry.param,
    conclusion: entry.conclusion,
    evidence_level: entry.evidence_level,
    chain_summary: entry.chain_summary,
    confirmed_stages: entry.confirmed_stages,
    source_evidence: entry.source_evidence,
    generation_path: entry.generation_path.map(({runtime_event_refs, ...step}) => step),
    unresolved_gaps: entry.unresolved_gaps,
    recommended_next_actions: entry.recommended_next_actions
  })), [{
    param: "X-Signature",
    conclusion: "attachment_observed_with_runtime_chain",
    evidence_level: "high",
    chain_summary: "input_url -> signature_mutation -> signed_request",
    confirmed_stages: [
      "input_url",
      "signature_mutation",
      "signed_request"
    ],
    source_evidence: [{
      ref: "sha1:f:1-1",
      asset_id: "sha1:f",
      url: "https://cdn.example.test/runtime-sdk.js",
      content_path: "assets/trace_demo/runtime-sdk.js",
      line_start: 1,
      line_end: 1,
      preview: "function sign(url) { url.searchParams.set('X-Signature', 'redacted'); }",
      source_candidate_ids: ["source_candidate_1"],
      review_entry_ids: ["review_entry_1"],
      signals: ["url_signature"],
      calls: ["url.searchParams.set"]
    }],
    generation_path: [
      {
        order: 1,
        stage: "input_url",
        role: "input",
        seq_start: 1,
        seq_end: 1,
        apis: ["URL.constructor"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation_to_signed_request: "before_signed_request",
        distance_to_signed_request: 2,
        distance_basis: "seq",
        evidence_flags: [
          "runtime_api_observed",
          "source_context_observed",
          "data_refs_observed",
          "pre_request_observed"
        ],
        evidence_gaps: [],
        recommended_next_actions: ["review_step_source_context"],
        source_calls: [],
        source_signals: [],
        source_operators: [],
        source_constants: [],
        source_evidence: [{
          ref: "sha1:f:1-1",
          asset_id: "sha1:f",
          url: "https://cdn.example.test/runtime-sdk.js",
          content_path: "assets/trace_demo/runtime-sdk.js",
          line_start: 1,
          line_end: 1,
          preview: "function sign(url) { url.searchParams.set('X-Signature', 'redacted'); }",
          source_candidate_ids: ["source_candidate_1"],
          review_entry_ids: ["review_entry_1"],
          signals: ["url_signature"],
          calls: ["url.searchParams.set"]
        }],
        object_refs: ["url_object:1", "search_params:2"],
        value_refs: ["url_shape:eae29bcd94fa2e62518eac6d12027a89ea4bba77", "string:length:10"]
      },
      {
        order: 2,
        stage: "signature_mutation",
        role: "parameter_attachment",
        seq_start: 2,
        seq_end: 2,
        apis: ["URLSearchParams.set"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation_to_signed_request: "before_signed_request",
        distance_to_signed_request: 1,
        distance_basis: "seq",
        evidence_flags: [
          "runtime_api_observed",
          "source_context_observed",
          "data_refs_observed",
          "pre_request_observed",
          "target_param_observed"
        ],
        evidence_gaps: [],
        recommended_next_actions: ["review_step_source_context"],
        source_calls: [],
        source_signals: ["url_signature"],
        source_operators: [],
        source_constants: [],
        source_evidence: [{
          ref: "sha1:f:1-1",
          asset_id: "sha1:f",
          url: "https://cdn.example.test/runtime-sdk.js",
          content_path: "assets/trace_demo/runtime-sdk.js",
          line_start: 1,
          line_end: 1,
          preview: "function sign(url) { url.searchParams.set('X-Signature', 'redacted'); }",
          source_candidate_ids: ["source_candidate_1"],
          review_entry_ids: ["review_entry_1"],
          signals: ["url_signature"],
          calls: ["url.searchParams.set"]
        }],
        object_refs: ["url_object:1", "search_params:2"],
        value_refs: ["target_params:X-Signature", "string:length:10"]
      },
      {
        order: 3,
        stage: "signed_request",
        role: "network_emit",
        seq_start: 3,
        seq_end: 3,
        apis: ["Request.constructor"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation_to_signed_request: "signed_request",
        distance_to_signed_request: 0,
        distance_basis: "seq",
        evidence_flags: [
          "runtime_api_observed",
          "source_context_observed",
          "data_refs_observed",
          "signed_request_observed",
          "target_param_observed"
        ],
        evidence_gaps: [],
        recommended_next_actions: ["review_step_source_context"],
        source_calls: [],
        source_signals: ["url_signature"],
        source_operators: [],
        source_constants: [],
        source_evidence: [{
          ref: "sha1:f:1-1",
          asset_id: "sha1:f",
          url: "https://cdn.example.test/runtime-sdk.js",
          content_path: "assets/trace_demo/runtime-sdk.js",
          line_start: 1,
          line_end: 1,
          preview: "function sign(url) { url.searchParams.set('X-Signature', 'redacted'); }",
          source_candidate_ids: ["source_candidate_1"],
          review_entry_ids: ["review_entry_1"],
          signals: ["url_signature"],
          calls: ["url.searchParams.set"]
        }],
        object_refs: ["url_object:1", "search_params:2"],
        value_refs: [
          "url_shape:e093994a3084790989a6a08806009b86bb0aad70",
          "target_params:X-Signature"
        ]
      }
    ],
    unresolved_gaps: [
      "material_source_not_observed",
      "mix_or_hash_not_observed"
    ],
    recommended_next_actions: [
      "review_source_refs",
      "capture_text_buffer_or_storage_material",
      "resolve_mix_or_hash_not_observed"
    ]
  }]);
  assert.deepEqual(result.agentPack.parameters.map((entry) => ({
    param: entry.param,
    status: entry.status,
    best_flow_id: entry.best_flow_id,
    endpoint: entry.endpoint,
    trace: entry.generation_trace.map((step) => ({
      stage: step.stage,
      apis: step.apis,
      target_params: step.target_params,
      param_relation: step.param_relation
    }))
  })), [{
    param: "X-Signature",
    status: "attachment_observed",
    best_flow_id: "material_flow_1",
    endpoint: "https://www.example.test/api/feed",
    trace: [
      {
        stage: "input_url",
        apis: ["URL.constructor"],
        target_params: ["X-Signature"],
        param_relation: "flow_target"
      },
      {
        stage: "signature_mutation",
        apis: ["URLSearchParams.set"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed"
      },
      {
        stage: "signed_request",
        apis: ["Request.constructor"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed"
      }
    ]
  }]);
  const agentPackJson = JSON.parse(fs.readFileSync(result.agentPackJsonPath, "utf8"));
  const packedLogicTrace = agentPackJson.parameters[0].agent_generation_summary.logic_hypothesis.agent_logic_trace;
  assert.equal(packedLogicTrace.summary, "X-Signature generation: input_material -> signature_attachment; status=needs_more_evidence");
  assert.deepEqual(packedLogicTrace.steps.map((step) => step.phase), ["input_material", "signature_attachment"]);
  assert.deepEqual(packedLogicTrace.steps[0].runtime_apis, ["URL.constructor"]);
  assert.deepEqual(packedLogicTrace.steps[1].target_params, ["X-Signature"]);
  assert.ok(packedLogicTrace.edges.some((edge) =>
    edge.from_phase === "input_material" &&
    edge.to_phase === "signature_attachment" &&
    edge.from_stage === "input_url" &&
    edge.to_stage === "signature_mutation" &&
    edge.relation === "shared_object_ref" &&
    edge.confidence === "medium"
  ));
  assert.ok(packedLogicTrace.edges.some((edge) =>
    edge.from_phase === "signature_attachment" &&
    edge.to_phase === "signature_attachment" &&
    edge.from_stage === "signature_mutation" &&
    edge.to_stage === "signed_request" &&
    edge.relation === "target_param_ref" &&
    edge.confidence === "high"
  ));
  assert.equal(
    agentPackJson.parameters[0].agent_generation_summary.logic_hypothesis.critical_path.edge_summary.total_edge_count,
    2
  );
  assert.deepEqual(agentPackJson.parameters[0].agent_generation_summary.steps.map((step) => ({
    stage: step.stage,
    runtime_event_refs: (step.runtime_event_refs || []).map((event) => ({
      event_ref: event.event_ref,
      seq: event.seq,
      api: event.api
    }))
  })), [
    {
      stage: "input_url",
      runtime_event_refs: [{
        event_ref: "seq:1:URL.constructor",
        seq: 1,
        api: "URL.constructor"
      }]
    },
    {
      stage: "signature_mutation",
      runtime_event_refs: [{
        event_ref: "seq:2:URLSearchParams.set",
        seq: 2,
        api: "URLSearchParams.set"
      }]
    },
    {
      stage: "signed_request",
      runtime_event_refs: [{
        event_ref: "seq:3:Request.constructor",
        seq: 3,
        api: "Request.constructor"
      }]
    }
  ]);
  assert.ok(packedLogicTrace.steps[0].runtime_events.some((event) =>
    event.event_ref === "seq:1:URL.constructor" &&
    event.seq === 1 &&
    event.api === "URL.constructor" &&
    event.stage === "input_url"
  ));
  assert.ok(packedLogicTrace.steps[1].runtime_events.some((event) =>
    event.event_ref === "seq:2:URLSearchParams.set" &&
    event.seq === 2 &&
    event.api === "URLSearchParams.set" &&
    event.stage === "signature_mutation"
  ));
  assert.ok(packedLogicTrace.steps[1].runtime_events.some((event) =>
    event.event_ref === "seq:3:Request.constructor" &&
    event.seq === 3 &&
    event.api === "Request.constructor" &&
    event.stage === "signed_request"
  ));
  assert.ok(
    agentPackJson.parameters[0].agent_generation_summary.logic_hypothesis.critical_path.path_evidence
      .includes("phase_edge:signature_attachment->signature_attachment:target_param_ref:high")
  );
  assert.deepEqual(packedLogicTrace.final_attachment, {
    observed: true,
    target_params: ["X-Signature"],
    apis: ["URLSearchParams.set"],
    evidence_mode: "direct_runtime_api"
  });
  assert.deepEqual(agentPackJson.parameters, result.agentPack.parameters);
  assert.deepEqual(agentPackJson.source_ref_index, result.agentPack.source_ref_index);
  const agentAnalysisJson = JSON.parse(fs.readFileSync(result.agentAnalysisJsonPath, "utf8"));
  assert.deepEqual(agentAnalysisJson.parameters, result.agentAnalysis.parameters);
  assert.match(fs.readFileSync(result.agentPackMarkdownPath, "utf8"), /XTrace Agent Input Pack/);
  assert.match(fs.readFileSync(result.agentPackMarkdownPath, "utf8"), /Capture Recipe/);
  assert.match(fs.readFileSync(result.agentPackMarkdownPath, "utf8"), /Source Ref Index/);
  assert.match(
    fs.readFileSync(result.agentPackMarkdownPath, "utf8"),
    /agent_generation=chain=input_url->signature_mutation->signed_request .*step_events=input_url\[URL\.constructor@1\]->signature_mutation\[URLSearchParams\.set@2\]->signed_request\[Request\.constructor@3\]/
  );
  assert.match(
    fs.readFileSync(result.agentPackMarkdownPath, "utf8"),
    /logic_trace=X-Signature generation: input_material -> signature_attachment; status=needs_more_evidence .*logic_step=1:input_material[^\n]*events=URL\.constructor@1 .*logic_step=2:signature_attachment[^\n]*events=URLSearchParams\.set@2\|Request\.constructor@3/
  );
  assert.match(fs.readFileSync(result.agentPackMarkdownPath, "utf8"), /sha1:f:1-1 path=assets\/trace_demo\/runtime-sdk\.js lines=1-1 .*preview=function sign\(url\) \{ url\.searchParams\.set\('X-Signature', 'redacted'\); \}/);
  assert.match(fs.readFileSync(result.agentPackMarkdownPath, "utf8"), /start_url=https:\/\/www\.example\.test\/api\/feed/);
  assert.match(fs.readFileSync(result.agentAnalysisMarkdownPath, "utf8"), /XTrace Agent Analysis/);
  assert.match(fs.readFileSync(result.agentAnalysisMarkdownPath, "utf8"), /Next Capture Focus/);
  assert.match(fs.readFileSync(result.agentAnalysisMarkdownPath, "utf8"), /X-Signature: attachment_observed_with_runtime_chain/);
  assert.match(fs.readFileSync(result.agentAnalysisMarkdownPath, "utf8"), /source_evidence=sha1:f:1-1@assets\/trace_demo\/runtime-sdk\.js:1-1/);
  assert.match(fs.readFileSync(result.agentAnalysisMarkdownPath, "utf8"), /source_preview=function sign\(url\) \{ url\.searchParams\.set\('X-Signature', 'redacted'\); \}/);
  assert.match(fs.readFileSync(result.agentAnalysisMarkdownPath, "utf8"), /path=1:input_url\[URL\.constructor d=2 relation=flow_target src=sha1:f:1-1@assets\/trace_demo\/runtime-sdk\.js:1-1\]->2:signature_mutation\[URLSearchParams\.set d=1 relation=direct_observed src=sha1:f:1-1@assets\/trace_demo\/runtime-sdk\.js:1-1\]->3:signed_request\[Request\.constructor d=0 relation=direct_observed src=sha1:f:1-1@assets\/trace_demo\/runtime-sdk\.js:1-1\]/);
});

test("buildAgentAnalysis resolves step source paths by asset id fallback", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_ref_fallback.ndjson", event_count: 3},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "strong",
      source_refs: ["sha1:sdk:1-1@4096-4300"],
      evidence_gaps: [],
      generation_trace: [{
        order: 1,
        stage: "dynamic_dispatch",
        role: "transform",
        apis: ["Reflect.apply"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 7,
        distance_basis: "trace_index",
        source_refs: ["sha1:sdk:1-1@4096-4300"],
        object_refs: ["target:12"],
        value_refs: []
      }]
    }],
    source_ref_index: [
      {
        ref: "sha1:sdk:1-1",
        asset_id: "sha1:sdk",
        content_path: "assets/trace_ref_fallback/runtime-sdk.js",
        line_start: 1,
        line_end: 1,
        source_candidate_ids: ["source_candidate_1"],
        review_entry_ids: ["review_entry_1"],
        target_params: ["X-Signature"],
        stages: ["dynamic_dispatch"]
      },
      {
        ref: "sha1:sdk:1-1@4096-4300",
        asset_id: "sha1:sdk",
        content_path: "",
        line_start: 1,
        line_end: 1,
        source_candidate_ids: [],
        review_entry_ids: [],
        target_params: ["X-Signature"],
        stages: ["dynamic_dispatch"]
      }
    ]
  });

  const expectedEvidence = [{
    ref: "sha1:sdk:1-1@4096-4300",
    asset_id: "sha1:sdk",
    content_path: "assets/trace_ref_fallback/runtime-sdk.js",
    line_start: 1,
    line_end: 1,
    source_candidate_ids: ["source_candidate_1"],
    review_entry_ids: ["review_entry_1"]
  }];
  assert.deepEqual(analysis.parameters[0].source_evidence, expectedEvidence);
  assert.deepEqual(analysis.parameters[0].generation_path[0].source_evidence, expectedEvidence);
});

test("buildAgentAnalysis emits generation edges from shared runtime refs", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_edges.ndjson", event_count: 8},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "strong",
      source_refs: ["sha1:sdk:1-6"],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "input_url",
          role: "input",
          apis: ["URL.constructor"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-6"],
          object_refs: ["url_object:1"],
          value_refs: ["url_shape:feed"]
        },
        {
          order: 2,
          stage: "text_or_string_decode",
          role: "material",
          apis: ["TextEncoder.encode"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 3,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-6"],
          source_calls: ["TextEncoder"],
          source_signals: ["text_codec"],
          object_refs: ["url_object:1"],
          value_refs: ["bytes:7"]
        },
        {
          order: 3,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Math.imul"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-6"],
          source_signals: ["int_bitwise"],
          source_operators: ["^"],
          source_constants: ["123"],
          object_refs: ["bytes:7"],
          value_refs: ["mix_state:9"]
        },
        {
          order: 4,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 1,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-6"],
          source_signals: ["url_signature"],
          object_refs: ["url_object:1"],
          value_refs: ["mix_state:9", "target_params:X-Signature"]
        },
        {
          order: 5,
          stage: "signed_request",
          role: "network_emit",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-6"],
          object_refs: ["url_object:1"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: "sha1:sdk:1-6",
      asset_id: "sha1:sdk",
      content_path: "assets/trace_edges/runtime-sdk.js",
      line_start: 1,
      line_end: 6,
      preview: "function sign(url) { /* redacted */ }",
      source_candidate_ids: ["source_candidate_1"],
      review_entry_ids: ["review_entry_1"],
      target_params: ["X-Signature"],
      stages: ["input_url", "text_or_string_decode", "integer_mixing", "signature_mutation", "signed_request"]
    }]
  });

  assert.deepEqual(analysis.parameters[0].generation_edges, [
    {
      from_order: 1,
      to_order: 2,
      from_stage: "input_url",
      to_stage: "text_or_string_decode",
      relation: "shared_object_ref",
      confidence: "high",
      refs: ["url_object:1"],
      source_refs: ["sha1:sdk:1-6"],
      evidence: ["shared_object_ref", "shared_source_ref"]
    },
    {
      from_order: 2,
      to_order: 3,
      from_stage: "text_or_string_decode",
      to_stage: "integer_mixing",
      relation: "value_to_object_ref",
      confidence: "high",
      refs: ["bytes:7"],
      source_refs: ["sha1:sdk:1-6"],
      evidence: ["value_to_object_ref", "shared_source_ref"]
    },
    {
      from_order: 3,
      to_order: 4,
      from_stage: "integer_mixing",
      to_stage: "signature_mutation",
      relation: "shared_value_ref",
      confidence: "high",
      refs: ["mix_state:9"],
      source_refs: ["sha1:sdk:1-6"],
      evidence: ["shared_value_ref", "shared_source_ref"]
    },
    {
      from_order: 4,
      to_order: 5,
      from_stage: "signature_mutation",
      to_stage: "signed_request",
      relation: "target_param_ref",
      confidence: "high",
      refs: ["target_params:X-Signature", "url_object:1"],
      source_refs: ["sha1:sdk:1-6"],
      evidence: ["target_param_ref", "shared_object_ref", "shared_source_ref"]
    }
  ]);
  assert.deepEqual(analysis.parameters[0].chain_quality, {
    status: "strong",
    step_count: 5,
    expected_edge_count: 4,
    edge_count: 4,
    high_confidence_edge_count: 4,
    medium_confidence_edge_count: 0,
    source_only_edge_count: 0,
    temporal_only_edge_count: 0,
    nearby_runtime_only_edge_count: 0,
    missing_edge_count: 0
  });
  assert.deepEqual(analysis.parameters[0].generation_edge_gaps, []);
});

test("buildAgentAnalysis marks shared signature params on critical path", () => {
  const sharedTargetRef = "target_params:X-Signature|X-Secondary-Signature";
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_shared_params.ndjson", event_count: 6},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_shared",
      endpoint: "https://www.example.test/api/feed",
      source_refs: ["sha1:sdk:1-8"],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "input_url",
          role: "input",
          apis: ["URL.constructor"],
          target_params: ["X-Signature", "X-Secondary-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-8"],
          object_refs: ["url_object:7"],
          value_refs: ["url_shape:feed"]
        },
        {
          order: 2,
          stage: "byte_buffer",
          role: "material",
          apis: ["TextEncoder.encode"],
          target_params: ["X-Signature", "X-Secondary-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 3,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-8"],
          object_refs: ["array_buffer:20"],
          value_refs: ["bytes:7"]
        },
        {
          order: 3,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Function.prototype.call"],
          target_params: ["X-Signature", "X-Secondary-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-8"],
          source_calls: ["Function.prototype.call.call"],
          source_signals: ["dynamic_dispatch"],
          object_refs: ["array_buffer:20"],
          value_refs: ["mix_state:9"]
        },
        {
          order: 4,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature", "X-Secondary-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 1,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-8"],
          object_refs: ["url_object:7"],
          value_refs: ["mix_state:9", sharedTargetRef]
        },
        {
          order: 5,
          stage: "signed_request",
          role: "network_emit",
          apis: ["Request.constructor"],
          target_params: ["X-Signature", "X-Secondary-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-8"],
          object_refs: ["url_object:7"],
          value_refs: [sharedTargetRef]
        }
      ]
    }],
    source_ref_index: [{
      ref: "sha1:sdk:1-8",
      asset_id: "sha1:sdk",
      content_path: "assets/trace_shared_params/runtime-sdk.js",
      line_start: 1,
      line_end: 8,
      target_params: ["X-Signature", "X-Secondary-Signature"],
      stages: ["input_url", "byte_buffer", "dynamic_dispatch", "signature_mutation", "signed_request"]
    }]
  });

  const criticalPath = analysis.parameters[0].candidate_generation_summary.logic_hypothesis.critical_path;

  assert.equal(criticalPath.primary_target_param, "X-Signature");
  assert.deepEqual(criticalPath.observed_target_params, ["X-Signature", "X-Secondary-Signature"]);
  assert.deepEqual(criticalPath.related_target_params, ["X-Secondary-Signature"]);
  assert.deepEqual(criticalPath.shared_target_param_groups, [{
    ref: sharedTargetRef,
    params: ["X-Signature", "X-Secondary-Signature"],
    primary_param: "X-Signature",
    related_params: ["X-Secondary-Signature"]
  }]);
  assert.deepEqual(criticalPath.strongest_attachment_edge.refs, [
    sharedTargetRef,
    "url_object:7"
  ]);
  assert.deepEqual(analysis.parameters[0].related_param_evidence, [{
    param: "X-Secondary-Signature",
    relation: "shared_target_param_ref",
    confidence: "high",
    shared_refs: [sharedTargetRef],
    stages: ["input_url", "byte_buffer", "dynamic_dispatch", "signature_mutation", "signed_request"],
    apis: [
      "URL.constructor",
      "TextEncoder.encode",
      "Function.prototype.call",
      "URLSearchParams.set",
      "Request.constructor"
    ],
    evidence: ["shared_target_param_ref", "shared_generation_path"]
  }]);
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /related_params=X-Secondary-Signature\[shared_target_param_ref refs=target_params:X-Signature\|X-Secondary-Signature stages=input_url->byte_buffer->dynamic_dispatch->signature_mutation->signed_request apis=URL\.constructor\|TextEncoder\.encode\|Function\.prototype\.call\|URLSearchParams\.set\|Request\.constructor\]/
  );
});

test("buildAgentAnalysis emits native capture requirements for unresolved VMP refs", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_native_requirements.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_native_gap",
      endpoint: "https://www.example.test/api/feed",
      source_refs: ["sha1:runtime-sdk:1-8"],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "input_url",
          role: "input",
          apis: ["URL.constructor"],
          target_params: ["X-Signature"],
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          object_refs: ["url_object:7"],
          value_refs: ["url_shape:feed"],
          source_refs: ["sha1:runtime-sdk:1-8"]
        },
        {
          order: 2,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: [],
          target_params: ["X-Signature"],
          relation: "before_signed_request",
          distance_to_signed_request: 3,
          distance_basis: "trace_index",
          source_refs: ["sha1:runtime-sdk:1-8"],
          source_calls: ["Reflect.apply"],
          source_signals: ["vmp_dynamic_dispatch", "vmp_handler_table"]
        },
        {
          order: 3,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor"],
          target_params: ["X-Signature"],
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          source_refs: ["sha1:runtime-sdk:1-8"]
        },
        {
          order: 4,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 1,
          distance_basis: "trace_index",
          object_refs: ["url_object:7", "search_params:8"],
          value_refs: ["target_params:X-Signature"],
          source_refs: ["sha1:runtime-sdk:1-8"]
        },
        {
          order: 5,
          stage: "signed_request",
          role: "network_emit",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          object_refs: ["url_object:7", "network_request:9"],
          value_refs: ["target_params:X-Signature"],
          source_refs: ["sha1:runtime-sdk:1-8"]
        }
      ]
    }],
    source_ref_index: [{
      ref: "sha1:runtime-sdk:1-8",
      asset_id: "sha1:runtime-sdk",
      content_path: "assets/trace_native_requirements/runtime-sdk.js",
      line_start: 1,
      line_end: 8,
      target_params: ["X-Signature"],
      stages: ["dynamic_dispatch", "integer_mixing", "signature_mutation"],
      signals: ["vmp_dynamic_dispatch", "vmp_handler_table"]
    }]
  });

  assert.deepEqual(analysis.native_capture_requirements[0], {
    action: "capture_vmp_register_state_refs",
    priority: "high",
    native_layer: "v8",
    reason: "vmp_register_state_refs_missing",
    params: ["X-Signature"],
    stages: ["input_url", "dynamic_dispatch", "integer_mixing", "signature_mutation", "signed_request"],
    gaps: [],
    endpoints: ["https://www.example.test/api/feed"],
    missing_hook_targets: [],
    missing_ref_types: [
      "vmp.state_object_id",
      "vmp.register_ref",
      "vmp.handler.return_ref",
      "Bitwise.input_ref"
    ],
    observed_refs: {
      source_refs: ["sha1:runtime-sdk:1-8"],
      object_refs: ["url_object:7", "search_params:8", "network_request:9"],
      value_refs: ["url_shape:feed", "target_params:X-Signature"]
    },
    implementation_targets: [
      "v8:vmp.state_object_id",
      "v8:vmp.register_ref",
      "v8:vmp.handler.return_ref",
      "v8:Bitwise.input_ref"
    ],
    source_hints: [
      {
        path: "chromium/src/v8/src/runtime/runtime-typedarray.cc",
        reason: "vmp runtime ref serialization and dispatch result args"
      },
      {
        path: "chromium/src/v8/src/builtins/arm64/builtins-arm64.cc",
        reason: "arm64 dynamic dispatch boundary register capture"
      },
      {
        path: "chromium/src/v8/src/runtime/runtime.h",
        reason: "v8 runtime entry wiring"
      }
    ],
    validator_hints: {
      profile: "reverse",
      flags: [
        "--schema-version 1",
        "--require-vmp-next-hook-fields",
        "--require-vmp-family dynamic_dispatch",
        "--require-vmp-family int_bitwise"
      ]
    }
  });
  const runtimeRequirement = analysis.native_capture_requirements.find((item) =>
    item.action === "expand_vmp_runtime_hooks"
  );
  assert.equal(runtimeRequirement.native_layer, "v8");
  assert.ok(runtimeRequirement.missing_hook_targets.includes("Reflect.apply"));
  assert.ok(runtimeRequirement.missing_hook_targets.includes("Function.prototype.call"));
  assert.ok(runtimeRequirement.implementation_targets.includes("v8:Reflect.apply"));
  assert.ok(runtimeRequirement.source_hints.some((hint) =>
    hint.path === "chromium/src/v8/src/builtins/arm64/builtins-arm64.cc"
  ));
  assert.ok(runtimeRequirement.validator_hints.flags.includes("--require-vmp-family dynamic_dispatch"));
  assert.ok(analysis.native_capture_requirements.some((item) =>
    item.action === "capture_vmp_register_state_refs" &&
    item.missing_ref_types.includes("vmp.register_ref") &&
    item.implementation_targets.includes("v8:vmp.handler.return_ref")
  ));
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /Native Capture Requirements/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /native_requirement=capture_vmp_register_state_refs layer=v8 priority=high params=X-Signature stages=input_url,dynamic_dispatch,integer_mixing,signature_mutation,signed_request.*source_hints=chromium\/src\/v8\/src\/runtime\/runtime-typedarray\.cc\|chromium\/src\/v8\/src\/builtins\/arm64\/builtins-arm64\.cc\|chromium\/src\/v8\/src\/runtime\/runtime\.h.*validator=--schema-version 1\|--require-vmp-next-hook-fields\|--require-vmp-family dynamic_dispatch\|--require-vmp-family int_bitwise/
  );
});

test("buildAgentAnalysis summarizes request-anchor fallback attachment evidence", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_attachment_fallback.ndjson", event_count: 4},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_attachment_fallback",
      endpoint: "https://www.example.test/api/feed",
      source_refs: ["sha1:sdk:1-8"],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: [],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 1,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-8"],
          object_refs: ["url_object:7", "search_params:8"],
          value_refs: ["url_shape:feed", "target_params:X-Signature"]
        },
        {
          order: 2,
          stage: "signed_request",
          role: "network_emit",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-8"],
          object_refs: ["network_request:sha1:req"],
          value_refs: ["url_shape:feed", "target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: "sha1:sdk:1-8",
      asset_id: "sha1:sdk",
      content_path: "assets/trace_attachment_fallback/runtime-sdk.js",
      line_start: 1,
      line_end: 8,
      target_params: ["X-Signature"],
      stages: ["signature_mutation", "signed_request"]
    }]
  });

  const attachment = analysis.parameters[0].candidate_generation_summary.attachment;

  assert.equal(attachment.observed, true);
  assert.equal(attachment.evidence_mode, "request_anchor_fallback");
  assert.equal(attachment.direct_runtime_api_observed, false);
  assert.equal(attachment.request_anchor_observed, true);
  assert.equal(attachment.fallback_stage, "signed_request");
  assert.deepEqual(attachment.request_anchor_apis, ["Request.constructor"]);
  assert.deepEqual(attachment.missing_runtime_hooks, [
    "URLSearchParams.set",
    "URLSearchParams.append",
    "URL.search.set",
    "URL.href.set",
    "Headers.set",
    "XMLHttpRequest.setRequestHeader"
  ]);
  assert.deepEqual(attachment.request_anchor_refs, [
    "network_request:sha1:req",
    "url_shape:feed",
    "target_params:X-Signature"
  ]);
  assert.equal(
    analysis.parameters[0].analysis_readiness.next_probe_plan.reason,
    "direct_signature_mutation_runtime_api_missing"
  );
  assert.deepEqual(analysis.parameters[0].analysis_readiness.next_probe_plan.attachment_evidence, {
    mode: "request_anchor_fallback",
    direct_runtime_api_observed: false,
    request_anchor_observed: true,
    fallback_stage: "signed_request",
    request_anchor_apis: ["Request.constructor"],
    request_anchor_refs: [
      "network_request:sha1:req",
      "url_shape:feed",
      "target_params:X-Signature"
    ],
    missing_runtime_hooks: [
      "URLSearchParams.set",
      "URLSearchParams.append",
      "URL.search.set",
      "URL.href.set",
      "Headers.set",
      "XMLHttpRequest.setRequestHeader"
    ]
  });
  const attachmentRequirement = analysis.native_capture_requirements.find((item) =>
    item.action === "capture_url_search_params_mutation_or_header_set"
  );
  const attachmentFocus = analysis.next_capture_focus.find((item) =>
    item.action === "capture_url_search_params_mutation_or_header_set"
  );
  assert.ok(attachmentFocus);
  assert.equal(attachmentFocus.reason, "direct_signature_mutation_runtime_api_missing");
  assert.deepEqual(attachmentFocus.hook_targets, [
    "URLSearchParams.set",
    "URLSearchParams.append",
    "URL.search.set",
    "URL.href.set",
    "Headers.set",
    "XMLHttpRequest.setRequestHeader"
  ]);
  assert.equal(attachmentRequirement, undefined);
});

test("buildAgentAnalysis treats request construction as captured input material", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_request_input.ndjson", event_count: 6},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_request_input",
      endpoint: "https://www.example.test/api/feed",
      source_refs: ["sha1:sdk:2-9"],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "request_construction",
          role: "request",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:2-9"],
          object_refs: ["network_request:sha1:request", "headers:31"],
          value_refs: ["url_shape:feed", "target_params:X-Signature"]
        },
        {
          order: 2,
          stage: "byte_buffer",
          role: "material",
          apis: ["TypedArray.buffer.get"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 3,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:2-9"],
          object_refs: ["typed_array:12", "array_buffer:13"],
          value_refs: ["string:length:21"]
        },
        {
          order: 3,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:2-9"],
          object_refs: ["state_object:7"],
          value_refs: ["register:7/number:1"]
        },
        {
          order: 4,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 1,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:2-9"],
          object_refs: [],
          value_refs: ["register:7/number:1"]
        },
        {
          order: 5,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 1,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:2-9"],
          object_refs: ["url_object:7"],
          value_refs: ["target_params:X-Signature"]
        },
        {
          order: 6,
          stage: "signed_request",
          role: "network_emit",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:2-9"],
          object_refs: ["network_request:sha1:request"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: "sha1:sdk:2-9",
      asset_id: "sha1:sdk",
      content_path: "assets/trace_request_input/runtime-sdk.js",
      line_start: 2,
      line_end: 9,
      stages: ["request_construction", "byte_buffer", "dynamic_dispatch", "integer_mixing", "signature_mutation", "signed_request"]
    }]
  });

  const completeness = analysis.parameters[0].candidate_generation_summary.capture_completeness;
  assert.equal(completeness.status, "complete_enough_for_agent_analysis");
  assert.deepEqual(completeness.missing_items, []);
  assert.deepEqual(completeness.partial_items, []);
  assert.deepEqual(completeness.checklist.find((item) => item.item === "input_material_observed"), {
    item: "input_material_observed",
    status: "observed",
    evidence: [
      "runtime_api:Request.constructor",
      "object_ref:network_request:sha1:request",
      "object_ref:headers:31",
      "value_ref:url_shape:feed",
      "value_ref:target_params:X-Signature"
    ],
    missing: [],
    next_capture_hooks: []
  });
  assert.deepEqual(
    analysis.parameters[0].analysis_readiness.checklist.find((item) => item.item === "unsigned_input_observed"),
    {
      item: "unsigned_input_observed",
      status: "pass",
      evidence_refs: [
        "stage:request_construction",
        "api:Request.constructor",
        "source:sha1:sdk:2-9",
        "network_request:sha1:request",
        "headers:31",
        "url_shape:feed",
        "target_params:X-Signature"
      ],
      gaps: [],
      next_actions: []
    }
  );
});

test("buildAgentAnalysis summarizes VMP scalar operation patterns for parameters", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_patterns.ndjson", event_count: 8},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "strong",
      source_refs: ["sha1:runtime-sdk:9-9"],
      evidence_gaps: [],
      generation_trace: [{
        order: 1,
        stage: "input_url",
        role: "input",
        apis: ["URL.constructor"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 5,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:9-9"],
        object_refs: ["url_object:7"],
        value_refs: ["number:88.000000"]
      }, {
        order: 2,
        stage: "integer_mixing",
        role: "transform",
        apis: ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 4,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:9-9"],
        object_refs: [],
        value_refs: ["number:88.000000", "number:79.000000"]
      }, {
        order: 3,
        stage: "signature_mutation",
        role: "parameter_attachment",
        apis: ["URLSearchParams.set"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "before_signed_request",
        distance_to_signed_request: 2,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:9-9"],
        object_refs: ["url_object:7"],
        value_refs: ["number:79.000000", "target_params:X-Signature"]
      }, {
        order: 4,
        stage: "signed_request",
        role: "network_emit",
        apis: ["Request.constructor"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "signed_request",
        distance_to_signed_request: 0,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:9-9"],
        object_refs: ["url_object:7"],
        value_refs: ["target_params:X-Signature"]
      }],
      vmp_scalar_chain_links: [{
        chain_id: "vmp_scalar_chain_1",
        stage: "integer_mixing",
        relation: "shared_value_ref",
        confidence: "high",
        shared_refs: ["number:79.000000", "number:1325431901.000000"],
        apis: ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"],
        quality_score: 1551,
        quality_reasons: ["multiply_xor_unsigned_shift", "high_magnitude_scalar_refs"],
        source_context_refs: ["sha1:runtime-sdk:9-9"],
        operation_trace: [
          {
            seq: 11,
            trace_index: 3,
            api: "Bitwise.xor",
            input_refs: ["number:88.000000", "number:23.000000"],
            result_ref: "number:79.000000",
            source_context_refs: ["sha1:runtime-sdk:9-9"]
          },
          {
            seq: 12,
            trace_index: 4,
            api: "Math.imul",
            input_refs: ["number:79.000000", "number:16777619.000000"],
            result_ref: "number:1325431901.000000",
            source_context_refs: ["sha1:runtime-sdk:9-9"]
          },
          {
            seq: 13,
            trace_index: 5,
            api: "Shift.unsignedRight",
            input_refs: ["number:1325431901.000000", "number:0.000000"],
            result_ref: "number:1325431901.000000",
            source_context_refs: ["sha1:runtime-sdk:9-9"]
          }
        ]
      }]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;

  assert.deepEqual(parameter.vmp_operation_patterns, [{
    chain_id: "vmp_scalar_chain_1",
    stage: "integer_mixing",
    pattern: "xor_imul_urshift_mixing",
    operation_signature: "Bitwise.xor -> Math.imul -> Shift.unsignedRight",
    operation_count: 3,
    seq_start: 11,
    seq_end: 13,
    trace_start: 3,
    trace_end: 5,
    relation_to_signature_mutation: "before_signature_mutation",
    distance_to_signature_mutation: 2,
    stage_order: 2,
    signature_stage_order: 3,
    signature_distance_basis: "trace_index",
    confidence: "high",
    quality_score: 1551,
    quality_reasons: ["multiply_xor_unsigned_shift", "high_magnitude_scalar_refs"],
    shared_refs: ["number:79.000000", "number:1325431901.000000"],
    evidence_refs: [
      "number:88.000000",
      "number:23.000000",
      "number:79.000000",
      "number:16777619.000000",
      "number:1325431901.000000",
      "number:0.000000"
    ],
    source_context_refs: ["sha1:runtime-sdk:9-9"]
  }]);
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /vmp_patterns=xor_imul_urshift_mixing\[high\]:Bitwise\.xor -> Math\.imul -> Shift\.unsignedRight seq=11\.\.13 trace=3\.\.5 relation=before_signature_mutation d_sig=2 refs=number:79\.000000\|number:1325431901\.000000/
  );
  assert.deepEqual(parameter.generation_hypothesis, {
    status: "strong_pre_signature_runtime_chain",
    evidence_level: "high",
    chain_quality: "strong",
    direct_attachment_observed: true,
    pre_signature_pattern_observed: true,
    primary_pattern: "xor_imul_urshift_mixing",
    primary_pattern_confidence: "high",
    primary_operation_signature: "Bitwise.xor -> Math.imul -> Shift.unsignedRight",
    stage_chain: ["input_url", "integer_mixing", "signature_mutation", "signed_request"],
    evidence_refs: [
      "vmp_scalar_chain_1",
      "sha1:runtime-sdk:9-9",
      "number:79.000000",
      "number:1325431901.000000"
    ],
    remaining_gaps: [],
    next_actions: ["review_source_refs"]
  });
  assert.deepEqual(analysis.summary.hypothesis_summary, {
    status_counts: {
      strong_pre_signature_runtime_chain: 1
    },
    primary_pattern_counts: {
      xor_imul_urshift_mixing: 1
    },
    strong_chain_count: 1,
    partial_chain_count: 0,
    needs_more_evidence_count: 0,
    unresolved_hypothesis_gap_count: 0
  });
  assert.deepEqual(analysis.summary.readiness_summary, {
    ready_count: 1,
    partial_count: 0,
    insufficient_count: 0,
    average_score: 100
  });
  assert.deepEqual(parameter.analysis_readiness.summary, {
    status: "ready_for_detailed_generation_analysis",
    score: 100,
    passed_count: 7,
    partial_count: 0,
    failed_count: 0,
    primary_next_action: "review_source_refs"
  });
  const readinessByItem = new Map(parameter.analysis_readiness.checklist.map((item) => [item.item, item]));
  assert.deepEqual(readinessByItem.get("unsigned_input_observed"), {
    item: "unsigned_input_observed",
    status: "pass",
    evidence_refs: [
      "stage:input_url",
      "api:URL.constructor",
      "source:sha1:runtime-sdk:9-9",
      "url_object:7",
      "number:88.000000"
    ],
    gaps: [],
    next_actions: []
  });
  assert.deepEqual(readinessByItem.get("vmp_operation_pattern_observed"), {
    item: "vmp_operation_pattern_observed",
    status: "pass",
    evidence_refs: ["pattern:xor_imul_urshift_mixing", "vmp_scalar_chain_1"],
    gaps: [],
    next_actions: []
  });
  assert.deepEqual(readinessByItem.get("generation_edges_resolved"), {
    item: "generation_edges_resolved",
    status: "pass",
    evidence_refs: ["edges:3/3", "quality:strong"],
    gaps: [],
    next_actions: []
  });
  assert.deepEqual(parameter.analysis_readiness.next_probe_plan, {
    action: "review_source_refs",
    reason: "ready_for_agent_review",
    stages: ["input_url", "integer_mixing", "signature_mutation", "signed_request"],
    gaps: [],
    hook_targets: [],
    source_refs: ["sha1:runtime-sdk:9-9"],
    object_refs: ["url_object:7"],
    value_refs: [
      "number:88.000000",
      "number:79.000000",
      "target_params:X-Signature"
    ]
  });
  assert.deepEqual(parameter.generation_graph, {
    node_count: 4,
    edge_count: 3,
    unresolved_edge_count: 0,
    entry_node_id: "step_1_input_url",
    exit_node_id: "step_4_signed_request",
    readiness_status: "ready_for_detailed_generation_analysis",
    primary_next_probe: "review_source_refs",
    nodes: [
      {
        id: "step_1_input_url",
        order: 1,
        stage: "input_url",
        role: "input",
        status: "observed",
        apis: ["URL.constructor"],
        relation_to_signed_request: "before_signed_request",
        distance_to_signed_request: 5,
        evidence_flags: [
          "runtime_api_observed",
          "source_context_observed",
          "data_refs_observed",
          "pre_request_observed"
        ],
        evidence_gaps: [],
        source_refs: ["sha1:runtime-sdk:9-9"],
        object_refs: ["url_object:7"],
        value_refs: ["number:88.000000"]
      },
      {
        id: "step_2_integer_mixing",
        order: 2,
        stage: "integer_mixing",
        role: "transform",
        status: "observed",
        apis: ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"],
        relation_to_signed_request: "before_signed_request",
        distance_to_signed_request: 4,
        evidence_flags: [
          "runtime_api_observed",
          "source_context_observed",
          "data_refs_observed",
          "pre_request_observed"
        ],
        evidence_gaps: [],
        source_refs: ["sha1:runtime-sdk:9-9"],
        object_refs: [],
        value_refs: ["number:88.000000", "number:79.000000"]
      },
      {
        id: "step_3_signature_mutation",
        order: 3,
        stage: "signature_mutation",
        role: "parameter_attachment",
        status: "observed",
        apis: ["URLSearchParams.set"],
        relation_to_signed_request: "before_signed_request",
        distance_to_signed_request: 2,
        evidence_flags: [
          "runtime_api_observed",
          "source_context_observed",
          "data_refs_observed",
          "pre_request_observed",
          "target_param_observed"
        ],
        evidence_gaps: [],
        source_refs: ["sha1:runtime-sdk:9-9"],
        object_refs: ["url_object:7"],
        value_refs: ["number:79.000000", "target_params:X-Signature"]
      },
      {
        id: "step_4_signed_request",
        order: 4,
        stage: "signed_request",
        role: "network_emit",
        status: "observed",
        apis: ["Request.constructor"],
        relation_to_signed_request: "signed_request",
        distance_to_signed_request: 0,
        evidence_flags: [
          "runtime_api_observed",
          "source_context_observed",
          "data_refs_observed",
          "signed_request_observed",
          "target_param_observed"
        ],
        evidence_gaps: [],
        source_refs: ["sha1:runtime-sdk:9-9"],
        object_refs: ["url_object:7"],
        value_refs: ["target_params:X-Signature"]
      }
    ],
    edges: [
      {
        id: "edge_1_2",
        from: "step_1_input_url",
        to: "step_2_integer_mixing",
        status: "confirmed",
        relation: "shared_value_ref",
        confidence: "high",
        refs: ["number:88.000000"],
        source_refs: ["sha1:runtime-sdk:9-9"],
        evidence: ["shared_value_ref", "shared_source_ref"]
      },
      {
        id: "edge_2_3",
        from: "step_2_integer_mixing",
        to: "step_3_signature_mutation",
        status: "confirmed",
        relation: "shared_value_ref",
        confidence: "high",
        refs: ["number:79.000000"],
        source_refs: ["sha1:runtime-sdk:9-9"],
        evidence: ["shared_value_ref", "shared_source_ref"]
      },
      {
        id: "edge_3_4",
        from: "step_3_signature_mutation",
        to: "step_4_signed_request",
        status: "confirmed",
        relation: "target_param_ref",
        confidence: "high",
        refs: ["target_params:X-Signature", "url_object:7"],
        source_refs: ["sha1:runtime-sdk:9-9"],
        evidence: ["target_param_ref", "shared_object_ref", "shared_source_ref"]
      }
    ],
    unresolved_edges: [],
    operation_subgraphs: [{
      id: "opgraph_vmp_scalar_chain_1",
      chain_id: "vmp_scalar_chain_1",
      stage: "integer_mixing",
      attached_node_id: "step_2_integer_mixing",
      pattern: "xor_imul_urshift_mixing",
      operation_signature: "Bitwise.xor -> Math.imul -> Shift.unsignedRight",
      confidence: "high",
      operation_count: 3,
      shared_refs: ["number:79.000000", "number:1325431901.000000"],
      output_refs: ["number:79.000000", "number:1325431901.000000"],
      nodes: [
        {
          id: "op_vmp_scalar_chain_1_11",
          order: 1,
          api: "Bitwise.xor",
          seq: 11,
          trace_index: 3,
          input_refs: ["number:88.000000", "number:23.000000"],
          result_ref: "number:79.000000",
          source_refs: ["sha1:runtime-sdk:9-9"]
        },
        {
          id: "op_vmp_scalar_chain_1_12",
          order: 2,
          api: "Math.imul",
          seq: 12,
          trace_index: 4,
          input_refs: ["number:79.000000", "number:16777619.000000"],
          result_ref: "number:1325431901.000000",
          source_refs: ["sha1:runtime-sdk:9-9"]
        },
        {
          id: "op_vmp_scalar_chain_1_13",
          order: 3,
          api: "Shift.unsignedRight",
          seq: 13,
          trace_index: 5,
          input_refs: ["number:1325431901.000000", "number:0.000000"],
          result_ref: "number:1325431901.000000",
          source_refs: ["sha1:runtime-sdk:9-9"]
        }
      ],
      edges: [
        {
          id: "op_edge_vmp_scalar_chain_1_11_12",
          from: "op_vmp_scalar_chain_1_11",
          to: "op_vmp_scalar_chain_1_12",
          relation: "result_to_input",
          via_ref: "number:79.000000"
        },
        {
          id: "op_edge_vmp_scalar_chain_1_12_13",
          from: "op_vmp_scalar_chain_1_12",
          to: "op_vmp_scalar_chain_1_13",
          relation: "result_to_input",
          via_ref: "number:1325431901.000000"
        }
      ]
    }],
    dataflow_summary: {
      status: "vmp_output_reaches_signed_request",
      vmp_output_link_count: 1,
      attachment_to_request_link_observed: true,
      linked_output_refs: ["number:79.000000"],
      links: [{
        opgraph_id: "opgraph_vmp_scalar_chain_1",
        output_ref: "number:79.000000",
        to_node_id: "step_3_signature_mutation",
        to_stage: "signature_mutation",
        relation: "vmp_output_ref_on_signature_stage",
        confidence: "high"
      }],
      request_links: [{
        from_node_id: "step_3_signature_mutation",
        to_node_id: "step_4_signed_request",
        relation: "target_param_ref",
        refs: ["target_params:X-Signature", "url_object:7"]
      }],
      gaps: [],
      next_actions: ["review_source_refs"]
    }
  });
  assert.deepEqual(parameter.reconstruction_recipe, {
    status: "ready_for_agent_reconstruction",
    param: "X-Signature",
    endpoint: "https://www.example.test/api/feed",
    stage_chain: ["input_url", "integer_mixing", "signature_mutation", "signed_request"],
    dataflow_status: "vmp_output_reaches_signed_request",
    operation_programs: [{
      opgraph_id: "opgraph_vmp_scalar_chain_1",
      chain_id: "vmp_scalar_chain_1",
      stage: "integer_mixing",
      attached_node_id: "step_2_integer_mixing",
      pattern: "xor_imul_urshift_mixing",
      confidence: "high",
      output_refs: ["number:79.000000", "number:1325431901.000000"],
      output_bindings: [
        {
          output_ref: "number:79.000000",
          operation_id: "op_vmp_scalar_chain_1_11",
          target_stage: "signature_mutation",
          target_node_id: "step_3_signature_mutation",
          request_node_ids: ["step_4_signed_request"],
          relation: "vmp_output_ref_on_signature_stage",
          confidence: "high",
          target_params: ["X-Signature"],
          evidence: ["vmp_output_link", "request_attachment_link"]
        }
      ],
      input_bindings: [
        {
          input_ref: "number:88.000000",
          operation_id: "op_vmp_scalar_chain_1_11",
          role: "vmp_operation_input",
          source_stage: "integer_mixing",
          source_order: 2,
          source_refs: ["sha1:runtime-sdk:9-9"],
          target_params: ["X-Signature"],
          evidence: ["shared_runtime_ref", "vmp_operation_input_ref"]
        },
        {
          input_ref: "number:23.000000",
          operation_id: "op_vmp_scalar_chain_1_11",
          role: "vmp_operation_input",
          source_stage: "integer_mixing",
          source_order: 2,
          source_refs: ["sha1:runtime-sdk:9-9"],
          target_params: ["X-Signature"],
          evidence: ["vmp_operation_input_ref"]
        },
        {
          input_ref: "number:16777619.000000",
          operation_id: "op_vmp_scalar_chain_1_12",
          role: "vmp_operation_input",
          source_stage: "integer_mixing",
          source_order: 2,
          source_refs: ["sha1:runtime-sdk:9-9"],
          target_params: ["X-Signature"],
          evidence: ["vmp_operation_input_ref"]
        },
        {
          input_ref: "number:0.000000",
          operation_id: "op_vmp_scalar_chain_1_13",
          role: "vmp_operation_input",
          source_stage: "integer_mixing",
          source_order: 2,
          source_refs: ["sha1:runtime-sdk:9-9"],
          target_params: ["X-Signature"],
          evidence: ["vmp_operation_input_ref"]
        }
      ],
      lines: [
        "op1=Bitwise.xor(number:88.000000,number:23.000000)->number:79.000000",
        "op2=Math.imul(number:79.000000,number:16777619.000000)->number:1325431901.000000",
        "op3=Shift.unsignedRight(number:1325431901.000000,number:0.000000)->number:1325431901.000000"
      ],
      edges: [
        {
          from: "op_vmp_scalar_chain_1_11",
          to: "op_vmp_scalar_chain_1_12",
          via_ref: "number:79.000000"
        },
        {
          from: "op_vmp_scalar_chain_1_12",
          to: "op_vmp_scalar_chain_1_13",
          via_ref: "number:1325431901.000000"
        }
      ],
      operations: [
        {
          id: "op_vmp_scalar_chain_1_11",
          order: 1,
          api: "Bitwise.xor",
          seq: 11,
          trace_index: 3,
          input_refs: ["number:88.000000", "number:23.000000"],
          result_ref: "number:79.000000",
          source_refs: ["sha1:runtime-sdk:9-9"]
        },
        {
          id: "op_vmp_scalar_chain_1_12",
          order: 2,
          api: "Math.imul",
          seq: 12,
          trace_index: 4,
          input_refs: ["number:79.000000", "number:16777619.000000"],
          result_ref: "number:1325431901.000000",
          source_refs: ["sha1:runtime-sdk:9-9"]
        },
        {
          id: "op_vmp_scalar_chain_1_13",
          order: 3,
          api: "Shift.unsignedRight",
          seq: 13,
          trace_index: 5,
          input_refs: ["number:1325431901.000000", "number:0.000000"],
          result_ref: "number:1325431901.000000",
          source_refs: ["sha1:runtime-sdk:9-9"]
        }
      ]
    }],
    algorithm_outline: {
      status: "ready_for_agent_reconstruction",
      target_params: ["X-Signature"],
      reproducibility: "observed_runtime_replay",
      lines: [
        "input1=number:88.000000=>op_vmp_scalar_chain_1_11[vmp_operation_input stage=integer_mixing]",
        "input2=number:23.000000=>op_vmp_scalar_chain_1_11[vmp_operation_input stage=integer_mixing]",
        "input3=number:16777619.000000=>op_vmp_scalar_chain_1_12[vmp_operation_input stage=integer_mixing]",
        "input4=number:0.000000=>op_vmp_scalar_chain_1_13[vmp_operation_input stage=integer_mixing]",
        "program1=vmp_scalar_chain_1:integer_mixing pattern=xor_imul_urshift_mixing",
        "op1=Bitwise.xor(number:88.000000,number:23.000000)->number:79.000000",
        "op2=Math.imul(number:79.000000,number:16777619.000000)->number:1325431901.000000",
        "op3=Shift.unsignedRight(number:1325431901.000000,number:0.000000)->number:1325431901.000000",
        "attach1=number:79.000000->signature_mutation[step_3_signature_mutation confidence=high]",
        "request1=step_3_signature_mutation->step_4_signed_request[target_param_ref refs=target_params:X-Signature,url_object:7]"
      ],
      inputs: ["number:88.000000", "number:23.000000", "number:16777619.000000", "number:0.000000"],
      outputs: ["number:79.000000"],
      gaps: []
    },
    attachment: {
      status: "observed",
      signature_node_ids: ["step_3_signature_mutation"],
      request_node_ids: ["step_4_signed_request"],
      output_links: [{
        opgraph_id: "opgraph_vmp_scalar_chain_1",
        output_ref: "number:79.000000",
        to_node_id: "step_3_signature_mutation",
        relation: "vmp_output_ref_on_signature_stage",
        confidence: "high"
      }],
      request_links: [{
        from_node_id: "step_3_signature_mutation",
        to_node_id: "step_4_signed_request",
        relation: "target_param_ref",
        refs: ["target_params:X-Signature", "url_object:7"]
      }]
    },
    evidence_gaps: [],
    next_actions: ["review_source_refs"]
  });
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /hypothesis=strong_pre_signature_runtime_chain pattern=xor_imul_urshift_mixing quality=strong direct_attachment=true pre_signature_pattern=true/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /readiness=ready_for_detailed_generation_analysis score=100 passed=7 partial=0 failed=0 primary=review_source_refs checklist=unsigned_input_observed:pass,transform_runtime_observed:pass,vmp_operation_pattern_observed:pass,signature_attachment_observed:pass,signed_request_observed:pass,source_context_resolved:pass,generation_edges_resolved:pass/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /graph=nodes=4 edges=3 unresolved=0 opgraphs=1 ops=xor_imul_urshift_mixing:3 flow=vmp_output_reaches_signed_request links=1 request=true entry=step_1_input_url exit=step_4_signed_request readiness=ready_for_detailed_generation_analysis next=review_source_refs/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /op_details=vmp_scalar_chain_1:integer_mixing attached=step_2_integer_mixing outputs=number:79\.000000\|number:1325431901\.000000 edges=op_vmp_scalar_chain_1_11->op_vmp_scalar_chain_1_12:number:79\.000000\|op_vmp_scalar_chain_1_12->op_vmp_scalar_chain_1_13:number:1325431901\.000000 nodes=Bitwise\.xor/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /recipe=ready_for_agent_reconstruction stages=input_url->integer_mixing->signature_mutation->signed_request ops=vmp_scalar_chain_1:op1=Bitwise\.xor\(number:88\.000000,number:23\.000000\)->number:79\.000000\|op2=Math\.imul\(number:79\.000000,number:16777619\.000000\)->number:1325431901\.000000 alg=input1=number:88\.000000=>op_vmp_scalar_chain_1_11\[vmp_operation_input stage=integer_mixing\]\|input2=number:23\.000000=>op_vmp_scalar_chain_1_11\[vmp_operation_input stage=integer_mixing\]\|input3=number:16777619\.000000=>op_vmp_scalar_chain_1_12\[vmp_operation_input stage=integer_mixing\]\|input4=number:0\.000000=>op_vmp_scalar_chain_1_13\[vmp_operation_input stage=integer_mixing\]\|program1=vmp_scalar_chain_1:integer_mixing pattern=xor_imul_urshift_mixing\|op1=Bitwise\.xor\(number:88\.000000,number:23\.000000\)->number:79\.000000 inputs=number:88\.000000->op_vmp_scalar_chain_1_11\[vmp_operation_input from=integer_mixing request=none\]\|number:23\.000000->op_vmp_scalar_chain_1_11\[vmp_operation_input from=integer_mixing request=none\]\|number:16777619\.000000->op_vmp_scalar_chain_1_12\[vmp_operation_input from=integer_mixing request=none\]\|number:0\.000000->op_vmp_scalar_chain_1_13\[vmp_operation_input from=integer_mixing request=none\] outputs=number:79\.000000<-op_vmp_scalar_chain_1_11\[vmp_output_ref_on_signature_stage to=signature_mutation request=step_4_signed_request\] attach=observed flow=vmp_output_reaches_signed_request output_links=number:79\.000000 request_links=step_3_signature_mutation->step_4_signed_request gaps=none next=review_source_refs/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /Hypotheses: strong=1 partial=0 needs_more=0 gaps=0 patterns=xor_imul_urshift_mixing:1/
  );
});

test("buildAgentAnalysis marks VMP temporal bridge to signed request when output refs are missing", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_bridge.ndjson", event_count: 8},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      agent_generation_summary: {
        stage_chain: [
          "integer_mixing",
          "text_or_string_decode",
          "signature_mutation",
          "request_body",
          "signed_request"
        ],
        runtime_apis: [
          "TextEncoder.encode",
          "URLSearchParams.toString"
        ]
      },
      generation_trace: [{
        order: 1,
        stage: "integer_mixing",
        role: "transform",
        apis: ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 3,
        distance_basis: "trace_index",
        source_refs: [],
        object_refs: [],
        value_refs: ["number:2166136261.000000", "number:-227934230.000000"]
      }, {
        order: 2,
        stage: "signature_mutation",
        role: "parameter_attachment",
        apis: ["URL.search.set"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "before_signed_request",
        distance_to_signed_request: 2,
        distance_basis: "trace_index",
        source_refs: [],
        object_refs: ["url_object:7"],
        value_refs: ["url_shape:signed", "target_params:X-Signature"]
      }, {
        order: 3,
        stage: "request_body",
        role: "network_emit",
        apis: ["XMLHttpRequest.send"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "before_signed_request",
        distance_to_signed_request: 1,
        distance_basis: "trace_index",
        source_refs: [],
        object_refs: ["url_object:7", "network_request:sha1:feed"],
        value_refs: ["url_shape:signed", "target_params:X-Signature"]
      }, {
        order: 4,
        stage: "signed_request",
        role: "network_emit",
        apis: ["BrowserNetwork.request"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "signed_request",
        distance_to_signed_request: 0,
        distance_basis: "trace_index",
        source_refs: [],
        object_refs: ["network_request:sha1:feed"],
        value_refs: ["url_shape:signed", "target_params:X-Signature"]
      }],
      vmp_scalar_chain_links: [{
        chain_id: "vmp_scalar_chain_1",
        stage: "integer_mixing",
        relation: "shared_value_ref",
        confidence: "high",
        shared_refs: ["number:2166136261.000000", "number:-227934230.000000"],
        apis: ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"],
        quality_score: 1551,
        quality_reasons: ["multiply_xor_unsigned_shift", "high_magnitude_scalar_refs"],
        source_context_refs: [],
        operation_trace: [
          {
            seq: 11,
            trace_index: 3,
            api: "Bitwise.xor",
            input_refs: ["number:2166136261.000000", "number:1937072687.000000"],
            result_ref: "number:-227934230.000000",
            source_context_refs: []
          },
          {
            seq: 12,
            trace_index: 4,
            api: "Math.imul",
            input_refs: ["number:-227934230.000000", "number:16777619.000000"],
            result_ref: "number:-2032280226.000000",
            source_context_refs: []
          },
          {
            seq: 13,
            trace_index: 5,
            api: "Shift.unsignedRight",
            input_refs: ["number:-2032280226.000000", "number:0.000000"],
            result_ref: "number:2262687070.000000",
            source_context_refs: []
          }
        ]
      }]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_graph.dataflow_summary, {
    status: "vmp_stage_bridge_reaches_signed_request",
    vmp_output_link_count: 0,
    attachment_to_request_link_observed: true,
    linked_output_refs: [],
    links: [],
    request_links: [
      {
        from_node_id: "step_2_signature_mutation",
        to_node_id: "step_3_request_body",
        relation: "target_param_ref",
        refs: ["target_params:X-Signature", "url_shape:signed", "url_object:7"]
      },
      {
        from_node_id: "step_3_request_body",
        to_node_id: "step_4_signed_request",
        relation: "target_param_ref",
        refs: [
          "target_params:X-Signature",
          "url_shape:signed",
          "network_request:sha1:feed"
        ]
      }
    ],
    bridge_links: [{
      opgraph_id: "opgraph_vmp_scalar_chain_1",
      from_node_id: "step_1_integer_mixing",
      to_node_id: "step_2_signature_mutation",
      relation: "temporal_runtime_order",
      confidence: "low",
      refs: ["trace_distance:3->2"]
    }],
    unresolved_output_bridges: [{
      opgraph_id: "opgraph_vmp_scalar_chain_1",
      from_node_id: "step_1_integer_mixing",
      to_node_id: "step_2_signature_mutation",
      relation: "temporal_runtime_order",
      confidence: "low",
      candidate_output_refs: [
        "number:-227934230.000000",
        "number:-2032280226.000000",
        "number:2262687070.000000"
      ],
      last_operations: [
        {
          api: "Bitwise.xor",
          seq: 11,
          result_ref: "number:-227934230.000000"
        },
        {
          api: "Math.imul",
          seq: 12,
          result_ref: "number:-2032280226.000000"
        },
        {
          api: "Shift.unsignedRight",
          seq: 13,
          result_ref: "number:2262687070.000000"
        }
      ],
      missing_refs: [
        "vmp_output_ref_on_signature_stage",
        "vmp_output_ref_on_string_encoding_boundary"
      ],
      downstream_request_observed: true,
      next_actions: [
        "capture_string_encoding_boundary_refs",
        "capture_vmp_register_state_refs",
        "capture_object_ids_for_data_links"
      ]
    }],
    gaps: ["vmp_output_ref_to_signature_not_observed"],
    next_actions: [
      "capture_string_encoding_boundary_refs",
      "capture_object_ids_for_data_links",
      "capture_vmp_register_state_refs"
    ]
  });
  assert.deepEqual(parameter.candidate_generation_summary.unresolved_gaps, [
    "vmp_output_ref_to_signature_not_observed",
    "temporal_only_edge",
    "unsigned_input_not_observed",
    "source_context_not_available"
  ]);
  assert.ok(parameter.unresolved_gaps.includes("vmp_output_ref_to_signature_not_observed"));
  assert.deepEqual(parameter.candidate_generation_summary.next_actions, [
    "capture_vmp_register_state_refs",
    "capture_string_encoding_boundary_refs",
    "capture_object_ids_for_data_links",
  ]);
  assert.ok(parameter.recommended_next_actions.includes("capture_string_encoding_boundary_refs"));
  const focusByAction = new Map(analysis.next_capture_focus.map((item) => [item.action, item]));
  assert.ok(focusByAction.has("capture_string_encoding_boundary_refs"));
  assert.ok(focusByAction.has("capture_vmp_register_state_refs"));
  const stringBoundaryFocus = focusByAction.get("capture_string_encoding_boundary_refs");
  assert.ok(stringBoundaryFocus.hook_targets.includes("TextEncoder.encode"));
  assert.ok(stringBoundaryFocus.hook_targets.includes("String.fromCharCode"));
  const stringBoundaryStatuses = new Map(stringBoundaryFocus.hook_target_statuses.map((item) => [item.target, item.status]));
  assert.equal(stringBoundaryStatuses.get("TextEncoder.encode"), "observed_in_focus_stage");
  assert.equal(stringBoundaryStatuses.get("URLSearchParams.toString"), "observed_in_focus_stage");
  assert.equal(stringBoundaryStatuses.get("String.fromCharCode"), "missing");
  assert.ok(focusByAction.get("capture_vmp_register_state_refs").hook_targets.includes("vmp.register_ref"));
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /graph=nodes=4 edges=3 unresolved=1 opgraphs=1 ops=xor_imul_urshift_mixing:3 flow=vmp_stage_bridge_reaches_signed_request links=0 request=true bridges=1 entry=step_1_integer_mixing exit=step_4_signed_request/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /unresolved_bridges=opgraph_vmp_scalar_chain_1:step_1_integer_mixing->step_2_signature_mutation refs=number:-227934230\.000000\|number:-2032280226\.000000\|number:2262687070\.000000 ops=Bitwise\.xor@11->Math\.imul@12->Shift\.unsignedRight@13 missing=vmp_output_ref_on_signature_stage\|vmp_output_ref_on_string_encoding_boundary/
  );
});

test("buildAgentAnalysis links VMP output to signed request through string encoding boundary", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_string_boundary.ndjson", event_count: 8},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: ["sha1:runtime-sdk:10-12"],
      evidence_gaps: [],
      generation_trace: [{
        order: 1,
        stage: "integer_mixing",
        role: "transform",
        apis: ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 3,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:10-12"],
        object_refs: [],
        value_refs: ["number:-227934230.000000", "number:2262687070.000000"]
      }, {
        order: 2,
        stage: "text_or_string_decode",
        role: "string_material",
        apis: ["String.fromCharCode"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 2,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:10-12"],
        object_refs: [],
        value_refs: ["number:-227934230.000000", "string_ref:x-signature-material"]
      }, {
        order: 3,
        stage: "signature_mutation",
        role: "parameter_attachment",
        apis: ["URLSearchParams.set"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "before_signed_request",
        distance_to_signed_request: 1,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:10-12"],
        object_refs: ["url_object:7"],
        value_refs: ["string_ref:x-signature-material", "target_params:X-Signature"]
      }, {
        order: 4,
        stage: "signed_request",
        role: "network_emit",
        apis: ["BrowserNetwork.request"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "signed_request",
        distance_to_signed_request: 0,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:10-12"],
        object_refs: ["url_object:7"],
        value_refs: ["string_ref:x-signature-material", "target_params:X-Signature"]
      }],
      vmp_scalar_chain_links: [{
        chain_id: "vmp_scalar_chain_1",
        stage: "integer_mixing",
        relation: "shared_value_ref",
        confidence: "high",
        shared_refs: ["number:-227934230.000000", "number:2262687070.000000"],
        apis: ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"],
        quality_score: 1551,
        quality_reasons: ["multiply_xor_unsigned_shift", "high_magnitude_scalar_refs"],
        source_context_refs: ["sha1:runtime-sdk:10-12"],
        operation_trace: [
          {
            seq: 11,
            trace_index: 3,
            api: "Bitwise.xor",
            input_refs: ["number:2166136261.000000", "number:1937072687.000000"],
            result_ref: "number:-227934230.000000",
            source_context_refs: ["sha1:runtime-sdk:10-12"]
          },
          {
            seq: 12,
            trace_index: 4,
            api: "Math.imul",
            input_refs: ["number:-227934230.000000", "number:16777619.000000"],
            result_ref: "number:-2032280226.000000",
            source_context_refs: ["sha1:runtime-sdk:10-12"]
          },
          {
            seq: 13,
            trace_index: 5,
            api: "Shift.unsignedRight",
            input_refs: ["number:-2032280226.000000", "number:0.000000"],
            result_ref: "number:2262687070.000000",
            source_context_refs: ["sha1:runtime-sdk:10-12"]
          }
        ]
      }]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_graph.dataflow_summary, {
    status: "vmp_output_reaches_signed_request_via_string_boundary",
    vmp_output_link_count: 0,
    encoding_boundary_link_count: 1,
    attachment_to_request_link_observed: true,
    linked_output_refs: [],
    links: [],
    request_links: [{
      from_node_id: "step_3_signature_mutation",
      to_node_id: "step_4_signed_request",
      relation: "target_param_ref",
      refs: ["target_params:X-Signature", "string_ref:x-signature-material", "url_object:7"]
    }],
    encoding_boundary_links: [{
      opgraph_id: "opgraph_vmp_scalar_chain_1",
      output_ref: "number:-227934230.000000",
      from_node_id: "step_1_integer_mixing",
      via_node_id: "step_2_text_or_string_decode",
      via_stage: "text_or_string_decode",
      to_node_id: "step_3_signature_mutation",
      relation: "vmp_output_to_signature_via_string_boundary",
      confidence: "high",
      refs: ["number:-227934230.000000", "string_ref:x-signature-material"]
    }],
    gaps: [],
    next_actions: ["review_source_refs"]
  });
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /graph=nodes=4 edges=3 unresolved=0 opgraphs=1 ops=xor_imul_urshift_mixing:3 flow=vmp_output_reaches_signed_request_via_string_boundary links=0 request=true boundary=1 entry=step_1_integer_mixing exit=step_4_signed_request/
  );
});

test("buildAgentAnalysis links register string length VMP output to encoding boundary", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_register_string_boundary.ndjson", event_count: 8},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: ["sha1:runtime-sdk:20-22"],
      evidence_gaps: [],
      generation_trace: [{
        order: 1,
        stage: "integer_mixing",
        role: "transform",
        apis: ["Bitwise.xor"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 4,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:20-22"],
        object_refs: [],
        value_refs: ["number:3.000000"]
      }, {
        order: 2,
        stage: "string_transform",
        role: "string_material",
        apis: ["String.prototype.slice"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 3,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:20-22"],
        object_refs: [],
        value_refs: ["string:length:39"]
      }, {
        order: 3,
        stage: "url_encoding",
        role: "encoding",
        apis: ["encodeURIComponent"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 2,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:20-22"],
        object_refs: [],
        value_refs: ["string:length:39", "string:length:41"]
      }, {
        order: 4,
        stage: "signature_mutation",
        role: "parameter_attachment",
        apis: ["URLSearchParams.set"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "before_signed_request",
        distance_to_signed_request: 1,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:20-22"],
        object_refs: ["url_object:7"],
        value_refs: ["string:length:41", "target_params:X-Signature"]
      }, {
        order: 5,
        stage: "signed_request",
        role: "network_emit",
        apis: ["Request.constructor"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "signed_request",
        distance_to_signed_request: 0,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:20-22"],
        object_refs: ["url_object:7"],
        value_refs: ["target_params:X-Signature"]
      }],
      vmp_scalar_chain_links: [{
        chain_id: "vmp_scalar_chain_1",
        stage: "integer_mixing",
        relation: "shared_value_ref",
        confidence: "high",
        shared_refs: ["number:3.000000"],
        apis: ["Bitwise.xor"],
        quality_score: 1000,
        quality_reasons: ["high_magnitude_scalar_refs"],
        source_context_refs: ["sha1:runtime-sdk:20-22"],
        operation_trace: [{
          seq: 11,
          trace_index: 2,
          api: "Bitwise.xor",
          input_refs: ["number:1.000000", "number:2.000000"],
          result_ref: "number:3.000000",
          output_refs: [
            "number:3.000000",
            "register:string:length:39/number:3.000000"
          ],
          source_context_refs: ["sha1:runtime-sdk:20-22"]
        }]
      }]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.equal(
    parameter.generation_graph.dataflow_summary.status,
    "vmp_output_reaches_signed_request_via_string_boundary"
  );
  assert.equal(parameter.generation_graph.dataflow_summary.encoding_boundary_link_count, 1);
  assert.ok(!parameter.unresolved_gaps.includes("vmp_output_ref_to_signature_not_observed"));
  assert.deepEqual(parameter.generation_graph.dataflow_summary.encoding_boundary_links, [{
    opgraph_id: "opgraph_vmp_scalar_chain_1",
    output_ref: "register:string:length:39/number:3.000000",
    from_node_id: "step_1_integer_mixing",
    via_node_id: "step_2_string_transform",
    via_stage: "string_transform",
    to_node_id: "step_4_signature_mutation",
    relation: "vmp_output_to_signature_via_string_boundary",
    confidence: "high",
    refs: [
      "register:string:length:39/number:3.000000",
      "string:length:39",
      "string:length:41"
    ]
  }]);
});

test("buildAgentAnalysis bridges VMP register string source output across transformed string boundaries", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_register_source_boundary.ndjson", event_count: 12},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: ["sha1:runtime-sdk:30-34"],
      evidence_gaps: [],
      generation_trace: [{
        order: 1,
        stage: "integer_mixing",
        role: "transform",
        apis: ["Bitwise.xor"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 5,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:30-34"],
        object_refs: [],
        value_refs: [
          "handler_arg:299081/number:15.000000",
          "register:string:length:200/number:15.000000"
        ]
      }, {
        order: 2,
        stage: "signature_mutation",
        role: "parameter_attachment",
        apis: ["URLSearchParams.set"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "before_signed_request",
        distance_to_signed_request: 2,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:30-34"],
        object_refs: ["search_params:7", "url_object:7"],
        value_refs: ["target_params:X-Signature", "url_shape:signed"]
      }, {
        order: 3,
        stage: "signed_request",
        role: "network_emit",
        apis: ["BrowserNetwork.request"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "signed_request",
        distance_to_signed_request: 0,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:30-34"],
        object_refs: ["url_object:7", "network_request:sha1:feed"],
        value_refs: ["target_params:X-Signature", "url_shape:signed"]
      }, {
        order: 4,
        stage: "string_transform",
        role: "string_material",
        apis: ["String.prototype.replace"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 4,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:30-34"],
        object_refs: [],
        value_refs: [
          "string:length:0",
          "string:length:16",
          "string:length:1358",
          "regexp:/[\\u0000-\\uffff]/"
        ]
      }, {
        order: 5,
        stage: "url_encoding",
        role: "encoding",
        apis: ["URLSearchParams.toString"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 3,
        distance_basis: "trace_index",
        source_refs: ["sha1:runtime-sdk:30-34"],
        object_refs: [],
        value_refs: ["string:length:12"]
      }],
      vmp_scalar_chain_links: [{
        chain_id: "vmp_scalar_chain_1",
        stage: "integer_mixing",
        relation: "shared_value_ref",
        confidence: "high",
        shared_refs: [
          "handler_arg:299081/number:15.000000",
          "register:string:length:200/number:15.000000"
        ],
        apis: ["Bitwise.xor"],
        quality_score: 1200,
        quality_reasons: ["string_length_register_output"],
        source_context_refs: ["sha1:runtime-sdk:30-34"],
        operation_trace: [{
          seq: 31,
          trace_index: 3,
          api: "Bitwise.xor",
          input_refs: [
            "handler_arg:299081/number:15.000000",
            "register:string:length:200/number:15.000000",
            "number:42.000000"
          ],
          result_ref: "number:24.000000",
          output_refs: [
            "number:24.000000",
            "handler_arg:299081/number:15.000000",
            "register:string:length:200/number:15.000000"
          ],
          source_context_refs: ["sha1:runtime-sdk:30-34"]
        }]
      }]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.equal(
    parameter.generation_graph.dataflow_summary.status,
    "vmp_output_reaches_signed_request_via_string_boundary"
  );
  assert.equal(parameter.generation_graph.dataflow_summary.encoding_boundary_link_count, 1);
  assert.ok(!parameter.unresolved_gaps.includes("vmp_output_ref_to_signature_not_observed"));
  assert.deepEqual(parameter.generation_graph.dataflow_summary.encoding_boundary_links, [{
    opgraph_id: "opgraph_vmp_scalar_chain_1",
    output_ref: "register:string:length:200/number:15.000000",
    from_node_id: "step_1_integer_mixing",
    via_node_id: "step_4_string_transform",
    via_stage: "string_transform",
    to_node_id: "step_2_signature_mutation",
    relation: "vmp_output_to_signature_via_string_source_boundary",
    confidence: "medium",
    refs: [
      "register:string:length:200/number:15.000000",
      "string:length:1358",
      "sha1:runtime-sdk:30-34"
    ]
  }]);
});

test("buildAgentAnalysis summarizes blocking generation evidence gaps for agents", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_blocking_gaps.ndjson", event_count: 9},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: ["sha1:sdk:2-4"],
      evidence_gaps: ["signature_mutation_not_observed"],
      generation_trace: [{
        order: 1,
        stage: "input_url",
        role: "input",
        apis: ["URL.constructor"],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 4,
        distance_basis: "trace_index",
        source_refs: ["sha1:sdk:2-4"],
        object_refs: ["url_object:7"],
        value_refs: ["url_shape:feed"]
      }, {
        order: 2,
        stage: "dynamic_dispatch",
        role: "transform",
        apis: [],
        target_params: ["X-Signature"],
        param_relation: "flow_target",
        relation: "before_signed_request",
        distance_to_signed_request: 3,
        distance_basis: "trace_index",
        source_refs: ["sha1:sdk:2-4"],
        object_refs: [],
        value_refs: ["url_object:9"]
      }, {
        order: 3,
        stage: "signature_mutation",
        role: "parameter_attachment",
        apis: [],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "before_signed_request",
        distance_to_signed_request: 1,
        distance_basis: "trace_index",
        source_refs: [],
        object_refs: ["url_object:9"],
        value_refs: ["target_params:X-Signature"]
      }, {
        order: 4,
        stage: "signed_request",
        role: "network_emit",
        apis: ["Request.constructor"],
        target_params: ["X-Signature"],
        param_relation: "direct_observed",
        relation: "signed_request",
        distance_to_signed_request: 0,
        distance_basis: "trace_index",
        source_refs: ["sha1:sdk:2-4"],
        object_refs: ["url_object:9"],
        value_refs: ["target_params:X-Signature"]
      }]
    }],
    source_ref_index: [{
      ref: "sha1:sdk:2-4",
      asset_id: "sha1:sdk",
      content_path: "assets/trace_blocking_gaps/runtime-sdk.js",
      line_start: 2,
      line_end: 4
    }]
  });

  assert.deepEqual(analysis.summary.blocking_gap_summary, {
    total_observation_count: 5,
    gap_counts: {
      signature_mutation_not_observed: 1,
      runtime_api_not_observed: 2,
      source_context_not_available: 1,
      temporal_only_edge: 1
    },
    stage_counts: {
      signature_mutation: 3,
      dynamic_dispatch: 1,
      "input_url->dynamic_dispatch": 1
    },
    action_counts: {
      capture_url_search_params_mutation_or_header_set: 3,
      expand_vmp_runtime_hooks: 2,
      capture_or_retrieve_script_asset: 1,
      capture_object_ids_for_data_links: 1
    },
    top_blockers: [
      {
        gap: "runtime_api_not_observed",
        count: 2,
        priority: "high",
        params: ["X-Signature"],
        stages: ["dynamic_dispatch", "signature_mutation"],
        actions: ["expand_vmp_runtime_hooks", "capture_url_search_params_mutation_or_header_set"],
        endpoints: ["https://www.example.test/api/feed"],
        hook_targets: [
          "Reflect.apply",
          "Function.prototype.call",
          "Function.prototype.apply",
          "Proxy.get",
          "URLSearchParams.set",
          "URLSearchParams.append",
          "URL.search.set",
          "URL.href.set"
        ],
        source_refs: ["sha1:sdk:2-4"],
        object_refs: ["url_object:9"],
        value_refs: ["url_object:9", "target_params:X-Signature"]
      },
      {
        gap: "signature_mutation_not_observed",
        count: 1,
        priority: "high",
        params: ["X-Signature"],
        stages: ["signature_mutation"],
        actions: ["capture_url_search_params_mutation_or_header_set"],
        endpoints: ["https://www.example.test/api/feed"],
        hook_targets: [
          "URLSearchParams.set",
          "URLSearchParams.append",
          "URL.search.set",
          "URL.href.set",
          "Headers.set",
          "XMLHttpRequest.setRequestHeader"
        ],
        source_refs: ["sha1:sdk:2-4"],
        object_refs: [],
        value_refs: []
      },
      {
        gap: "source_context_not_available",
        count: 1,
        priority: "high",
        params: ["X-Signature"],
        stages: ["signature_mutation"],
        actions: ["capture_url_search_params_mutation_or_header_set", "capture_or_retrieve_script_asset"],
        endpoints: ["https://www.example.test/api/feed"],
        hook_targets: [
          "URLSearchParams.set",
          "URLSearchParams.append",
          "URL.search.set",
          "URL.href.set",
          "Headers.set",
          "XMLHttpRequest.setRequestHeader",
          "script.source.asset",
          "stack.asset_id"
        ],
        source_refs: [],
        object_refs: ["url_object:9"],
        value_refs: ["target_params:X-Signature"]
      },
      {
        gap: "temporal_only_edge",
        count: 1,
        priority: "medium",
        params: ["X-Signature"],
        stages: ["input_url->dynamic_dispatch"],
        actions: ["capture_object_ids_for_data_links"],
        endpoints: ["https://www.example.test/api/feed"],
        hook_targets: [
          "object_ref.url_object",
          "object_ref.search_params",
          "value_ref.url_shape",
          "value_ref.buffer"
        ],
        source_refs: ["sha1:sdk:2-4"],
        object_refs: ["url_object:7"],
        value_refs: ["url_shape:feed", "url_object:9"]
      }
    ]
  });
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /Blocking gaps: total=5 top=runtime_api_not_observed:2\[high\],signature_mutation_not_observed:1\[high\],source_context_not_available:1\[high\],temporal_only_edge:1\[medium\] actions=capture_url_search_params_mutation_or_header_set:3,expand_vmp_runtime_hooks:2,capture_or_retrieve_script_asset:1,capture_object_ids_for_data_links:1/
  );
});

test("buildAgentAnalysis reports temporal-only generation edge gaps for ordered weak chains", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_weak_edges.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: ["sha1:sdk:1-4"],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: [],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 3,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-4"],
          source_signals: ["dynamic_dispatch"],
          object_refs: [],
          value_refs: []
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: [],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:1-4"],
          source_operators: ["^"],
          object_refs: [],
          value_refs: []
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 1,
          distance_basis: "trace_index",
          source_refs: [],
          object_refs: ["url_object:3"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: "sha1:sdk:1-4",
      asset_id: "sha1:sdk",
      content_path: "assets/trace_weak_edges/runtime-sdk.js",
      line_start: 1,
      line_end: 4,
      preview: "function vm(){ /* redacted */ }",
      source_candidate_ids: ["source_candidate_1"],
      review_entry_ids: ["review_entry_1"],
      target_params: ["X-Signature"],
      stages: ["dynamic_dispatch", "integer_mixing"]
    }]
  });

  assert.deepEqual(analysis.parameters[0].generation_edges, [
    {
      from_order: 1,
      to_order: 2,
      from_stage: "dynamic_dispatch",
      to_stage: "integer_mixing",
      relation: "temporal_runtime_order",
      confidence: "low",
      refs: ["trace_distance:3->2"],
      source_refs: ["sha1:sdk:1-4"],
      evidence: ["temporal_runtime_order", "shared_source_ref"],
      temporal_basis: ["pre_request_distance_order", "trace_index"]
    },
    {
      from_order: 2,
      to_order: 3,
      from_stage: "integer_mixing",
      to_stage: "signature_mutation",
      relation: "temporal_runtime_order",
      confidence: "low",
      refs: ["trace_distance:2->1"],
      source_refs: [],
      evidence: ["temporal_runtime_order"],
      temporal_basis: ["pre_request_distance_order", "trace_index"]
    }
  ]);
  assert.deepEqual(analysis.parameters[0].chain_quality, {
    status: "partial",
    step_count: 3,
    expected_edge_count: 2,
    edge_count: 2,
    high_confidence_edge_count: 0,
    medium_confidence_edge_count: 0,
    source_only_edge_count: 0,
    temporal_only_edge_count: 2,
    nearby_runtime_only_edge_count: 0,
    missing_edge_count: 0
  });
  assert.deepEqual(analysis.parameters[0].generation_edge_gaps, [
    {
      from_order: 1,
      to_order: 2,
      from_stage: "dynamic_dispatch",
      to_stage: "integer_mixing",
      gap: "temporal_only_edge",
      reason: "ordered_runtime_window_no_shared_data_ref",
      priority: "medium",
      next_actions: ["capture_object_ids_for_data_links"],
      source_refs: ["sha1:sdk:1-4"],
      object_refs: [],
      value_refs: []
    },
    {
      from_order: 2,
      to_order: 3,
      from_stage: "integer_mixing",
      to_stage: "signature_mutation",
      gap: "temporal_only_edge",
      reason: "ordered_runtime_window_no_shared_data_ref",
      priority: "medium",
      next_actions: ["capture_object_ids_for_data_links"],
      source_refs: [],
      object_refs: ["url_object:3"],
      value_refs: ["target_params:X-Signature"]
    }
  ]);
  assert.ok(analysis.next_capture_focus.some((focus) =>
    focus.action === "capture_object_ids_for_data_links" &&
    focus.params.includes("X-Signature") &&
    focus.gaps.includes("temporal_only_edge")));
});

test("buildAgentAnalysis marks ordered runtime-only edges as temporal evidence", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_temporal_edges.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "input_url",
          role: "input",
          apis: ["decodeURIComponent"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 20,
          distance_basis: "trace_index",
          object_refs: [],
          value_refs: ["url_shape:feed"]
        },
        {
          order: 2,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          object_refs: ["target:7"],
          value_refs: []
        },
        {
          order: 3,
          stage: "hash_or_digest",
          role: "transform",
          apis: ["SubtleCrypto.digest"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 9,
          distance_basis: "trace_index",
          object_refs: [],
          value_refs: []
        }
      ]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_edges, [{
    from_order: 1,
    to_order: 2,
    from_stage: "input_url",
    to_stage: "dynamic_dispatch",
    relation: "temporal_runtime_order",
    confidence: "low",
    refs: ["trace_distance:20->4"],
    source_refs: [],
    evidence: ["temporal_runtime_order"],
    temporal_basis: ["pre_request_distance_order", "trace_index"]
  }]);
  assert.deepEqual(parameter.generation_edge_gaps, [
    {
      from_order: 1,
      to_order: 2,
      from_stage: "input_url",
      to_stage: "dynamic_dispatch",
      gap: "temporal_only_edge",
      reason: "ordered_runtime_window_no_shared_data_ref",
      priority: "medium",
      next_actions: ["capture_object_ids_for_data_links"],
      source_refs: [],
      object_refs: ["target:7"],
      value_refs: ["url_shape:feed"]
    },
    {
      from_order: 2,
      to_order: 3,
      from_stage: "dynamic_dispatch",
      to_stage: "hash_or_digest",
      gap: "missing_generation_edge",
      reason: "no_shared_runtime_or_source_ref",
      priority: "high",
      next_actions: [
        "capture_object_ids_for_data_links",
        "capture_or_retrieve_script_asset"
      ],
      source_refs: [],
      object_refs: ["target:7"],
      value_refs: []
    }
  ]);
  assert.equal(parameter.chain_quality.temporal_only_edge_count, 1);
});

test("buildAgentAnalysis links request boundary string stages without marking missing edges", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_request_boundary_edges.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_boundary",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "signed_request",
          role: "network_emit",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          object_refs: ["network_request:sha1:req"],
          value_refs: ["target_params:X-Signature"]
        },
        {
          order: 2,
          stage: "string_transform",
          role: "transform",
          apis: ["String.prototype.slice"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 3,
          distance_basis: "trace_index",
          object_refs: [],
          value_refs: ["string:length:1802", "string:length:16"]
        },
        {
          order: 3,
          stage: "url_encoding",
          role: "transform",
          apis: ["encodeURIComponent"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          object_refs: [],
          value_refs: ["string:length:12", "url_encoded:length:12"]
        }
      ]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_edges, [
    {
      from_order: 1,
      to_order: 2,
      from_stage: "signed_request",
      to_stage: "string_transform",
      relation: "request_boundary_runtime_window",
      confidence: "low",
      refs: ["trace_distance:0~3"],
      source_refs: [],
      evidence: ["request_boundary_runtime_window"],
      boundary_basis: ["request_boundary_window", "trace_index", "stage_pair:signed_request->string_transform"]
    },
    {
      from_order: 2,
      to_order: 3,
      from_stage: "string_transform",
      to_stage: "url_encoding",
      relation: "request_boundary_runtime_window",
      confidence: "low",
      refs: ["trace_distance:3~4"],
      source_refs: [],
      evidence: ["request_boundary_runtime_window"],
      boundary_basis: ["request_boundary_window", "trace_index", "stage_pair:string_transform->url_encoding"]
    }
  ]);
  assert.deepEqual(parameter.generation_edge_gaps, [
    {
      from_order: 1,
      to_order: 2,
      from_stage: "signed_request",
      to_stage: "string_transform",
      gap: "temporal_only_edge",
      reason: "request_boundary_window_no_shared_data_ref",
      priority: "medium",
      next_actions: ["capture_object_ids_for_data_links"],
      source_refs: [],
      object_refs: ["network_request:sha1:req"],
      value_refs: ["target_params:X-Signature", "string:length:1802", "string:length:16"]
    },
    {
      from_order: 2,
      to_order: 3,
      from_stage: "string_transform",
      to_stage: "url_encoding",
      gap: "temporal_only_edge",
      reason: "request_boundary_window_no_shared_data_ref",
      priority: "medium",
      next_actions: ["capture_object_ids_for_data_links"],
      source_refs: [],
      object_refs: [],
      value_refs: ["string:length:1802", "string:length:16", "string:length:12", "url_encoded:length:12"]
    }
  ]);
  assert.equal(parameter.chain_quality.missing_edge_count, 0);
  assert.equal(parameter.chain_quality.temporal_only_edge_count, 2);
});

test("buildAgentAnalysis links URL encoding into request construction at request boundary", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_url_encoding_request_boundary.ndjson", event_count: 4},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_url_encoding_boundary",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "url_encoding",
          role: "transform",
          apis: ["encodeURIComponent"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          object_refs: [],
          value_refs: ["string:length:12", "url_encoded:length:12"]
        },
        {
          order: 2,
          stage: "request_construction",
          role: "request",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 14,
          distance_basis: "trace_index",
          object_refs: ["network_request:sha1:req"],
          value_refs: ["target_params:X-Signature", "url_shape:feed"]
        }
      ]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_edges, [{
    from_order: 1,
    to_order: 2,
    from_stage: "url_encoding",
    to_stage: "request_construction",
    relation: "request_boundary_runtime_window",
    confidence: "low",
    refs: ["trace_distance:4~14"],
    source_refs: [],
    evidence: ["request_boundary_runtime_window"],
    boundary_basis: [
      "request_boundary_window",
      "trace_index",
      "stage_pair:url_encoding->request_construction"
    ]
  }]);
  assert.deepEqual(parameter.generation_edge_gaps, [{
    from_order: 1,
    to_order: 2,
    from_stage: "url_encoding",
    to_stage: "request_construction",
    gap: "temporal_only_edge",
    reason: "request_boundary_window_no_shared_data_ref",
    priority: "medium",
    next_actions: ["capture_object_ids_for_data_links"],
    source_refs: [],
    object_refs: ["network_request:sha1:req"],
    value_refs: ["string:length:12", "url_encoded:length:12", "url_shape:feed", "target_params:X-Signature"]
  }]);
  assert.equal(parameter.chain_quality.missing_edge_count, 0);
  assert.equal(parameter.chain_quality.temporal_only_edge_count, 1);
});

test("buildAgentAnalysis labels signature mutation to URL encoding as signature encoding boundary", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_signature_encoding_boundary.ndjson", event_count: 4},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_signature_encoding_boundary",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: [],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 5,
          distance_basis: "trace_index",
          object_refs: ["url_object:7", "search_params:8"],
          value_refs: ["target_params:X-Signature", "url_shape:feed"]
        },
        {
          order: 2,
          stage: "url_encoding",
          role: "transform",
          apis: ["encodeURIComponent"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          object_refs: [],
          value_refs: ["string:length:12", "url_encoded:length:12"]
        }
      ]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_edges, [{
    from_order: 1,
    to_order: 2,
    from_stage: "signature_mutation",
    to_stage: "url_encoding",
    relation: "signature_encoding_boundary",
    confidence: "low",
    refs: ["trace_distance:5->4"],
    source_refs: [],
    evidence: ["signature_encoding_boundary"],
    signature_encoding_basis: [
      "signature_param_to_url_encoding",
      "trace_index",
      "stage_pair:signature_mutation->url_encoding"
    ]
  }]);
  assert.deepEqual(parameter.generation_edge_gaps, [{
    from_order: 1,
    to_order: 2,
    from_stage: "signature_mutation",
    to_stage: "url_encoding",
    gap: "temporal_only_edge",
    reason: "signature_encoding_boundary_no_shared_value_ref",
    priority: "medium",
    next_actions: ["capture_object_ids_for_data_links"],
    source_refs: [],
    object_refs: ["url_object:7", "search_params:8"],
    value_refs: ["url_shape:feed", "target_params:X-Signature", "string:length:12", "url_encoded:length:12"]
  }]);
});

test("buildAgentAnalysis labels source-only string material attachment to signature params", () => {
  const sourceRef = "sha1:runtime-sdk:2-5";
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_signature_material_attachment.ndjson", event_count: 4},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_signature_attachment",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [sourceRef],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "string_transform",
          role: "transform",
          apis: ["StringAdd"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: [],
          value_refs: ["string:length:6", "string:length:1768"]
        },
        {
          order: 2,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 5,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: ["url_object:118", "search_params:119"],
          value_refs: ["target_params:X-Signature", "url_shape:feed"]
        }
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      asset_id: "sha1:runtime-sdk",
      url: "https://www.example.test/runtime-sdk.js",
      line_start: 2,
      line_end: 5,
      calls: ["StringAdd", "URLSearchParams.set"]
    }]
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_edges, [{
    from_order: 1,
    to_order: 2,
    from_stage: "string_transform",
    to_stage: "signature_mutation",
    relation: "signature_material_attachment_window",
    confidence: "low",
    refs: ["trace_distance:0~5"],
    source_refs: [sourceRef],
    evidence: ["signature_material_attachment_window", "shared_source_ref"],
    signature_attachment_basis: [
      "signature_material_to_param_attachment",
      "trace_index",
      "stage_pair:string_transform->signature_mutation"
    ]
  }]);
  assert.deepEqual(parameter.generation_edge_gaps, [{
    from_order: 1,
    to_order: 2,
    from_stage: "string_transform",
    to_stage: "signature_mutation",
    gap: "source_only_edge",
    reason: "signature_attachment_window_no_shared_value_ref",
    priority: "medium",
    next_actions: ["capture_object_ids_for_data_links"],
    source_refs: [sourceRef],
    object_refs: ["url_object:118", "search_params:119"],
    value_refs: ["string:length:6", "string:length:1768", "url_shape:feed", "target_params:X-Signature"]
  }]);
  assert.equal(parameter.chain_quality.missing_edge_count, 0);
  assert.equal(parameter.chain_quality.source_only_edge_count, 1);
});

test("buildAgentAnalysis treats post-request regexp probes as side evidence, not missing core edges", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_signed_request_probe_side_edge.ndjson", event_count: 3},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_probe_side_edge",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "signed_request",
          role: "network_emit",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          object_refs: ["network_request:sha1:req"],
          value_refs: ["target_params:X-Signature", "url_shape:feed"]
        },
        {
          order: 2,
          stage: "regexp_probe",
          role: "guard_or_probe",
          apis: ["RegExp.prototype.test"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          object_refs: ["regexp:17"],
          value_refs: ["string:length:1815"]
        }
      ]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_edges, [{
    from_order: 1,
    to_order: 2,
    from_stage: "signed_request",
    to_stage: "regexp_probe",
    relation: "side_probe_runtime_window",
    confidence: "low",
    refs: ["trace_distance:0~2"],
    source_refs: [],
    evidence: ["side_probe_runtime_window"],
    side_probe_basis: [
      "guard_or_probe_side_evidence",
      "trace_index",
      "stage_pair:signed_request->regexp_probe"
    ]
  }]);
  assert.deepEqual(parameter.generation_edge_gaps, []);
  assert.equal(parameter.chain_quality.missing_edge_count, 0);
});

test("buildAgentAnalysis labels VMP material to dispatch windows distinctly", () => {
  const sourceRef = "sha1:runtime-sdk:1-5";
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_material_dispatch.ndjson", event_count: 8},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_vmp_boundary",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [sourceRef],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "byte_buffer",
          role: "material",
          apis: ["TypedArray.buffer.get"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "after_signed_request",
          distance_to_signed_request: 10,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: ["typed_array:7", "array_buffer:8"],
          value_refs: []
        },
        {
          order: 2,
          stage: "dynamic_dispatch",
          role: "control_flow",
          apis: ["Function.prototype.call", "Array.prototype.push"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: ["state_object:9", "target:10", "arguments_list:9"],
          value_refs: ["register:9/number:1.000000", "handler_return:10/number:2.000000"]
        }
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      asset_id: "sha1:runtime-sdk",
      content_path: "assets/trace_vmp_material_dispatch/runtime-sdk.js",
      line_start: 1,
      line_end: 5,
      preview: "function dispatch(vm, bytes) { return handlers[vm.pc++](vm, bytes); }",
      source_candidate_ids: ["source_candidate_1"],
      review_entry_ids: ["review_entry_1"],
      target_params: ["X-Signature"],
      stages: ["byte_buffer", "dynamic_dispatch"]
    }]
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_edges, [{
    from_order: 1,
    to_order: 2,
    from_stage: "byte_buffer",
    to_stage: "dynamic_dispatch",
    relation: "vmp_material_dispatch_window",
    confidence: "low",
    refs: ["trace_distance:10~0"],
    source_refs: [sourceRef],
    evidence: ["vmp_material_dispatch_window", "shared_source_ref"],
    material_dispatch_basis: [
      "vmp_material_dispatch_window",
      "trace_index",
      "stage_pair:byte_buffer->dynamic_dispatch",
      "typed_array_or_buffer_to_vmp_dispatch"
    ]
  }]);
  assert.deepEqual(parameter.generation_edge_gaps, [{
    from_order: 1,
    to_order: 2,
    from_stage: "byte_buffer",
    to_stage: "dynamic_dispatch",
    gap: "nearby_runtime_only_edge",
    reason: "vmp_material_dispatch_window_no_shared_data_ref",
    priority: "medium",
    next_actions: [
      "capture_vmp_register_state_refs",
      "capture_object_ids_for_data_links"
    ],
    source_refs: [sourceRef],
    object_refs: ["typed_array:7", "array_buffer:8", "state_object:9", "target:10", "arguments_list:9"],
    value_refs: ["register:9/number:1.000000", "handler_return:10/number:2.000000"]
  }]);
  assert.equal(parameter.chain_quality.source_only_edge_count, 0);
  assert.equal(parameter.chain_quality.nearby_runtime_only_edge_count, 1);
});

test("buildAgentAnalysis prioritizes primary readiness focus over generic VMP expansion", () => {
  const sourceRef = "sha1:runtime-sdk:1-1";
  const tracedStep = (order, stage, apis, refs = {}) => ({
    order,
    stage,
    role: stage === "signature_mutation"
      ? "parameter_attachment"
      : stage === "signed_request"
        ? "network_emit"
        : stage === "input_url"
          ? "input"
          : "transform",
    apis,
    target_params: ["X-Signature"],
    param_relation: stage === "signature_mutation" || stage === "signed_request"
      ? "direct_observed"
      : "flow_target",
    relation: stage === "signed_request" ? "signed_request" : "before_signed_request",
    distance_to_signed_request: 5 - order,
    source_refs: [sourceRef],
    object_refs: refs.object_refs || [],
    value_refs: refs.value_refs || []
  });

  const analysis = buildAgentAnalysis({
    version: 1,
    trace: {path: "/tmp/xtrace/logs/trace_focus_rank.ndjson", event_count: 5},
    parameters: [{
      param: "X-Signature",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      status: "attachment_observed",
      source_refs: [sourceRef],
      generation_trace: [
        tracedStep(1, "input_url", ["URL.constructor"], {
          object_refs: ["url_object:1"],
          value_refs: ["url_shape:unsigned"]
        }),
        tracedStep(2, "dynamic_dispatch", ["Function.prototype.call"], {
          object_refs: ["target:1"]
        }),
        tracedStep(3, "integer_mixing", ["Bitwise.xor"], {
          value_refs: ["number:1.000000"]
        }),
        tracedStep(4, "signature_mutation", ["URLSearchParams.set"], {
          object_refs: ["url_object:1", "search_params:1"],
          value_refs: ["target_params:X-Signature"]
        }),
        tracedStep(5, "signed_request", ["Request.constructor"], {
          object_refs: ["url_object:1"],
          value_refs: ["target_params:X-Signature"]
        })
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      content_path: "assets/trace_focus_rank/runtime-sdk.js",
      line_start: 1,
      line_end: 1,
      preview: "function sign(url) { url.searchParams.set('X-Signature', mix(url)); }"
    }]
  });

  assert.equal(
    analysis.parameters[0].analysis_readiness.summary.primary_next_action,
    "capture_vmp_register_state_refs"
  );
  assert.equal(analysis.next_capture_focus[0].action, "capture_vmp_register_state_refs");
  assert.equal(analysis.next_capture_focus[1].action, "expand_vmp_runtime_hooks");
});

test("buildAgentAnalysis marks reversed VMP dispatch and integer stages as nearby runtime evidence", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_nearby_edges.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "control_flow",
          apis: ["Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          object_refs: ["target:998861"],
          value_refs: []
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.and", "Shift.left"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 39,
          distance_basis: "trace_index",
          object_refs: [],
          value_refs: []
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: [],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 8,
          distance_basis: "trace_index",
          object_refs: ["url_object:254"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: []
  });

  const [parameter] = analysis.parameters;
  assert.deepEqual(parameter.generation_edges[0], {
    from_order: 1,
    to_order: 2,
    from_stage: "dynamic_dispatch",
    to_stage: "integer_mixing",
    relation: "vmp_nearby_runtime_window",
    confidence: "low",
    refs: ["trace_distance:4~39"],
    source_refs: [],
    evidence: ["vmp_nearby_runtime_window"],
    nearby_basis: [
      "same_pre_request_window",
      "trace_index",
      "stage_pair:dynamic_dispatch->integer_mixing"
    ]
  });
  assert.deepEqual(parameter.generation_edge_gaps[0], {
    from_order: 1,
    to_order: 2,
    from_stage: "dynamic_dispatch",
    to_stage: "integer_mixing",
    gap: "nearby_runtime_only_edge",
    reason: "nearby_vmp_runtime_window_no_shared_data_ref",
    priority: "medium",
    next_actions: [
      "capture_vmp_register_state_refs",
      "capture_object_ids_for_data_links"
    ],
    source_refs: [],
    object_refs: ["target:998861"],
    value_refs: []
  });
  assert.equal(parameter.chain_quality.nearby_runtime_only_edge_count, 1);
  const registerFocus = analysis.next_capture_focus.find((focus) =>
    focus.action === "capture_vmp_register_state_refs");
  assert.ok(registerFocus);
  assert.deepEqual(registerFocus.gaps, ["nearby_runtime_only_edge"]);
  assert.ok(registerFocus.hook_targets.includes("vmp.handler.return_ref"));
  assert.ok(registerFocus.hook_targets.includes("Bitwise.input_ref"));
});

test("buildAgentAnalysis carries observed buffer refs into data-link capture focus", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_buffer_focus.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      inferred_data_links: [{
        from: "byte_buffer",
        to: "integer_mixing",
        confidence: "medium",
        basis: ["ordered_runtime_window"],
        refs: ["array_buffer:20"]
      }],
      generation_trace: [
        {
          order: 1,
          stage: "byte_buffer",
          role: "material",
          apis: ["DataView.getUint32"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 90,
          distance_basis: "trace_index",
          object_refs: ["data_view:21", "array_buffer:20"],
          value_refs: []
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Math.imul"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 40,
          distance_basis: "trace_index",
          object_refs: [],
          value_refs: ["number:456.000000"]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          object_refs: ["url_object:7"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: []
  });

  const focus = analysis.next_capture_focus.find((item) =>
    item.action === "capture_object_ids_for_data_links");
  assert.ok(focus);
  assert.ok(focus.gaps.includes("temporal_only_edge"));
  assert.ok(focus.object_refs.includes("array_buffer:20"));
  assert.ok(focus.object_refs.includes("data_view:21"));
  const statuses = new Map(focus.hook_target_statuses.map((item) => [item.target, item]));
  assert.equal(statuses.get("value_ref.buffer").status, "observed_in_focus_refs");
  assert.deepEqual(statuses.get("value_ref.buffer").observed_refs, [
    "data_view:21",
    "array_buffer:20"
  ]);
});

test("buildAgentAnalysis recognizes VMP state refs in register capture focus", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_state_focus.ndjson", event_count: 4},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 40,
          distance_basis: "trace_index",
          object_refs: [
            "state_object:1001",
            "target:2002",
            "this:1001",
            "arguments_list:3003"
          ],
          value_refs: [
            "register:1001/3003",
            "handler_return:2002/3003"
          ]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 20,
          distance_basis: "trace_index",
          object_refs: [],
          value_refs: [
            "register:1001/3003",
            "number:123.000000"
          ]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          object_refs: ["url_object:7"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: []
  });

  const focus = analysis.next_capture_focus.find((item) =>
    item.action === "capture_vmp_register_state_refs");
  assert.ok(focus);
  const statuses = new Map(focus.hook_target_statuses.map((item) => [item.target, item]));
  assert.equal(statuses.get("vmp.state_object_id").status, "observed_in_focus_refs");
  assert.deepEqual(statuses.get("vmp.state_object_id").observed_refs, ["state_object:1001"]);
  assert.equal(statuses.get("vmp.register_ref").status, "observed_in_focus_refs");
  assert.deepEqual(statuses.get("vmp.register_ref").observed_refs, ["register:1001/3003"]);
  assert.equal(statuses.get("vmp.handler.return_ref").status, "observed_in_focus_refs");
  assert.deepEqual(statuses.get("vmp.handler.return_ref").observed_refs, ["handler_return:2002/3003"]);
  assert.equal(statuses.get("Bitwise.input_ref").status, "observed_in_focus_refs");
  assert.deepEqual(statuses.get("Bitwise.input_ref").observed_refs, [
    "register:1001/3003",
    "number:123.000000"
  ]);
});

test("buildAgentAnalysis keeps VMP state refs when focus refs are dense", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_dense_state_focus.ndjson", event_count: 4},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 40,
          distance_basis: "trace_index",
          object_refs: [
            "url_object:1",
            "typed_array:2",
            "array_buffer:3",
            "data_view:4",
            "subject:5",
            "target:6",
            "arguments_list:7",
            "subject:8",
            "state_object:9"
          ],
          value_refs: [
            "url_shape:abc",
            "target_params:X-Signature",
            "register:9/7",
            "handler_return:6/7"
          ]
        },
        {
          order: 2,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          object_refs: ["url_object:1"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: []
  });

  const focus = analysis.next_capture_focus.find((item) =>
    item.action === "capture_vmp_register_state_refs");
  assert.ok(focus);
  assert.ok(focus.object_refs.includes("state_object:9"));
  const statuses = new Map(focus.hook_target_statuses.map((item) => [item.target, item]));
  assert.equal(statuses.get("vmp.state_object_id").status, "observed_in_focus_refs");
  assert.deepEqual(statuses.get("vmp.state_object_id").observed_refs, ["state_object:9"]);
});

test("buildAgentAnalysis summarizes VMP handler state model for parameter traces", () => {
  const sourceRef = "sha1:runtime-sdk:10-18";
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_state_model.ndjson", event_count: 6},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [sourceRef],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Reflect.apply", "Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 56,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          source_calls: ["Reflect.apply"],
          source_signals: [
            "vmp_bytecode_array",
            "vmp_handler_table",
            "vmp_dispatch_loop",
            "vmp_dynamic_dispatch"
          ],
          object_refs: [
            "state_object:105",
            "target:102",
            "arguments_list:103"
          ],
          value_refs: [
            "register:105/103",
            "handler_return:102/103"
          ]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor", "Math.imul"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 28,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          source_calls: ["Math.imul"],
          source_signals: ["vmp_dynamic_dispatch"],
          object_refs: [],
          value_refs: [
            "register:105/103",
            "number:456.000000",
            "number:16777619.000000"
          ]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          object_refs: ["search_params:7"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      asset_id: "sha1:runtime-sdk",
      content_path: "/tmp/xtrace/assets/runtime-sdk.js",
      line_start: 10,
      line_end: 18,
      preview: "const bytecode=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]; const handlers=[function(vm){vm.reg[bytecode[vm.pc++]]=vm.mixed},function(vm){vm.mixed=Math.imul(vm.mixed ^ vm.reg[bytecode[vm.pc++]],16777619)}]; while(vm.pc < bytecode.length){ Reflect.apply(handlers[bytecode[vm.pc++]], null, [vm]); }",
      target_params: ["X-Signature"],
      stages: ["dynamic_dispatch", "integer_mixing"]
    }]
  });

  const parameter = analysis.parameters[0];
  assert.equal(parameter.vmp_state_model.status, "observed");
  assert.equal(parameter.vmp_state_model.handler_table, "observed_source_and_runtime");
  assert.equal(parameter.vmp_state_model.bytecode_pc, "observed_source");
  assert.equal(parameter.vmp_state_model.dispatch_boundary, "observed_runtime");
  assert.deepEqual(parameter.vmp_state_model.state_refs, ["state_object:105"]);
  assert.deepEqual(parameter.vmp_state_model.register_refs, ["register:105/103"]);
  assert.deepEqual(parameter.vmp_state_model.handler_return_refs, ["handler_return:102/103"]);
  assert.equal(parameter.vmp_state_model.linkage.register_to_integer_mixing, "observed");
  assert.ok(parameter.vmp_state_model.source_signals.includes("vmp_handler_table"));
  assert.ok(parameter.vmp_state_model.source_signals.includes("vmp_bytecode_array"));
  assert.ok(parameter.vmp_state_model.runtime_apis.includes("Reflect.apply"));
  assert.deepEqual(parameter.vmp_state_model.next_actions, ["review_vmp_state_model"]);
  assert.match(renderAgentAnalysisMarkdown(analysis), /vmp_state_model=observed handler_table=observed_source_and_runtime bytecode_pc=observed_source/);
});

test("buildAgentAnalysis promotes VMP state gaps onto parameter actions", () => {
  const sourceRef = "sha1:runtime-sdk:44-50";
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_state_gap.ndjson", event_count: 4},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      source_refs: [sourceRef],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 20,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          source_calls: ["Function.prototype.call.call"],
          source_signals: ["vmp_handler_table", "vmp_dynamic_dispatch"],
          object_refs: ["state_object:42"],
          value_refs: ["register:42/7", "handler_return:9/7"]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 10,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: [],
          value_refs: ["number:123.000000"]
        },
        {
          order: 3,
          stage: "signed_request",
          role: "output",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          object_refs: ["network_request:sha1:request"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      asset_id: "sha1:runtime-sdk",
      content_path: "/tmp/xtrace/assets/runtime-sdk.js",
      line_start: 44,
      line_end: 50,
      preview: "const handlers=[function(vm){return vm.reg[vm.pc++]},function(vm){return vm.seed^7}]; Function.prototype.call.call(handlers[0],null,vm);",
      target_params: ["X-Signature"],
      stages: ["dynamic_dispatch", "integer_mixing"]
    }]
  });

  const parameter = analysis.parameters[0];
  assert.ok(parameter.vmp_state_model.unresolved_gaps.includes("vmp_register_to_mixing_link_not_observed"));
  assert.ok(parameter.unresolved_gaps.includes("vmp_register_to_mixing_link_not_observed"));
  assert.ok(parameter.recommended_next_actions.includes("capture_vmp_register_state_refs"));
  assert.ok(parameter.candidate_generation_summary.unresolved_gaps.includes("vmp_register_to_mixing_link_not_observed"));
  assert.ok(parameter.candidate_generation_summary.next_actions.includes("capture_vmp_register_state_refs"));
});

test("buildAgentAnalysis infers VMP handler table from compact source preview", () => {
  const sourceRef = "sha1:runtime-sdk:17-21";
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_compact_state_model.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [sourceRef],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Reflect.apply", "Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 42,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          source_calls: ["Reflect.apply", "Function.prototype.call.call"],
          source_signals: [],
          object_refs: ["state_object:869339", "target:265007", "arguments_list:719246"],
          value_refs: ["register:869339/719246", "handler_return:265007/719246"]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor", "Math.imul"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 20,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: [],
          value_refs: ["register:869339/719246", "number:16777619.000000"]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          object_refs: ["search_params:7"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      asset_id: "sha1:runtime-sdk",
      content_path: "/tmp/xtrace/assets/runtime-sdk.js",
      line_start: 17,
      line_end: 21,
      preview: "for (; offset + 4 <= bytes.byteLength; offset += 4) { vm.offset = offset; const word = Reflect.apply(handlers[0], null, [vm]); Function.prototype.call.call(handlers[1], null, vm, word); Function.prototype.apply.call(function applyProbe(state, value){ return handlers[state.opcode & 3](state, value); }, null, [vm, word]); vm.reg[vm.pc++] = word; }",
      target_params: ["X-Signature"],
      stages: ["dynamic_dispatch", "integer_mixing"]
    }]
  });

  const model = analysis.parameters[0].vmp_state_model;
  assert.equal(model.status, "observed");
  assert.equal(model.handler_table, "observed_source_and_runtime");
  assert.equal(model.bytecode_pc, "observed_source");
  assert.ok(model.source_signals.includes("vmp_handler_table"));
  assert.ok(model.source_signals.includes("vmp_dispatch_loop"));
  assert.ok(model.source_signals.includes("vmp_register_state"));
  assert.deepEqual(model.unresolved_gaps, []);
});

test("buildAgentAnalysis distinguishes inferred VMP register to mixing links", () => {
  const sourceRef = "sha1:runtime-sdk:30-36";
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_inferred_register_mix.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [sourceRef],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Reflect.apply"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 55,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: ["state_object:5", "target:7", "arguments_list:9"],
          value_refs: ["register:5/9", "handler_return:7/9"]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor", "Math.imul"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 22,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: [],
          value_refs: ["number:2166136261.000000", "number:16777619.000000"]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          object_refs: ["search_params:7"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      asset_id: "sha1:runtime-sdk",
      content_path: "/tmp/xtrace/assets/runtime-sdk.js",
      line_start: 30,
      line_end: 36,
      preview: "for (; offset + 4 <= bytes.byteLength; offset += 4) { vm.offset = offset; const word = Reflect.apply(handlers[0], null, [vm]); Function.prototype.call.call(handlers[1], null, vm, word); vm.reg[vm.pc++] = Math.imul(word ^ vm.reg[vm.pc], 16777619); }",
      target_params: ["X-Signature"],
      stages: ["dynamic_dispatch", "integer_mixing"]
    }]
  });

  const model = analysis.parameters[0].vmp_state_model;
  assert.equal(model.linkage.register_to_integer_mixing, "inferred_source_window");
  assert.equal(model.linkage.handler_return_to_integer_mixing, "via_inferred_register_state");
  assert.deepEqual(model.linkage.register_to_integer_mixing_refs, ["register:5/9"]);
  assert.deepEqual(model.linkage.register_to_integer_mixing_source_refs, [sourceRef]);
  assert.deepEqual(model.unresolved_gaps, ["vmp_register_value_ref_to_mixing_not_observed"]);
  assert.deepEqual(model.next_actions, ["capture_vmp_register_state_refs"]);
});

test("buildAgentAnalysis treats VMP register refs on integer mixing as observed inputs", () => {
  const sourceRef = "sha1:runtime-sdk:70-76";
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_mixing_input_refs.ndjson", event_count: 8},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "medium",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [sourceRef],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Function.prototype.apply", "Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 30,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          source_signals: ["vmp_dynamic_dispatch"],
          object_refs: ["state_object:278106", "target:309563"],
          value_refs: [
            "register:278106/278106",
            "handler_return:309563/278106"
          ]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.and", "Shift.left", "Shift.unsignedRight"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 12,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: [],
          value_refs: [
            "register:string:length:249/number:158.000000",
            "handler_arg:302832/number:158.000000",
            "number:158.000000"
          ]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          object_refs: ["search_params:7"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      asset_id: "sha1:runtime-sdk",
      content_path: "/tmp/xtrace/assets/runtime-sdk.js",
      line_start: 70,
      line_end: 76,
      preview: "return (state.buf[i] & 158) << 8 >>> 0; Function.prototype.apply.call(handler, null, [state]);",
      target_params: ["X-Signature"],
      stages: ["dynamic_dispatch", "integer_mixing"]
    }]
  });

  const model = analysis.parameters[0].vmp_state_model;
  assert.equal(model.linkage.register_to_integer_mixing, "observed_mixing_input");
  assert.equal(model.linkage.handler_arg_to_integer_mixing, "observed");
  assert.deepEqual(model.linkage.register_to_integer_mixing_refs, [
    "register:string:length:249/number:158.000000"
  ]);
  assert.deepEqual(model.linkage.handler_arg_to_integer_mixing_refs, [
    "handler_arg:302832/number:158.000000"
  ]);
  assert.ok(model.handler_arg_refs.includes("handler_arg:302832/number:158.000000"));
  assert.ok(!model.unresolved_gaps.includes("vmp_register_to_mixing_link_not_observed"));
});

test("buildAgentAnalysis hydrates source evidence from char-offset asset refs", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-source-offset-"));
  const traceDir = path.join(tempDir, "logs");
  const assetDir = path.join(traceDir, "assets", "trace_source_offset");
  fs.mkdirSync(assetDir, {recursive: true});
  const tracePath = path.join(traceDir, "trace_source_offset.ndjson");
  fs.writeFileSync(tracePath, "", "utf8");
  const sourceAssetPath = path.join(assetDir, "sha1_runtime-sdk.js");
  const vmpSnippet = [
    "var bytecode=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26];",
    "var handlers=[function(vm){vm.reg[bytecode[vm.pc++]]=vm.seed},function(vm){return handlers[bytecode[vm.pc++]].call(null,vm)}];",
    "while(vm.pc<bytecode.length){Reflect.apply(handlers[bytecode[vm.pc++]],null,[vm])}"
  ].join("");
  const source = `${"x".repeat(900)}${vmpSnippet}${"y".repeat(900)}`;
  fs.writeFileSync(sourceAssetPath, source, "utf8");
  const charOffset = source.indexOf("var handlers");
  const sourceRef = `sha1:runtime-sdk:1-1@${charOffset}-${charOffset + vmpSnippet.length}`;
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: tracePath, event_count: 6},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      source_refs: [sourceRef],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Reflect.apply", "Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 30,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: ["state_object:105", "target:102"],
          value_refs: ["register:105/103", "handler_return:102/103"]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 12,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          value_refs: ["register:105/103", "number:16777619.000000"]
        }
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      asset_id: "sha1:runtime-sdk",
      content_path: path.relative(traceDir, sourceAssetPath),
      line_start: 1,
      line_end: 1,
      source_candidate_ids: ["source_candidate_1"],
      review_entry_ids: ["review_entry_1"],
      target_params: ["X-Signature"],
      stages: ["dynamic_dispatch", "integer_mixing"]
    }]
  });

  const parameter = analysis.parameters[0];
  assert.match(parameter.source_evidence[0].preview, /bytecode=\[1,2,3/);
  assert.match(parameter.source_evidence[0].preview, /handlers=\[function/);
  assert.ok(parameter.vmp_state_model.source_signals.includes("vmp_bytecode_array"));
  assert.ok(parameter.vmp_state_model.source_signals.includes("vmp_handler_table"));
  assert.equal(parameter.vmp_state_model.handler_table, "observed_source_and_runtime");
  assert.equal(parameter.vmp_state_model.bytecode_pc, "observed_source");
  assert.ok(!parameter.vmp_state_model.unresolved_gaps.includes("vmp_handler_table_source_not_observed"));
  assert.ok(!parameter.vmp_state_model.unresolved_gaps.includes("vmp_bytecode_pc_source_not_observed"));
});

test("buildAgentAnalysis exposes observed VMP state as agent-readable generation evidence", () => {
  const sourceRef = "sha1:runtime-sdk:12-18";
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_vmp_state_trace.ndjson", event_count: 7},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      source_refs: [sourceRef],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Reflect.apply", "Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 30,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: ["state_object:105", "target:102", "arguments_list:103"],
          value_refs: ["register:105/103", "handler_return:102/103"]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor", "Shift.unsignedRight"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 18,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          value_refs: [
            "register:string:length:249/number:158.000000",
            "handler_arg:302832/number:158.000000",
            "number:158.000000"
          ]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: ["search_params:7"],
          value_refs: ["target_params:X-Signature"]
        },
        {
          order: 4,
          stage: "signed_request",
          role: "output",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          source_refs: [sourceRef],
          object_refs: ["network_request:sha1:request"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: sourceRef,
      asset_id: "sha1:runtime-sdk",
      content_path: "/tmp/xtrace/assets/runtime-sdk.js",
      line_start: 12,
      line_end: 18,
      preview: "var bytecode=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]; var handlers=[function(vm){vm.reg[bytecode[vm.pc++]]=vm.seed},function(vm){return handlers[bytecode[vm.pc++]].call(null,vm)}]; while(vm.pc<bytecode.length){Reflect.apply(handlers[bytecode[vm.pc++]],null,[vm])}",
      target_params: ["X-Signature"],
      stages: ["dynamic_dispatch", "integer_mixing", "signature_mutation", "signed_request"]
    }]
  });

  const parameter = analysis.parameters[0];
  assert.equal(parameter.vmp_state_model.status, "observed");
  assert.equal(parameter.vmp_state_trace.status, "observed");
  assert.deepEqual(parameter.vmp_state_trace.stage_chain, [
    "dynamic_dispatch",
    "integer_mixing",
    "signature_mutation",
    "signed_request"
  ]);
  assert.ok(parameter.vmp_state_trace.evidence_refs.includes("state_object:105"));
  assert.ok(parameter.vmp_state_trace.evidence_refs.includes("handler_arg:302832/number:158.000000"));
  assert.equal(parameter.generation_hypothesis.status, "observed_vmp_state_runtime_chain");
  assert.equal(parameter.generation_hypothesis.pre_signature_pattern_observed, true);
  assert.equal(parameter.generation_hypothesis.vmp_state_trace.status, "observed");
  const readiness = new Map(parameter.analysis_readiness.checklist.map((item) => [item.item, item]));
  assert.equal(readiness.get("vmp_operation_pattern_observed").status, "pass");
  assert.ok(!readiness.get("vmp_operation_pattern_observed").gaps.includes("vmp_pattern_not_ranked"));
});

test("buildAgentAnalysis keeps search params refs in data-link capture focus", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_search_params_focus.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "byte_buffer",
          role: "material",
          apis: ["DataView.getUint32"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 90,
          distance_basis: "trace_index",
          object_refs: [
            "typed_array:1",
            "array_buffer:1",
            "data_view:1",
            "subject:1",
            "target:1",
            "arguments_list:1"
          ],
          value_refs: []
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Math.imul"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 40,
          distance_basis: "trace_index",
          object_refs: ["subject:2", "target:2"],
          value_refs: ["number:456.000000"]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          object_refs: ["url_object:7", "search_params:7"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: []
  });

  const focus = analysis.next_capture_focus.find((item) =>
    item.action === "capture_object_ids_for_data_links");
  assert.ok(focus);
  assert.ok(focus.object_refs.includes("search_params:7"));
  const statuses = new Map(focus.hook_target_statuses.map((item) => [item.target, item]));
  assert.equal(statuses.get("object_ref.search_params").status, "observed_in_focus_refs");
  assert.deepEqual(statuses.get("object_ref.search_params").observed_refs, ["search_params:7"]);
});

test("buildAgentAnalysis annotates generation path step evidence and capture gaps", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_step_gaps.ndjson", event_count: 5},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      confidence: "high",
      evidence_status: "observed_only",
      readiness: "partial",
      source_refs: ["sha1:sdk:2-4"],
      evidence_gaps: ["signature_mutation_not_observed"],
      generation_trace: [
        {
          order: 1,
          stage: "request_construction",
          role: "input",
          apis: ["XMLHttpRequest.open"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 4,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:2-4"],
          object_refs: ["xhr:7"],
          value_refs: ["url_shape:feed"]
        },
        {
          order: 2,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: [],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 3,
          distance_basis: "trace_index",
          source_refs: ["sha1:sdk:2-4"],
          object_refs: ["target:11"],
          value_refs: []
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: [],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 1,
          distance_basis: "trace_index",
          source_refs: [],
          object_refs: ["url_object:9"],
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [{
      ref: "sha1:sdk:2-4",
      asset_id: "sha1:sdk",
      content_path: "assets/trace_step_gaps/runtime-sdk.js",
      line_start: 2,
      line_end: 4,
      source_candidate_ids: ["source_candidate_1"],
      review_entry_ids: ["review_entry_1"],
      target_params: ["X-Signature"],
      stages: ["request_construction", "dynamic_dispatch"]
    }]
  });

  assert.deepEqual(analysis.parameters[0].generation_path.map((step) => ({
    stage: step.stage,
    evidence_flags: step.evidence_flags,
    evidence_gaps: step.evidence_gaps,
    recommended_next_actions: step.recommended_next_actions
  })), [
    {
      stage: "request_construction",
      evidence_flags: [
        "runtime_api_observed",
        "source_context_observed",
        "data_refs_observed",
        "pre_request_observed"
      ],
      evidence_gaps: [],
      recommended_next_actions: ["review_step_source_context"]
    },
    {
      stage: "dynamic_dispatch",
      evidence_flags: [
        "source_context_observed",
        "data_refs_observed",
        "pre_request_observed"
      ],
      evidence_gaps: ["runtime_api_not_observed"],
      recommended_next_actions: ["expand_vmp_runtime_hooks"]
    },
    {
      stage: "signature_mutation",
      evidence_flags: [
        "data_refs_observed",
        "pre_request_observed",
        "target_param_observed"
      ],
      evidence_gaps: [
        "runtime_api_not_observed",
        "source_context_not_available"
      ],
      recommended_next_actions: [
        "capture_url_search_params_mutation_or_header_set",
        "expand_vmp_runtime_hooks",
        "capture_or_retrieve_script_asset"
      ]
    }
  ]);
  const focusByAction = new Map(analysis.next_capture_focus.map((focus) => [focus.action, focus]));
  const mutationFocus = focusByAction.get("capture_url_search_params_mutation_or_header_set");
  assert.equal(mutationFocus.priority, "high");
  assert.deepEqual(mutationFocus.gaps, [
    "runtime_api_not_observed",
    "source_context_not_available"
  ]);
  assert.ok(mutationFocus.hook_targets.includes("URLSearchParams.set"));
  assert.ok(mutationFocus.hook_targets.includes("XMLHttpRequest.setRequestHeader"));

  const vmpFocus = focusByAction.get("expand_vmp_runtime_hooks");
  assert.equal(vmpFocus.priority, "high");
  assert.ok(vmpFocus.stages.includes("dynamic_dispatch"));
  assert.ok(vmpFocus.hook_targets.includes("Reflect.apply"));

  const sourceFocus = focusByAction.get("capture_or_retrieve_script_asset");
  assert.equal(sourceFocus.priority, "medium");
  assert.deepEqual(sourceFocus.gaps, ["source_context_not_available"]);
  assert.ok(!sourceFocus.gaps.includes("missing_generation_edge"));

  const dataLinkFocus = focusByAction.get("capture_object_ids_for_data_links");
  assert.equal(dataLinkFocus.priority, "medium");
  assert.ok(dataLinkFocus.gaps.includes("temporal_only_edge"));
  assert.ok(dataLinkFocus.params.includes("X-Signature"));
  assert.ok(dataLinkFocus.object_refs.includes("xhr:7"));
  assert.ok(dataLinkFocus.value_refs.includes("target_params:X-Signature"));
  const dataLinkHookStatus = new Map(dataLinkFocus.hook_target_statuses.map((item) => [item.target, item.status]));
  assert.equal(dataLinkHookStatus.get("object_ref.url_object"), "observed_in_focus_refs");
  assert.equal(dataLinkHookStatus.get("value_ref.url_shape"), "observed_in_focus_refs");
  assert.equal(dataLinkHookStatus.get("object_ref.search_params"), "missing");
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /ref_gaps=request_construction->dynamic_dispatch:temporal_only_edge:object_ref\.url_object\|value_ref\.url_shape\|vmp\.state_object_id/
  );
  assert.deepEqual(dataLinkFocus.ref_gap_plan.map((entry) => ({
    param: entry.param,
    from_stage: entry.from_stage,
    to_stage: entry.to_stage,
    gap: entry.gap,
    required_link: entry.required_link,
    expected_ref_types: entry.expected_ref_types,
    observed_refs: entry.observed_refs
  })), [
    {
      param: "X-Signature",
      from_stage: "request_construction",
      to_stage: "dynamic_dispatch",
      gap: "temporal_only_edge",
      required_link: "shared_runtime_ref",
      expected_ref_types: [
        "object_ref.url_object",
        "value_ref.url_shape",
        "vmp.state_object_id",
        "vmp.register_ref",
        "vmp.handler.return_ref"
      ],
      observed_refs: {
        source_refs: ["sha1:sdk:2-4"],
        object_refs: ["xhr:7", "target:11"],
        value_refs: ["url_shape:feed"]
      }
    },
    {
      param: "X-Signature",
      from_stage: "dynamic_dispatch",
      to_stage: "signature_mutation",
      gap: "temporal_only_edge",
      required_link: "shared_runtime_ref",
      expected_ref_types: [
        "vmp.state_object_id",
        "vmp.register_ref",
        "vmp.handler.return_ref",
        "object_ref.url_object",
        "object_ref.search_params",
        "value_ref.url_shape",
        "URLSearchParams.toString.result_ref"
      ],
      observed_refs: {
        source_refs: ["sha1:sdk:2-4"],
        object_refs: ["target:11", "url_object:9"],
        value_refs: ["target_params:X-Signature"]
      }
    }
  ]);
});

test("readTraceEvents parses traces in bounded string chunks", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-report-chunked-"));
  const tracePath = path.join(dir, "trace_large.ndjson");
  const events = [
    {seq: 1, category: "reverse", api: "URL.constructor", args: [{url: "https://example.test/path?alpha=1"}]},
    {seq: 2, category: "reverse", api: "DataView.getUint32", args: [{byte_offset: 4, result: 305419896}]},
    {seq: 3, category: "network", api: "Request.constructor", args: [{url: "https://example.test/path?alpha=1&X-Signature=secret"}]}
  ];
  fs.writeFileSync(tracePath, events.map((event) => JSON.stringify(event)).join("\n") + "\n", "utf8");

  const originalToString = Buffer.prototype.toString;
  let largestStringBuffer = 0;
  Buffer.prototype.toString = function patchedToString(...args) {
    largestStringBuffer = Math.max(largestStringBuffer, this.length);
    if (this.length > 16) throw new Error(`chunk too large: ${this.length}`);
    return originalToString.apply(this, args);
  };
  try {
    const parsed = readTraceEvents(tracePath, {maxBytes: 4096, chunkBytes: 16});
    assert.deepEqual(parsed.map((event) => event.seq), [1, 2, 3]);
    assert.deepEqual(parsed.map((event) => event._trace_index), [0, 1, 2]);
    assert.deepEqual(parsed.map((event) => event._file_index), [0, 1, 2]);
    assert.ok(largestStringBuffer <= 16);
  } finally {
    Buffer.prototype.toString = originalToString;
  }
});

test("readTargetedTraceEvents keeps signature windows and correlated browser requests", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-targeted-"));
  const tracePath = path.join(dir, "trace_targeted.ndjson");
  const rows = [
    {seq: 1, api: "TextEncoder.encode", args: [{input: "noise-before"}]},
    {seq: 2, api: "Bitwise.xor", args: [{left: 1, right: 2, result: 3}]},
    {
      seq: 3,
      api: "Request.constructor",
      args: [{
        method: "GET",
        url: "https://www.example.test/api/feed?cursor=1&X-Signature=abc",
        network_correlation_key: "sha1:target"
      }]
    },
    {seq: 4, api: "fetch", args: [{url: "https://www.example.test/api/feed?cursor=1&X-Signature=abc"}]},
    {seq: 5, api: "TextEncoder.encode", args: [{input: "noise-after"}]},
    {
      seq: 6,
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://www.example.test/api/feed?cursor=1",
        network_correlation_key: "sha1:target"
      }]
    },
    {
      seq: 7,
      api: "BrowserNetwork.request",
      args: [{
        method: "GET",
        url: "https://www.example.test/api/other",
        network_correlation_key: "sha1:other"
      }]
    }
  ];
  fs.writeFileSync(tracePath, rows.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");

  const events = readTargetedTraceEvents(tracePath, {windowBefore: 1, windowAfter: 0});

  assert.deepEqual(events.map((event) => event.seq), [2, 3, 4, 6]);
  assert.deepEqual(events.map((event) => event._trace_index), [1, 2, 3, 5]);

  const report = buildReportForTrace(tracePath, {
    targetedSignatureOnly: true,
    windowBefore: 1,
    windowAfter: 0,
    retrieveExternalScripts: false
  });
  assert.equal(report.trace.event_count, 4);
  assert.ok(report.signature.event_count >= 1);
});

test("readTargetedTraceEvents skips JSON parsing for irrelevant non-target lines", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-targeted-parse-skip-"));
  const tracePath = path.join(dir, "trace_targeted_parse_skip.ndjson");
  const rows = [];
  for (let index = 1; index <= 1000; index += 1) {
    rows.push({
      seq: index,
      api: "Performance.now",
      args: [{padding: `noise-${index}`}]
    });
  }
  rows.splice(500, 0,
    {seq: 2001, api: "Bitwise.xor", args: [{left: 1, right: 2, result: 3}]},
    {
      seq: 2002,
      api: "Request.constructor",
      args: [{
        url: "https://www.example.test/api/feed?X-Signature=abc",
        network_correlation_key: "sha1:target"
      }]
    },
    {
      seq: 2003,
      api: "BrowserNetwork.request",
      args: [{
        url: "https://www.example.test/api/feed",
        network_correlation_key: "sha1:target"
      }]
    }
  );
  fs.writeFileSync(tracePath, rows.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");

  const originalParse = JSON.parse;
  let parseCount = 0;
  JSON.parse = function countedParse(...args) {
    parseCount += 1;
    return originalParse.apply(this, args);
  };
  try {
    const events = readTargetedTraceEvents(tracePath, {windowBefore: 1, windowAfter: 0});
    assert.deepEqual(events.map((event) => event.seq), [2001, 2002, 2003]);
    assert.ok(parseCount < 50, `expected targeted reader to avoid full parse, saw ${parseCount}`);
  } finally {
    JSON.parse = originalParse;
  }
});

test("readTargetedTraceEvents avoids linear window scans per trace line", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-targeted-window-scan-"));
  const tracePath = path.join(dir, "trace_targeted_window_scan.ndjson");
  const rows = [];
  for (let index = 1; index <= 20; index += 1) {
    rows.push({
      seq: index,
      api: "Request.constructor",
      args: [{url: `https://www.example.test/api/feed?cursor=${index}&X-Signature=sig-${index}`}]
    });
    rows.push({
      seq: 1000 + index,
      api: "Performance.now",
      args: [{padding: `noise-${index}`}]
    });
  }
  fs.writeFileSync(tracePath, rows.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");

  const originalSome = Array.prototype.some;
  Array.prototype.some = function patchedSome(...args) {
    if (this.length && this[0] && typeof this[0] === "object" &&
        Object.prototype.hasOwnProperty.call(this[0], "start") &&
        Object.prototype.hasOwnProperty.call(this[0], "end")) {
      throw new Error("targeted reader should not linearly scan windows for each trace line");
    }
    return originalSome.apply(this, args);
  };
  try {
    const events = readTargetedTraceEvents(tracePath, {windowBefore: 0, windowAfter: 0});
    assert.equal(events.filter((event) => event.api === "Request.constructor").length, 20);
  } finally {
    Array.prototype.some = originalSome;
  }
});

test("buildLocalReport reuses URL extraction while matching repeated signature anchors", () => {
  const events = [];
  for (let index = 0; index < 80; index += 1) {
    events.push({
      seq: index + 1,
      api: "URL.constructor",
      args: [{url: `https://www.example.test/api/feed?cursor=${index}&region=US`}]
    });
  }
  for (let index = 0; index < 20; index += 1) {
    events.push({
      seq: 1000 + index,
      api: "Request.constructor",
      args: [{url: `https://www.example.test/api/feed?cursor=${index}&region=US&X-Signature=sig-${index}`}]
    });
  }

  const OriginalURL = global.URL;
  let urlParseCount = 0;
  global.URL = class CountingURL extends OriginalURL {
    constructor(...args) {
      urlParseCount += 1;
      super(...args);
    }
  };
  try {
    const report = buildLocalReport({
      tracePath: "/tmp/xtrace/logs/trace_repeated_signature_anchors.ndjson",
      events,
      assets: []
    });
    assert.equal(report.signature.event_count, 20);
    assert.ok(urlParseCount < 800, `expected bounded cached URL extraction, saw ${urlParseCount}`);
  } finally {
    global.URL = OriginalURL;
  }
});

test("buildLocalReport avoids quadratic scalar-chain prefix scans", () => {
  const events = [];
  let previousRef = "number:1.000000";
  for (let index = 0; index < 40; index += 1) {
    const resultRef = `number:${index + 2}.000000`;
    events.push({
      seq: index + 1,
      api: index % 3 === 0 ? "Bitwise.xor" : index % 3 === 1 ? "Math.imul" : "Shift.unsignedRight",
      args: [{
        left_ref: previousRef,
        right_ref: `number:${16777619 + index}.000000`,
        result_ref: resultRef
      }]
    });
    previousRef = resultRef;
  }

  const originalSome = Array.prototype.some;
  Array.prototype.some = function patchedSome(...args) {
    if (this.length && this[0] && Array.isArray(this[0].steps) &&
        Object.prototype.hasOwnProperty.call(this[0], "updated_at")) {
      throw new Error("scalar chains should not use quadratic candidate.some prefix scans");
    }
    return originalSome.apply(this, args);
  };
  try {
    const report = buildLocalReport({
      tracePath: "/tmp/xtrace/logs/trace_scalar_prefix_scan.ndjson",
      events,
      assets: []
    });
    assert.ok(report.signature.agent_evidence_pack.vmp_scalar_ref_chains.length >= 1);
  } finally {
    Array.prototype.some = originalSome;
  }
});

test("generateReportForTrace scans beyond the normal byte cap for late signature anchors", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-report-late-signature-"));
  const tracePath = path.join(dir, "trace_late_signature.ndjson");
  const rows = [];
  for (let index = 1; index <= 200; index += 1) {
    rows.push({
      seq: index,
      api: "Bitwise.xor",
      category: "reverse",
      args: [{left: index, right: 7, result: index ^ 7, padding: "x".repeat(100)}]
    });
  }
  rows.push({
    seq: 201,
    api: "Request.constructor",
    category: "network",
    args: [{
      method: "GET",
      url: "https://www.example.test/api/feed?cursor=1&X-Signature=secret-late",
      network_correlation_key: "sha1:late"
    }]
  });
  fs.writeFileSync(tracePath, rows.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");

  const result = generateReportForTrace(tracePath, {
    maxBytes: 1024,
    windowBefore: 10,
    windowAfter: 0,
    retrieveExternalScripts: false
  });

  assert.ok(result.report.trace.event_count > 0);
  assert.ok(result.report.trace.event_count < rows.length);
  assert.ok(result.report.signature.event_count >= 1);
});

test("generateReportForTrace auto-targets tight signature windows for large traces", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-report-tight-signature-"));
  const tracePath = path.join(dir, "trace_tight_signature.ndjson");
  const rows = [];

  rows.push({
    seq: 1,
    api: "URL.constructor",
    category: "reverse",
    args: [{url: "https://www.example.test/path?cursor=1"}]
  });
  rows.push({
    seq: 2,
    api: "Navigator.webdriver",
    category: "fingerprint",
    args: [{value: "sessionToken=early-noise"}]
  });
  for (let index = 3; index <= 5299; index += 1) {
    rows.push({
      seq: index,
      api: "Bitwise.and",
      category: "reverse",
      args: [{left: index, right: 255, result: index & 255, padding: "x".repeat(80)}]
    });
  }
  rows.push({
    seq: 5300,
    api: "Request.constructor",
    category: "network",
    args: [{
      method: "GET",
      url: "https://www.example.test/api/feed?cursor=1&X-Signature=late-signature",
      network_correlation_key: "sha1:tight"
    }]
  });
  fs.writeFileSync(tracePath, rows.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");

  const result = generateReportForTrace(tracePath, {
    maxBytes: 1024,
    retrieveExternalScripts: false
  });

  assert.ok(result.report.trace.event_count > 0);
  assert.ok(result.report.trace.event_count < rows.length);
  assert.ok(result.report.signature.event_count >= 1);
  assert.ok(!result.report.fingerprint.apis.includes("Navigator.webdriver"));
});

test("buildReportForTrace retrieves external stack scripts for VMP subflow source context", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-report-fetch-"));
  const tracePath = path.join(dir, "trace_external_stack.ndjson");
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "A", url: scriptUrl, line: 4, column: 2}];
  const events = [
    {schema_version: 1, seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url: "https://www.example.test/api/list"}], result: {href: "https://www.example.test/api/list"}, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {schema_version: 1, seq: 2, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{byte_offset: 4}], result: 123, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {schema_version: 1, seq: 3, category: "reverse", phase: "call", api: "String.fromCharCode", args: [{first_code: 88}], result: "X", stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {schema_version: 1, seq: 4, category: "network", phase: "call", api: "Request.constructor", args: [{url: "https://www.example.test/api/list?X-Signature=secret-one&X-Secondary-Signature=secret-two"}], result: {}, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false}
  ];
  fs.writeFileSync(tracePath, events.map((event) => JSON.stringify(event)).join("\n") + "\n", "utf8");

  const report = buildReportForTrace(tracePath, {
    retrieveExternalScripts: true,
    retrieveExternalScript(url) {
      assert.equal(url, scriptUrl);
      return [
        "const salt = 1;",
        "function helper(x) { return x + salt; }",
        "function A(vm) {",
        "  const token = \"X-Signature=secret-one&X-Secondary-Signature=secret-two\";",
        "  return DataView.prototype.getUint32.call(vm.view, 4, true);",
        "}",
        "window.A = A;"
      ].join("\n");
    }
  });

  const [subflow] = report.signature.agent_evidence_pack.flows
    .flatMap((flow) => flow.suspected_signature_subflows || []);

  assert.ok(subflow);
  assert.equal(subflow.asset_id.startsWith("external-script:"), true);
  assert.deepEqual(subflow.source_context_refs, [`${subflow.asset_id}:2-6`]);
  assert.match(subflow.source_contexts[0].preview, /X-Signature=secret-one&X-Secondary-Signature=secret-two/);
  assert.match(renderMarkdownReport(report), /subflow_sources=external-script:/);
});

test("buildReportForTrace prioritizes runtime-sdk request URL retrieval over loader stack scripts", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-report-runtime-sdk-url-fetch-"));
  const tracePath = path.join(dir, "trace_runtime-sdk_url_fetch.ndjson");
  const loaderUrl = "https://cdn.example.test/loader.js";
  const sdkUrl = "https://cdn.example.test/runtime-sdk/1.0.0/runtime-sdk.js";
  const stack = [{function: "loadSecuritySdk", url: loaderUrl, line: 2, column: 4}];
  const events = [
    {schema_version: 1, seq: 1, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{}], stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {schema_version: 1, seq: 2, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: sdkUrl, request_destination: "script", is_fetch_like_api: true}], pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false}
  ];
  fs.writeFileSync(tracePath, events.map((event) => JSON.stringify(event)).join("\n") + "\n", "utf8");

  const fetchedUrls = [];
  const report = buildReportForTrace(tracePath, {
    retrieveExternalScripts: true,
    externalScriptLimit: 1,
    retrieveExternalScript(url) {
      fetchedUrls.push(url);
      return [
        "const bytecode = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];",
        "const handlers = [function(vm){ return new TextEncoder().encode(vm.seed); }];",
        "export function runtimeSdk(vm){ return handlers[bytecode[0]].call(null, vm); }"
      ].join("\n");
    }
  });

  assert.deepEqual(fetchedUrls, [sdkUrl]);
  const sdkAsset = report.assets.find((asset) => asset.url === sdkUrl);
  assert.ok(sdkAsset);
  assert.equal(sdkAsset.asset_id.startsWith("external-script:"), true);
  assert.equal(sdkAsset.retrieval_status, "fetched");
  assert.ok(sdkAsset.score > 0);
  assert.ok(sdkAsset.signals.includes("vmp_dynamic_dispatch"));
  const focusAsset = report.signature.agent_evidence_pack.next_capture_plan.focus_assets[0];
  assert.deepEqual({
    asset_id: focusAsset.asset_id,
    stack_url: focusAsset.stack_url,
    content_path: focusAsset.content_path,
    retrieval_status: focusAsset.retrieval_status,
    score: focusAsset.score,
    signals: focusAsset.signals,
    asset_focus: focusAsset.asset_focus,
    asset_role: focusAsset.asset_role
  }, {
    asset_id: sdkAsset.asset_id,
    stack_url: sdkUrl,
    content_path: sdkAsset.content_path,
    retrieval_status: "fetched",
    score: sdkAsset.score,
    signals: sdkAsset.signals,
    asset_focus: "core_signature_asset",
    asset_role: "security_sdk_signature_generator"
  });
  assert.match(renderMarkdownReport(report), new RegExp(`asset=${sdkAsset.asset_id} stack=https:\\/\\/cdn\\.example\\.test\\/runtime-sdk\\/1\\.0\\.0\\/runtime-sdk\\.js .* retrieval=fetched .* signals=.*vmp_dynamic_dispatch.* role=security_sdk_signature_generator`));
});

test("buildLocalReport emits core asset review windows for runtime-sdk source", () => {
  const sdkUrl = "https://cdn.example.test/runtime-sdk/1.0.0/runtime-sdk.js";
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "TextEncoder.encode", stack: [{function: "mix", url: sdkUrl, line: 4, column: 15}]},
    {seq: 2, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: sdkUrl, request_destination: "script", is_fetch_like_api: true}]}
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: sdkUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    retrieval_status: "captured",
    content: [
      "function collect(){ return navigator.userAgent + screen.width + Intl.DateTimeFormat().resolvedOptions().timeZone; }",
      "const bytecode=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]; const handlers=[function(vm){return vm.reg[bytecode[vm.pc++]];}];",
      "function mix(url){ const u=new URL(url); u.searchParams.set('X-Signature','secret-one'); const bytes=new TextEncoder().encode(u.href); return Math.imul((bytes[0]^0x9e3779b1)>>>0,2654435761); }",
      "const guarded = Function('return eval')();"
    ].join("\n")
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_core_asset_review.ndjson", events, assets});
  const review = report.signature.agent_evidence_pack.core_asset_review_package;

  assert.equal(review.purpose, "agent_core_asset_source_review");
  assert.equal(review.entry_count, 1);
  assert.equal(review.entries[0].asset_id, "sha1:runtime-sdk");
  assert.equal(review.entries[0].asset_role, "security_sdk_signature_generator");
  assert.deepEqual(review.entries[0].review_focus.slice(0, 4), [
    "url_signature_boundary",
    "vmp_runtime_surface",
    "fingerprint_collection",
    "dynamic_code_boundary"
  ]);
  assert.deepEqual(review.entries[0].source_windows.map((window) => window.focus).slice(0, 4), [
    "url_signature_boundary",
    "vmp_runtime_surface",
    "fingerprint_collection",
    "dynamic_code_boundary"
  ]);
  const signatureWindow = review.entries[0].source_windows.find((window) => window.focus === "url_signature_boundary");
  assert.ok(signatureWindow);
  assert.match(signatureWindow.preview, /X-Signature/);
  assert.match(signatureWindow.preview, /secret-one/);
  assert.match(renderMarkdownReport(report), /Core Asset Review Package/);
  assert.match(renderMarkdownReport(report), /core_asset=sha1:runtime-sdk role=security_sdk_signature_generator/);
  assert.match(renderMarkdownReport(report), /source_window=url_signature_boundary lines=3-3/);
});

test("buildAgentAnalysis surfaces runtime-sdk as a core signature asset for agent review", () => {
  const sdkUrl = "https://cdn.example.test/runtime-sdk/1.0.0/runtime-sdk.js";
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "TextEncoder.encode", stack: [{function: "mix", url: sdkUrl, line: 3, column: 20}]},
    {seq: 2, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: sdkUrl, request_destination: "script", is_fetch_like_api: true}]}
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: sdkUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    retrieval_status: "captured",
    content: [
      "function collect(){ return navigator.userAgent + screen.width; }",
      "const bytecode=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]; const handlers=[function(vm){return vm.reg[bytecode[vm.pc++]];}];",
      "function mix(url){ const u=new URL(url); u.searchParams.set('X-Signature','secret-one'); return new TextEncoder().encode(u.href); }"
    ].join("\n")
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_agent_core_asset.ndjson", events, assets});
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);

  assert.deepEqual(pack.core_assets.map((asset) => ({
    asset_id: asset.asset_id,
    asset_role: asset.asset_role,
    source_status: asset.source_status,
    content_path: asset.content_path,
    target_params: asset.target_params,
    review_focus: asset.review_focus
  })), [{
    asset_id: "sha1:runtime-sdk",
    asset_role: "security_sdk_signature_generator",
    source_status: "available",
    content_path: "assets/trace_demo/runtime-sdk.js",
    target_params: ["X-Signature"],
    review_focus: [
      "url_signature_boundary",
      "vmp_runtime_surface",
      "fingerprint_collection",
      "encoding_or_hash_boundary"
    ]
  }]);
  assert.deepEqual(analysis.core_assets[0].source_windows.map((window) => ({
    focus: window.focus,
    line_start: window.line_start,
    target_params: window.target_params
  })).slice(0, 2), [
    {focus: "url_signature_boundary", line_start: 3, target_params: ["X-Signature"]},
    {focus: "vmp_runtime_surface", line_start: 2, target_params: []}
  ]);
  const markdown = renderAgentAnalysisMarkdown(analysis);
  assert.match(markdown, /## Core Signature Assets/);
  assert.match(markdown, /core_asset=sha1:runtime-sdk role=security_sdk_signature_generator status=available path=assets\/trace_demo\/runtime-sdk\.js params=X-Signature focus=url_signature_boundary,vmp_runtime_surface,fingerprint_collection,encoding_or_hash_boundary/);
  assert.match(markdown, /source_window=url_signature_boundary lines=3-3 params=X-Signature preview=.*X-Signature.*secret-one/);
});

test("buildAgentAnalysis attaches observed signature params to core assets without literal source terms", () => {
  const sdkUrl = "https://cdn.example.test/runtime-sdk/1.0.0/runtime-sdk.js";
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "TextEncoder.encode", stack: [{function: "mix", url: sdkUrl, line: 2, column: 20}]},
    {seq: 2, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: "https://www.example.test/api/feed?X-Signature=secret-one", is_fetch_like_api: true}], stack: [{function: "mix", url: sdkUrl, line: 2, column: 20}]}
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: sdkUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    retrieval_status: "captured",
    content: [
      "const bytecode=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]; const handlers=[function(vm){return vm.reg[bytecode[vm.pc++]];}];",
      "function mix(url){ const bytes=new TextEncoder().encode(url); return Math.imul(bytes[0]^0x9e3779b1,2654435761); }"
    ].join("\n")
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_agent_core_asset_related_params.ndjson", events, assets});
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));

  assert.deepEqual(analysis.core_assets[0].target_params, []);
  assert.deepEqual(analysis.core_assets[0].related_params, ["X-Signature"]);
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /core_asset=sha1:runtime-sdk role=security_sdk_signature_generator status=available path=assets\/trace_demo\/runtime-sdk\.js params=none focus=vmp_runtime_surface,encoding_or_hash_boundary related_params=X-Signature/
  );
});

test("buildAgentAnalysis links core assets to observed runtime entrypoints", () => {
  const sdkUrl = "https://cdn.example.test/runtime-sdk/1.0.0/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: sdkUrl,
    line: 3,
    column: 14,
    asset_id: "sha1:runtime-sdk",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 11, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 24}], stack},
    {seq: 12, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left: 1, right: 2, result: 3}], stack},
    {seq: 13, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 14, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];
  const assets = [{
    asset_id: "sha1:runtime-sdk",
    kind: "script",
    url: sdkUrl,
    content_path: "assets/trace_demo/runtime-sdk.js",
    retrieval_status: "captured",
    content: [
      "function helper(x) { return x; }",
      "function signVm(input) {",
      "  const data = new TextEncoder().encode(input.url);",
      "  const mixed = data.length ^ 123;",
      "  url.searchParams.set('X-Signature', mixed);",
      "  return new Request(url.href);",
      "}"
    ].join("\n")
  }];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_core_asset_runtime_entrypoints.ndjson", events, assets});
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const [entrypoint] = analysis.core_assets[0].runtime_entrypoints;

  assert.deepEqual({
    function: entrypoint.function,
    source_candidate_id: entrypoint.source_candidate_id,
    review_entry_id: entrypoint.review_entry_id,
    source_refs: entrypoint.source_refs,
    target_params: entrypoint.target_params,
    stages: entrypoint.stages,
    runtime_apis: entrypoint.runtime_apis,
    endpoints: entrypoint.endpoints,
    causality: entrypoint.causality,
    review_priority: entrypoint.review_priority
  }, {
    function: "signVm",
    source_candidate_id: "source_candidate_1",
    review_entry_id: "review_entry_1",
    source_refs: ["sha1:runtime-sdk:1-5"],
    target_params: ["X-Signature"],
    stages: [
      "input_url",
      "text_or_string_decode",
      "integer_mixing",
      "signature_mutation",
      "signed_request"
    ],
    runtime_apis: [
      "Bitwise.xor",
      "Request.constructor",
      "TextEncoder.encode",
      "URL.constructor",
      "URLSearchParams.set"
    ],
    endpoints: ["https://www.example.test/api/list"],
    causality: "pre_request_chain",
    review_priority: "high"
  });
  const markdown = renderAgentAnalysisMarkdown(analysis);
  assert.match(markdown, /runtime_entry=signVm candidate=source_candidate_1 review=review_entry_1 causality=pre_request_chain priority=high params=X-Signature related_params=X-Signature link_status=direct_param_runtime_entry missing=none next_hooks=none stages=input_url,text_or_string_decode,integer_mixing,signature_mutation,signed_request apis=Bitwise\.xor,Request\.constructor,TextEncoder\.encode,URL\.constructor,URLSearchParams\.set refs=sha1:runtime-sdk:1-5 endpoints=https:\/\/www\.example\.test\/api\/list/);
});

test("buildAgentAnalysis carries core asset related params onto encoded runtime entrypoints", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    trace: {path: "/tmp/xtrace/logs/trace_core_asset_related_entrypoint.ndjson", event_count: 3},
    capture_recipe: null,
    parameters: [],
    source_ref_index: [],
    core_assets: [{
      asset_id: "sha1:runtime-sdk",
      asset_role: "security_sdk_signature_generator",
      source_status: "available",
      content_path: "assets/trace_demo/runtime-sdk.js",
      related_params: ["X-Signature"],
      review_focus: ["vmp_runtime_surface"],
      runtime_entrypoints: [{
        function: "vmDispatch",
        source_candidate_id: "source_candidate_1",
        review_entry_id: "review_entry_1",
        source_refs: ["sha1:runtime-sdk:1-1@102091-103290"],
        target_params: [],
        stages: ["dynamic_dispatch", "integer_mixing"],
        runtime_apis: ["Function.prototype.call", "Bitwise.xor"],
        endpoints: ["https://www.example.test/api/feed"],
        causality: "pre_request_chain",
        review_priority: "high"
      }]
    }]
  });

  assert.deepEqual(analysis.core_assets[0].runtime_entrypoints[0].target_params, []);
  assert.deepEqual(analysis.core_assets[0].runtime_entrypoints[0].related_params, ["X-Signature"]);
  assert.deepEqual({
    link_status: analysis.core_assets[0].runtime_entrypoints[0].link_status,
    missing_links: analysis.core_assets[0].runtime_entrypoints[0].missing_links,
    next_hooks: analysis.core_assets[0].runtime_entrypoints[0].next_hooks
  }, {
    link_status: "encoded_or_vmp_boundary_unresolved",
    missing_links: [
      "vmp_register_ref",
      "dynamic_dispatch_boundary_ref"
    ],
    next_hooks: [
      "vmp.register_ref",
      "vmp.handler.return_ref",
      "Bitwise.result_ref"
    ]
  });
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /runtime_entry=vmDispatch candidate=source_candidate_1 review=review_entry_1 causality=pre_request_chain priority=high params=none related_params=X-Signature link_status=encoded_or_vmp_boundary_unresolved missing=vmp_register_ref,dynamic_dispatch_boundary_ref next_hooks=vmp\.register_ref,vmp\.handler\.return_ref,Bitwise\.result_ref stages=dynamic_dispatch,integer_mixing apis=Function\.prototype\.call,Bitwise\.xor/
  );
  assert.doesNotMatch(renderAgentAnalysisMarkdown(analysis), /Function\.prototype\.call\.result_ref/);
});

test("buildAgentAnalysis promotes related core asset VMP source windows into parameter evidence", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_core_asset_vmp_source.ndjson", event_count: 8},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Reflect.apply", "Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 30,
          distance_basis: "trace_index",
          object_refs: ["state_object:105", "target:102", "arguments_list:103"],
          value_refs: ["register:105/103", "handler_return:102/103"]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor", "Shift.unsignedRight"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 18,
          distance_basis: "trace_index",
          value_refs: [
            "register:string:length:249/number:158.000000",
            "handler_arg:302832/number:158.000000",
            "number:158.000000"
          ]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          value_refs: ["target_params:X-Signature"]
        },
        {
          order: 4,
          stage: "signed_request",
          role: "output",
          apis: ["Request.constructor"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "signed_request",
          distance_to_signed_request: 0,
          distance_basis: "trace_index",
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [],
    core_assets: [{
      asset_id: "sha1:runtime-sdk",
      asset_role: "security_sdk_signature_generator",
      asset_focus: "core_signature_asset",
      url: "https://cdn.example.test/runtime-sdk.js",
      content_path: "assets/trace_demo/runtime-sdk.js",
      source_status: "available",
      related_params: ["X-Signature"],
      source_windows: [{
        focus: "vmp_runtime_surface",
        priority: "high",
        content_path: "assets/trace_demo/runtime-sdk.js",
        line_start: 1,
        line_end: 1,
        preview: "var bytecode=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]; var handlers=[function(vm){vm.reg[bytecode[vm.pc++]]=vm.seed},function(vm){return handlers[bytecode[vm.pc++]].call(null,vm)}]; while(vm.pc<bytecode.length){Reflect.apply(handlers[bytecode[vm.pc++]],null,[vm])}"
      }]
    }]
  });

  const parameter = analysis.parameters[0];
  assert.ok(parameter.source_refs.some((ref) => ref.startsWith("sha1:runtime-sdk:1-1")));
  const vmpSourceEvidence = parameter.source_evidence.find((source) => /bytecode=\[1,2,3/.test(source.preview || ""));
  assert.ok(vmpSourceEvidence);
  assert.equal(parameter.vmp_state_model.handler_table, "observed_source_and_runtime");
  assert.equal(parameter.vmp_state_model.bytecode_pc, "observed_source");
  assert.ok(!parameter.vmp_state_model.unresolved_gaps.includes("vmp_handler_table_source_not_observed"));
  assert.ok(!parameter.vmp_state_model.unresolved_gaps.includes("vmp_bytecode_pc_source_not_observed"));
});

test("buildAgentAnalysis uses core asset VMP signals when minified source preview is local", () => {
  const analysis = buildAgentAnalysis({
    version: 1,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {path: "/tmp/xtrace/logs/trace_core_asset_vmp_signals.ndjson", event_count: 8},
    capture_recipe: null,
    parameters: [{
      param: "X-Signature",
      status: "attachment_observed",
      best_flow_id: "material_flow_1",
      endpoint: "https://www.example.test/api/feed",
      source_refs: [],
      evidence_gaps: [],
      generation_trace: [
        {
          order: 1,
          stage: "dynamic_dispatch",
          role: "transform",
          apis: ["Function.prototype.call"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 30,
          distance_basis: "trace_index",
          object_refs: ["state_object:105"],
          value_refs: ["register:105/103"]
        },
        {
          order: 2,
          stage: "integer_mixing",
          role: "transform",
          apis: ["Bitwise.xor"],
          target_params: ["X-Signature"],
          param_relation: "flow_target",
          relation: "before_signed_request",
          distance_to_signed_request: 18,
          distance_basis: "trace_index",
          value_refs: ["register:105/103", "number:158.000000"]
        },
        {
          order: 3,
          stage: "signature_mutation",
          role: "parameter_attachment",
          apis: ["URLSearchParams.set"],
          target_params: ["X-Signature"],
          param_relation: "direct_observed",
          relation: "before_signed_request",
          distance_to_signed_request: 2,
          distance_basis: "trace_index",
          value_refs: ["target_params:X-Signature"]
        }
      ]
    }],
    source_ref_index: [],
    core_assets: [{
      asset_id: "sha1:runtime-sdk",
      asset_role: "security_sdk_signature_generator",
      asset_focus: "core_signature_asset",
      content_path: "assets/trace_demo/runtime-sdk.js",
      source_status: "available",
      related_params: ["X-Signature"],
      signals: ["vmp_handler_table", "vmp_bytecode_cursor", "vmp_dispatch_loop"],
      source_windows: [{
        focus: "vmp_runtime_surface",
        priority: "high",
        content_path: "assets/trace_demo/runtime-sdk.js",
        line_start: 1,
        line_end: 1,
        column_start: 12029,
        column_end: 13228,
        preview: "...o[898].v=t.o[835].v.call(void 0,10);var s=a(t.o[898].v,(function(){return k(67460,t,this,arguments,0,11)})..."
      }]
    }]
  });

  const parameter = analysis.parameters[0];
  assert.ok(parameter.source_evidence.some((source) => (source.signals || []).includes("vmp_handler_table")));
  assert.equal(parameter.vmp_state_model.handler_table, "observed_source_and_runtime");
  assert.equal(parameter.vmp_state_model.bytecode_pc, "observed_source");
});

test("buildLocalReport treats generic WAF and security runtime scripts as core security SDK assets", () => {
  const wafUrl = "https://cdn.example.test/security/waf-runtime.js";
  const secsdkUrl = "https://cdn.example.test/security/security-runtime-bundler.js";
  const slardarWafUrl = "https://cdn.example.test/security/waf-browser.js?bid=security_waf";
  const commonMonitorUrl = "https://cdn.example.test/telemetry/sdk-web/plugins/common-monitors.1.16.7.js";
  const wafStack = [{
    function: "calc",
    url: wafUrl,
    line: 2,
    column: 22,
    asset_id: "sha1:waf",
    asset_path: "assets/trace_demo/waf-aiso/dd9808.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "TextEncoder.encode", stack: wafStack},
    {seq: 2, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "POST", url: "https://telemetry.example.test/monitor_browser/collect/batch/", is_fetch_like_api: true}], stack: wafStack}
  ];
  const source = [
    "const bytecode=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25];",
    "function calc(url){ const bytes=new TextEncoder().encode(url); return SHA256.digest(bytes); }",
    "function guard(){ return Function.prototype.toString.call(calc); }"
  ].join("\n");
  const assets = [
    {
      asset_id: "sha1:waf",
      kind: "script",
      url: wafUrl,
      content_path: "assets/trace_demo/waf-aiso/dd9808.js",
      content: source
    },
    {
      asset_id: "sha1:security-runtime",
      kind: "script",
      url: secsdkUrl,
      content_path: "assets/trace_demo/security-runtime-bundler.js",
      content: source
    },
    {
      asset_id: "sha1:slardar-waf",
      kind: "script",
      url: slardarWafUrl,
      content_path: "assets/trace_demo/browser.sg.js",
      content: source
    },
    {
      asset_id: "sha1:common-monitor",
      kind: "script",
      url: commonMonitorUrl,
      content_path: "assets/trace_demo/common-monitors.1.16.7.js",
      content: source
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_core_waf_assets.ndjson", events, assets});
  const review = report.signature.agent_evidence_pack.core_asset_review_package;
  const reviewedIds = review.entries.map((entry) => entry.asset_id).sort();

  assert.deepEqual(reviewedIds, [
    "sha1:security-runtime",
    "sha1:slardar-waf",
    "sha1:waf"
  ]);
  assert.ok(!review.entries.some((entry) => entry.asset_id === "sha1:common-monitor"));
  assert.deepEqual(review.entries.map((entry) => entry.asset_role), [
    "security_sdk_signature_generator",
    "security_sdk_signature_generator",
    "security_sdk_signature_generator"
  ]);
  assert.ok(report.signature.agent_evidence_pack.next_capture_plan.focus_assets.some((asset) =>
    asset.asset_id === "sha1:waf" &&
    asset.asset_focus === "core_signature_asset" &&
    asset.asset_role === "security_sdk_signature_generator"
  ));
  assert.ok(report.signature.agent_evidence_pack.next_capture_plan.capture_checklist
    .find((item) => item.id === "confirm_core_sdk_asset")
    .evidence.some((item) => item.includes("sha1:waf@")));
  assert.match(renderMarkdownReport(report), /core_asset=sha1:waf role=security_sdk_signature_generator/);
  assert.match(renderMarkdownReport(report), /capture_check item=confirm_core_sdk_asset status=observed/);
});

test("buildLocalReport preserves cookie setters in core asset review windows", () => {
  const sdkUrl = "https://cdn.example.test/runtime-sdk.js";
  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_core_asset_cookie_redaction.ndjson",
    events: [
      {seq: 1, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: sdkUrl, request_destination: "script", is_fetch_like_api: true}]}
    ],
    assets: [{
      asset_id: "sha1:runtime-sdk",
      kind: "script",
      url: sdkUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: "function collect(){ document.cookie = 'sessionid=secret-cookie'; return navigator.userAgent + screen.width; }"
    }]
  });

  const reviewText = JSON.stringify(report.signature.agent_evidence_pack.core_asset_review_package);
  assert.match(reviewText, /document\.cookie\s*=/);
  assert.match(reviewText, /sessionid=secret-cookie/);
});

test("buildReportForTrace can use cached external scripts without network fetch", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-report-cache-only-"));
  const tracePath = path.join(dir, "trace_cached_external_stack.ndjson");
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const missingScriptUrl = "https://cdn.example.test/not-cached.js";
  const stack = [{function: "A", url: scriptUrl, line: 4, column: 2}];
  const missingStack = [{function: "B", url: missingScriptUrl, line: 1, column: 1}];
  const events = [
    {schema_version: 1, seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url: "https://www.example.test/api/list"}], stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {schema_version: 1, seq: 2, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{}], stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {schema_version: 1, seq: 3, category: "reverse", phase: "call", api: "TextDecoder.decode", args: [{}], stack: missingStack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {schema_version: 1, seq: 4, category: "network", phase: "call", api: "Request.constructor", args: [{url: "https://www.example.test/api/list?X-Signature=secret-one"}], stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false}
  ];
  fs.writeFileSync(tracePath, events.map((event) => JSON.stringify(event)).join("\n") + "\n", "utf8");

  const assetId = `external-script:${crypto.createHash("sha1").update(scriptUrl).digest("hex").slice(0, 16)}`;
  const assetDir = path.join(reportDirectoryForTrace(tracePath), "assets");
  fs.mkdirSync(assetDir, {recursive: true});
  fs.writeFileSync(path.join(assetDir, `${assetId.replace(/[^a-zA-Z0-9._-]/g, "_")}.js`), [
    "function helper(x) { return x; }",
    "function A(input) {",
    "  const encoded = new TextEncoder().encode(input);",
    "  return encoded;",
    "}"
  ].join("\n"), "utf8");

  let networkCalls = 0;
  const report = buildReportForTrace(tracePath, {
    retrieveExternalScripts: true,
    externalScriptLimit: 2,
    externalScriptCacheOnly: true,
    retrieveExternalScript() {
      networkCalls += 1;
      throw new Error("network fetch should not run in cache-only mode");
    }
  });
  const [flow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.equal(networkCalls, 0);
  assert.equal(flow.source_context_refs.length, 1);
  assert.equal(flow.source_context_refs[0], `${assetId}:2-5`);
  assert.match(flow.source_contexts[0].preview, /TextEncoder/);
});

test("buildLocalReport extracts source context around stack column for minified scripts", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const prefix = "a".repeat(1500);
  const focus = "function A(vm){var x=DataView.prototype.getUint32.call(vm.view,4,true)^vm.seed;return Math.imul(x,2654435761)>>>0}";
  const suffix = "b".repeat(1500);
  const column = prefix.length + 20;
  const stack = [{
    function: "A",
    url: scriptUrl,
    line: 1,
    column,
    asset_id: "sha1:minified",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list"}], result: {href: "https://www.example.test/api/list"}, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {seq: 2, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 21, array_buffer_id: 20, byte_offset: 4}], result: 123, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {seq: 3, category: "reverse", phase: "call", api: "Math.imul", args: [{data_view_id: 21, mix_state_id: 30, a: 123, b: 2654435761}], result: 456, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {seq: 4, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?X-Signature=secret-one"}], result: {}, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false}
  ];
  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_minified_source.ndjson",
    events,
    assets: [{
      asset_id: "sha1:minified",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: `${prefix}${focus}${suffix}`
    }]
  });

  const [subflow] = report.signature.agent_evidence_pack.flows
    .flatMap((flow) => flow.suspected_signature_subflows || []);

  assert.ok(subflow);
  assert.equal(subflow.source_contexts[0].line_start, 1);
  assert.equal(subflow.source_contexts[0].column_anchor, column);
  assert.match(subflow.source_contexts[0].preview, /DataView\.prototype\.getUint32/);
  assert.deepEqual(subflow.source_contexts[0].analysis.signals.sort(), [
    "byte_buffer",
    "int_bitwise",
    "int_multiply",
    "prototype_call"
  ]);
  assert.deepEqual(subflow.source_contexts[0].analysis.calls.slice(0, 3), [
    "DataView.prototype.getUint32.call",
    "Math.imul"
  ]);
  assert.ok(subflow.source_contexts[0].analysis.properties.includes("vm.seed"));
  assert.ok(subflow.source_contexts[0].analysis.operators.includes("^"));
  assert.ok(subflow.source_contexts[0].analysis.operators.includes(">>>"));
  assert.doesNotMatch(subflow.source_contexts[0].preview, /^a{100}/);
  assert.deepEqual(subflow.candidate_signature_pipeline.stages.map((stage) => ({
    stage: stage.stage,
    runtime_apis: stage.runtime_apis,
    source_calls: stage.source_calls,
    source_signals: stage.source_signals,
    source_operators: stage.source_operators,
    source_constants: stage.source_constants,
    object_refs: stage.object_refs
  })), [
    {
      stage: "input_url",
      runtime_apis: ["URL.constructor"],
      source_calls: [],
      source_signals: [],
      source_operators: [],
      source_constants: [],
      object_refs: ["url_object:11", "search_params:12"]
    },
    {
      stage: "byte_buffer",
      runtime_apis: ["DataView.getUint32"],
      source_calls: ["DataView.prototype.getUint32.call"],
      source_signals: ["byte_buffer"],
      source_operators: [],
      source_constants: [],
      object_refs: ["data_view:21", "array_buffer:20"]
    },
    {
      stage: "integer_mixing",
      runtime_apis: ["Math.imul"],
      source_calls: ["Math.imul"],
      source_signals: ["int_bitwise", "int_multiply"],
      source_operators: ["^", ">>>"],
      source_constants: ["2654435761"],
      object_refs: ["data_view:21", "mix_state:30"]
    },
    {
      stage: "signed_request",
      runtime_apis: ["Request.constructor"],
      source_calls: [],
      source_signals: [],
      source_operators: [],
      source_constants: [],
      object_refs: ["url_object:11", "search_params:12"]
    }
  ]);
  assert.deepEqual(subflow.candidate_signature_pipeline.data_links, [
    {from: "input_url", to: "signed_request", refs: ["url_object:11", "search_params:12"]},
    {from: "byte_buffer", to: "integer_mixing", refs: ["data_view:21"]}
  ]);
  assert.equal(subflow.candidate_signature_pipeline.confidence, "high");
  assert.match(renderMarkdownReport(report), /source_analysis=signals:byte_buffer,int_bitwise,int_multiply,prototype_call calls:DataView\.prototype\.getUint32\.call,Math\.imul props:/);
  assert.match(renderMarkdownReport(report), /candidate_pipeline=input_url\[URL\.constructor\]->byte_buffer\[DataView\.getUint32\]->integer_mixing\[Math\.imul\]->signed_request\[Request\.constructor\]/);
  assert.match(renderMarkdownReport(report), /data_links=input_url->signed_request:url_object:11\|search_params:12,byte_buffer->integer_mixing:data_view:21/);
});

test("buildLocalReport emits agent-readable signature material flows", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 4,
    column: 14,
    asset_id: "sha1:material",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 11, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 21, array_buffer_id: 20, byte_offset: 4}], stack},
    {seq: 12, category: "reverse", phase: "call", api: "Math.imul", args: [{data_view_id: 21, mix_state_id: 30, x: 123, y: 2654435761}], stack},
    {seq: 13, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one&X-Secondary-Signature=secret-two"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_material_flow.ndjson",
    events,
    assets: [{
      asset_id: "sha1:material",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function helper(x) { return x; }",
        "function signVm(input) {",
        "  const raw = \"X-Signature=secret-one&X-Secondary-Signature=secret-two\";",
        "  const view = new DataView(input);",
        "  const mixed = Math.imul(view.getUint32(4, true) ^ 123, 2654435761) >>> 0;",
        "  return mixed;",
        "}"
      ].join("\n")
    }]
  });

  const materialFlows = report.signature.agent_evidence_pack.signature_material_flows;
  assert.equal(materialFlows.length, 1);
  const [materialFlow] = materialFlows;

  assert.deepEqual({
    id: materialFlow.id,
    flow_id: materialFlow.flow_id,
    endpoint: materialFlow.endpoint,
    confidence: materialFlow.confidence,
    evidence_status: materialFlow.evidence_status,
    function: materialFlow.function,
    stack_url: materialFlow.stack_url,
    asset_id: materialFlow.asset_id,
    seq_start: materialFlow.seq_start,
    seq_end: materialFlow.seq_end,
    target_params: materialFlow.target_params,
    stage_count: materialFlow.stage_count
  }, {
    id: "material_flow_1",
    flow_id: "signature_flow_1",
    endpoint: "https://www.example.test/api/list",
    confidence: "high",
    evidence_status: "observed_only",
    function: "signVm",
    stack_url: scriptUrl,
    asset_id: "sha1:material",
    seq_start: 10,
    seq_end: 13,
    target_params: ["X-Signature", "X-Secondary-Signature"],
    stage_count: 4
  });
  assert.deepEqual(materialFlow.stages.map((stage) => ({
    stage: stage.stage,
    runtime_apis: stage.runtime_apis,
    source_signals: stage.source_signals,
    source_operators: stage.source_operators,
    source_constants: stage.source_constants,
    object_refs: stage.object_refs
  })), [
    {
      stage: "input_url",
      runtime_apis: ["URL.constructor"],
      source_signals: [],
      source_operators: [],
      source_constants: [],
      object_refs: ["url_object:11", "search_params:12"]
    },
    {
      stage: "byte_buffer",
      runtime_apis: ["DataView.getUint32"],
      source_signals: ["byte_buffer"],
      source_operators: [],
      source_constants: [],
      object_refs: ["data_view:21", "array_buffer:20"]
    },
    {
      stage: "integer_mixing",
      runtime_apis: ["Math.imul"],
      source_signals: ["int_bitwise", "int_multiply"],
      source_operators: ["^", ">>>"],
      source_constants: ["123", "2654435761"],
      object_refs: ["data_view:21", "mix_state:30"]
    },
    {
      stage: "signed_request",
      runtime_apis: ["Request.constructor"],
      source_signals: ["byte_buffer", "int_bitwise", "int_multiply", "url_signature"],
      source_operators: ["^", ">>>"],
      source_constants: ["123", "2654435761"],
      object_refs: ["url_object:11", "search_params:12"]
    }
  ]);
  assert.deepEqual(materialFlow.data_links, [
    {from: "input_url", to: "signed_request", refs: ["url_object:11", "search_params:12"]},
    {from: "byte_buffer", to: "integer_mixing", refs: ["data_view:21"]}
  ]);
  assert.deepEqual(materialFlow.agent_generation_summary.stage_chain, [
    "input_url",
    "byte_buffer",
    "integer_mixing",
    "signed_request"
  ]);
  assert.equal(
    materialFlow.agent_generation_summary.summary_text,
    "input_url -> byte_buffer -> integer_mixing -> signed_request"
  );
  assert.equal(materialFlow.agent_generation_summary.evidence_profile, "runtime_and_source");
  assert.deepEqual(materialFlow.agent_generation_summary.target_params, ["X-Signature", "X-Secondary-Signature"]);
  assert.deepEqual(materialFlow.agent_generation_summary.runtime_apis, [
    "URL.constructor",
    "DataView.getUint32",
    "Math.imul",
    "Request.constructor"
  ]);
  assert.deepEqual(materialFlow.agent_generation_summary.source_observed_hooks, []);
  assert.ok(materialFlow.agent_generation_summary.runtime_observed_hooks.includes("vmp_bytecode_or_register_access"));
  assert.ok(materialFlow.agent_generation_summary.runtime_observed_hooks.includes("vmp_hash_or_signature_pipeline"));
  assert.equal(materialFlow.agent_generation_summary.data_link_count, 2);
  assert.deepEqual(materialFlow.agent_stage_trace.map((step) => ({
    order: step.order,
    stage: step.stage,
    role: step.role,
    apis: step.apis,
    evidence: step.evidence,
    relation: step.relation,
    distance: step.distance_to_signed_request,
    params: step.params,
    target_params: step.target_params,
    param_relation: step.param_relation,
    source_refs: step.source_refs,
    object_refs: step.object_refs
  })), [
    {
      order: 1,
      stage: "input_url",
      role: "input",
      apis: ["URL.constructor"],
      evidence: ["runtime_api", "source_context", "object_ref", "value_ref"],
      relation: "before_signed_request",
      distance: 3,
      params: [],
      target_params: ["X-Signature", "X-Secondary-Signature"],
      param_relation: "flow_target",
      source_refs: ["sha1:material:2-6"],
      object_refs: ["url_object:11", "search_params:12"]
    },
    {
      order: 2,
      stage: "byte_buffer",
      role: "material",
      apis: ["DataView.getUint32"],
      evidence: ["runtime_api", "source_context", "object_ref", "value_ref"],
      relation: "before_signed_request",
      distance: 2,
      params: [],
      target_params: ["X-Signature", "X-Secondary-Signature"],
      param_relation: "flow_target",
      source_refs: ["sha1:material:2-6"],
      object_refs: ["data_view:21", "array_buffer:20"]
    },
    {
      order: 3,
      stage: "integer_mixing",
      role: "transform",
      apis: ["Math.imul"],
      evidence: ["runtime_api", "source_context", "object_ref", "value_ref", "source_operator", "source_constant"],
      relation: "before_signed_request",
      distance: 1,
      params: [],
      target_params: ["X-Signature", "X-Secondary-Signature"],
      param_relation: "flow_target",
      source_refs: ["sha1:material:2-6"],
      object_refs: ["data_view:21", "mix_state:30"]
    },
    {
      order: 4,
      stage: "signed_request",
      role: "network_emit",
      apis: ["Request.constructor"],
      evidence: ["runtime_api", "source_context", "object_ref", "value_ref"],
      relation: "signed_request",
      distance: 0,
      params: ["X-Signature", "X-Secondary-Signature"],
      target_params: ["X-Signature", "X-Secondary-Signature"],
      param_relation: "direct_observed",
      source_refs: ["sha1:material:2-6"],
      object_refs: ["url_object:11", "search_params:12"]
    }
  ]);
  assert.match(
    renderMarkdownReport(report),
    /agent_stage_trace=1:input_url\(input\)\[URL\.constructor\].*params=none target_params=X-Signature\|X-Secondary-Signature param_relation=flow_target/
  );
  assert.deepEqual(materialFlow.source_context_refs, ["sha1:material:2-6"]);
  assert.deepEqual(materialFlow.analysis_readiness, {
    status: "partial",
    observed_stages: [
      "input_url",
      "byte_buffer",
      "integer_mixing",
      "signed_request"
    ],
    missing_stages: ["signature_mutation"],
    evidence_gaps: ["signature_mutation_not_observed"],
    next_actions: ["capture_url_search_params_mutation_or_header_set"]
  });
  assert.deepEqual(materialFlow.vmp_hook_points.map((point) => ({
    type: point.type,
    status: point.status,
    observed_apis: point.observed_apis,
    next_action: point.next_action
  })), [
    {
      type: "vmp_string_decoder",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_bytecode_or_register_access",
      status: "observed",
      observed_apis: ["DataView.getUint32"],
      next_action: "review_observed_events"
    },
    {
      type: "vmp_array_table",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_dynamic_dispatch",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_collection_table",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_proxy_trap",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_json_serialization",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_hash_or_signature_pipeline",
      status: "observed",
      observed_apis: ["Math.imul"],
      next_action: "review_observed_events"
    },
    {
      type: "vmp_int_bitwise_pipeline",
      status: "observed",
      observed_apis: ["Math.imul"],
      next_action: "review_observed_events"
    },
    {
      type: "vmp_anti_debug_timing_gate",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_source_integrity_probe",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_stack_trace_probe",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_exception_control_flow",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_string_transform",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_regexp_probe",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    },
    {
      type: "vmp_url_encoding_boundary",
      status: "missing",
      observed_apis: [],
      next_action: "add_or_link_hooks"
    }
  ]);
  assert.match(materialFlow.source_contexts[0].preview, /X-Signature=secret-one&X-Secondary-Signature=secret-two/);
  assert.match(renderMarkdownReport(report), /Signature Material Flows/);
  assert.match(renderMarkdownReport(report), /material_flow_1 flow=signature_flow_1 confidence=high status=observed_only readiness=partial gaps=signature_mutation_not_observed endpoint=https:\/\/www\.example\.test\/api\/list params=X-Signature,X-Secondary-Signature stages=input_url\[URL\.constructor\]->byte_buffer\[DataView\.getUint32\]->integer_mixing\[Math\.imul\]->signed_request\[Request\.constructor\]/);
  assert.match(renderMarkdownReport(report), /agent_generation=chain=input_url->byte_buffer->integer_mixing->signed_request evidence=runtime_and_source runtime=URL\.constructor\|DataView\.getUint32\|Math\.imul\|Request\.constructor source_hooks=none runtime_hooks=.*vmp_bytecode_or_register_access/);
  assert.match(renderMarkdownReport(report), /hook_points=vmp_string_decoder:missing\[none\],vmp_bytecode_or_register_access:observed\[runtime:DataView\.getUint32\]/);
});

test("buildLocalReport preserves VMP state refs from dense dispatch events", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 4, column: 14}];
  const dispatchEvents = Array.from({length: 9}, (_, index) => {
    const targetId = 102 + index;
    const argumentsListId = 103 + index;
    const stateObjectId = 105 + index;
    return {
      seq: 2 + index,
      category: "reverse",
      phase: "call",
      api: "Function.prototype.call",
      args: [{
        subject_id: 101 + index,
        target_id: targetId,
        arguments_list_id: argumentsListId,
        this_id: 104 + index,
        state_object_id: stateObjectId,
        register_ref: `register:${stateObjectId}/${argumentsListId}`,
        handler_return_ref: `handler_return:${targetId}/${argumentsListId}`,
        arg_count: 2
      }],
      stack
    };
  });
  const events = [
    {
      seq: 1,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}],
      stack
    },
    ...dispatchEvents,
    {
      seq: 20,
      category: "reverse",
      phase: "call",
      api: "Bitwise.xor",
      args: [{
        left: 123,
        left_ref: "register:105/103",
        right: 456,
        right_ref: "number:456.000000",
        result: 435,
        result_ref: "number:435.000000"
      }],
      stack
    },
    {
      seq: 21,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.set",
      args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-one"}],
      stack
    },
    {
      seq: 22,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_dense_vmp_state_material.ndjson", events, assets: []});
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const focus = analysis.next_capture_focus.find((item) =>
    item.action === "capture_vmp_register_state_refs");

  assert.ok(focus);
  assert.ok(focus.object_refs.includes("state_object:105"));
  const statuses = new Map(focus.hook_target_statuses.map((item) => [item.target, item]));
  assert.equal(statuses.get("vmp.state_object_id").status, "observed_in_focus_refs");
  assert.ok(statuses.get("vmp.state_object_id").observed_refs.includes("state_object:105"));
  assert.equal(statuses.get("vmp.handler.return_ref").status, "observed_in_focus_refs");
  assert.ok(statuses.get("vmp.handler.return_ref").observed_refs.includes("handler_return:102/103"));
});

test("buildLocalReport preserves VMP handler returns when register refs are high-cardinality", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 4, column: 14}];
  const dispatchEvents = Array.from({length: 40}, (_, index) => {
    const targetId = 102 + index;
    const argumentsListId = 103 + index;
    const stateObjectId = 105 + index;
    return {
      seq: 2 + index,
      category: "reverse",
      phase: "call",
      api: index % 2 ? "Function.prototype.apply" : "Function.prototype.call",
      args: [{
        subject_id: 101 + index,
        target_id: targetId,
        arguments_list_id: argumentsListId,
        this_id: 104 + index,
        state_object_id: stateObjectId,
        register_ref: `register:${stateObjectId}/${argumentsListId}`,
        handler_return_ref: `handler_return:${targetId}/${argumentsListId}`,
        arg_count: 2
      }],
      stack
    };
  });
  const events = [
    {
      seq: 1,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}],
      stack
    },
    ...dispatchEvents,
    {
      seq: 60,
      category: "reverse",
      phase: "call",
      api: "Bitwise.xor",
      args: [{
        left: 123,
        left_register_ref: "register:105/103",
        right: 456,
        right_ref: "number:456.000000",
        result: 435,
        result_ref: "number:435.000000"
      }],
      stack
    },
    {
      seq: 61,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.set",
      args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-one"}],
      stack
    },
    {
      seq: 62,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}],
      stack
    }
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_dense_vmp_handler_returns.ndjson",
    events,
    assets: []
  });
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = analysis.parameters.find((entry) => entry.param === "X-Signature");
  const dynamicStep = parameter.generation_path.find((step) => step.stage === "dynamic_dispatch");

  assert.ok(dynamicStep.value_refs.some((ref) => ref.startsWith("handler_return:")));
  assert.ok(parameter.vmp_state_model.handler_return_refs.some((ref) => ref.startsWith("handler_return:")));
  assert.ok(!parameter.vmp_state_model.unresolved_gaps.includes("vmp_handler_return_ref_not_observed"));
});

test("buildLocalReport links bitwise source refs back to VMP register state", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 4, column: 14}];
  const events = [
    {
      seq: 1,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}],
      stack
    },
    {
      seq: 2,
      category: "reverse",
      phase: "call",
      api: "Function.prototype.call",
      args: [{
        target_id: 102,
        arguments_list_id: 103,
        this_id: 105,
        state_object_id: 105,
        register_ref: "register:105/103",
        handler_return_ref: "handler_return:102/103",
        arg_count: 2
      }],
      stack
    },
    {
      seq: 3,
      category: "reverse",
      phase: "call",
      api: "Bitwise.xor",
      args: [{
        left: 123,
        left_ref: "number:123.000000",
        left_source_ref: "handler_return:102/103",
        left_register_ref: "register:105/103",
        right: 456,
        right_ref: "number:456.000000",
        result: 435,
        result_ref: "number:435.000000"
      }],
      stack
    },
    {
      seq: 4,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.set",
      args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-one"}],
      stack
    },
    {
      seq: 5,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_bitwise_vmp_source_refs.ndjson", events, assets: []});
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const model = analysis.parameters[0].vmp_state_model;

  assert.equal(model.linkage.register_to_integer_mixing, "observed");
  assert.equal(model.linkage.handler_return_to_integer_mixing, "observed");
  assert.deepEqual(model.linkage.register_to_integer_mixing_refs, ["register:105/103"]);
  assert.deepEqual(model.linkage.handler_return_to_integer_mixing_refs, ["handler_return:102/103"]);
  assert.ok(!model.unresolved_gaps.includes("vmp_register_to_mixing_link_not_observed"));
  assert.ok(!model.unresolved_gaps.includes("vmp_register_value_ref_to_mixing_not_observed"));
});

test("buildLocalReport links handler argument refs back to integer mixing", () => {
  const stack = [{function: "signVm", url: "https://cdn.example.test/runtime-sdk.js", line: 9, column: 20}];
  const events = [
    {
      seq: 1,
      category: "reverse",
      phase: "call",
      api: "URL.constructor",
      args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}],
      stack
    },
    {
      seq: 2,
      category: "reverse",
      phase: "call",
      api: "Function.prototype.call",
      args: [{
        target_id: 102,
        this_id: null,
        first_arg_ref: "object",
        second_arg_ref: "number:123.000000",
        state_object_id: 105,
        register_ref: "register:105/number:123.000000",
        handler_arg_ref: "handler_arg:102/number:123.000000",
        handler_return_ref: "handler_return:102/number:123.000000",
        arg_count: 2
      }],
      stack
    },
    {
      seq: 3,
      category: "reverse",
      phase: "call",
      api: "Bitwise.xor",
      args: [{
        left: 123,
        left_ref: "number:123.000000",
        left_source_ref: "handler_arg:102/number:123.000000",
        left_register_ref: "register:105/number:123.000000",
        right: 456,
        right_ref: "number:456.000000",
        result: 435,
        result_ref: "number:435.000000"
      }],
      stack
    },
    {
      seq: 4,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.set",
      args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-one"}],
      stack
    },
    {
      seq: 5,
      category: "network",
      phase: "call",
      api: "Request.constructor",
      args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_handler_arg_vmp_refs.ndjson", events, assets: []});
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const model = analysis.parameters[0].vmp_state_model;

  assert.equal(model.linkage.register_to_integer_mixing, "observed");
  assert.equal(model.linkage.handler_arg_to_integer_mixing, "observed");
  assert.deepEqual(model.linkage.handler_arg_to_integer_mixing_refs, ["handler_arg:102/number:123.000000"]);
  assert.deepEqual(model.handler_arg_refs, ["handler_arg:102/number:123.000000"]);
});

test("buildLocalReport carries observed request stages into candidate material flows", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const wrapperUrl = "https://cdn.example.test/secsdk-wrapper.js";
  const vmStack = [{
    function: "signVm",
    url: scriptUrl,
    line: 4,
    column: 14,
    asset_id: "sha1:material",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const requestStack = [{
    function: "onRequest",
    url: wrapperUrl,
    line: 7,
    column: 42,
    asset_id: "sha1:wrapper",
    asset_path: "assets/trace_demo/secsdk-wrapper.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}], stack: vmStack},
    {seq: 11, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 21, array_buffer_id: 20, byte_offset: 4}], stack: vmStack},
    {seq: 12, category: "reverse", phase: "call", api: "Math.imul", args: [{data_view_id: 21, mix_state_id: 30, x: 123, y: 2654435761}], stack: vmStack},
    {seq: 13, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack: requestStack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_material_flow_merge.ndjson",
    events,
    assets: [
      {
        asset_id: "sha1:material",
        kind: "external-script",
        url: scriptUrl,
        content_path: "assets/trace_demo/runtime-sdk.js",
        content: "function signVm(input) { const view = new DataView(input); return Math.imul(view.getUint32(4, true) ^ 123, 2654435761); }"
      },
      {
        asset_id: "sha1:wrapper",
        kind: "external-script",
        url: wrapperUrl,
        content_path: "assets/trace_demo/secsdk-wrapper.js",
        content: "function onRequest(url) { return fetch(url); }"
      }
    ]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.deepEqual(materialFlow.stages.map((stage) => ({
    stage: stage.stage,
    runtime_apis: stage.runtime_apis,
    object_refs: stage.object_refs
  })), [
    {stage: "input_url", runtime_apis: ["URL.constructor"], object_refs: ["url_object:11", "search_params:12"]},
    {stage: "byte_buffer", runtime_apis: ["DataView.getUint32"], object_refs: ["data_view:21", "array_buffer:20"]},
    {stage: "integer_mixing", runtime_apis: ["Math.imul"], object_refs: ["data_view:21", "mix_state:30"]},
    {stage: "signed_request", runtime_apis: ["Request.constructor"], object_refs: ["url_object:11", "search_params:12"]}
  ]);
  assert.deepEqual(materialFlow.data_links, [
    {from: "input_url", to: "signed_request", refs: ["url_object:11", "search_params:12"]},
    {from: "byte_buffer", to: "integer_mixing", refs: ["data_view:21"]}
  ]);
  assert.deepEqual(materialFlow.analysis_readiness.evidence_gaps, ["signature_mutation_not_observed"]);
});

test("buildLocalReport carries JSON serialization into candidate material flows", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk-json.js";
  const stack = [{
    function: "signJson",
    url: scriptUrl,
    line: 3,
    column: 12,
    asset_id: "sha1:json-material",
    asset_path: "assets/trace_demo/runtime-sdk-json.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6"}], stack},
    {seq: 11, category: "reverse", phase: "call", api: "JSON.stringify", args: [{input_type: "object", result_length: 42, result_truncated: false}], stack},
    {seq: 12, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_ref: "string_ref:json-body", input_length: 42, result_length: 42, result_array_buffer_id: 72}], stack},
    {seq: 13, category: "reverse", phase: "call", api: "SubtleCrypto.digest", args: [{operation_id: 2001, algorithm: "SHA-256", input_ref: "bytes_sha1:json-body", array_buffer_id: 72, byte_length: 42}], stack},
    {seq: 14, category: "reverse", phase: "return", api: "SubtleCrypto.digest", args: [{operation_id: 2001, result_type: "array_buffer", result_ref: "bytes_sha1:json-digest", result_array_buffer_id: 73, byte_length: 32}], stack: []},
    {seq: 15, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/list?count=6&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_json_material_flow.ndjson",
    events,
    assets: [{
      asset_id: "sha1:json-material",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk-json.js",
      content: "function signJson(payload){ const body = JSON.stringify(payload); return crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)); }"
    }]
  });

  const jsonPoint = report.vmp.analysis_points.find((point) => point.type === "vmp_json_serialization");
  assert.equal(jsonPoint.event_count, 1);
  assert.deepEqual(report.vmp.families.find((item) => item.family === "json_serialization"), {
    family: "json_serialization",
    count: 1
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  assert.deepEqual(materialFlow.stages.map((stage) => stage.stage), [
    "input_url",
    "json_serialization",
    "text_or_string_decode",
    "hash_or_digest",
    "signed_request"
  ]);
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const parameter = analysis.parameters.find((item) => item.param === "X-Signature");
  const logic = parameter.candidate_generation_summary.logic_hypothesis;
  assert.equal(logic.status, "direct_webcrypto_chain_observed");
  assert.equal(logic.critical_path.status, "direct_webcrypto_path_observed");
  assert.ok(!logic.open_questions.includes("missing_vmp_execution"));
  assert.ok(!logic.open_questions.includes("which_runtime_values_flow_between_observed_phases"));
  assert.ok(!logic.open_questions.includes("dataflow_vmp_operation_subgraph_not_observed"));
  assert.ok(!logic.open_questions.includes("which_vmp_handler_produces_signature_material"));
  assert.ok(parameter.candidate_generation_summary.next_actions.includes("capture_url_search_params_mutation_or_header_set"));
  assert.ok(!parameter.candidate_generation_summary.next_actions.includes("expand_vmp_runtime_hooks"));
  assert.ok(!parameter.candidate_generation_summary.unresolved_gaps.includes("vmp_operation_subgraph_not_observed"));
  assert.ok(!parameter.candidate_generation_summary.unresolved_gaps.includes("vmp_pattern_not_ranked"));
  assert.ok(!parameter.candidate_generation_summary.dataflow_gaps.includes("vmp_operation_subgraph_not_observed"));
  assert.equal(parameter.generation_graph.dataflow_summary.status, "direct_webcrypto_operation_path");
  assert.deepEqual(parameter.generation_graph.dataflow_summary.gaps, []);
  assert.deepEqual(parameter.generation_graph.dataflow_summary.next_actions, ["capture_url_search_params_mutation_or_header_set"]);
  assert.equal(parameter.reconstruction_recipe.status, "direct_webcrypto_reconstruction_candidate");
  assert.equal(parameter.reconstruction_recipe.attachment.status, "observed");
  assert.deepEqual(parameter.reconstruction_recipe.attachment.output_links, [{
    opgraph_id: "webcrypto_X-Signature",
    output_ref: "bytes_sha1:json-digest",
    to_node_id: "step_5_signed_request",
    relation: "webcrypto_result_ref_on_request_path",
    confidence: "medium"
  }, {
    opgraph_id: "webcrypto_X-Signature",
    output_ref: "array_buffer:73",
    to_node_id: "step_5_signed_request",
    relation: "webcrypto_result_ref_on_request_path",
    confidence: "medium"
  }]);
  assert.deepEqual(parameter.reconstruction_recipe.evidence_gaps, []);
  assert.ok(parameter.reconstruction_recipe.next_actions.includes("capture_url_search_params_mutation_or_header_set"));
  assert.ok(!parameter.reconstruction_recipe.next_actions.includes("expand_vmp_runtime_hooks"));
  const [digestProgram] = parameter.reconstruction_recipe.operation_programs;
  assert.ok(digestProgram);
  assert.equal(digestProgram.chain_id, "direct_webcrypto_X-Signature");
  assert.equal(digestProgram.stage, "hash_or_digest");
  assert.equal(digestProgram.attached_node_id, "step_4_hash_or_digest");
  assert.equal(digestProgram.pattern, "webcrypto_digest");
  assert.deepEqual(digestProgram.output_refs, ["bytes_sha1:json-digest", "array_buffer:73"]);
  assert.deepEqual(digestProgram.output_bindings, [{
    output_ref: "bytes_sha1:json-digest",
    operation_id: "webcrypto_operation_2001_return",
    target_stage: "signed_request",
    target_node_id: "step_5_signed_request",
    request_node_ids: ["step_5_signed_request"],
    relation: "webcrypto_result_ref_on_request_path",
    confidence: "medium",
    target_params: ["X-Signature"],
    evidence: ["webcrypto_output_link", "request_attachment_link"]
  }, {
    output_ref: "array_buffer:73",
    operation_id: "webcrypto_operation_2001_return",
    target_stage: "signed_request",
    target_node_id: "step_5_signed_request",
    request_node_ids: ["step_5_signed_request"],
    relation: "webcrypto_result_ref_on_request_path",
    confidence: "medium",
    target_params: ["X-Signature"],
    evidence: ["webcrypto_output_link", "request_attachment_link"]
  }]);
  assert.deepEqual(digestProgram.lines, [
    "op1=SubtleCrypto.digest[call role=digest_input op=operation:2001 alg=SHA-256](bytes_sha1:json-body,array_buffer:72)->operation:2001",
    "op2=SubtleCrypto.digest[return role=digest_output op=operation:2001](operation:2001)->bytes_sha1:json-digest"
  ]);
  assert.deepEqual(digestProgram.edges, [{
    from: "webcrypto_operation_2001_call",
    to: "webcrypto_operation_2001_return",
    via_ref: "operation:2001"
  }]);
  assert.deepEqual(digestProgram.input_bindings, [{
    input_ref: "bytes_sha1:json-body",
    operation_id: "webcrypto_operation_2001_call",
    role: "digest_input",
    source_stage: "hash_or_digest",
    source_order: 4,
    source_refs: ["sha1:json-material:1-1"],
    request_input_categories: ["url_query"],
    target_params: ["X-Signature"],
    evidence: ["webcrypto_input_ref"]
  }, {
    input_ref: "array_buffer:72",
    operation_id: "webcrypto_operation_2001_call",
    role: "digest_input",
    source_stage: "text_or_string_decode",
    source_order: 3,
    source_refs: ["sha1:json-material:1-1"],
    request_input_categories: ["url_query"],
    target_params: ["X-Signature"],
    evidence: ["shared_runtime_ref", "webcrypto_input_ref"]
  }]);
  assert.deepEqual(parameter.reconstruction_recipe.algorithm_outline.lines.slice(0, 5), [
    "input1=bytes_sha1:json-body=>webcrypto_operation_2001_call[digest_input stage=hash_or_digest]",
    "input2=array_buffer:72=>webcrypto_operation_2001_call[digest_input stage=text_or_string_decode]",
    "program1=direct_webcrypto_X-Signature:hash_or_digest pattern=webcrypto_digest",
    "op1=SubtleCrypto.digest[call role=digest_input op=operation:2001 alg=SHA-256](bytes_sha1:json-body,array_buffer:72)->operation:2001",
    "op2=SubtleCrypto.digest[return role=digest_output op=operation:2001](operation:2001)->bytes_sha1:json-digest"
  ]);
  assert.ok(parameter.reconstruction_recipe.algorithm_outline.lines.some((line) =>
    line === "attach1=bytes_sha1:json-digest->signed_request[step_5_signed_request confidence=medium]"
  ));
  assert.ok(!analysis.next_capture_focus.some((item) => item.action === "expand_vmp_runtime_hooks"));
  assert.ok(!analysis.native_capture_requirements.some((item) => item.action === "expand_vmp_runtime_hooks"));
  assert.equal(parameter.vmp_state_model.status, "not_applicable");
  assert.deepEqual(parameter.vmp_state_model.unresolved_gaps, []);
  assert.deepEqual(parameter.vmp_state_model.next_actions, []);
  const markdown = renderAgentAnalysisMarkdown(analysis);
  assert.doesNotMatch(markdown, /expand_vmp_runtime_hooks/);
  const vmpPhase = logic.phases.find((phase) => phase.id === "vmp_execution");
  assert.equal(vmpPhase.status, "not_applicable");
  assert.equal(vmpPhase.confidence, "not_applicable");
  assert.ok(vmpPhase.evidence.includes("direct_webcrypto_operation_path"));
  const digestPhase = parameter.candidate_generation_summary.logic_hypothesis.phases
    .find((phase) => phase.id === "mixing_or_hash");
  assert.deepEqual(
    digestPhase.webcrypto_operations.map((operation) => ({
      api: operation.api,
      phase: operation.phase,
      seq: operation.seq,
      operation_ref: operation.operation_ref,
      role: operation.role,
      input_ref: operation.input_ref || "",
      result_ref: operation.result_ref || ""
    })),
    [
      {
        api: "SubtleCrypto.digest",
        phase: "call",
        seq: 13,
        operation_ref: "operation:2001",
        role: "digest_input",
        input_ref: "bytes_sha1:json-body",
        result_ref: ""
      },
      {
        api: "SubtleCrypto.digest",
        phase: "return",
        seq: 14,
        operation_ref: "operation:2001",
        role: "digest_output",
        input_ref: "",
        result_ref: "bytes_sha1:json-digest"
      }
    ]
  );
  const inputEdge = parameter.candidate_generation_summary.logic_hypothesis.phase_edges.find((edge) =>
    edge.from_phase === "input_material" && edge.to_phase === "mixing_or_hash"
  );
  assert.ok(inputEdge.refs.includes("bytes_sha1:json-body"));
  assert.ok(inputEdge.refs.includes("operation:2001"));
  assert.ok(inputEdge.evidence.includes("webcrypto_input_ref:bytes_sha1:json-body"));
  assert.ok(inputEdge.evidence.includes("webcrypto_operation_ref:operation:2001"));
  const outputEdge = parameter.candidate_generation_summary.logic_hypothesis.phase_edges.find((edge) =>
    edge.from_phase === "mixing_or_hash" && edge.to_phase === "signature_attachment"
  );
  assert.ok(outputEdge.refs.includes("bytes_sha1:json-digest"));
  assert.ok(outputEdge.refs.includes("operation:2001"));
  assert.ok(outputEdge.evidence.includes("webcrypto_result_ref:bytes_sha1:json-digest"));
  assert.ok(outputEdge.evidence.includes("webcrypto_operation_ref:operation:2001"));
  assert.match(
    markdown,
    /webcrypto_ops=SubtleCrypto\.digest@13:call\[role=digest_input op=operation:2001 alg=SHA-256 input=bytes_sha1:json-body input_buffer=array_buffer:72\]->SubtleCrypto\.digest@14:return\[role=digest_output op=operation:2001 result=bytes_sha1:json-digest result_buffer=array_buffer:73\]/
  );
  assert.match(
    markdown,
    /logic=direct_webcrypto_chain_observed critical_path=direct_webcrypto_path_observed/
  );
  assert.match(
    markdown,
    /logic_step=2:vmp_execution\[not_applicable\/not_applicable\]/
  );
  assert.match(
    markdown,
    /recipe=direct_webcrypto_reconstruction_candidate[^\n]+ops=direct_webcrypto_X-Signature:op1=SubtleCrypto\.digest\[call role=digest_input op=operation:2001 alg=SHA-256\]\(bytes_sha1:json-body,array_buffer:72\)->operation:2001\|op2=SubtleCrypto\.digest\[return role=digest_output op=operation:2001\]\(operation:2001\)->bytes_sha1:json-digest alg=input1=bytes_sha1:json-body=>webcrypto_operation_2001_call\[digest_input stage=hash_or_digest\]\|input2=array_buffer:72=>webcrypto_operation_2001_call\[digest_input stage=text_or_string_decode\]\|program1=direct_webcrypto_X-Signature:hash_or_digest pattern=webcrypto_digest\|op1=SubtleCrypto\.digest\[call role=digest_input op=operation:2001 alg=SHA-256\]\(bytes_sha1:json-body,array_buffer:72\)->operation:2001\|op2=SubtleCrypto\.digest\[return role=digest_output op=operation:2001\]\(operation:2001\)->bytes_sha1:json-digest\|attach1=bytes_sha1:json-digest->signed_request\[step_5_signed_request confidence=medium\] inputs=bytes_sha1:json-body->webcrypto_operation_2001_call\[digest_input from=hash_or_digest request=url_query\]\|array_buffer:72->webcrypto_operation_2001_call\[digest_input from=text_or_string_decode request=url_query\] outputs=bytes_sha1:json-digest<-webcrypto_operation_2001_return\[webcrypto_result_ref_on_request_path to=signed_request request=step_5_signed_request\]\|array_buffer:73<-webcrypto_operation_2001_return\[webcrypto_result_ref_on_request_path to=signed_request request=step_5_signed_request\] attach=observed flow=direct_webcrypto_operation_path output_links=bytes_sha1:json-digest\|array_buffer:73 request_links=step_4_hash_or_digest->step_5_signed_request/
  );
});

test("buildLocalReport treats SubtleCrypto sign and importKey as signature material", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk-crypto.js";
  const stack = [{
    function: "signWithKey",
    url: scriptUrl,
    line: 9,
    column: 16,
    asset_id: "sha1:crypto-material",
    asset_path: "assets/trace_demo/runtime-sdk-crypto.js"
  }];
  const events = [
    {seq: 20, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 44, search_params_id: 45, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 21, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_ref: "string_ref:canonical-request", result_array_buffer_id: 82}], stack},
    {seq: 22, category: "reverse", phase: "call", api: "SubtleCrypto.importKey", args: [{operation_id: 1001, algorithm: "HMAC", format: "raw", key_data_length: 32, key_data_ref: "bytes_sha1:key-material", key_usages_mask: 4}], stack},
    {seq: 23, category: "reverse", phase: "return", api: "SubtleCrypto.importKey", args: [{operation_id: 1001, result_type: "crypto_key", key_ref: "crypto_key:7001", key_handle_id: 7001, key_algorithm: "HMAC", key_type: "secret"}], stack: []},
    {seq: 24, category: "reverse", phase: "call", api: "SubtleCrypto.sign", args: [{operation_id: 1002, algorithm: "HMAC", key_algorithm: "HMAC", key_type: "secret", key_ref: "crypto_key:7001", input_ref: "bytes_sha1:canonical-request", array_buffer_id: 82, byte_length: 96}], stack},
    {seq: 25, category: "reverse", phase: "return", api: "SubtleCrypto.sign", args: [{operation_id: 1002, result_type: "array_buffer", result_ref: "bytes_sha1:signature-output", result_array_buffer_id: 83, byte_length: 32}], stack: []},
    {seq: 26, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 44, search_params_id: 45, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_sign_material_flow.ndjson",
    events,
    assets: [{
      asset_id: "sha1:crypto-material",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk-crypto.js",
      content: "async function signWithKey(body,key){ const k=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']); return crypto.subtle.sign('HMAC',k,body); }"
    }]
  });

  const hashPoint = report.vmp.analysis_points.find((point) => point.type === "vmp_hash_or_signature_pipeline");
  assert.ok(hashPoint.apis.some((item) => item.api === "SubtleCrypto.importKey"));
  assert.ok(hashPoint.apis.some((item) => item.api === "SubtleCrypto.sign"));
  assert.deepEqual(report.vmp.families.find((item) => item.family === "hash_crypto"), {
    family: "hash_crypto",
    count: 4
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const hashStage = materialFlow.stages.find((stage) => stage.stage === "hash_or_digest");
  assert.ok(hashStage);
  assert.ok(hashStage.runtime_apis.includes("SubtleCrypto.importKey"));
  assert.ok(hashStage.runtime_apis.includes("SubtleCrypto.sign"));
  assert.ok(hashStage.object_refs.includes("operation:1001"));
  assert.ok(hashStage.object_refs.includes("operation:1002"));
  assert.ok(hashStage.object_refs.includes("array_buffer:83"));
  assert.ok(hashStage.value_refs.includes("crypto_key:7001"));
  assert.ok(hashStage.value_refs.includes("bytes_sha1:signature-output"));

  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");
  assert.ok(packParameter.webcrypto_signature_summary);
  assert.ok(packParameter.webcrypto_signature_summary.observed);
  assert.deepEqual(packParameter.webcrypto_signature_summary.apis, [
    "SubtleCrypto.importKey",
    "SubtleCrypto.sign"
  ]);
  assert.deepEqual(packParameter.webcrypto_signature_summary.operation_refs, [
    "operation:1001",
    "operation:1002"
  ]);
  assert.deepEqual(packParameter.webcrypto_signature_summary.key_refs, ["crypto_key:7001"]);
  assert.deepEqual(packParameter.webcrypto_signature_summary.key_material_refs, ["bytes_sha1:key-material"]);
  assert.deepEqual(packParameter.webcrypto_signature_summary.input_refs, ["bytes_sha1:canonical-request"]);
  assert.deepEqual(packParameter.webcrypto_signature_summary.result_refs, ["bytes_sha1:signature-output"]);
  assert.deepEqual(packParameter.webcrypto_signature_summary.result_array_buffer_refs, ["array_buffer:83"]);
  assert.deepEqual(
    packParameter.webcrypto_signature_summary.operations.map((operation) => ({
      api: operation.api,
      phase: operation.phase,
      seq: operation.seq,
      operation_ref: operation.operation_ref,
      algorithm: operation.algorithm
    })),
    [
      {
        api: "SubtleCrypto.importKey",
        phase: "call",
        seq: 22,
        operation_ref: "operation:1001",
        algorithm: "HMAC"
      },
      {
        api: "SubtleCrypto.importKey",
        phase: "return",
        seq: 23,
        operation_ref: "operation:1001",
        algorithm: "HMAC"
      },
      {
        api: "SubtleCrypto.sign",
        phase: "call",
        seq: 24,
        operation_ref: "operation:1002",
        algorithm: "HMAC"
      },
      {
        api: "SubtleCrypto.sign",
        phase: "return",
        seq: 25,
        operation_ref: "operation:1002",
        algorithm: ""
      }
    ]
  );
  assert.deepEqual(
    analysisParameter.candidate_generation_summary.webcrypto_signature_summary,
    packParameter.webcrypto_signature_summary
  );
  const webcryptoLogicPhases = new Map(
    analysisParameter.candidate_generation_summary.logic_hypothesis.phases
      .map((phase) => [phase.id, phase])
  );
  const webcryptoMixingPhase = webcryptoLogicPhases.get("mixing_or_hash");
  assert.ok(webcryptoMixingPhase);
  assert.deepEqual(webcryptoMixingPhase.stages, ["hash_or_digest"]);
  assert.ok(webcryptoMixingPhase.runtime_apis.includes("SubtleCrypto.importKey"));
  assert.ok(webcryptoMixingPhase.runtime_apis.includes("SubtleCrypto.sign"));
  assert.ok(webcryptoMixingPhase.value_refs.includes("crypto_key:7001"));
  assert.ok(webcryptoMixingPhase.value_refs.includes("bytes_sha1:signature-output"));
  assert.ok(webcryptoMixingPhase.evidence.includes("webcrypto_operation:SubtleCrypto.importKey"));
  assert.ok(webcryptoMixingPhase.evidence.includes("webcrypto_operation:SubtleCrypto.sign"));
  assert.ok(webcryptoMixingPhase.evidence.includes("webcrypto_key_ref:crypto_key:7001"));
  assert.ok(webcryptoMixingPhase.evidence.includes("webcrypto_key_material_ref:bytes_sha1:key-material"));
  assert.ok(webcryptoMixingPhase.evidence.includes("webcrypto_input_ref:bytes_sha1:canonical-request"));
  assert.ok(webcryptoMixingPhase.evidence.includes("webcrypto_result_ref:bytes_sha1:signature-output"));
  assert.deepEqual(
    webcryptoMixingPhase.webcrypto_operations.map((operation) => ({
      api: operation.api,
      phase: operation.phase,
      seq: operation.seq,
      operation_ref: operation.operation_ref,
      role: operation.role,
      key_ref: operation.key_ref || "",
      key_material_ref: operation.key_material_ref || "",
      input_ref: operation.input_ref || "",
      result_ref: operation.result_ref || ""
    })),
    [
      {
        api: "SubtleCrypto.importKey",
        phase: "call",
        seq: 22,
        operation_ref: "operation:1001",
        role: "key_material_input",
        key_ref: "",
        key_material_ref: "bytes_sha1:key-material",
        input_ref: "",
        result_ref: ""
      },
      {
        api: "SubtleCrypto.importKey",
        phase: "return",
        seq: 23,
        operation_ref: "operation:1001",
        role: "key_handle_output",
        key_ref: "crypto_key:7001",
        key_material_ref: "",
        input_ref: "",
        result_ref: ""
      },
      {
        api: "SubtleCrypto.sign",
        phase: "call",
        seq: 24,
        operation_ref: "operation:1002",
        role: "signature_input",
        key_ref: "crypto_key:7001",
        key_material_ref: "",
        input_ref: "bytes_sha1:canonical-request",
        result_ref: ""
      },
      {
        api: "SubtleCrypto.sign",
        phase: "return",
        seq: 25,
        operation_ref: "operation:1002",
        role: "signature_output",
        key_ref: "",
        key_material_ref: "",
        input_ref: "",
        result_ref: "bytes_sha1:signature-output"
      }
    ]
  );
  const webcryptoLogicStep = analysisParameter.candidate_generation_summary.logic_hypothesis.agent_logic_trace.steps
    .find((step) => step.phase === "mixing_or_hash");
  assert.ok(webcryptoLogicStep.evidence.includes("webcrypto_operation:SubtleCrypto.sign"));
  assert.deepEqual(
    webcryptoLogicStep.webcrypto_operations.map((operation) => operation.role),
    ["key_material_input", "key_handle_output", "signature_input", "signature_output"]
  );
  const webcryptoLogic = analysisParameter.candidate_generation_summary.logic_hypothesis;
  const webcryptoInputEdge = webcryptoLogic.phase_edges.find((edge) =>
    edge.from_phase === "input_material" && edge.to_phase === "mixing_or_hash"
  );
  assert.ok(webcryptoInputEdge);
  assert.ok(webcryptoInputEdge.refs.includes("bytes_sha1:canonical-request"));
  assert.ok(webcryptoInputEdge.refs.includes("bytes_sha1:key-material"));
  assert.ok(webcryptoInputEdge.evidence.includes("webcrypto_input_ref:bytes_sha1:canonical-request"));
  assert.ok(webcryptoInputEdge.evidence.includes("webcrypto_key_material_ref:bytes_sha1:key-material"));
  const webcryptoOutputEdge = webcryptoLogic.phase_edges.find((edge) =>
    edge.from_phase === "mixing_or_hash" && edge.to_phase === "signature_attachment"
  );
  assert.ok(webcryptoOutputEdge);
  assert.ok(webcryptoOutputEdge.refs.includes("bytes_sha1:signature-output"));
  assert.ok(webcryptoOutputEdge.refs.includes("operation:1002"));
  assert.ok(webcryptoOutputEdge.evidence.includes("webcrypto_result_ref:bytes_sha1:signature-output"));
  assert.ok(webcryptoOutputEdge.evidence.includes("webcrypto_operation_ref:operation:1002"));
  const webcryptoTraceOutputEdge = webcryptoLogic.agent_logic_trace.edges.find((edge) =>
    edge.from_phase === "mixing_or_hash" && edge.to_phase === "signature_attachment"
  );
  assert.ok(webcryptoTraceOutputEdge.evidence.includes("webcrypto_result_ref:bytes_sha1:signature-output"));
  const [signProgram] = analysisParameter.reconstruction_recipe.operation_programs;
  assert.ok(signProgram);
  assert.equal(signProgram.chain_id, "direct_webcrypto_X-Signature");
  assert.equal(signProgram.stage, "hash_or_digest");
  assert.equal(signProgram.attached_node_id, "step_3_hash_or_digest");
  assert.equal(signProgram.pattern, "webcrypto_importKey_sign");
  assert.deepEqual(signProgram.output_refs, ["bytes_sha1:signature-output", "array_buffer:83", "crypto_key:7001"]);
  assert.deepEqual(signProgram.lines, [
    "op1=SubtleCrypto.importKey[call role=key_material_input op=operation:1001 alg=HMAC](bytes_sha1:key-material)->operation:1001",
    "op2=SubtleCrypto.importKey[return role=key_handle_output op=operation:1001 alg=HMAC](operation:1001)->crypto_key:7001",
    "op3=SubtleCrypto.sign[call role=signature_input op=operation:1002 alg=HMAC](crypto_key:7001,bytes_sha1:canonical-request,array_buffer:82)->operation:1002",
    "op4=SubtleCrypto.sign[return role=signature_output op=operation:1002](operation:1002)->bytes_sha1:signature-output"
  ]);
  assert.ok(signProgram.edges.some((edge) =>
    edge.from === "webcrypto_operation_1001_return" &&
    edge.to === "webcrypto_operation_1002_call" &&
    edge.via_ref === "crypto_key:7001"
  ));
  assert.ok(signProgram.input_bindings.some((binding) =>
    binding.input_ref === "array_buffer:82" &&
    binding.operation_id === "webcrypto_operation_1002_call" &&
    binding.role === "signature_input" &&
    binding.source_stage === "text_or_string_decode" &&
    binding.request_input_categories.includes("url_query") &&
    binding.evidence.includes("shared_runtime_ref")
  ));
  assert.ok(signProgram.input_bindings.some((binding) =>
    binding.input_ref === "bytes_sha1:key-material" &&
    binding.operation_id === "webcrypto_operation_1001_call" &&
    binding.role === "key_material_input" &&
    binding.source_stage === "hash_or_digest" &&
    binding.evidence.includes("webcrypto_input_ref")
  ));
  assert.ok(signProgram.input_bindings.some((binding) =>
    binding.input_ref === "bytes_sha1:canonical-request" &&
    binding.operation_id === "webcrypto_operation_1002_call" &&
    binding.role === "signature_input" &&
    binding.source_stage === "hash_or_digest" &&
    binding.request_input_categories.includes("url_query")
  ));
  assert.equal(analysisParameter.reconstruction_recipe.attachment.status, "observed");
  assert.ok(analysisParameter.reconstruction_recipe.attachment.output_links.some((link) =>
    link.opgraph_id === "webcrypto_X-Signature" &&
    link.output_ref === "bytes_sha1:signature-output" &&
    link.to_node_id === "step_4_signed_request" &&
    link.relation === "webcrypto_result_ref_on_request_path" &&
    link.confidence === "medium"
  ));
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /logic_step=3:mixing_or_hash\[[^\]]+\][^\n]+evidence=[^\n]*webcrypto_operation:SubtleCrypto\.sign/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /logic_edge=\d+:mixing_or_hash->signature_attachment\[[^\]]+\][^\n]+evidence=[^\n]*webcrypto_result_ref:bytes_sha1:signature-output/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /webcrypto_ops=SubtleCrypto\.importKey@22:call\[role=key_material_input op=operation:1001 alg=HMAC key_material=bytes_sha1:key-material\]->SubtleCrypto\.importKey@23:return\[role=key_handle_output op=operation:1001 alg=HMAC key=crypto_key:7001\]->SubtleCrypto\.sign@24:call\[role=signature_input op=operation:1002 alg=HMAC key=crypto_key:7001 input=bytes_sha1:canonical-request input_buffer=array_buffer:82\]->SubtleCrypto\.sign@25:return\[role=signature_output op=operation:1002 result=bytes_sha1:signature-output result_buffer=array_buffer:83\]/
  );
  assert.equal(
    analysisParameter.candidate_generation_summary.capture_completeness.checklist
      .find((item) => item.item === "mixing_runtime_observed")
      .status,
    "observed"
  );
  assert.match(
    renderAgentInputPackMarkdown(pack),
    /webcrypto=apis=SubtleCrypto\.importKey\|SubtleCrypto\.sign ops=operation:1001\|operation:1002 key_refs=crypto_key:7001 input_refs=bytes_sha1:canonical-request result_refs=bytes_sha1:signature-output/
  );
});

test("buildLocalReport carries request headers and body boundaries into material flows", () => {
  const scriptUrl = "https://cdn.example.test/runtime-sdk-xhr.js";
  const stack = [{
    function: "sendSignedXhr",
    url: scriptUrl,
    line: 6,
    column: 18,
    asset_id: "sha1:xhr-material",
    asset_path: "assets/trace_demo/runtime-sdk-xhr.js"
  }];
  const events = [
    {_trace_index: 1, seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {_trace_index: 2, seq: 2, category: "reverse", phase: "call", api: "JSON.stringify", args: [{input_type: "object", result_length: 37, result_truncated: false}], stack},
    {_trace_index: 3, seq: 3, category: "reverse", phase: "call", api: "XMLHttpRequest.open", args: [{method: "POST", url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one", network_correlation_key: "sha1:xhr"}], stack},
    {_trace_index: 4, seq: 4, category: "reverse", phase: "call", api: "XMLHttpRequest.setRequestHeader", args: [{name: "X-Signature", value: "secret-one", xhr_id: 77, network_correlation_key: "sha1:xhr"}], stack},
    {_trace_index: 5, seq: 5, category: "reverse", phase: "call", api: "XMLHttpRequest.send", args: [{method: "POST", url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one", body_size: 37, body_preview: "{\"cursor\":\"1\"}", network_correlation_key: "sha1:xhr"}], stack},
    {
      _trace_index: 6,
      seq: 6,
      category: "network",
      phase: "call",
      api: "BrowserNetwork.request",
      args: [{
        method: "POST",
        url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
        network_correlation_key: "sha1:xhr",
        is_fetch_like_api: true,
        headers: [{name: "x-signature", value: "secret-one"}],
        has_request_body: true,
        upload_body: {element_count: 1, total_bytes: 37, in_memory_bytes: 37, truncated: false}
      }],
      stack: []
    }
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_xhr_material_flow.ndjson",
    events,
    assets: [{
      asset_id: "sha1:xhr-material",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk-xhr.js",
      content: "function sendSignedXhr(url,payload){ const body=JSON.stringify(payload); xhr.setRequestHeader('X-Signature', sign(body)); xhr.send(body); }"
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  assert.deepEqual(materialFlow.stages.map((stage) => stage.stage), [
    "input_url",
    "request_construction",
    "json_serialization",
    "request_headers",
    "request_body",
    "signed_request"
  ]);
  assert.deepEqual(materialFlow.stages.find((stage) => stage.stage === "request_headers").runtime_apis, [
    "XMLHttpRequest.setRequestHeader"
  ]);
  assert.deepEqual(materialFlow.stages.find((stage) => stage.stage === "request_body").runtime_apis, [
    "BrowserNetwork.request",
    "XMLHttpRequest.send"
  ]);
  assert.deepEqual(materialFlow.renderer_request_link.match, "network_correlation_key");
  assert.deepEqual(materialFlow.request_context.upload, {
    element_count: 1,
    total_bytes: 37,
    in_memory_bytes: 37
  });
  assert.deepEqual(materialFlow.signature_attachment_events, [{
    seq: 4,
    api: "XMLHttpRequest.setRequestHeader",
    phase: "request_headers",
    action: "set_header",
    target_params: ["X-Signature"],
    object_refs: ["xhr:77", "network_request:sha1:xhr"],
    value_refs: []
  }]);
  const headerStep = materialFlow.generation_steps.find((step) => step.stage === "request_headers");
  assert.deepEqual({
    stage: headerStep.stage,
    role: headerStep.role,
    runtime_apis: headerStep.runtime_apis,
    target_params: headerStep.target_params,
    object_refs: headerStep.object_refs,
    attachment_events: headerStep.attachment_events
  }, {
    stage: "request_headers",
    role: "request_metadata",
    runtime_apis: ["XMLHttpRequest.setRequestHeader"],
    target_params: ["X-Signature"],
    object_refs: ["xhr:77", "network_request:sha1:xhr"],
    attachment_events: [{
      seq: 4,
      api: "XMLHttpRequest.setRequestHeader",
      action: "set_header",
      target_params: ["X-Signature"],
      object_refs: ["xhr:77", "network_request:sha1:xhr"],
      value_refs: ["target_params:X-Signature"]
    }]
  });
  assert.ok(headerStep.evidence.includes("attachment_event"));
  assert.ok(headerStep.evidence.includes("object_ref"));
  assert.ok(headerStep.evidence.includes("value_ref"));
  assert.ok(headerStep.source_locations.some((location) =>
    location.asset_id === "sha1:xhr-material" &&
    location.url === scriptUrl &&
    location.calls.includes("xhr.setRequestHeader")
  ));
  assert.ok(materialFlow.parameter_attachment_graph.edges.some((edge) =>
    edge.from === "param:X-Signature" &&
    edge.to === "attach:4" &&
    edge.relation === "attached_by" &&
    edge.evidence === "XMLHttpRequest.setRequestHeader@4"
  ));
  assert.ok(materialFlow.parameter_attachment_graph.edges.some((edge) =>
    edge.from === "ref:network_request:sha1:xhr" &&
    edge.to === "stage:signed_request" &&
    edge.relation === "flows_to_stage"
  ));
  assert.ok(!materialFlow.analysis_readiness.evidence_gaps.includes("signature_mutation_not_observed"));
});

test("request input bundle links browser headers by network correlation key without renderer link", () => {
  const rendererRequest = {
    _trace_index: 40,
    seq: 400,
    category: "network",
    phase: "call",
    api: "Request.constructor",
    args: [{
      method: "GET",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      network_correlation_key: "sha1:browser-header-link"
    }],
    stack: [{
      function: "sign",
      url: "https://cdn.example.test/runtime-sdk.js",
      line: 4,
      column: 10,
      asset_id: "sha1:browser-header-link"
    }]
  };
  const browserRequest = {
    _trace_index: 43,
    seq: 12,
    category: "network",
    phase: "call",
    api: "BrowserNetwork.request",
    args: [{
      method: "GET",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      network_correlation_key: "sha1:browser-header-link",
      headers: [
        {name: "Accept-Language", value: "en-US,en;q=0.9", value_length: 14},
        {name: "Cookie", redacted: true, value_length: 64}
      ]
    }],
    stack: []
  };

  const bundle = __testHooks.buildRequestInputBundleForMaterialFlow({
    endpoint: "https://www.example.test/api/feed/list",
    target_params: ["X-Signature"],
    _request_input_event_windows: [{
      phase: "signed_request",
      events: [{seq: 400, api: "Request.constructor"}]
    }]
  }, [
    rendererRequest,
    browserRequest
  ]);

  assert.ok(bundle.headers.observed);
  assert.deepEqual(bundle.headers.header_names, ["accept-language", "cookie"]);
  assert.deepEqual(bundle.headers.sensitive_header_names, ["cookie"]);
  assert.deepEqual(bundle.headers.evidence_refs, ["headers:BrowserNetwork.request@12"]);
  assert.ok(!bundle.capture_gaps.includes("request_headers_not_captured"));
});

test("request input bundle links browser response metadata by network correlation key", () => {
  const rendererRequest = {
    _trace_index: 40,
    seq: 400,
    category: "network",
    phase: "call",
    api: "Request.constructor",
    args: [{
      method: "GET",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      network_correlation_key: "sha1:browser-response-link"
    }],
    stack: [{
      function: "sign",
      url: "https://cdn.example.test/runtime-sdk.js",
      line: 4,
      column: 10,
      asset_id: "sha1:browser-response-link"
    }]
  };
  const browserRequest = {
    _trace_index: 43,
    seq: 12,
    category: "network",
    phase: "call",
    api: "BrowserNetwork.request",
    args: [{
      method: "GET",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      network_correlation_key: "sha1:browser-response-link"
    }],
    stack: []
  };
  const browserResponse = {
    _trace_index: 44,
    seq: 13,
    category: "network",
    phase: "return",
    api: "BrowserNetwork.response",
    args: [{
      method: "GET",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      network_correlation_key: "sha1:browser-response-link",
      response_code: 200,
      status_line: "HTTP/1.1 200 OK",
      mime_type: "application/json",
      encoded_data_length: 512,
      response_headers: [
        {name: "content-type", value: "application/json", value_length: 16},
        {name: "set-cookie", redacted: true, value_length: 64}
      ]
    }],
    stack: []
  };

  const bundle = __testHooks.buildRequestInputBundleForMaterialFlow({
    endpoint: "https://www.example.test/api/feed/list",
    target_params: ["X-Signature"],
    _request_input_event_windows: [{
      phase: "signed_request",
      events: [{seq: 400, api: "Request.constructor"}]
    }]
  }, [
    rendererRequest,
    browserRequest,
    browserResponse
  ]);

  assert.ok(bundle.response.observed);
  assert.equal(bundle.response.status_code, 200);
  assert.equal(bundle.response.mime_type, "application/json");
  assert.deepEqual(bundle.response.header_names, ["content-type", "set-cookie"]);
  assert.deepEqual(bundle.response.sensitive_header_names, ["set-cookie"]);
  assert.deepEqual(bundle.response.evidence_refs, ["response:BrowserNetwork.response@13"]);
  assert.ok(bundle.evidence_refs.includes("response:BrowserNetwork.response@13"));
});

test("buildLocalReport uses strongest endpoint material flow for capture status gaps", () => {
  const scriptUrl = "https://www.example.test/business-api-smoke.html";
  const stack = [
    {
      function: "makeDemoTraceMarker",
      url: scriptUrl,
      line: 20,
      column: 8,
      asset_id: "sha1:business-smoke",
      asset_path: "assets/trace_demo/business-api-smoke.html"
    }
  ];
  const requestStack = [
    {
      function: "run",
      url: scriptUrl,
      line: 45,
      column: 10,
      asset_id: "sha1:business-smoke",
      asset_path: "assets/trace_demo/business-api-smoke.html"
    }
  ];
  const events = [
    {seq: 7, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input: "local-material"}], stack},
    {seq: 8, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 21, array_buffer_id: 20, byte_offset: 0}], stack},
    {seq: 9, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left: 1, right: 2, result: 3}], stack},
    {seq: 10, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 3, y: 16777619, result: 42}], stack},
    {seq: 20, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1"}], stack: requestStack},
    {seq: 21, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 31, search_params_id: 32, name: "X-Signature", value: "secret-one"}], stack: requestStack},
    {seq: 22, category: "reverse", phase: "set", api: "URL.search.set", args: [{url_object_id: 31, search_params_id: 32, href: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack: requestStack},
    {seq: 23, category: "reverse", phase: "call", api: "Request.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one", network_correlation_key: "sha1:request"}], stack: requestStack},
    {seq: 24, category: "reverse", phase: "call", api: "fetch", args: [{url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack: requestStack},
    {seq: 25, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one", method: "GET", network_correlation_key: "sha1:request", is_fetch_like_api: true}], stack: requestStack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_business_material.ndjson",
    events,
    assets: [{
      asset_id: "sha1:business-smoke",
      kind: "inline-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/business-api-smoke.html",
      content: [
        "function makeDemoTraceMarker(seed) {",
        "  const bytes = new TextEncoder().encode(seed);",
        "  const view = new DataView(bytes.buffer);",
        "  return Math.imul(view.getUint32(0, true) ^ 2, 16777619);",
        "}",
        "function run(url) {",
        "  url.searchParams.set('X-Signature', makeDemoTraceMarker('local-material'));",
        "  return fetch(new Request(url.href));",
        "}"
      ].join("\n")
    }]
  });

  const plan = report.signature.agent_evidence_pack.next_capture_plan;
  const [endpoint] = plan.business_api_capture_status.endpoints;
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.equal(plan.capture_gate.status, "passed");
  assert.equal(endpoint.endpoint, "https://www.example.test/api/feed/list");
  assert.ok(endpoint.flow_count >= 2);
  assert.deepEqual(endpoint.evidence_gaps, []);
  assert.ok(materialFlow.stages.some((stage) => stage.stage === "input_url"));
  assert.ok(!materialFlow.analysis_readiness.evidence_gaps.includes("unsigned_input_not_observed"));
  assert.deepEqual(plan.capture_gate.remaining_analysis_gaps, []);
  assert.deepEqual(
    plan.capture_checklist.find((item) => item.id === "complete_material_linking"),
    {
      id: "complete_material_linking",
      status: "observed",
      priority: "medium",
      evidence: ["analysis_ready"],
      next_action: "review_agent_evidence_pack"
    }
  );
  assert.ok(!endpoint.evidence_gaps.includes("material_source_not_observed"));
  assert.ok(!endpoint.evidence_gaps.includes("mix_or_hash_not_observed"));
});

test("buildLocalReport surfaces source-only VMP dynamic dispatch in material flows", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk-local.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 8,
    column: 16,
    asset_id: "sha1:runtime-sdk-local",
    asset_path: "assets/trace_demo/runtime-sdk-local.js"
  }];
  const events = [
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 11, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input: "cursor=1"}], stack},
    {seq: 12, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 21, array_buffer_id: 20, byte_offset: 0}], stack},
    {seq: 13, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 3, y: 16777619, result: 42}], stack},
    {seq: 14, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 31, search_params_id: 32, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 15, category: "reverse", phase: "call", api: "Request.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack},
    {seq: 16, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one", method: "GET"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_source_dispatch.ndjson",
    events,
    assets: [{
      asset_id: "sha1:runtime-sdk-local",
      kind: "script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk-local.js",
      content: [
        "function signVm(url) {",
        "  const handlers = [function(vm){ return vm.seed; }, function(vm){ return vm.seed ^ 7; }, function(vm){ return vm.seed >>> 1; }];",
        "  const state = {seed: url.search.length};",
        "  const source = url.search;",
        "  const bytes = new TextEncoder().encode(source);",
        "  const dispatched = Reflect.apply(handlers[0], null, [state]) + Function.prototype.call.call(handlers[1], null, state) + Function.prototype.apply.call(handlers[2], null, [state]);",
        "  const view = new DataView(bytes.buffer);",
        "  const mix = Math.imul(view.getUint32(0, true) ^ dispatched, 16777619) >>> 0;",
        "  url.searchParams.set('X-Signature', `demo-${mix}`);",
        "  return fetch(new Request(url.href));",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const dynamicStage = materialFlow.stages.find((stage) => stage.stage === "dynamic_dispatch");
  const dynamicHookPoint = materialFlow.vmp_hook_points.find((point) => point.type === "vmp_dynamic_dispatch");

  assert.ok(dynamicStage);
  assert.deepEqual(dynamicStage.runtime_apis, []);
  assert.deepEqual(dynamicStage.source_calls, [
    "Reflect.apply",
    "Function.prototype.call.call",
    "Function.prototype.apply.call"
  ]);
  assert.deepEqual(dynamicStage.source_signals, ["prototype_call", "dynamic_dispatch"]);
  assert.equal(dynamicHookPoint.status, "source_observed");
  assert.deepEqual(dynamicHookPoint.observed_apis, []);
  assert.deepEqual(dynamicHookPoint.source_signals, ["prototype_call", "dynamic_dispatch"]);
  assert.deepEqual(dynamicHookPoint.source_calls, [
    "Reflect.apply",
    "Function.prototype.call.call",
    "Function.prototype.apply.call"
  ]);
  assert.deepEqual(materialFlow.agent_generation_summary.stage_chain, [
    "input_url",
    "byte_buffer",
    "dynamic_dispatch",
    "text_or_string_decode",
    "integer_mixing",
    "signature_mutation",
    "signed_request"
  ]);
  assert.equal(
    materialFlow.agent_generation_summary.summary_text,
    "input_url -> byte_buffer -> dynamic_dispatch -> text_or_string_decode -> integer_mixing -> signature_mutation -> signed_request"
  );
  assert.equal(materialFlow.agent_generation_summary.evidence_profile, "runtime_and_source");
  assert.deepEqual(materialFlow.agent_generation_summary.source_observed_hooks, ["vmp_dynamic_dispatch"]);
  assert.ok(materialFlow.agent_generation_summary.runtime_apis.includes("TextEncoder.encode"));
  assert.ok(materialFlow.agent_generation_summary.runtime_apis.includes("URLSearchParams.set"));
  assert.ok(materialFlow.agent_generation_summary.source_calls.includes("Reflect.apply"));
  assert.ok(materialFlow.agent_generation_summary.source_calls.includes("Function.prototype.call.call"));
  assert.deepEqual(materialFlow.agent_generation_summary.attachment_params, ["X-Signature"]);
  assert.equal(dynamicHookPoint.next_action, "review_source_context_or_add_runtime_hook");
  assert.match(renderMarkdownReport(report), /dynamic_dispatch\[Reflect\.apply,Function\.prototype\.call\.call,Function\.prototype\.apply\.call\]/);
  assert.match(renderMarkdownReport(report), /agent_generation=chain=input_url->byte_buffer->dynamic_dispatch->text_or_string_decode->integer_mixing->signature_mutation->signed_request evidence=runtime_and_source .*source_hooks=vmp_dynamic_dispatch/);
  assert.match(renderMarkdownReport(report), /hook_points=.*vmp_dynamic_dispatch:source_observed\[source:Reflect\.apply\|Function\.prototype\.call\.call\|Function\.prototype\.apply\.call signals:prototype_call\|dynamic_dispatch\]/);

  const agentPack = buildAgentInputPack(report);
  const agentPackMarkdown = renderAgentInputPackMarkdown(agentPack);
  const packParameter = agentPack.parameters.find((entry) => entry.param === "X-Signature");
  assert.ok(packParameter);
  const packLogicTrace = packParameter.agent_generation_summary.logic_hypothesis.agent_logic_trace;
  const packMixingStep = packLogicTrace.steps.find((step) => step.phase === "mixing_or_hash");
  assert.ok(packMixingStep);
  assert.ok((packMixingStep.source_operators || []).includes("^"));
  assert.ok((packMixingStep.source_constants || []).includes("16777619"));
  assert.ok((packMixingStep.value_refs || []).includes("number:3.000000"));
  assert.ok((packMixingStep.value_refs || []).includes("number:16777619.000000"));
  assert.ok((packMixingStep.value_refs || []).includes("number:42.000000"));
  assert.match(agentPackMarkdown, /logic_step=3:mixing_or_hash[^\n]*ops=\^[^\n]*constants=16777619/);
  assert.match(
    agentPackMarkdown,
    /logic_step=3:mixing_or_hash[^\n]*refs=[^\n]*number:3\.000000\|number:16777619\.000000\|number:42\.000000/
  );
  assert.match(
    agentPackMarkdown,
    /logic_edge=\d+:mixing_or_hash->signature_attachment\[low\/shared_source_ref\] stages=integer_mixing->signature_mutation sources=sha1:runtime-sdk-local:6-10/
  );
  assert.match(
    agentPackMarkdown,
    /final_attachment=observed params=X-Signature apis=URLSearchParams\.set mode=direct_runtime_api/
  );
  assert.match(
    agentPackMarkdown,
    /data_links=.*signature_mutation->signed_request\[medium\/shared_object_ref\] refs=url_object:31\|search_params:32/
  );
  assert.match(
    agentPackMarkdown,
    /inferred_links=.*integer_mixing->signature_mutation\[medium\/shared_object_ref\] refs=source:sha1:runtime-sdk-local:6-10\|seq:13-14 basis=same_source_context\|ordered_runtime_window/
  );

  const agentAnalysis = buildAgentAnalysis(agentPack);
  const parameter = agentAnalysis.parameters.find((entry) => entry.param === "X-Signature");
  assert.ok(parameter);
  assert.deepEqual(parameter.candidate_generation_summary.stage_chain, [
    "input_url",
    "byte_buffer",
    "dynamic_dispatch",
    "text_or_string_decode",
    "integer_mixing",
    "signature_mutation",
    "signed_request"
  ]);
  assert.equal(parameter.candidate_generation_summary.evidence_profile, "runtime_and_source");
  assert.deepEqual(parameter.candidate_generation_summary.source_observed_hooks, ["vmp_dynamic_dispatch"]);
  assert.ok(parameter.candidate_generation_summary.runtime_apis.includes("TextEncoder.encode"));
  assert.ok(parameter.candidate_generation_summary.runtime_apis.includes("URLSearchParams.set"));
  assert.ok(parameter.candidate_generation_summary.source_calls.includes("Reflect.apply"));
  assert.ok(parameter.candidate_generation_summary.source_windows.some((window) =>
    window.content_path === "assets/trace_demo/runtime-sdk-local.js" &&
    window.asset_id === "sha1:runtime-sdk-local" &&
    window.url === scriptUrl &&
    /Reflect\.apply/.test(window.preview || "")
  ));
  assert.deepEqual(parameter.candidate_generation_summary.key_refs.search_params, ["search_params:32"]);
  assert.deepEqual(parameter.candidate_generation_summary.key_refs.url_objects, ["url_object:31"]);
  assert.deepEqual(parameter.candidate_generation_summary.key_refs.buffers, [
    "array_buffer:20",
    "data_view:21"
  ]);
  assert.deepEqual(parameter.candidate_generation_summary.attachment.target_params, ["X-Signature"]);
  assert.deepEqual(parameter.candidate_generation_summary.attachment.object_refs, [
    "url_object:31",
    "search_params:32"
  ]);
  assert.deepEqual(parameter.candidate_generation_summary.generation_steps.map((step) => step.stage), [
    "input_url",
    "byte_buffer",
    "dynamic_dispatch",
    "text_or_string_decode",
    "integer_mixing",
    "signature_mutation",
    "signed_request"
  ]);
  const dynamicSummaryStep = parameter.candidate_generation_summary.generation_steps.find((step) =>
    step.stage === "dynamic_dispatch"
  );
  assert.ok(dynamicSummaryStep.source_calls.includes("Reflect.apply"));
  assert.equal(dynamicSummaryStep.param_relation, "flow_target");
  const dynamicHookSummary = parameter.candidate_generation_summary.vmp_hook_ref_summary.find((hook) =>
    hook.type === "vmp_dynamic_dispatch"
  );
  assert.ok(dynamicHookSummary);
  assert.deepEqual(dynamicHookSummary.source_calls, [
    "Reflect.apply",
    "Function.prototype.call.call",
    "Function.prototype.apply.call"
  ]);
  assert.ok(dynamicHookSummary.source_windows.some((window) =>
    window.ref === "sha1:runtime-sdk-local:6-10" &&
    window.asset_id === "sha1:runtime-sdk-local" &&
    window.url === scriptUrl &&
    window.content_path === "assets/trace_demo/runtime-sdk-local.js" &&
    /Reflect\.apply/.test(window.preview || "")
  ));
  const dynamicHookWindow = dynamicHookSummary.source_windows.find((window) =>
    window.ref === "sha1:runtime-sdk-local:6-10"
  );
  assert.ok(dynamicHookWindow.calls.includes("Reflect.apply"));
  assert.ok(dynamicHookWindow.calls.includes("Function.prototype.call.call"));
  assert.ok(dynamicHookWindow.signals.includes("dynamic_dispatch"));
  assert.ok(dynamicHookWindow.operators.includes("^"));
  assert.ok(dynamicHookWindow.numeric_literals.includes("16777619"));
  const signatureSummaryStep = parameter.candidate_generation_summary.generation_steps.find((step) =>
    step.stage === "signature_mutation"
  );
  assert.deepEqual(signatureSummaryStep.target_params, ["X-Signature"]);
  assert.ok(signatureSummaryStep.value_refs.includes("target_params:X-Signature"));
  const logic = parameter.candidate_generation_summary.logic_hypothesis;
  assert.equal(logic.status, "runtime_and_source_chain_observed");
  assert.deepEqual(logic.ordered_stage_chain, [
    "input_url",
    "byte_buffer",
    "dynamic_dispatch",
    "text_or_string_decode",
    "integer_mixing",
    "signature_mutation",
    "signed_request"
  ]);
  assert.match(logic.summary, /X-Signature/);
  const phasesById = new Map(logic.phases.map((phase) => [phase.id, phase]));
  assert.deepEqual(phasesById.get("input_material").stages, [
    "input_url",
    "byte_buffer",
    "text_or_string_decode"
  ]);
  assert.ok(phasesById.get("input_material").evidence.includes("runtime_api:TextEncoder.encode"));
  assert.ok(phasesById.get("vmp_execution").source_calls.includes("Reflect.apply"));
  assert.ok(phasesById.get("vmp_execution").source_signals.includes("dynamic_dispatch"));
  assert.ok(phasesById.get("mixing_or_hash").evidence.includes("runtime_api:Math.imul"));
  assert.ok(phasesById.get("mixing_or_hash").source_operators.includes("^"));
  assert.ok(phasesById.get("mixing_or_hash").source_constants.includes("16777619"));
  assert.deepEqual(phasesById.get("signature_attachment").target_params, ["X-Signature"]);
  assert.ok(phasesById.get("signature_attachment").evidence.includes("runtime_api:URLSearchParams.set"));
  assert.equal(logic.final_attachment.observed, true);
  assert.deepEqual(logic.final_attachment.target_params, ["X-Signature"]);
  assert.ok(logic.source_focus.some((source) =>
    source.ref === "sha1:runtime-sdk-local:6-10" &&
    source.role === "security_sdk_signature_generator"
  ));
  const phaseEdges = logic.phase_edges.map((edge) => ({
    from_phase: edge.from_phase,
    to_phase: edge.to_phase,
    from_stage: edge.from_stage,
    to_stage: edge.to_stage,
    relation: edge.relation,
    confidence: edge.confidence
  }));
  assert.ok(phaseEdges.some((edge) =>
    edge.from_phase === "input_material" &&
    edge.to_phase === "vmp_execution" &&
    edge.from_stage === "byte_buffer" &&
    edge.to_stage === "dynamic_dispatch" &&
    edge.relation === "inferred_data_link" &&
    edge.confidence === "low"
  ));
  assert.ok(phaseEdges.some((edge) =>
    edge.from_phase === "mixing_or_hash" &&
    edge.to_phase === "signature_attachment" &&
    edge.from_stage === "integer_mixing" &&
    edge.to_stage === "signature_mutation" &&
    edge.relation === "inferred_data_link" &&
    edge.confidence === "medium"
  ));
  const attachmentEdge = logic.phase_edges.find((edge) =>
    edge.from_stage === "signature_mutation" &&
    edge.to_stage === "signed_request"
  );
  assert.equal(attachmentEdge.scope, "intra_phase");
  assert.equal(attachmentEdge.from_phase, "signature_attachment");
  assert.equal(attachmentEdge.to_phase, "signature_attachment");
  assert.equal(attachmentEdge.relation, "target_param_ref");
  assert.deepEqual(attachmentEdge.refs, [
    "target_params:X-Signature",
    "url_object:31",
    "search_params:32"
  ]);
  assert.equal(logic.critical_path.status, "partial_runtime_source_path");
  assert.deepEqual(logic.critical_path.phase_sequence, [
    "input_material",
    "vmp_execution",
    "mixing_or_hash",
    "signature_attachment"
  ]);
  assert.deepEqual(logic.critical_path.stage_sequence, [
    "input_url",
    "byte_buffer",
    "dynamic_dispatch",
    "text_or_string_decode",
    "integer_mixing",
    "signature_mutation",
    "signed_request"
  ]);
  assert.equal(logic.critical_path.strongest_attachment_edge.relation, "target_param_ref");
  assert.deepEqual(logic.critical_path.strongest_attachment_edge.refs, [
    "target_params:X-Signature",
    "url_object:31",
    "search_params:32"
  ]);
  assert.equal(logic.critical_path.edge_summary.cross_phase_edge_count, 4);
  assert.equal(logic.critical_path.edge_summary.high_confidence_edge_count, 1);
  assert.equal(logic.critical_path.edge_summary.low_confidence_edge_count, 3);
  assert.deepEqual(logic.critical_path.blocking_gaps, []);
  assert.ok(logic.critical_path.path_evidence.includes("phase_edge:input_material->vmp_execution:inferred_data_link:low"));
  assert.ok(logic.critical_path.path_evidence.includes("phase_edge:signature_attachment->signature_attachment:target_param_ref:high"));
  assert.equal(
    logic.agent_logic_trace.summary,
    "X-Signature generation: input_material -> vmp_execution -> mixing_or_hash -> signature_attachment; status=partial_runtime_source_path"
  );
  assert.deepEqual(logic.agent_logic_trace.steps.map((step) => step.phase), [
    "input_material",
    "vmp_execution",
    "mixing_or_hash",
    "signature_attachment"
  ]);
  assert.match(logic.agent_logic_trace.steps[0].claim, /input material observed/);
  assert.ok(logic.agent_logic_trace.steps[0].evidence.includes("runtime_api:TextEncoder.encode"));
  assert.match(logic.agent_logic_trace.steps[1].claim, /VMP dispatch and handler execution observed/);
  assert.ok(logic.agent_logic_trace.steps[1].source_calls.includes("Reflect.apply"));
  assert.match(logic.agent_logic_trace.steps[2].claim, /integer mixing or digest observed/);
  assert.ok(logic.agent_logic_trace.steps[2].evidence.includes("runtime_api:Math.imul"));
  assert.ok(Array.isArray(logic.agent_logic_trace.steps[2].runtime_events));
  assert.deepEqual(logic.agent_logic_trace.steps[2].runtime_events.map((event) => ({
    event_ref: event.event_ref,
    seq: event.seq,
    api: event.api,
    stage: event.stage
  })), [{
    event_ref: "seq:13:Math.imul",
    seq: 13,
    api: "Math.imul",
    stage: "integer_mixing"
  }]);
  assert.match(logic.agent_logic_trace.steps[3].claim, /signature attachment and request send observed/);
  assert.deepEqual(logic.agent_logic_trace.steps[3].target_params, ["X-Signature"]);
  assert.ok(logic.agent_logic_trace.steps[3].runtime_events.some((event) =>
    event.event_ref === "seq:14:URLSearchParams.set" &&
    event.api === "URLSearchParams.set" &&
    event.stage === "signature_mutation"
  ));
  assert.ok(logic.agent_logic_trace.steps[3].runtime_events.some((event) =>
    event.event_ref === "seq:15:Request.constructor" &&
    event.api === "Request.constructor" &&
    event.stage === "signed_request"
  ));
  assert.ok(logic.agent_logic_trace.edges.some((edge) =>
    edge.from_phase === "mixing_or_hash" &&
    edge.to_phase === "signature_attachment" &&
    edge.relation === "inferred_data_link" &&
    edge.confidence === "medium"
  ));
  assert.ok(logic.agent_logic_trace.edges.some((edge) =>
    edge.from_phase === "signature_attachment" &&
    edge.to_phase === "signature_attachment" &&
    edge.relation === "target_param_ref" &&
    edge.confidence === "high"
  ));
  assert.deepEqual(logic.agent_logic_trace.final_attachment, {
    observed: true,
    target_params: ["X-Signature"],
    apis: ["URLSearchParams.set"],
    evidence_mode: "direct_runtime_api"
  });
  const completeness = parameter.candidate_generation_summary.capture_completeness;
  assert.equal(completeness.status, "needs_more_runtime_capture");
  assert.equal(completeness.score.observed_count, 6);
  assert.equal(completeness.score.missing_count, 1);
  assert.deepEqual(completeness.missing_items, ["vmp_dispatch_runtime_observed"]);
  assert.ok(completeness.next_capture_hooks.includes("VMP.dispatch.runtime_call"));
  assert.deepEqual(
    completeness.checklist.find((item) => item.item === "vmp_dispatch_runtime_observed"),
    {
      item: "vmp_dispatch_runtime_observed",
      status: "missing",
      evidence: ["source_call:Reflect.apply", "source_signal:dynamic_dispatch"],
      missing: ["dynamic_dispatch_runtime_api"],
      next_capture_hooks: ["VMP.dispatch.runtime_call", "Function.prototype.call.apply"]
    }
  );
  assert.match(
    renderAgentAnalysisMarkdown(agentAnalysis),
    /candidate_generation=chain=input_url->byte_buffer->dynamic_dispatch->text_or_string_decode->integer_mixing->signature_mutation->signed_request evidence=runtime_and_source/
  );
  assert.match(renderAgentAnalysisMarkdown(agentAnalysis), /logic=runtime_and_source_chain_observed critical_path=partial_runtime_source_path phase_edges=/);
  assert.match(renderAgentAnalysisMarkdown(agentAnalysis), /logic_trace=X-Signature generation: input_material -> vmp_execution -> mixing_or_hash -> signature_attachment; status=partial_runtime_source_path/);
  assert.match(renderAgentAnalysisMarkdown(agentAnalysis), /logic_step=3:mixing_or_hash[^\n]*ops=\^[^\n]*constants=16777619/);
  assert.match(renderAgentAnalysisMarkdown(agentAnalysis), /logic_step=3:mixing_or_hash[^\n]*events=Math\.imul@13/);
  assert.match(renderAgentAnalysisMarkdown(agentAnalysis), /logic_step=4:signature_attachment[^\n]*events=URLSearchParams\.set@14\|Request\.constructor@15/);
  const sourceOperationSubgraph = parameter.generation_graph.operation_subgraphs.find((subgraph) =>
    subgraph.stage === "integer_mixing"
  );
  assert.ok(sourceOperationSubgraph);
  assert.equal(sourceOperationSubgraph.pattern, "source_xor_imul_shift_mixing");
  assert.equal(sourceOperationSubgraph.attached_node_id, "step_5_integer_mixing");
  assert.equal(sourceOperationSubgraph.confidence, "medium");
  assert.deepEqual(sourceOperationSubgraph.source_operators, ["^", ">>>"]);
  assert.deepEqual(sourceOperationSubgraph.source_constants, ["16777619"]);
  assert.deepEqual(sourceOperationSubgraph.nodes.map((node) => ({
    api: node.api,
    source_operators: node.source_operators,
    source_constants: node.source_constants,
    source_refs: node.source_refs
  })), [{
    api: "Math.imul",
    source_operators: ["^", ">>>"],
    source_constants: ["16777619"],
    source_refs: ["sha1:runtime-sdk-local:6-10"]
  }]);
  assert.equal(parameter.generation_graph.dataflow_summary.status, "vmp_stage_bridge_reaches_signed_request");
  assert.ok(parameter.generation_graph.dataflow_summary.gaps.includes("vmp_output_ref_to_signature_not_observed"));
  assert.match(renderAgentAnalysisMarkdown(agentAnalysis), /graph=nodes=7 edges=6 unresolved=0 opgraphs=1 ops=source_xor_imul_shift_mixing:1 flow=vmp_stage_bridge_reaches_signed_request/);
  assert.match(
    renderAgentAnalysisMarkdown(agentAnalysis),
    /op_details=source_5_integer_mixing:integer_mixing attached=step_5_integer_mixing outputs=number:3\.000000\|number:16777619\.000000\|number:42\.000000 edges=none nodes=Math\.imul ops=\^\|>>> constants=16777619 src=sha1:runtime-sdk-local:6-10 outputs=number:3\.000000\|number:16777619\.000000\|number:42\.000000 pattern=source_xor_imul_shift_mixing/
  );
});

test("buildAgentAnalysis ranks security SDK hook source windows before loader wrappers", () => {
  const loaderUrl = "https://cdn.example.test/privacy/loader/index.js";
  const sdkUrl = "https://cdn.example.test/runtime-sdk/1.0.0/runtime-sdk.js";
  const stack = [{
    function: "loadAndCall",
    url: loaderUrl,
    line: 2,
    column: 20,
    asset_id: "sha1:loader",
    asset_path: "assets/trace_demo/loader.js"
  }, {
    function: "vmDispatch",
    url: sdkUrl,
    line: 2,
    column: 26,
    asset_id: "sha1:runtime-sdk",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 2, category: "reverse", phase: "call", api: "Function.prototype.call", args: [{target_ref: "handler:1", this_ref: "state:1", result_ref: "register:1/number:42"}], stack},
    {seq: 3, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 11, search_params_id: 12, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 4, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 11, search_params_id: 12, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack}
  ];
  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_hook_window_rank.ndjson",
    events,
    assets: [{
      asset_id: "sha1:loader",
      kind: "script",
      url: loaderUrl,
      content_path: "assets/trace_demo/loader.js",
      content: [
        "function loadAndCall(url) {",
        "  return window.sdk.vmDispatch.call(null, url);",
        "}"
      ].join("\n")
    }, {
      asset_id: "sha1:runtime-sdk",
      kind: "script",
      url: sdkUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function vmDispatch(url) {",
        "  const result = Function.prototype.call.call(handlerTable[op], null, state);",
        "  url.searchParams.set('X-Signature', result);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = analysis.parameters.find((entry) => entry.param === "X-Signature");
  const dynamicHook = parameter.candidate_generation_summary.vmp_hook_ref_summary
    .find((hook) => hook.type === "vmp_dynamic_dispatch");

  assert.ok(dynamicHook);
  assert.equal(dynamicHook.source_windows[0].url, sdkUrl);
  assert.equal(dynamicHook.source_windows[0].source_role, "security_sdk_signature_generator");
  assert.equal(dynamicHook.source_windows[1].url, loaderUrl);
  assert.equal(dynamicHook.source_windows[1].source_role, "loader_or_wrapper");
});

test("buildLocalReport uses asset source fallback for VMP dynamic dispatch material stage", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk-inline.html";
  const stack = [{
    function: "readWord",
    url: scriptUrl,
    line: 12,
    column: 30,
    asset_id: "sha1:runtime-sdk-inline",
    asset_path: "assets/trace_demo/runtime-sdk-inline.js"
  }, {
    function: "signVm",
    url: scriptUrl,
    line: 19,
    column: 28,
    asset_id: "sha1:runtime-sdk-inline",
    asset_path: "assets/trace_demo/runtime-sdk-inline.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input: "cursor=1"}], stack},
    {seq: 2, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 21, array_buffer_id: 20, byte_offset: 0}], stack},
    {seq: 3, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 3, y: 16777619, result: 42}], stack},
    {seq: 4, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 5, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 31, search_params_id: 32, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 6, category: "reverse", phase: "call", api: "Request.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_asset_dispatch_fallback.ndjson",
    events,
    assets: [{
      asset_id: "sha1:runtime-sdk-inline",
      kind: "inline-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk-inline.js",
      content: [
        "function signVm(url) {",
        "  const source = url.search;",
        "  const bytes = new TextEncoder().encode(source);",
        "  const view = new DataView(bytes.buffer);",
        "  const handlers = [function readWord(state){ return view.getUint32(state.offset, true); }, function mixWord(state, word){ state.mixed = Math.imul(state.mixed ^ word, 16777619); }];",
        "  const state = {offset: 0, mixed: 0x811c9dc5};",
        "  const word = Reflect.apply(handlers[0], null, [state]);",
        "  Function.prototype.call.call(handlers[1], null, state, word);",
        "  Function.prototype.apply.call(function applyProbe(vm){ return vm.mixed; }, null, [state]);",
        "  url.searchParams.set('X-Signature', state.mixed);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const dynamicStage = materialFlow.stages.find((stage) => stage.stage === "dynamic_dispatch");
  const dynamicHookPoint = materialFlow.vmp_hook_points.find((point) => point.type === "vmp_dynamic_dispatch");

  assert.ok(dynamicStage);
  assert.deepEqual(dynamicStage.runtime_apis, []);
  assert.deepEqual(dynamicStage.source_calls, [
    "Reflect.apply",
    "Function.prototype.call.call",
    "Function.prototype.apply.call"
  ]);
  assert.equal(dynamicHookPoint.status, "source_observed");
});

test("buildLocalReport merges URLSearchParams serialization refs into signature generation step", () => {
  const scriptUrl = "https://www.example.test/business-api-smoke.html";
  const vmpStack = [{
    function: "makeDemoTraceMarker",
    url: scriptUrl,
    line: 3,
    column: 16,
    asset_id: "sha1:params-merge",
    asset_path: "assets/trace_demo/params-merge.js"
  }];
  const stack = [{
    function: "run",
    url: scriptUrl,
    line: 7,
    column: 4,
    asset_id: "sha1:params-merge",
    asset_path: "assets/trace_demo/params-merge.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input: "cursor=1"}], stack: vmpStack},
    {seq: 2, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 21, array_buffer_id: 20, byte_offset: 0}], stack: vmpStack},
    {seq: 3, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 3, y: 16777619, result: 42}], stack: vmpStack},
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 0, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 11, category: "reverse", phase: "call", api: "URLSearchParams.toString", args: [{url_object_id: 0, search_params_id: 32, size: 2, serialized: "cursor=1&X-Signature=secret-one"}], stack},
    {seq: 12, category: "reverse", phase: "set", api: "URL.search.set", args: [{url_object_id: 31, search_params_id: 0, value: "cursor=1&X-Signature=secret-one", href: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack},
    {seq: 13, category: "reverse", phase: "call", api: "Request.constructor", args: [{url_object_id: 31, search_params_id: 0, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_params_merge.ndjson",
    events,
    assets: [{
      asset_id: "sha1:params-merge",
      kind: "inline-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/params-merge.js",
      content: [
        "function makeDemoTraceMarker(seed) {",
        "  const bytes = new TextEncoder().encode(seed);",
        "  const view = new DataView(bytes.buffer);",
        "  return Math.imul(view.getUint32(0, true), 16777619);",
        "}",
        "function run(url) {",
        "  const params = new URLSearchParams(url.search);",
        "  params.set('X-Signature', sign(url.search));",
        "  url.search = params.toString();",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const signatureStep = materialFlow.generation_steps.find((step) => step.stage === "signature_mutation");
  assert.ok(signatureStep);
  assert.ok(materialFlow.agent_generation_summary.runtime_apis.includes("URLSearchParams.toString"));
  assert.deepEqual(signatureStep.attachment_events.map((event) => ({
    api: event.api,
    object_refs: event.object_refs
  })), [
    {api: "URLSearchParams.toString", object_refs: ["search_params:32"]},
    {api: "URL.search.set", object_refs: ["url_object:31"]}
  ]);
  assert.ok(signatureStep.object_refs.includes("url_object:31"));
  assert.ok(signatureStep.object_refs.includes("search_params:32"));

  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = analysis.parameters.find((item) => item.param === "X-Signature");
  assert.ok(parameter.candidate_generation_summary.runtime_apis.includes("URLSearchParams.toString"));
  const agentSignatureStep = parameter.generation_path.find((step) => step.stage === "signature_mutation");
  assert.ok(agentSignatureStep.object_refs.includes("url_object:31"));
  assert.ok(agentSignatureStep.object_refs.includes("search_params:32"));
});

test("buildLocalReport treats V8 StringAdd refs as signature string material", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "sign",
    url: scriptUrl,
    line: 4,
    column: 12,
    asset_id: "sha1:string-add",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 2, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 123, y: 16777619, result_ref: "number:signature-mix"}], stack},
    {seq: 3, category: "reverse", phase: "call", api: "StringAdd", args: [{left_ref: "string:length:4", right_ref: "number:signature-mix", result_ref: "string:length:10", result_length: 10}], stack},
    {seq: 4, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 31, search_params_id: 32, name: "X-Signature", value: "secret-one"}], stack},
    {seq: 5, category: "reverse", phase: "call", api: "URLSearchParams.toString", args: [{search_params_id: 32, url_object_id: 31, serialized: "cursor=1&X-Signature=secret-one"}], stack},
    {seq: 6, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_string_add_signature.ndjson",
    events,
    assets: [{
      asset_id: "sha1:string-add",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function sign(url) {",
        "  const mixed = Math.imul(seed, 16777619);",
        "  const token = 'xbg-' + mixed;",
        "  url.searchParams.set('X-Signature', token);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const stringStage = materialFlow.generation_steps.find((step) => step.stage === "string_transform");
  const signatureStage = materialFlow.generation_steps.find((step) => step.stage === "signature_mutation");
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = analysis.parameters.find((item) => item.param === "X-Signature");
  const edgeSummary = (parameter.generation_edges || []).map((edge) => ({
    from: edge.from_stage,
    to: edge.to_stage,
    relation: edge.relation,
    refs: edge.refs
  }));

  assert.ok(stringStage);
  assert.ok(stringStage.runtime_apis.includes("StringAdd"));
  assert.ok(stringStage.value_refs.includes("number:signature-mix"));
  assert.ok(stringStage.value_refs.includes("string:length:10"));
  assert.ok(signatureStage.value_refs.includes("string:length:10"));
  assert.ok(edgeSummary.some((edge) =>
    edge.from === "integer_mixing" &&
    edge.to === "string_transform" &&
    edge.relation === "shared_value_ref" &&
    edge.refs.includes("number:signature-mix")
  ));
  assert.ok(
    stringStage.value_refs.includes("string:length:10") &&
    signatureStage.value_refs.includes("string:length:10")
  );

  assert.ok(parameter.candidate_generation_summary.runtime_apis.includes("StringAdd"));
});

test("buildLocalReport links URLSearchParams native refs through signature attachment and request boundary", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "sign",
    url: scriptUrl,
    line: 4,
    column: 12,
    asset_id: "sha1:urlsearch-native-refs",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "Math.imul", args: [{x_ref: "number:seed", y_ref: "number:16777619.000000", result_ref: "number:mix"}], stack},
    {seq: 2, category: "reverse", phase: "call", api: "StringAdd", args: [{left_ref: "string:prefix", right_ref: "number:mix", result_ref: "string_ref:xsignature-token", result_length: 18}], stack},
    {seq: 3, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 4, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{
      url_object_id: 31,
      search_params_id: 32,
      name: "X-Signature",
      value: "secret-one",
      value_ref: "string_ref:xsignature-token",
      serialized_ref: "string_ref:signed-query",
      before_serialized_ref: "string_ref:unsigned-query"
    }], stack},
    {seq: 5, category: "reverse", phase: "call", api: "URLSearchParams.toString", args: [{
      search_params_id: 32,
      url_object_id: 31,
      serialized: "cursor=1&X-Signature=secret-one",
      serialized_ref: "string_ref:signed-query",
      result_ref: "string_ref:signed-query"
    }], stack},
    {seq: 6, category: "network", phase: "call", api: "Request.constructor", args: [{
      url_object_id: 31,
      search_params_id: 32,
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      url_ref: "string_ref:signed-query"
    }], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_urlsearch_native_refs.ndjson",
    events,
    assets: [{
      asset_id: "sha1:urlsearch-native-refs",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function sign(url) {",
        "  const mixed = Math.imul(seed, 16777619);",
        "  const token = 'xbg-' + mixed;",
        "  url.searchParams.set('X-Signature', token);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const signatureStep = materialFlow.generation_steps.find((step) => step.stage === "signature_mutation");
  const signedStep = materialFlow.generation_steps.find((step) => step.stage === "signed_request");
  const pack = buildAgentInputPack(report);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const packMarkdown = renderAgentInputPackMarkdown(pack);
  const analysis = buildAgentAnalysis(pack);
  const parameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.ok(signatureStep.value_refs.includes("string_ref:xsignature-token"));
  assert.ok(signatureStep.value_refs.includes("string_ref:signed-query"));
  assert.ok(signedStep.value_refs.includes("string_ref:signed-query"));
  assert.ok(materialFlow.data_links.some((link) =>
    link.from === "signature_mutation" &&
    link.to === "signed_request" &&
    link.relation === "shared_runtime_value_ref" &&
    link.refs.includes("string_ref:signed-query")
  ));
  assert.ok(parameter.generation_edges.some((edge) =>
    edge.from_stage === "string_transform" &&
    edge.to_stage === "signature_mutation" &&
    edge.relation === "shared_value_ref" &&
    edge.refs.includes("string_ref:xsignature-token")
  ));
  assert.ok(parameter.generation_edges.some((edge) =>
    edge.from_stage === "signature_mutation" &&
    edge.to_stage === "url_encoding" &&
    edge.relation === "shared_value_ref" &&
    edge.refs.includes("string_ref:signed-query")
  ));
  assert.ok(parameter.generation_edges.some((edge) =>
    edge.from_stage === "url_encoding" &&
    edge.to_stage === "signed_request" &&
    edge.relation === "shared_value_ref" &&
    edge.refs.includes("string_ref:signed-query")
  ));
  assert.ok(Array.isArray(packParameter.runtime_ref_lineage));
  assert.ok(Array.isArray(packParameter.runtime_ref_event_evidence));
  const packLineageByRef = new Map(packParameter.runtime_ref_lineage.map((entry) => [entry.ref, entry]));
  assert.deepEqual(packLineageByRef.get("string_ref:xsignature-token"), {
    ref: "string_ref:xsignature-token",
    kind: "value_ref",
    first_stage: "string_transform",
    last_stage: "signature_mutation",
    stages: ["string_transform", "signature_mutation"],
    apis: ["StringAdd", "URLSearchParams.set"],
    occurrence_count: 2,
    edge_count: 1,
    occurrences: [
      {order: 3, stage: "string_transform", apis: ["StringAdd"], field: "value_refs"},
      {order: 4, stage: "signature_mutation", apis: ["URLSearchParams.set"], field: "value_refs"}
    ],
    edges: [{
      from_stage: "string_transform",
      to_stage: "signature_mutation",
      relation: "shared_value_ref",
      confidence: "high"
    }]
  });
  const packRefEventsByRef = new Map(packParameter.runtime_ref_event_evidence.map((entry) => [entry.ref, entry]));
  assert.deepEqual(packRefEventsByRef.get("string_ref:xsignature-token").events.map((event) => ({
    stage: event.stage,
    event_ref: event.event_ref,
    seq: event.seq,
    api: event.api,
    category: event.category
  })), [
    {stage: "string_transform", event_ref: "seq:2:StringAdd", seq: 2, api: "StringAdd", category: "reverse"},
    {stage: "signature_mutation", event_ref: "seq:4:URLSearchParams.set", seq: 4, api: "URLSearchParams.set", category: "reverse"}
  ]);
  assert.match(
    packMarkdown,
    /ref_lineage=string_ref:xsignature-token:value_ref:string_transform->signature_mutation edges=1;string_ref:signed-query:value_ref:signature_mutation->url_encoding->signed_request edges=2/
  );
  assert.match(
    packMarkdown,
    /ref_events=string_ref:xsignature-token\[StringAdd@2->URLSearchParams\.set@4\];string_ref:signed-query\[URLSearchParams\.set@4->URLSearchParams\.toString@5->Request\.constructor@6\]/
  );
  const lineageByRef = new Map(parameter.runtime_ref_lineage.map((entry) => [entry.ref, entry]));
  assert.deepEqual(lineageByRef.get("string_ref:xsignature-token"), {
    ref: "string_ref:xsignature-token",
    kind: "value_ref",
    first_stage: "string_transform",
    last_stage: "signature_mutation",
    stages: ["string_transform", "signature_mutation"],
    apis: ["StringAdd", "URLSearchParams.set"],
    occurrence_count: 2,
    edge_count: 1,
    occurrences: [
      {order: 3, stage: "string_transform", apis: ["StringAdd"], field: "value_refs"},
      {order: 4, stage: "signature_mutation", apis: ["URLSearchParams.set"], field: "value_refs"}
    ],
    edges: [{
      from_stage: "string_transform",
      to_stage: "signature_mutation",
      relation: "shared_value_ref",
      confidence: "high"
    }]
  });
  assert.deepEqual(lineageByRef.get("string_ref:signed-query"), {
    ref: "string_ref:signed-query",
    kind: "value_ref",
    first_stage: "signature_mutation",
    last_stage: "signed_request",
    stages: ["signature_mutation", "url_encoding", "signed_request"],
    apis: ["URLSearchParams.set", "URLSearchParams.toString", "Request.constructor"],
    occurrence_count: 3,
    edge_count: 2,
    occurrences: [
      {order: 4, stage: "signature_mutation", apis: ["URLSearchParams.set"], field: "value_refs"},
      {order: 5, stage: "url_encoding", apis: ["URLSearchParams.toString"], field: "value_refs"},
      {order: 6, stage: "signed_request", apis: ["Request.constructor"], field: "value_refs"}
    ],
    edges: [
      {
        from_stage: "signature_mutation",
        to_stage: "url_encoding",
        relation: "shared_value_ref",
        confidence: "high"
      },
      {
        from_stage: "url_encoding",
        to_stage: "signed_request",
        relation: "shared_value_ref",
        confidence: "high"
      }
    ]
  });
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /ref_lineage=string_ref:xsignature-token:value_ref:string_transform->signature_mutation edges=1;string_ref:signed-query:value_ref:signature_mutation->url_encoding->signed_request edges=2/
  );
  const eventEvidenceByStage = new Map(parameter.runtime_event_evidence.map((entry) => [entry.stage, entry]));
  assert.deepEqual(eventEvidenceByStage.get("string_transform"), {
    order: 3,
    stage: "string_transform",
    seq_start: 2,
    seq_end: 2,
    apis: ["StringAdd"],
    event_count: 1,
    events: [{
      event_ref: "seq:2:StringAdd",
      seq: 2,
      trace_index: null,
      api: "StringAdd",
      category: "reverse",
      phase: "call",
      stack_url: scriptUrl,
      asset_id: "sha1:urlsearch-native-refs"
    }],
    object_refs: [],
    value_refs: ["number:mix", "string:length:18", "string:prefix", "string_ref:xsignature-token"],
    source_refs: ["sha1:urlsearch-native-refs:2-6"]
  });
  assert.deepEqual(eventEvidenceByStage.get("signature_mutation").events, [{
    event_ref: "seq:4:URLSearchParams.set",
    seq: 4,
    trace_index: null,
    api: "URLSearchParams.set",
    category: "reverse",
    phase: "call",
    stack_url: scriptUrl,
    asset_id: "sha1:urlsearch-native-refs"
  }]);
  assert.deepEqual(eventEvidenceByStage.get("url_encoding").events, [{
    event_ref: "seq:5:URLSearchParams.toString",
    seq: 5,
    trace_index: null,
    api: "URLSearchParams.toString",
    category: "reverse",
    phase: "call",
    stack_url: scriptUrl,
    asset_id: "sha1:urlsearch-native-refs"
  }]);
  assert.deepEqual(eventEvidenceByStage.get("signed_request").events, [{
    event_ref: "seq:6:Request.constructor",
    seq: 6,
    trace_index: null,
    api: "Request.constructor",
    category: "network",
    phase: "call",
    stack_url: scriptUrl,
    asset_id: "sha1:urlsearch-native-refs"
  }]);
  const refEventEvidenceByRef = new Map(parameter.runtime_ref_event_evidence.map((entry) => [entry.ref, entry]));
  assert.deepEqual(refEventEvidenceByRef.get("string_ref:xsignature-token"), {
    ref: "string_ref:xsignature-token",
    kind: "value_ref",
    first_stage: "string_transform",
    last_stage: "signature_mutation",
    stages: ["string_transform", "signature_mutation"],
    apis: ["StringAdd", "URLSearchParams.set"],
    event_count: 2,
    events: [
      {
        order: 3,
        stage: "string_transform",
        event_ref: "seq:2:StringAdd",
        seq: 2,
        trace_index: null,
        api: "StringAdd",
        category: "reverse",
        phase: "call",
        stack_url: scriptUrl,
        asset_id: "sha1:urlsearch-native-refs"
      },
      {
        order: 4,
        stage: "signature_mutation",
        event_ref: "seq:4:URLSearchParams.set",
        seq: 4,
        trace_index: null,
        api: "URLSearchParams.set",
        category: "reverse",
        phase: "call",
        stack_url: scriptUrl,
        asset_id: "sha1:urlsearch-native-refs"
      }
    ]
  });
  assert.deepEqual(refEventEvidenceByRef.get("string_ref:signed-query"), {
    ref: "string_ref:signed-query",
    kind: "value_ref",
    first_stage: "signature_mutation",
    last_stage: "signed_request",
    stages: ["signature_mutation", "url_encoding", "signed_request"],
    apis: ["URLSearchParams.set", "URLSearchParams.toString", "Request.constructor"],
    event_count: 3,
    events: [
      {
        order: 4,
        stage: "signature_mutation",
        event_ref: "seq:4:URLSearchParams.set",
        seq: 4,
        trace_index: null,
        api: "URLSearchParams.set",
        category: "reverse",
        phase: "call",
        stack_url: scriptUrl,
        asset_id: "sha1:urlsearch-native-refs"
      },
      {
        order: 5,
        stage: "url_encoding",
        event_ref: "seq:5:URLSearchParams.toString",
        seq: 5,
        trace_index: null,
        api: "URLSearchParams.toString",
        category: "reverse",
        phase: "call",
        stack_url: scriptUrl,
        asset_id: "sha1:urlsearch-native-refs"
      },
      {
        order: 6,
        stage: "signed_request",
        event_ref: "seq:6:Request.constructor",
        seq: 6,
        trace_index: null,
        api: "Request.constructor",
        category: "network",
        phase: "call",
        stack_url: scriptUrl,
        asset_id: "sha1:urlsearch-native-refs"
      }
    ]
  });
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /ref_events=string_ref:xsignature-token\[StringAdd@2->URLSearchParams\.set@4\];string_ref:signed-query\[URLSearchParams\.set@4->URLSearchParams\.toString@5->Request\.constructor@6\]/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /event_evidence=.*string_transform\[StringAdd@2\];signature_mutation\[URLSearchParams\.set@4\];url_encoding\[URLSearchParams\.toString@5\];signed_request\[Request\.constructor@6\]/
  );
});

test("buildLocalReport inherits URLSearchParams hash refs into request boundary by object id", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const tokenRef = "string_ref:sha1:1111111111111111111111111111111111111111";
  const queryRef = "string_ref:sha1:2222222222222222222222222222222222222222";
  const stack = [{
    function: "sign",
    url: scriptUrl,
    line: 4,
    column: 12,
    asset_id: "sha1:urlsearch-hash-refs",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "StringAdd", args: [{left_ref: "string:prefix", right_ref: "number:mix", result_ref: tokenRef, result_length: 18}], stack},
    {seq: 2, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 3, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{
      url_object_id: 31,
      search_params_id: 32,
      name: "X-Signature",
      value: "secret-one",
      value_ref: tokenRef,
      serialized_ref: queryRef
    }], stack},
    {seq: 4, category: "reverse", phase: "call", api: "URLSearchParams.toString", args: [{
      search_params_id: 32,
      url_object_id: 31,
      serialized: "cursor=1&X-Signature=secret-one",
      serialized_ref: queryRef,
      result_ref: queryRef
    }], stack},
    {seq: 5, category: "network", phase: "call", api: "Request.constructor", args: [{
      url_object_id: 31,
      search_params_id: 32,
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
    }], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_urlsearch_hash_ref_inheritance.ndjson",
    events,
    assets: [{
      asset_id: "sha1:urlsearch-hash-refs",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function sign(url) {",
        "  const token = 'xbg-' + mix;",
        "  url.searchParams.set('X-Signature', token);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = analysis.parameters.find((item) => item.param === "X-Signature");
  const signedStep = parameter.generation_path.find((step) => step.stage === "signed_request");

  assert.ok(signedStep.value_refs.includes(queryRef));
  assert.ok(parameter.generation_edges.some((edge) =>
    edge.from_stage === "url_encoding" &&
    edge.to_stage === "signed_request" &&
    edge.relation === "shared_value_ref" &&
    edge.confidence === "high" &&
    edge.refs.includes(queryRef)
  ));
  const lineage = parameter.runtime_ref_lineage.find((entry) => entry.ref === queryRef);
  assert.deepEqual(lineage.stages, ["signature_mutation", "url_encoding", "signed_request"]);
  assert.deepEqual(lineage.apis, ["URLSearchParams.set", "URLSearchParams.toString", "Request.constructor"]);
  assert.equal(parameter.chain_quality.missing_edge_count, 0);
});

test("buildLocalReport inherits URL constructor base refs into request boundary", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const baseRef = "string_ref:sha1:3333333333333333333333333333333333333333";
  const hrefRef = "string_ref:sha1:4444444444444444444444444444444444444444";
  const queryRef = "string_ref:sha1:5555555555555555555555555555555555555555";
  const tokenRef = "string_ref:xsignature-token";
  const stack = [{
    function: "signRelative",
    url: scriptUrl,
    line: 6,
    column: 10,
    asset_id: "sha1:url-base-refs",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{
      url_object_id: 41,
      search_params_id: 42,
      url: "/api/feed/list?cursor=1",
      url_ref: "string_ref:relative-url",
      base: "https://www.example.test/feed",
      base_ref: baseRef,
      href: "https://www.example.test/api/feed/list?cursor=1",
      href_ref: hrefRef
    }], stack},
    {seq: 2, category: "reverse", phase: "call", api: "StringAdd", args: [{
      left_ref: "string:prefix",
      right_ref: "number:mix",
      result_ref: tokenRef,
      result_length: 18
    }], stack},
    {seq: 3, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{
      url_object_id: 41,
      search_params_id: 42,
      name: "X-Signature",
      value: "secret-one",
      value_ref: tokenRef,
      serialized_ref: queryRef
    }], stack},
    {seq: 4, category: "network", phase: "call", api: "Request.constructor", args: [{
      url_object_id: 41,
      search_params_id: 42,
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
    }], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_url_base_ref_inheritance.ndjson",
    events,
    assets: [{
      asset_id: "sha1:url-base-refs",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signRelative(path, base) {",
        "  const url = new URL(path, base);",
        "  url.searchParams.set('X-Signature', token);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = analysis.parameters.find((item) => item.param === "X-Signature");
  const signedStep = parameter.generation_path.find((step) => step.stage === "signed_request");

  assert.ok(signedStep.value_refs.includes(baseRef));
  assert.ok(signedStep.value_refs.includes(hrefRef));
  assert.ok(parameter.request_input_bundle.url.value_refs.includes(baseRef));
  assert.ok(parameter.request_input_bundle.url.value_refs.includes(hrefRef));
  assert.ok(
    parameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "url_query")
      .value_refs.includes(baseRef)
  );
});

test("buildLocalReport links URL href setter refs through signature attachment", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "sign",
    url: scriptUrl,
    line: 4,
    column: 12,
    asset_id: "sha1:url-href-native-refs",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "StringAdd", args: [{left_ref: "string:prefix", right_ref: "number:mix", result_ref: "string_ref:xsignature-token", result_length: 18}], stack},
    {seq: 2, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 3, category: "reverse", phase: "set", api: "URL.href.set", args: [{
      url_object_id: 31,
      search_params_id: 32,
      value: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      href: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      value_ref: "string_ref:xsignature-token",
      href_ref: "string_ref:signed-url"
    }], stack},
    {seq: 4, category: "network", phase: "call", api: "Request.constructor", args: [{
      url_object_id: 31,
      search_params_id: 32,
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      url_ref: "string_ref:signed-url"
    }], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_url_href_native_refs.ndjson",
    events,
    assets: [{
      asset_id: "sha1:url-href-native-refs",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function sign(url) {",
        "  const token = 'xbg-' + mix;",
        "  url.href = url.origin + '/api/feed/list?cursor=1&X-Signature=' + token;",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const signatureStep = materialFlow.generation_steps.find((step) => step.stage === "signature_mutation");
  const signedStep = materialFlow.generation_steps.find((step) => step.stage === "signed_request");
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.ok(signatureStep.value_refs.includes("string_ref:xsignature-token"));
  assert.ok(signatureStep.value_refs.includes("string_ref:signed-url"));
  assert.ok(signedStep.value_refs.includes("string_ref:signed-url"));
  assert.ok(parameter.generation_edges.some((edge) =>
    edge.from_stage === "string_transform" &&
    edge.to_stage === "signature_mutation" &&
    edge.relation === "shared_value_ref" &&
    edge.refs.includes("string_ref:xsignature-token")
  ));
  assert.ok(parameter.generation_edges.some((edge) =>
    edge.from_stage === "signature_mutation" &&
    edge.to_stage === "signed_request" &&
    edge.evidence.includes("shared_value_ref") &&
    edge.refs.includes("string_ref:signed-url")
  ));
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /ref_lineage=.*string_ref:xsignature-token:value_ref:.*string_transform->signature_mutation.*;string_ref:signed-url:value_ref:signature_mutation->signed_request edges=1/
  );
});

test("buildLocalReport preserves observed text encoder windows outside the selected VMP subflow", () => {
  const scriptUrl = "https://www.example.test/business-api-smoke.html";
  const encoderStack = [{
    function: "makeDemoTraceMarker",
    url: scriptUrl,
    line: 12,
    column: 27,
    asset_id: "sha1:subflow-boundary",
    asset_path: "assets/trace_demo/subflow-boundary.js"
  }];
  const stack = [{
    function: "",
    url: scriptUrl,
    line: 40,
    column: 1,
    asset_id: "sha1:subflow-boundary",
    asset_path: "assets/trace_demo/subflow-boundary.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "TextEncoder.constructor", args: [{text_encoder_id: 10}], stack: encoderStack},
    {seq: 2, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{text_encoder_id: 10, input: "seed", result_typed_array_id: 11, result_array_buffer_id: 20}], stack: encoderStack},
    {seq: 3, category: "reverse", phase: "get", api: "TypedArray.buffer.get", args: [{typed_array_id: 111, array_buffer_id: 222}], stack},
    {seq: 4, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{data_view_id: 30, array_buffer_id: 222, byte_offset: 0, result: 123}], stack},
    {seq: 5, category: "reverse", phase: "call", api: "Object.getOwnPropertyNames", args: [{subject_id: 1}], stack},
    {seq: 6, category: "reverse", phase: "call", api: "Reflect.apply", args: [{target_id: 2}], stack},
    {seq: 7, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left: 1, right: 2, result: 3}], stack},
    {seq: 8, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 3, y: 16777619, result: 42}], stack},
    {seq: 10, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 31, search_params_id: 32, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 11, category: "reverse", phase: "call", api: "URLSearchParams.toString", args: [{search_params_id: 32, url_object_id: 31, serialized: "cursor=1&X-Signature=secret-one"}], stack},
    {seq: 12, category: "reverse", phase: "set", api: "URL.search.set", args: [{url_object_id: 31, search_params_id: 32, value: "cursor=1&X-Signature=secret-one", href: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack},
    {seq: 13, category: "reverse", phase: "call", api: "XMLHttpRequest.setRequestHeader", args: [{name: "X-Signature", value: "secret-one"}], stack},
    {seq: 14, category: "reverse", phase: "call", api: "XMLHttpRequest.send", args: [{url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack},
    {seq: 15, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one", method: "GET"}], stack}
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_subflow_boundary.ndjson", events, assets: []});
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const textStage = materialFlow.stages.find((stage) => stage.stage === "text_or_string_decode");

  assert.ok(textStage.runtime_apis.includes("TextEncoder.encode"));
  assert.ok(materialFlow.agent_generation_summary.runtime_apis.includes("TextEncoder.encode"));
});

test("buildLocalReport treats inferred material data links as readiness evidence", () => {
  const scriptUrl = "https://www.example.test/app.js";
  const stack = [{
    function: "sign",
    url: scriptUrl,
    line: 5,
    column: 2,
    asset_id: "sha1:app",
    asset_path: "assets/trace_demo/app.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input: "local-material"}], stack},
    {seq: 2, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{byte_offset: 0, result: 123}], stack},
    {seq: 3, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 123, y: 16777619, result: 456}], stack},
    {seq: 4, category: "reverse", phase: "call", api: "URL.constructor", args: [{url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 5, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{name: "X-Signature", value: "secret-one"}], stack},
    {seq: 6, category: "reverse", phase: "call", api: "Request.constructor", args: [{url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_inferred_only.ndjson",
    events,
    assets: [{
      asset_id: "sha1:app",
      kind: "script",
      url: scriptUrl,
      content_path: "assets/trace_demo/app.js",
      content: [
        "function sign(seed) {",
        "  const bytes = new TextEncoder().encode(seed);",
        "  const view = new DataView(bytes.buffer);",
        "  const mixed = Math.imul(view.getUint32(0, true), 16777619);",
        "  url.searchParams.set('X-Signature', mixed);",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.equal(materialFlow.data_links.length, 0);
  assert.ok(materialFlow.inferred_data_links.length >= 3);
  assert.ok(!materialFlow.analysis_readiness.evidence_gaps.includes("data_links_not_observed"));
  assert.equal(materialFlow.analysis_readiness.status, "strong");

  const agentPack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(agentPack);
  const [parameter] = analysis.parameters;
  assert.ok(parameter.generation_edges.some((edge) =>
    edge.relation === "inferred_data_link" &&
    edge.evidence.includes("inferred_data_link") &&
    edge.refs.some((ref) => ref.startsWith("source:sha1:app:"))
  ));
  assert.equal(parameter.chain_quality.missing_edge_count, 0);
  assert.ok(parameter.generation_edge_gaps.every((gap) => gap.gap !== "missing_generation_edge"));
  assert.ok(parameter.generation_edge_gaps.some((gap) => gap.gap === "source_only_edge"));
});

test("buildLocalReport canonicalizes TextEncoder result buffer refs for strong material links", () => {
  const stack = [{function: "sign", url: "https://www.example.test/app.js", line: 5, column: 2}];
  const events = [
    {
      seq: 1,
      category: "reverse",
      phase: "call",
      api: "TextEncoder.encode",
      args: [{
        text_encoder_id: 10,
        input: "local-material",
        result_typed_array_id: 11,
        result_array_buffer_id: 20
      }],
      stack
    },
    {
      seq: 2,
      category: "reverse",
      phase: "call",
      api: "DataView.getUint32",
      args: [{data_view_id: 30, array_buffer_id: 20, byte_offset: 0, result: 123}],
      stack
    },
    {
      seq: 3,
      category: "reverse",
      phase: "call",
      api: "Math.imul",
      args: [{data_view_id: 30, x: 123, y: 16777619, result: 456}],
      stack
    },
    {
      seq: 4,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.set",
      args: [{name: "X-Signature", value: "secret-one"}],
      stack
    },
    {
      seq: 5,
      category: "reverse",
      phase: "call",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/feed/list?X-Signature=secret-one"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_strong_buffer_link.ndjson", events, assets: []});
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;

  assert.ok(materialFlow.data_links.some((link) =>
    link.from === "text_or_string_decode" &&
    link.to === "byte_buffer" &&
    link.refs.includes("array_buffer:20")
  ));
  assert.deepEqual(
    materialFlow.stages.find((stage) => stage.stage === "text_or_string_decode").object_refs,
    ["text_encoder:10", "typed_array:11", "array_buffer:20"]
  );
  assert.ok(!materialFlow.analysis_readiness.evidence_gaps.includes("data_links_not_observed"));
});

test("buildLocalReport uses TypedArray buffer getter as TextEncoder byte bridge", () => {
  const stack = [{function: "sign", url: "https://www.example.test/app.js", line: 5, column: 2}];
  const events = [
    {
      seq: 1,
      category: "reverse",
      phase: "call",
      api: "TextEncoder.encode",
      args: [{
        text_encoder_id: 10,
        input: "local-material",
        result_typed_array_id: 1111,
        result_array_buffer_id: 2222
      }],
      stack
    },
    {
      seq: 2,
      category: "reverse",
      phase: "get",
      api: "TypedArray.buffer.get",
      args: [{typed_array_id: 3333, array_buffer_id: 20}],
      stack
    },
    {
      seq: 3,
      category: "reverse",
      phase: "call",
      api: "DataView.getUint32",
      args: [{data_view_id: 30, array_buffer_id: 20, byte_offset: 0, result: 123}],
      stack
    },
    {
      seq: 4,
      category: "reverse",
      phase: "call",
      api: "Math.imul",
      args: [{data_view_id: 30, x: 123, y: 16777619, result: 456}],
      stack
    },
    {
      seq: 5,
      category: "reverse",
      phase: "call",
      api: "URLSearchParams.set",
      args: [{name: "X-Signature", value: "secret-one"}],
      stack
    },
    {
      seq: 6,
      category: "reverse",
      phase: "call",
      api: "Request.constructor",
      args: [{url: "https://www.example.test/api/feed/list?X-Signature=secret-one"}],
      stack
    }
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_getter_buffer_link.ndjson", events, assets: []});
  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  const textStage = materialFlow.stages.find((stage) => stage.stage === "text_or_string_decode");
  const byteStage = materialFlow.stages.find((stage) => stage.stage === "byte_buffer");

  assert.ok(textStage.runtime_apis.includes("TypedArray.buffer.get"));
  assert.ok(byteStage.runtime_apis.includes("TypedArray.buffer.get"));
  assert.ok(materialFlow.data_links.some((link) =>
    link.from === "text_or_string_decode" &&
    link.to === "byte_buffer" &&
    link.refs.includes("array_buffer:20")
  ));
  assert.ok(!materialFlow.analysis_readiness.evidence_gaps.includes("data_links_not_observed"));
});

test("buildLocalReport treats JSON and string runtime stages as observed material source evidence", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 5,
    column: 10,
    asset_id: "sha1:json-string-material",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 756, url: "https://www.example.test/api/feed/list?cursor=1"}], stack},
    {seq: 2, category: "reverse", phase: "call", api: "JSON.stringify", args: [{input_type: "object", result_length: 140, result_ref: "string_ref:canonical-json"}], stack},
    {seq: 3, category: "reverse", phase: "call", api: "Function.prototype.call", args: [{state_object_id: 269603, target_id: 149873, arguments_list_id: 269603, result_ref: "register:269603/string_ref:canonical-json"}], stack},
    {seq: 4, category: "reverse", phase: "call", api: "Object.keys", args: [{subject_id: 269603, result_ref: "register:269603/keys"}], stack},
    {seq: 5, category: "reverse", phase: "call", api: "Bitwise.and", args: [{left_register_ref: "register:string:length:200", right: 255, result: 120}], stack},
    {seq: 6, category: "reverse", phase: "call", api: "Shift.left", args: [{left_register_ref: "register:string:length:200", right: 8, result: 30720}], stack},
    {seq: 7, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 757, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one&X-Secondary-Signature=secret-two"}], stack},
    {seq: 8, category: "reverse", phase: "get", api: "URL.search.get", args: [{url_object_id: 757, result_ref: "string_ref:signed-search"}], stack},
    {seq: 9, category: "reverse", phase: "call", api: "String.prototype.slice", args: [{subject_ref: "string_ref:signed-search", start: 1, result_ref: "string_ref:signed-search-no-prefix"}], stack},
    {seq: 10, category: "reverse", phase: "call", api: "encodeURIComponent", args: [{input_ref: "string_ref:signed-search-no-prefix", result_ref: "string_ref:encoded-search"}], stack},
    {seq: 11, category: "reverse", phase: "call", api: "RegExp.prototype.test", args: [{regexp_id: 676628, input_ref: "string_ref:encoded-search"}], stack},
    {seq: 12, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 757, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one&X-Secondary-Signature=secret-two"}], stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_json_string_material.ndjson",
    events,
    assets: [{
      asset_id: "sha1:json-string-material",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signVm(url, payload) {",
        "  const json = JSON.stringify(payload);",
        "  const state = dispatch(json);",
        "  const mixed = (state.length & 255) << 8;",
        "  const signed = new URL(url + '&X-Signature=secret-one&X-Secondary-Signature=secret-two');",
        "  return new Request(signed.href);",
        "}"
      ].join("\n")
    }]
  });

  const [materialFlow] = report.signature.agent_evidence_pack.signature_material_flows;
  assert.ok(materialFlow.stages.some((stage) => stage.stage === "json_serialization"));
  assert.ok(materialFlow.stages.some((stage) => stage.stage === "string_transform"));
  assert.ok(materialFlow.stages.some((stage) => stage.stage === "url_encoding"));
  assert.ok(!materialFlow.analysis_readiness.evidence_gaps.includes("material_source_not_observed"));

  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = analysis.parameters.find((item) => item.param === "X-Signature");
  assert.ok(parameter);
  assert.ok(!parameter.unresolved_gaps.includes("material_source_not_observed"));
  assert.ok(parameter.candidate_generation_summary.runtime_apis.includes("JSON.stringify"));
  assert.ok(parameter.candidate_generation_summary.runtime_apis.includes("encodeURIComponent"));
});

test("buildAgentInputPack emits request input bundle for signed parameters", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 5,
    column: 10,
    asset_id: "sha1:request-input",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list?cursor=1"}], origin: "https://www.example.test", stack},
    {seq: 2, category: "reverse", phase: "call", api: "localStorage.getItem", args: [{key: "fp_seed", value_length: 24, result_ref: "storage:local:fp_seed"}], origin: "https://www.example.test", stack},
    {seq: 3, category: "reverse", phase: "get", api: "document.cookie.get", args: [{cookie_names: ["sessionToken"], value: "sessionToken=secret-token"}], origin: "https://www.example.test", stack},
    {seq: 4, category: "reverse", phase: "call", api: "JSON.stringify", args: [{input_type: "object", result_length: 96, result_ref: "string_ref:canonical-request"}], origin: "https://www.example.test", stack},
    {seq: 5, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_ref: "string_ref:canonical-request", result_array_buffer_id: 93}], origin: "https://www.example.test", stack},
    {seq: 6, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{array_buffer_id: 93, data_view_id: 94, byte_offset: 0, result: 123}], origin: "https://www.example.test", stack},
    {seq: 7, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 123, y: 16777619, result_ref: "number:signature-mix"}], origin: "https://www.example.test", stack},
    {seq: 8, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 91, search_params_id: 92, name: "X-Signature", value: "secret-one"}], origin: "https://www.example.test", stack},
    {seq: 9, category: "reverse", phase: "call", api: "XMLHttpRequest.setRequestHeader", args: [{name: "X-Signature", value: "secret-one", value_ref: "string_ref:native-header-xsignature", network_correlation_key: "sha1:req"}], origin: "https://www.example.test", stack},
    {seq: 10, category: "reverse", phase: "call", api: "XMLHttpRequest.send", args: [{method: "POST", url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one&X-Secondary-Signature=secret-two", url_ref: "string_ref:native-signed-url", network_correlation_key: "sha1:req", body_ref: "string_ref:native-xhr-body", body_preview: "{\"X-Secondary-Signature\":\"secret-two\",\"cursor\":\"1\"}", body_size: 42}], origin: "https://www.example.test", stack},
    {seq: 11, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{
      method: "POST",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one&X-Secondary-Signature=secret-two",
      network_correlation_key: "sha1:req",
      request_initiator: "https://www.example.test",
      referrer: "https://www.example.test/feed",
      is_fetch_like_api: true,
      headers: [
        {name: "content-type", value: "application/json"},
        {name: "x-signature", redacted: true, value_length: 10},
        {name: "cookie", redacted: true, value_length: 22}
      ],
      upload_body: {
        element_count: 1,
        total_bytes: 42,
        in_memory_bytes: 42,
        preview_sha256: "sha256:body-preview",
        preview_size: 42,
        truncated: false
      }
    }], origin: "https://www.example.test", stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_request_input_bundle.ndjson",
    events,
    assets: [{
      asset_id: "sha1:request-input",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signVm(url, payload) {",
        "  const seed = localStorage.getItem('fp_seed') + document.cookie;",
        "  const canonical = JSON.stringify({url, payload, seed});",
        "  const bytes = new TextEncoder().encode(canonical);",
        "  const mixed = Math.imul(new DataView(bytes.buffer).getUint32(0, true), 16777619);",
        "  url.searchParams.set('X-Signature', mixed);",
        "  xhr.setRequestHeader('X-Signature', mixed);",
        "  return xhr.send(payload);",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.ok(packParameter.request_input_bundle);
  assert.deepEqual(packParameter.request_input_bundle.url.query_keys, ["X-Signature", "X-Secondary-Signature", "cursor"]);
  assert.deepEqual(packParameter.request_input_bundle.url.target_params, ["X-Signature", "X-Secondary-Signature"]);
  assert.match(packParameter.request_input_bundle.url.url, /X-Signature=secret-one/);
  assert.deepEqual(packParameter.request_input_bundle.url.events, [{
    seq: 10,
    api: "XMLHttpRequest.send",
    phase: "call",
    action: "send",
    method: "POST",
    endpoint: "https://www.example.test/api/feed/list",
    url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one&X-Secondary-Signature=secret-two",
    query_keys: ["X-Signature", "X-Secondary-Signature", "cursor"],
    target_params: ["X-Signature", "X-Secondary-Signature"],
    value_refs: [
      "url_shape:e42f66658604e40f4df0fca83d0a6a5a55858711",
      "target_params:X-Signature|X-Secondary-Signature",
      "string_ref:native-signed-url"
    ],
    evidence_ref: "url:XMLHttpRequest.send@10"
  }, {
    seq: 11,
    api: "BrowserNetwork.request",
    phase: "call",
    action: "observe",
    method: "POST",
    endpoint: "https://www.example.test/api/feed/list",
    url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one&X-Secondary-Signature=secret-two",
    query_keys: ["X-Signature", "X-Secondary-Signature", "cursor"],
    target_params: ["X-Signature", "X-Secondary-Signature"],
    value_refs: [
      "url_shape:e42f66658604e40f4df0fca83d0a6a5a55858711",
      "target_params:X-Signature|X-Secondary-Signature"
    ],
    evidence_ref: "url:BrowserNetwork.request@11"
  }]);
  assert.ok(packParameter.request_input_bundle.url.value_refs.includes("string_ref:native-signed-url"));
  assert.deepEqual(packParameter.request_input_bundle.headers.header_names, ["content-type", "cookie", "x-signature"]);
  assert.deepEqual(packParameter.request_input_bundle.headers.target_params, ["X-Signature"]);
  assert.deepEqual(
    packParameter.request_input_bundle.headers.events
      .filter((event) => event.header_name === "x-signature"),
    [{
      seq: 9,
      api: "XMLHttpRequest.setRequestHeader",
      phase: "call",
      action: "set",
      header_name: "x-signature",
      target_params: ["X-Signature"],
      value_length: "secret-one".length,
      value_refs: ["string_ref:native-header-xsignature"],
      evidence_ref: "headers:XMLHttpRequest.setRequestHeader@9"
    }, {
      seq: 11,
      api: "BrowserNetwork.request",
      phase: "call",
      action: "observe",
      header_name: "x-signature",
      target_params: ["X-Signature"],
      redacted: true,
      value_length: 10,
      evidence_ref: "headers:BrowserNetwork.request@11"
    }]
  );
  assert.deepEqual(packParameter.request_input_bundle.headers.value_refs, ["string_ref:native-header-xsignature"]);
  assert.deepEqual(packParameter.request_input_bundle.body.target_params, ["X-Secondary-Signature"]);
  assert.deepEqual(packParameter.request_input_bundle.body.upload_body, {
    element_count: 1,
    total_bytes: 42,
    in_memory_bytes: 42,
    preview_sha256: "sha256:body-preview",
    preview_size: 42,
    truncated: false
  });
  assert.deepEqual(packParameter.request_input_bundle.body.events, [{
    seq: 10,
    api: "XMLHttpRequest.send",
    phase: "call",
    action: "send",
    method: "POST",
    target_params: ["X-Secondary-Signature"],
    body_size: 42,
    preview: "{\"X-Secondary-Signature\":\"secret-two\",\"cursor\":\"1\"}",
    value_refs: [
      "url_shape:e42f66658604e40f4df0fca83d0a6a5a55858711",
      "target_params:X-Signature|X-Secondary-Signature",
      "string_ref:native-signed-url",
      "string_ref:native-xhr-body"
    ],
    evidence_ref: "body:XMLHttpRequest.send@10"
  }, {
    seq: 11,
    api: "BrowserNetwork.request",
    phase: "call",
    action: "observe",
    method: "POST",
    target_params: [],
    upload_body: {
      element_count: 1,
      total_bytes: 42,
      in_memory_bytes: 42,
      preview_sha256: "sha256:body-preview",
      preview_size: 42,
      truncated: false
    },
    value_refs: [
      "url_shape:e42f66658604e40f4df0fca83d0a6a5a55858711",
      "target_params:X-Signature|X-Secondary-Signature"
    ],
    evidence_ref: "body:BrowserNetwork.request@11"
  }]);
  assert.deepEqual(packParameter.request_input_bundle.cookies.names, ["sessionToken"]);
  assert.deepEqual(packParameter.request_input_bundle.storage.keys, ["fp_seed"]);
  assert.ok(packParameter.request_input_bundle.evidence_refs.includes("request:BrowserNetwork.request@11"));
  assert.ok(packParameter.request_input_bundle.evidence_refs.includes("storage:localStorage.getItem@2"));
  assert.ok(packParameter.request_input_bundle.evidence_refs.includes("cookie:document.cookie.get@3"));
  assert.deepEqual(analysisParameter.request_input_bundle, packParameter.request_input_bundle);
  assert.deepEqual(analysisParameter.candidate_generation_summary.request_input_summary.observed_categories, [
    "url_query",
    "request_headers",
    "request_body",
    "cookies",
    "storage"
  ]);
  assert.deepEqual(analysisParameter.candidate_generation_summary.request_input_summary.target_params, [
    "X-Signature",
    "X-Secondary-Signature"
  ]);
  assert.deepEqual(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "url_query")
      .events,
    packParameter.request_input_bundle.url.events
  );
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "url_query")
      .value_refs.includes("string_ref:native-signed-url")
  );
  assert.deepEqual(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "request_headers")
      .value_refs,
    ["string_ref:native-header-xsignature"]
  );
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "request_body")
      .value_refs.includes("string_ref:native-xhr-body")
  );
  assert.deepEqual(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "storage")
      .keys,
    ["fp_seed"]
  );
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "cookies")
      .evidence_refs.includes("cookie:document.cookie.get@3")
  );
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.evidence_refs
      .includes("request:BrowserNetwork.request@11")
  );
  const logic = analysisParameter.candidate_generation_summary.logic_hypothesis;
  const inputPhase = logic.phases.find((phase) => phase.id === "input_material");
  assert.deepEqual(
    inputPhase.request_inputs.map((item) => item.category),
    ["url_query", "request_headers", "request_body", "cookies", "storage"]
  );
  assert.ok(inputPhase.evidence.includes("request_input:url_query"));
  assert.ok(inputPhase.evidence.includes("request_input:request_headers"));
  assert.ok(inputPhase.evidence.includes("request_input:cookies"));
  assert.ok(inputPhase.value_refs.includes("string_ref:native-header-xsignature"));
  assert.ok(inputPhase.value_refs.includes("string_ref:native-xhr-body"));
  assert.ok(inputPhase.value_refs.includes("storage:local:fp_seed"));
  const inputTraceStep = logic.agent_logic_trace.steps.find((step) => step.phase === "input_material");
  assert.deepEqual(inputTraceStep.request_input_categories, [
    "url_query",
    "request_headers",
    "request_body",
    "cookies",
    "storage"
  ]);
  assert.ok(inputTraceStep.request_inputs.find((item) =>
    item.category === "request_headers" &&
    item.header_names.includes("x-signature") &&
    item.value_refs.includes("string_ref:native-header-xsignature")
  ));
  assert.ok(inputTraceStep.request_inputs.find((item) =>
    item.category === "storage" &&
    item.keys.includes("fp_seed") &&
    item.value_refs.includes("storage:local:fp_seed")
  ));
  assert.match(inputTraceStep.claim, /request_inputs=url_query\|request_headers\|request_body\|cookies\|storage/);
  assert.ok(inputTraceStep.evidence.includes("request_input:request_body"));
  const markdown = renderAgentAnalysisMarkdown(analysis);
  assert.match(markdown, /logic_step=1:input_material\[[^\]]+\] claim=input material observed for X-Signature/);
  assert.match(markdown, /request_inputs=url_query\(params=X-Signature\|X-Secondary-Signature query=X-Signature\|X-Secondary-Signature\|cursor refs=[^)]*string_ref:native-signed-url\);request_headers\(params=X-Signature headers=content-type\|cookie\|x-signature refs=string_ref:native-header-xsignature\);request_body\(params=X-Secondary-Signature body_size=42 refs=[^)]*string_ref:native-xhr-body\);cookies\(names=sessionToken\);storage\(keys=fp_seed(?: scopes=local)? refs=storage:local:fp_seed\)/);
});

test("buildAgentInputPack surfaces signature parameter materialization events", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "vmStep",
    url: scriptUrl,
    line: 4,
    column: 12,
    asset_id: "sha1:vmp-materialization",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const signedUrl = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one&X-Secondary-Signature=secret-two";
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list?cursor=1"}], origin: "https://www.example.test", stack},
    {seq: 2, category: "reverse", phase: "call", api: "String.prototype.substr", args: [{subject_ref: "string:length:64", start: 8, length: 18, result_preview: "X-Signature=secret-one", result_length: 18, result_ref: "string:length:18"}], origin: "https://www.example.test", stack: []},
    {seq: 3, category: "reverse", phase: "call", api: "String.prototype.substr", args: [{subject_ref: "string:length:72", start: 9, length: 20, result_preview: "X-Secondary-Signature=secret-two", result_length: 20, result_ref: "string:length:20"}], origin: "https://www.example.test", stack: []},
    {seq: 4, category: "reverse", phase: "call", api: "Request.constructor", args: [{method: "GET", url_object_id: 91, search_params_id: 92, url: signedUrl, url_ref: "string_ref:vmp-signed-url"}], origin: "https://www.example.test", stack},
    {seq: 5, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{method: "GET", url: signedUrl, request_initiator: "https://www.example.test"}], origin: "https://www.example.test", stack: []}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_signature_materialization.ndjson",
    events,
    assets: [{
      asset_id: "sha1:vmp-materialization",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function vmStep(buf) {",
        "  const signature = buf.substr(8, 18);",
        "  const secondarySignature = buf.substr(9, 20);",
        "  return new Request('/api/feed/list?' + signature + '&' + secondarySignature);",
        "}"
      ].join("\n")
    }]
  });
  const materialFlow = report.signature.agent_evidence_pack.signature_material_flows
    .find((flow) => (flow.target_params || []).includes("X-Signature"));

  assert.ok(materialFlow);
  assert.deepEqual(
    (materialFlow.signature_param_materializations || []).map((event) => event.param).sort(),
    ["X-Secondary-Signature", "X-Signature"]
  );
  assert.ok(materialFlow.signature_param_materializations.some((event) =>
    event.param === "X-Signature" &&
    event.api === "String.prototype.substr" &&
    event.seq === 2 &&
    event.value_refs.includes("string:length:18") &&
    event.value_refs.includes("string:length:64")
  ));
  assert.ok(materialFlow.agent_generation_summary.signature_param_materializations.some((event) =>
    event.param === "X-Secondary-Signature" &&
    event.api === "String.prototype.substr" &&
    event.seq === 3
  ));

  const pack = buildAgentInputPack(report);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  assert.ok(packParameter.signature_param_materializations.some((event) =>
    event.param === "X-Signature" &&
    event.api === "String.prototype.substr" &&
    event.seq === 2
  ));

  const analysis = buildAgentAnalysis(pack);
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");
  assert.ok(analysisParameter.candidate_generation_summary.signature_param_materializations.some((event) =>
    event.param === "X-Signature" &&
    event.api === "String.prototype.substr" &&
    event.seq === 2
  ));
  assert.ok(analysisParameter.reconstruction_recipe.materialization_programs.some((program) =>
    program.target_params.includes("X-Signature") &&
    program.lines.includes("mat1=X-Signature:String.prototype.substr@2(string:length:64->string:length:18)")
  ));
  assert.ok(analysisParameter.reconstruction_recipe.algorithm_outline.lines.some((line) =>
    line === "mat1=X-Signature:String.prototype.substr@2(string:length:64->string:length:18)"
  ));
  assert.ok(analysisParameter.reconstruction_recipe.algorithm_outline.lines.some((line) =>
    line === "request1=step_2_string_transform->step_3_signed_request[temporal_runtime_order refs=seq_distance:1->0]"
  ));
  assert.ok(analysisParameter.reconstruction_recipe.algorithm_outline.inputs.includes("string:length:64"));
  assert.ok(analysisParameter.reconstruction_recipe.algorithm_outline.outputs.includes("string:length:18"));
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /materializations=X-Signature:String\.prototype\.substr@2\|X-Secondary-Signature:String\.prototype\.substr@3/
  );
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /recipe=.*materials=mat1=X-Signature:String\.prototype\.substr@2\(string:length:64->string:length:18\)\|mat2=X-Secondary-Signature:String\.prototype\.substr@3\(string:length:72->string:length:20\)/
  );
});

test("buildAgentInputPack recognizes native string transform materialization events", () => {
  const signedUrl = "https://www.example.test/api/feed/list?X-Signature=secret-one&X-Secondary-Signature=secret-two";
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list"}], origin: "https://www.example.test", stack: []},
    {seq: 2, category: "reverse", phase: "call", api: "String.prototype.padStart", args: [{shape: "string_pad", subject_ref: "string:length:8", fill_ref: "string:length:10", result_preview: "X-Signature=secret-one", result_length: 18, result_ref: "string:length:18"}], origin: "https://www.example.test", stack: []},
    {seq: 3, category: "reverse", phase: "call", api: "String.prototype.toUpperCase", args: [{shape: "string_case", subject_ref: "string:length:20", result_preview: "X-Secondary-Signature=secret-two", result_length: 20, result_ref: "string:length:20"}], origin: "https://www.example.test", stack: []},
    {seq: 4, category: "reverse", phase: "call", api: "String.prototype.split", args: [{shape: "string_split", subject_ref: "string:length:39", separator_ref: "string:length:1", result_preview: "X-Signature=secret-one&X-Secondary-Signature=secret-two", result_length: 2, result_ref: "array:length:2"}], origin: "https://www.example.test", stack: []},
    {seq: 5, category: "reverse", phase: "call", api: "Request.constructor", args: [{method: "GET", url_object_id: 91, search_params_id: 92, url: signedUrl, url_ref: "string_ref:signed-url"}], origin: "https://www.example.test", stack: []}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_native_string_materialization.ndjson",
    events,
    assets: []
  });
  const materialFlow = report.signature.agent_evidence_pack.signature_material_flows
    .find((flow) => (flow.target_params || []).includes("X-Signature"));

  assert.ok(materialFlow);
  assert.ok(materialFlow.stages.some((stage) =>
    stage.stage === "string_transform" &&
    stage.runtime_apis.includes("String.prototype.padStart") &&
    stage.runtime_apis.includes("String.prototype.toUpperCase") &&
    stage.runtime_apis.includes("String.prototype.split")
  ));
  assert.ok(materialFlow.signature_param_materializations.some((event) =>
    event.param === "X-Signature" &&
    event.api === "String.prototype.padStart" &&
    event.seq === 2
  ));
  assert.ok(materialFlow.signature_param_materializations.some((event) =>
    event.param === "X-Secondary-Signature" &&
    event.api === "String.prototype.toUpperCase" &&
    event.seq === 3
  ));
  assert.ok(materialFlow.signature_param_materializations.some((event) =>
    event.param === "X-Signature" &&
    event.api === "String.prototype.split" &&
    event.seq === 4
  ));

  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  assert.match(
    renderAgentAnalysisMarkdown(analysis),
    /materializations=X-Signature:String\.prototype\.padStart@2\|X-Secondary-Signature:String\.prototype\.toUpperCase@3\|X-Secondary-Signature:String\.prototype\.split@4\|X-Signature:String\.prototype\.split@4/
  );
});

test("buildAgentInputPack maps records request fields and header sources", () => {
  const endpoint = "https://www.example.test/api/records/list/";
  const scriptUrl = "https://cdn.example.test/obj/generic_web_runtime/example/webapp/main/react-v18/webapp-desktop/feed-prefetch.c2241f3b.js";
  const stack = [{
    function: "fetchRecords",
    url: scriptUrl,
    line: 48,
    column: 16,
    asset_id: "sha1:records-source",
    asset_path: "assets/trace_records/feed-prefetch.js"
  }];
  const signedUrl = `${endpoint}?client_time=1&app_id=1000&app_name=demo_web&browser_language=en-US&count=30&device_platform=web&sessionToken=secret-token&X-Signature=secret-one`;
  const events = [
    {seq: 1, category: "reverse", phase: "get", api: "Document.cookie.get", args: [{cookie_names: ["sessionToken", "visitor_id"], value: "sessionToken=secret-token; visitor_id=seed-cookie"}], origin: "https://www.example.test", stack},
    {seq: 2, category: "reverse", phase: "call", api: "localStorage.getItem", args: [{key: "web_id", value_length: 19, result_ref: "storage:local:web_id"}], origin: "https://www.example.test", stack},
    {seq: 3, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_ref: "string_ref:records-canonical", result_array_buffer_id: 701}], origin: "https://www.example.test", stack},
    {seq: 4, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{array_buffer_id: 701, data_view_id: 702, byte_offset: 0, little_endian: true, result: 123}], origin: "https://www.example.test", stack},
    {seq: 5, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 123, y: 16777619, result_ref: "number:records-mix"}], origin: "https://www.example.test", stack},
    {seq: 6, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: `${endpoint}?client_time=1&app_id=1000&app_name=demo_web&browser_language=en-US&count=30&device_platform=web&sessionToken=secret-token`}], origin: "https://www.example.test", stack},
    {seq: 7, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 91, search_params_id: 92, name: "X-Signature", value: "secret-one", value_ref: "string_ref:records-query-xsignature"}], origin: "https://www.example.test", stack},
    {seq: 8, category: "reverse", phase: "call", api: "Headers.constructor", args: [{headers_id: 501}], origin: "https://www.example.test", stack},
    {seq: 9, category: "reverse", phase: "call", api: "Headers.set", args: [{headers_id: 501, name: "X-Session-Token", value: "secret-token", value_ref: "string_ref:records-header-sessiontoken", redacted: true}], origin: "https://www.example.test", stack},
    {seq: 10, category: "reverse", phase: "call", api: "Headers.set", args: [{headers_id: 501, name: "X-Signature", value: "secret-one", value_ref: "string_ref:records-header-xsignature"}], origin: "https://www.example.test", stack},
    {seq: 11, category: "reverse", phase: "call", api: "Request.constructor", args: [{method: "GET", url_object_id: 91, search_params_id: 92, url: signedUrl, headers_id: 501, network_correlation_key: "sha1:records-request"}], origin: "https://www.example.test", stack},
    {seq: 12, category: "reverse", phase: "call", api: "fetch", args: [{method: "GET", url: signedUrl, url_ref: "string_ref:records-signed-url", headers_id: 501, network_correlation_key: "sha1:records-request"}], origin: "https://www.example.test", stack},
    {seq: 13, category: "network", phase: "call", api: "BrowserNetwork.request", args: [{
      method: "GET",
      url: signedUrl,
      network_correlation_key: "sha1:records-request",
      request_initiator: "https://www.example.test",
      referrer: "https://www.example.test/feed",
      is_fetch_like_api: true,
      headers: [
        {name: "accept", value: "application/json", value_length: 16},
        {name: "accept-language", value: "en-US,en;q=0.9", value_length: 14},
        {name: "cookie", redacted: true, value_length: 64},
        {name: "referer", value: "https://www.example.test/feed", value_length: 29},
        {name: "sec-fetch-site", value: "same-origin", value_length: 11},
        {name: "user-agent", value_length: 120},
        {name: "x-signature", redacted: true, value_length: 10},
        {name: "x-session-token", redacted: true, value_length: 12}
      ]
    }], origin: "https://www.example.test", stack: []},
    {seq: 14, category: "network", phase: "return", api: "BrowserNetwork.response", args: [{
      method: "GET",
      url: signedUrl,
      network_correlation_key: "sha1:records-request",
      response_code: 200,
      mime_type: "application/json",
      response_headers: [
        {name: "content-type", value: "application/json", value_length: 16},
        {name: "set-cookie", redacted: true, value_length: 64}
      ]
    }], origin: "https://www.example.test", stack: []}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_records_request_fields.ndjson",
    events,
    assets: [{
      asset_id: "sha1:records-source",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_records/feed-prefetch.js",
      content: [
        "function fetchRecords(baseUrl) {",
        "  const seed = document.cookie + localStorage.getItem('web_id');",
        "  const mixed = Math.imul(new DataView(new TextEncoder().encode(seed).buffer).getUint32(0, true), 16777619);",
        "  baseUrl.searchParams.set('X-Signature', mixed);",
        "  const headers = new Headers();",
        "  headers.set('X-Session-Token', readToken());",
        "  headers.set('X-Signature', mixed);",
        "  return fetch(new Request(baseUrl.href, {headers}));",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");
  const bundle = packParameter.request_input_bundle;
  const materialFlow = report.signature.agent_evidence_pack.signature_material_flows
    .find((flow) => flow.endpoint === endpoint);

  assert.ok(bundle);
  assert.ok(materialFlow);
  assert.equal(bundle.endpoint, endpoint);
  assert.equal(bundle.network_anchor.api, "BrowserNetwork.request");
  assert.equal(bundle.network_anchor.network_correlation_key, "sha1:records-request");
  for (const key of ["client_time", "app_id", "app_name", "browser_language", "count", "device_platform", "sessionToken", "X-Signature"]) {
    assert.ok(bundle.url.query_keys.includes(key), `missing query key ${key}`);
  }
  assert.ok(materialFlow.signature_attachment_events.some((event) =>
    event.api === "URLSearchParams.set" &&
    event.target_params.includes("X-Signature") &&
    event.value_refs.includes("string_ref:records-query-xsignature")
  ));
  assert.match(bundle.url.url, /sessionToken=secret-token/);
  assert.match(bundle.url.url, /X-Signature=secret-one/);

  for (const name of ["accept", "accept-language", "cookie", "referer", "sec-fetch-site", "user-agent", "x-signature", "x-session-token"]) {
    assert.ok(bundle.headers.header_names.includes(name), `missing header ${name}`);
  }
  assert.ok(bundle.headers.events.some((event) =>
    event.api === "Headers.set" &&
    event.header_name === "x-signature" &&
    event.value_refs.includes("string_ref:records-header-xsignature")
  ));
  assert.ok(bundle.headers.events.some((event) =>
    event.api === "Headers.set" &&
    event.header_name === "x-session-token" &&
    event.value_refs.includes("string_ref:records-header-sessiontoken")
  ));
  assert.ok(bundle.headers.events.some((event) =>
    event.api === "BrowserNetwork.request" &&
    event.header_name === "accept" &&
    event.action === "observe"
  ));
  assert.ok(bundle.response.observed);
  assert.equal(bundle.response.status_code, 200);
  assert.deepEqual(bundle.cookies.names, ["sessionToken", "visitor_id"]);
  assert.deepEqual(bundle.storage.keys, ["web_id"]);
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "request_headers")
      .events.some((event) => event.api === "Headers.set" && event.header_name === "x-signature")
  );
});

test("buildAgentInputPack links distant same-source cookie and storage inputs", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "signVm",
    url: scriptUrl,
    line: 5,
    column: 10,
    asset_id: "sha1:distant-input",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "get", api: "Storage.getItem", args: [{storage: "localStorage", key: "visitor_id", result: "seed-value"}], origin: "https://www.example.test", stack},
    {seq: 2, category: "reverse", phase: "get", api: "Document.cookie.get", args: [{value: "sessionToken=secret-token; visitor_id=seed-cookie"}], origin: "https://www.example.test", stack},
    {seq: 500, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list?cursor=1"}], origin: "https://www.example.test", stack},
    {seq: 501, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_length: 120, result_array_buffer_id: 93}], origin: "https://www.example.test", stack},
    {seq: 502, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{array_buffer_id: 93, data_view_id: 94, byte_offset: 0, result: 123}], origin: "https://www.example.test", stack},
    {seq: 503, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 123, y: 16777619, result_ref: "number:signature-mix"}], origin: "https://www.example.test", stack},
    {seq: 504, category: "reverse", phase: "call", api: "Request.constructor", args: [{method: "GET", url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one&X-Secondary-Signature=secret-two"}], origin: "https://www.example.test", stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_distant_request_input_bundle.ndjson",
    events,
    assets: [{
      asset_id: "sha1:distant-input",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function signVm(url) {",
        "  const seed = localStorage.getItem('visitor_id') + document.cookie;",
        "  const bytes = new TextEncoder().encode(seed + url.href);",
        "  const mixed = Math.imul(new DataView(bytes.buffer).getUint32(0, true), 16777619);",
        "  return new Request(url.href + '&X-Signature=' + mixed + '&X-Secondary-Signature=' + mixed);",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.deepEqual(packParameter.request_input_bundle.storage.keys, ["visitor_id"]);
  assert.deepEqual(packParameter.request_input_bundle.storage.scopes, ["local"]);
  assert.deepEqual(packParameter.request_input_bundle.cookies.names, ["sessionToken", "visitor_id"]);
  assert.ok(!packParameter.request_input_bundle.capture_gaps.includes("storage_material_not_observed"));
  assert.ok(!packParameter.request_input_bundle.capture_gaps.includes("cookie_material_not_observed"));
  assert.ok(packParameter.request_input_bundle.evidence_refs.includes("storage:Storage.getItem@1"));
  assert.ok(packParameter.request_input_bundle.evidence_refs.includes("cookie:Document.cookie.get@2"));
  assert.deepEqual(analysisParameter.request_input_bundle, packParameter.request_input_bundle);
});

test("buildAgentInputPack carries Request constructor body refs into request inputs", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "sendSignedFetch",
    url: scriptUrl,
    line: 8,
    column: 12,
    asset_id: "sha1:request-body-ref",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "JSON.stringify", args: [{result_length: 41, result_ref: "string_ref:canonical-body"}], origin: "https://www.example.test", stack},
    {seq: 2, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_ref: "string_ref:canonical-body", result_array_buffer_id: 501}], origin: "https://www.example.test", stack},
    {seq: 3, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 123, y: 16777619, result_ref: "number:request-body-mix"}], origin: "https://www.example.test", stack},
    {seq: 4, category: "reverse", phase: "call", api: "Request.constructor", args: [{
      method: "POST",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      url_ref: "string_ref:native-request-url",
      has_body: true,
      body_byte_length: 41,
      body_preview: "{\"X-Secondary-Signature\":\"secret-two\",\"cursor\":\"1\"}",
      body_ref: "string_ref:native-request-body",
      network_correlation_key: "sha1:request-body"
    }], origin: "https://www.example.test", stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_request_body_ref.ndjson",
    events,
    assets: [{
      asset_id: "sha1:request-body-ref",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function sendSignedFetch(payload) {",
        "  const body = JSON.stringify(payload);",
        "  const bytes = new TextEncoder().encode(body);",
        "  const mixed = Math.imul(bytes[0], 16777619);",
        "  return new Request('/api/feed/list?X-Signature=' + mixed, {method: 'POST', body});",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.ok(packParameter.request_input_bundle);
  assert.ok(packParameter.request_input_bundle.body.value_refs.includes("string_ref:native-request-body"));
  assert.ok(packParameter.request_input_bundle.body.events.some((event) =>
    event.api === "Request.constructor" &&
    event.value_refs.includes("string_ref:native-request-body")
  ));
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "request_body")
      .value_refs.includes("string_ref:native-request-body")
  );
});

test("buildAgentInputPack links distant FormData mutations by form data id", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "sendSignedForm",
    url: scriptUrl,
    line: 7,
    column: 14,
    asset_id: "sha1:formdata-id",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {_trace_index: 1, seq: 1, category: "reverse", phase: "call", api: "FormData.constructor", args: [{form_data_id: 901}], origin: "https://www.example.test", stack},
    {_trace_index: 2, seq: 2, category: "reverse", phase: "call", api: "FormData.set", args: [{form_data_id: 901, name: "X-Secondary-Signature", value: "secret-two", value_length: "secret-two".length, value_ref: "string_ref:formdata-xsecondarysignature", value_kind: "string", entry_count: 1}], origin: "https://www.example.test", stack},
    {_trace_index: 3, seq: 3, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list?cursor=1"}], origin: "https://www.example.test", stack},
    {_trace_index: 4, seq: 4, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 91, search_params_id: 92, name: "X-Signature", value: "secret-one"}], origin: "https://www.example.test", stack},
    {_trace_index: 500, seq: 500, category: "reverse", phase: "call", api: "Request.constructor", args: [{
      method: "POST",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      form_data_id: 901,
      has_body: true,
      body_byte_length: 128,
      body_ref: "string_ref:multipart-body",
      network_correlation_key: "sha1:formdata-request"
    }], origin: "https://www.example.test", stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_formdata_id_request_input.ndjson",
    events,
    assets: [{
      asset_id: "sha1:formdata-id",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function sendSignedForm(url) {",
        "  const fd = new FormData();",
        "  fd.set('X-Secondary-Signature', signBody());",
        "  url.searchParams.set('X-Signature', signUrl());",
        "  return fetch(url.href, {method: 'POST', body: fd});",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.ok(packParameter.request_input_bundle);
  assert.deepEqual(packParameter.request_input_bundle.body.form_field_names, ["X-Secondary-Signature"]);
  assert.deepEqual(packParameter.request_input_bundle.body.target_params, ["X-Secondary-Signature"]);
  assert.ok(packParameter.request_input_bundle.body.value_refs.includes("string_ref:formdata-xsecondarysignature"));
  assert.ok(packParameter.request_input_bundle.body.value_refs.includes("string_ref:multipart-body"));
  assert.ok(packParameter.request_input_bundle.body.events.some((event) =>
    event.api === "FormData.set" &&
    event.form_data_id === 901 &&
    event.value_refs.includes("string_ref:formdata-xsecondarysignature")
  ));
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "request_body")
      .value_refs.includes("string_ref:formdata-xsecondarysignature")
  );
});

test("buildAgentInputPack links URLSearchParams body mutations by body search params id", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "sendSignedUrlencoded",
    url: scriptUrl,
    line: 9,
    column: 18,
    asset_id: "sha1:urlencoded-body-id",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {_trace_index: 1, seq: 1, category: "reverse", phase: "call", api: "URLSearchParams.constructor", args: [{search_params_id: 902}], origin: "https://www.example.test", stack},
    {_trace_index: 2, seq: 2, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{search_params_id: 902, name: "X-Secondary-Signature", value: "secret-two", value_length: "secret-two".length, value_ref: "string_ref:urlencoded-xsecondarysignature", serialized_ref: "string_ref:urlencoded-body", serialized_length: 19}], origin: "https://www.example.test", stack},
    {_trace_index: 3, seq: 3, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list?cursor=1"}], origin: "https://www.example.test", stack},
    {_trace_index: 4, seq: 4, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 91, search_params_id: 92, name: "X-Signature", value: "secret-one"}], origin: "https://www.example.test", stack},
    {_trace_index: 500, seq: 500, category: "reverse", phase: "call", api: "Request.constructor", args: [{
      method: "POST",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      body_search_params_id: 902,
      has_body: true,
      body_byte_length: 19,
      body_ref: "string_ref:urlencoded-request-body",
      network_correlation_key: "sha1:urlencoded-request"
    }], origin: "https://www.example.test", stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_urlencoded_body_id_request_input.ndjson",
    events,
    assets: [{
      asset_id: "sha1:urlencoded-body-id",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function sendSignedUrlencoded(url) {",
        "  const body = new URLSearchParams();",
        "  body.set('X-Secondary-Signature', signBody());",
        "  url.searchParams.set('X-Signature', signUrl());",
        "  return fetch(url.href, {method: 'POST', body});",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.ok(packParameter.request_input_bundle);
  assert.deepEqual(packParameter.request_input_bundle.body.urlencoded_param_names, ["X-Secondary-Signature"]);
  assert.deepEqual(packParameter.request_input_bundle.body.target_params, ["X-Secondary-Signature"]);
  assert.ok(packParameter.request_input_bundle.body.value_refs.includes("string_ref:urlencoded-xsecondarysignature"));
  assert.ok(packParameter.request_input_bundle.body.value_refs.includes("string_ref:urlencoded-request-body"));
  assert.ok(packParameter.request_input_bundle.body.events.some((event) =>
    event.api === "URLSearchParams.set" &&
    event.body_search_params_id === 902 &&
    event.value_refs.includes("string_ref:urlencoded-xsecondarysignature")
  ));
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "request_body")
      .value_refs.includes("string_ref:urlencoded-xsecondarysignature")
  );
});

test("buildAgentInputPack links URLSearchParams body constructor params by body search params id", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "sendConstructedUrlencoded",
    url: scriptUrl,
    line: 10,
    column: 20,
    asset_id: "sha1:urlencoded-constructor-body-id",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {_trace_index: 1, seq: 1, category: "reverse", phase: "call", api: "URLSearchParams.constructor", args: [{search_params_id: 903, init_type: "record", has_init: true, entry_count: 1, param_names: ["X-Secondary-Signature"], param_value_refs: ["string_ref:urlencoded-xsecondarysignature-init"], param_value_lengths: [10], serialized_ref: "string_ref:urlencoded-init-body", serialized_length: 19}], origin: "https://www.example.test", stack},
    {_trace_index: 2, seq: 2, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list?cursor=1"}], origin: "https://www.example.test", stack},
    {_trace_index: 3, seq: 3, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 91, search_params_id: 92, name: "X-Signature", value: "secret-one"}], origin: "https://www.example.test", stack},
    {_trace_index: 500, seq: 500, category: "reverse", phase: "call", api: "Request.constructor", args: [{
      method: "POST",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      body_search_params_id: 903,
      has_body: true,
      body_byte_length: 19,
      body_ref: "string_ref:urlencoded-request-body",
      network_correlation_key: "sha1:urlencoded-constructor-request"
    }], origin: "https://www.example.test", stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_urlencoded_constructor_body_id_request_input.ndjson",
    events,
    assets: [{
      asset_id: "sha1:urlencoded-constructor-body-id",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function sendConstructedUrlencoded(url) {",
        "  const body = new URLSearchParams({ 'X-Secondary-Signature': signBody() });",
        "  url.searchParams.set('X-Signature', signUrl());",
        "  return fetch(url.href, {method: 'POST', body});",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.ok(packParameter.request_input_bundle);
  assert.deepEqual(packParameter.request_input_bundle.body.urlencoded_param_names, ["X-Secondary-Signature"]);
  assert.deepEqual(packParameter.request_input_bundle.body.target_params, ["X-Secondary-Signature"]);
  assert.ok(packParameter.request_input_bundle.body.value_refs.includes("string_ref:urlencoded-init-body"));
  assert.ok(packParameter.request_input_bundle.body.value_refs.includes("string_ref:urlencoded-xsecondarysignature-init"));
  assert.ok(packParameter.request_input_bundle.body.value_refs.includes("string_ref:urlencoded-request-body"));
  assert.ok(packParameter.request_input_bundle.body.events.some((event) =>
    event.api === "URLSearchParams.constructor" &&
    event.body_search_params_id === 903 &&
    event.urlencoded_param_names.includes("X-Secondary-Signature") &&
    event.urlencoded_param_value_refs.includes("string_ref:urlencoded-xsecondarysignature-init")
  ));
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "request_body")
      .value_refs.includes("string_ref:urlencoded-xsecondarysignature-init")
  );
});

test("buildAgentInputPack links distant Headers object mutations by headers id", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "sendWithPreparedHeaders",
    url: scriptUrl,
    line: 6,
    column: 16,
    asset_id: "sha1:headers-id",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {_trace_index: 1, seq: 1, category: "reverse", phase: "call", api: "Headers.constructor", args: [{headers_id: 701}], origin: "https://www.example.test", stack},
    {_trace_index: 2, seq: 2, category: "reverse", phase: "call", api: "Headers.set", args: [{headers_id: 701, name: "X-Signature", value: "secret-one", value_ref: "string_ref:headers-object-xsignature"}], origin: "https://www.example.test", stack},
    {_trace_index: 500, seq: 500, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list?cursor=1"}], origin: "https://www.example.test", stack},
    {_trace_index: 501, seq: 501, category: "reverse", phase: "call", api: "Math.imul", args: [{x: 123, y: 16777619, result_ref: "number:headers-id-mix"}], origin: "https://www.example.test", stack},
    {_trace_index: 502, seq: 502, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 91, search_params_id: 92, name: "X-Signature", value: "secret-one"}], origin: "https://www.example.test", stack},
    {_trace_index: 503, seq: 503, category: "reverse", phase: "call", api: "Request.constructor", args: [{method: "GET", url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one", headers_id: 701}], origin: "https://www.example.test", stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_headers_id_request_input.ndjson",
    events,
    assets: [{
      asset_id: "sha1:headers-id",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "const preparedHeaders = new Headers();",
        "preparedHeaders.set('X-Signature', signSeed());",
        "function sendWithPreparedHeaders(url) {",
        "  url.searchParams.set('X-Signature', signUrl(url));",
        "  return new Request(url.href, {headers: preparedHeaders});",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.ok(packParameter.request_input_bundle);
  assert.deepEqual(packParameter.request_input_bundle.headers.header_names, ["x-signature"]);
  assert.deepEqual(packParameter.request_input_bundle.headers.value_refs, ["string_ref:headers-object-xsignature"]);
  assert.deepEqual(packParameter.request_input_bundle.headers.events, [{
    seq: 2,
    api: "Headers.set",
    phase: "call",
    action: "set",
    header_name: "x-signature",
    target_params: ["X-Signature"],
    value_length: "secret-one".length,
    value_refs: ["string_ref:headers-object-xsignature"],
    evidence_ref: "headers:Headers.set@2"
  }]);
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "request_headers")
      .value_refs.includes("string_ref:headers-object-xsignature")
  );
});

test("buildAgentInputPack carries fetch boundary refs into request inputs", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "fetchSigned",
    url: scriptUrl,
    line: 7,
    column: 14,
    asset_id: "sha1:fetch-boundary",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {_trace_index: 1, seq: 1, category: "reverse", phase: "call", api: "Headers.set", args: [{headers_id: 808, name: "X-Signature", value: "secret-one", value_ref: "string_ref:fetch-header-xsignature"}], origin: "https://www.example.test", stack},
    {_trace_index: 200, seq: 200, category: "reverse", phase: "call", api: "TextEncoder.encode", args: [{input_ref: "string_ref:fetch-body-canonical", result_array_buffer_id: 901}], origin: "https://www.example.test", stack},
    {_trace_index: 201, seq: 201, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 91, search_params_id: 92, name: "X-Signature", value: "secret-one"}], origin: "https://www.example.test", stack},
    {_trace_index: 202, seq: 202, category: "reverse", phase: "call", api: "fetch", args: [{
      method: "POST",
      url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one",
      url_ref: "string_ref:fetch-url",
      headers_id: 808,
      has_body: true,
      body_byte_length: 42,
      network_correlation_key: "sha1:fetch-boundary"
    }], origin: "https://www.example.test", stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_fetch_boundary_refs.ndjson",
    events,
    assets: [{
      asset_id: "sha1:fetch-boundary",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "const h = new Headers();",
        "h.set('X-Signature', signHeader());",
        "function fetchSigned(url, body) {",
        "  url.searchParams.set('X-Signature', signUrl(url));",
        "  return fetch(url.href, {method: 'POST', headers: h, body});",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const analysis = buildAgentAnalysis(pack);
  const packParameter = pack.parameters.find((item) => item.param === "X-Signature");
  const analysisParameter = analysis.parameters.find((item) => item.param === "X-Signature");

  assert.ok(packParameter.request_input_bundle);
  assert.equal(packParameter.request_input_bundle.network_anchor.api, "fetch");
  assert.equal(packParameter.request_input_bundle.network_anchor.network_correlation_key, "sha1:fetch-boundary");
  assert.ok(packParameter.request_input_bundle.url.value_refs.includes("string_ref:fetch-url"));
  assert.deepEqual(packParameter.request_input_bundle.headers.value_refs, ["string_ref:fetch-header-xsignature"]);
  assert.equal(packParameter.request_input_bundle.body.body_size, 42);
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "url_query")
      .value_refs.includes("string_ref:fetch-url")
  );
  assert.ok(
    analysisParameter.candidate_generation_summary.request_input_summary.categories
      .find((category) => category.category === "request_headers")
      .value_refs.includes("string_ref:fetch-header-xsignature")
  );
});

test("buildAgentInputPack parses cookie setter names without cookie attributes", () => {
  const scriptUrl = "https://www.example.test/runtime-sdk.js";
  const stack = [{
    function: "primeSeedAndSign",
    url: scriptUrl,
    line: 4,
    column: 8,
    asset_id: "sha1:cookie-set-input",
    asset_path: "assets/trace_demo/runtime-sdk.js"
  }];
  const events = [
    {seq: 1, category: "reverse", phase: "set", api: "Document.cookie.set", args: [{value: "sessionToken=secret-token; path=/; SameSite=Lax"}], origin: "https://www.example.test", stack},
    {seq: 2, category: "reverse", phase: "set", api: "Storage.setItem", args: [{storage: "localStorage", key: "fp_seed", value_ref: "storage:local:fp_seed"}], origin: "https://www.example.test", stack},
    {seq: 3, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list?cursor=1"}], origin: "https://www.example.test", stack},
    {seq: 4, category: "reverse", phase: "call", api: "URLSearchParams.set", args: [{url_object_id: 91, search_params_id: 92, name: "X-Signature", value: "secret-one"}], origin: "https://www.example.test", stack},
    {seq: 5, category: "network", phase: "call", api: "Request.constructor", args: [{method: "GET", url_object_id: 91, search_params_id: 92, url: "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"}], origin: "https://www.example.test", stack}
  ];

  const report = buildLocalReport({
    tracePath: "/tmp/xtrace/logs/trace_cookie_set_input_bundle.ndjson",
    events,
    assets: [{
      asset_id: "sha1:cookie-set-input",
      kind: "external-script",
      url: scriptUrl,
      content_path: "assets/trace_demo/runtime-sdk.js",
      content: [
        "function primeSeedAndSign(url) {",
        "  document.cookie = 'sessionToken=' + token + '; path=/; SameSite=Lax';",
        "  localStorage.setItem('fp_seed', seed);",
        "  url.searchParams.set('X-Signature', sign(seed));",
        "  return new Request(url.href);",
        "}"
      ].join("\n")
    }]
  });
  const pack = buildAgentInputPack(report);
  const parameter = pack.parameters.find((item) => item.param === "X-Signature");

  assert.ok(parameter.request_input_bundle);
  assert.deepEqual(parameter.request_input_bundle.cookies.names, ["sessionToken"]);
  assert.ok(!parameter.request_input_bundle.cookies.names.includes("path"));
  assert.ok(!parameter.request_input_bundle.cookies.names.includes("SameSite"));
  assert.deepEqual(parameter.request_input_bundle.storage.keys, ["fp_seed"]);
  assert.deepEqual(parameter.request_input_bundle.cookies.events, [{
    seq: 1,
    api: "Document.cookie.set",
    phase: "set",
    action: "set",
    names: ["sessionToken"],
    value_length: "sessionToken=secret-token; path=/; SameSite=Lax".length,
    evidence_ref: "cookie:Document.cookie.set@1"
  }]);
  assert.deepEqual(parameter.request_input_bundle.storage.events, [{
    seq: 2,
    api: "Storage.setItem",
    phase: "set",
    action: "setItem",
    scope: "local",
    keys: ["fp_seed"],
    value_refs: ["storage:local:fp_seed"],
    evidence_ref: "storage:Storage.setItem@2"
  }]);
  assert.ok(parameter.request_input_bundle.evidence_refs.includes("cookie:Document.cookie.set@1"));
  assert.ok(parameter.request_input_bundle.evidence_refs.includes("storage:Storage.setItem@2"));
});

test("buildLocalReport derives string boundary refs from length-only runtime hooks", () => {
  const stack = [{function: "sign", url: "https://www.example.test/app.js", line: 4, column: 2}];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "Bitwise.xor", args: [{left_ref: "number:1", right_ref: "number:2", result_ref: "number:3"}], stack},
    {seq: 2, category: "reverse", phase: "call", api: "String.prototype.slice", args: [{subject_length: 40, start: 1, end: 40, result_length: 39}], stack},
    {seq: 3, category: "reverse", phase: "call", api: "encodeURIComponent", args: [{input_length: 39, result_length: 41}], stack},
    {seq: 4, category: "reverse", phase: "call", api: "URL.constructor", args: [{url_object_id: 7, url: "https://www.example.test/api/feed/list?X-Signature=secret-one"}], stack},
    {seq: 5, category: "network", phase: "call", api: "Request.constructor", args: [{url_object_id: 7, url: "https://www.example.test/api/feed/list?X-Signature=secret-one"}], stack}
  ];

  const report = buildLocalReport({tracePath: "/tmp/xtrace/logs/trace_string_length_refs.ndjson", events, assets: []});
  const analysis = buildAgentAnalysis(buildAgentInputPack(report));
  const parameter = analysis.parameters.find((item) => item.param === "X-Signature");
  const stringStep = parameter.generation_path.find((step) => step.stage === "string_transform");
  const encodingStep = parameter.generation_path.find((step) => step.stage === "url_encoding");

  assert.ok(stringStep.value_refs.includes("string:length:40"));
  assert.ok(stringStep.value_refs.includes("string:length:39"));
  assert.ok(encodingStep.value_refs.includes("string:length:39"));
  assert.ok(encodingStep.value_refs.includes("string:length:41"));
});

test("generateReportForTrace defaults to retrieving external stack scripts", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "xtrace-report-generate-fetch-"));
  const binDir = path.join(dir, "bin");
  fs.mkdirSync(binDir);
  const fakeCurl = path.join(binDir, "curl");
  fs.writeFileSync(fakeCurl, [
    "#!/bin/sh",
    "cat <<'EOF'",
    "const salt = 1;",
    "function A(vm) {",
    "  const raw = \"X-Signature=secret-one&X-Secondary-Signature=secret-two\";",
    "  return DataView.prototype.getUint32.call(vm.view, 4, true);",
    "}",
    "EOF"
  ].join("\n"), {mode: 0o755});

  const tracePath = path.join(dir, "trace_external_default.ndjson");
  const scriptUrl = "https://cdn.example.test/runtime-sdk.js";
  const stack = [{function: "A", url: scriptUrl, line: 3, column: 2}];
  const events = [
    {seq: 1, category: "reverse", phase: "call", api: "URL.constructor", args: [{url: "https://www.example.test/api/list"}], result: {href: "https://www.example.test/api/list"}, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {seq: 2, category: "reverse", phase: "call", api: "DataView.getUint32", args: [{byte_offset: 4}], result: 123, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false},
    {seq: 3, category: "network", phase: "call", api: "Request.constructor", args: [{url: "https://www.example.test/api/list?X-Signature=secret-one&X-Secondary-Signature=secret-two"}], result: {}, stack, pid: 1, tid: 1, frame_url: "https://www.example.test/", origin: "https://www.example.test", truncated: false}
  ];
  fs.writeFileSync(tracePath, events.map((event) => JSON.stringify(event)).join("\n") + "\n", "utf8");

  const previousPath = process.env.PATH;
  process.env.PATH = `${binDir}${path.delimiter}${previousPath}`;
  try {
    const result = generateReportForTrace(tracePath);
    const sourceRefs = result.report.signature.agent_evidence_pack.flows
      .flatMap((flow) => flow.suspected_signature_subflows || [])
      .flatMap((subflow) => subflow.source_context_refs || []);
    assert.equal(sourceRefs.length, 1);
    assert.match(sourceRefs[0], /^external-script:/);
  } finally {
    process.env.PATH = previousPath;
  }
});

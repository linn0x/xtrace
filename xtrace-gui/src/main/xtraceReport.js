const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const childProcess = require("node:child_process");
const {StringDecoder} = require("node:string_decoder");
const {attachAssetContent, readAssetManifest} = require("./xtraceAssets");
const {parseNdjsonLines} = require("./xtraceProcess");

const DEFAULT_TRACE_REPORT_MAX_BYTES = 64 * 1024 * 1024;
const DEFAULT_TRACE_READ_CHUNK_BYTES = 8 * 1024 * 1024;
const DEFAULT_EXTERNAL_SCRIPT_LIMIT = 8;
const DEFAULT_EXTERNAL_SCRIPT_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_EXTERNAL_SCRIPT_TIMEOUT_MS = 6000;
const MAX_RUNTIME_VALUE_REF_CHARS = 160;
const URLS_FROM_EVENT_CACHE = new WeakMap();
const NETWORK_REQUEST_INFO_CACHE = new WeakMap();
const NETWORK_INFO_FROM_ENDPOINT_CACHE = new Map();
const FINGERPRINT_API_PREFIXES = [
  "CanvasRenderingContext2D.",
  "HTMLCanvasElement.",
  "Crypto.getRandomValues",
  "Navigator.",
  "Screen.",
  "WebGLRenderingContext.",
  "AudioContext.",
  "OfflineAudioContext.",
  "BaseAudioContext.",
  "Permissions.",
  "MediaDevices.",
  "RTCPeerConnection.",
  "Intl."
];
const DYNAMIC_EXECUTION_APIS = new Set([
  "eval",
  "Function",
  "setTimeout.string",
  "setInterval.string"
]);
const WEBCRYPTO_SIGNATURE_APIS = new Set([
  "SubtleCrypto.digest",
  "SubtleCrypto.importKey",
  "SubtleCrypto.sign"
]);
const VMP_RUNTIME_APIS = new Set([
  "btoa",
  "atob",
  "TextEncoder.constructor",
  "TextEncoder.encode",
  "TextEncoder.encodeInto",
  "TextDecoder.constructor",
  "TextDecoder.decode",
  "SubtleCrypto.digest",
  "SubtleCrypto.importKey",
  "SubtleCrypto.sign",
  "ArrayBuffer.constructor",
  "DataView.getUint8",
  "DataView.getUint16",
  "DataView.getUint32",
  "DataView.getInt32",
  "DataView.setUint8",
  "DataView.setUint16",
  "DataView.setUint32",
  "DataView.setInt32",
  "TypedArray.buffer.get",
  "TypedArray.at",
  "TypedArray.slice",
  "TypedArray.subarray",
  "TypedArray.join",
  "Array.prototype.push",
  "Array.prototype.slice",
  "Array.prototype.join",
  "Array.prototype.shift",
  "Reflect.apply",
  "Reflect.apply.call",
  "Reflect.ownKeys",
  "Reflect.getOwnPropertyDescriptor",
  "Reflect.get",
  "Reflect.has",
  "Function.prototype.call",
  "Function.prototype.call.call",
  "Function.prototype.apply",
  "Function.prototype.apply.call",
  "Object.keys",
  "Object.getOwnPropertyNames",
  "Map.prototype.get",
  "Map.prototype.has",
  "Map.prototype.set",
  "Map.prototype.delete",
  "Set.prototype.add",
  "Set.prototype.has",
  "Set.prototype.delete",
  "Proxy.get",
  "Proxy.set",
  "Proxy.has",
  "Proxy.ownKeys",
  "Proxy.getOwnPropertyDescriptor",
  "Proxy.defineProperty",
  "Proxy.deleteProperty",
  "Bitwise.and",
  "Bitwise.or",
  "Bitwise.xor",
  "Bitwise.not",
  "Shift.left",
  "Shift.right",
  "Shift.unsignedRight",
  "String.fromCharCode",
  "String.fromCodePoint",
  "String.prototype.charAt",
  "String.prototype.charCodeAt",
  "String.prototype.concat",
  "StringAdd",
  "StringAdd.constant_lhs",
  "StringAdd.constant_rhs",
  "String.prototype.substr",
  "String.prototype.slice",
  "String.prototype.substring",
  "String.prototype.padStart",
  "String.prototype.padEnd",
  "Number.prototype.toString",
  "BigInt.prototype.toString",
  "String.prototype.indexOf",
  "String.prototype.includes",
  "String.prototype.replace",
  "String.prototype.split",
  "String.prototype.toLowerCase",
  "String.prototype.toUpperCase",
  "RegExp.prototype.test",
  "RegExp.prototype.exec",
  "encodeURI",
  "encodeURIComponent",
  "decodeURI",
  "decodeURIComponent",
  "JSON.parse",
  "JSON.stringify",
  "URLSearchParams.toString",
  "URLSearchParams.sort",
  "Math.imul",
  "Performance.now",
  "Date.now",
  "console.debug",
  "console.clear",
  "debugger.statement",
  "Function.prototype.toString",
  "Error.captureStackTrace",
  "Error.stack.get",
  "Error.constructor",
  "Exception.throw"
]);
const BUSINESS_API_RUNTIME_APIS = new Set([
  "decodeURI",
  "decodeURIComponent",
  "encodeURI",
  "encodeURIComponent",
  "URL.constructor",
  "URLSearchParams.toString",
  "URLSearchParams.sort",
  "URLSearchParams.set",
  "URLSearchParams.append",
  "Request.constructor",
  "fetch",
  "XMLHttpRequest.open"
]);
const VMP_API_FAMILY = new Map([
  ["btoa", "base64"],
  ["atob", "base64"],
  ["TextEncoder.constructor", "text_codec"],
  ["TextEncoder.encode", "text_codec"],
  ["TextEncoder.encodeInto", "text_codec"],
  ["TextDecoder.constructor", "text_codec"],
  ["TextDecoder.decode", "text_codec"],
  ["JSON.parse", "json_serialization"],
  ["JSON.stringify", "json_serialization"],
  ["SubtleCrypto.digest", "hash_crypto"],
  ["SubtleCrypto.importKey", "hash_crypto"],
  ["SubtleCrypto.sign", "hash_crypto"],
  ["ArrayBuffer.constructor", "byte_buffer"],
  ["DataView.getUint8", "byte_buffer"],
  ["DataView.getUint16", "byte_buffer"],
  ["DataView.getUint32", "byte_buffer"],
  ["DataView.getInt32", "byte_buffer"],
  ["DataView.setUint8", "byte_buffer"],
  ["DataView.setUint16", "byte_buffer"],
  ["DataView.setUint32", "byte_buffer"],
  ["DataView.setInt32", "byte_buffer"],
  ["TypedArray.buffer.get", "typed_array"],
  ["TypedArray.at", "typed_array"],
  ["TypedArray.slice", "typed_array"],
  ["TypedArray.subarray", "typed_array"],
  ["TypedArray.join", "typed_array"],
  ["Array.prototype.push", "array_table"],
  ["Array.prototype.slice", "array_table"],
  ["Array.prototype.join", "array_table"],
  ["Array.prototype.shift", "array_table"],
  ["Reflect.apply", "dynamic_dispatch"],
  ["Reflect.apply.call", "dynamic_dispatch"],
  ["Reflect.ownKeys", "dynamic_dispatch"],
  ["Reflect.getOwnPropertyDescriptor", "dynamic_dispatch"],
  ["Reflect.get", "dynamic_dispatch"],
  ["Reflect.has", "dynamic_dispatch"],
  ["Function.prototype.call", "dynamic_dispatch"],
  ["Function.prototype.call.call", "dynamic_dispatch"],
  ["Function.prototype.apply", "dynamic_dispatch"],
  ["Function.prototype.apply.call", "dynamic_dispatch"],
  ["Object.keys", "dynamic_dispatch"],
  ["Object.getOwnPropertyNames", "dynamic_dispatch"],
  ["Map.prototype.get", "collection_table"],
  ["Map.prototype.has", "collection_table"],
  ["Map.prototype.set", "collection_table"],
  ["Map.prototype.delete", "collection_table"],
  ["Set.prototype.add", "collection_table"],
  ["Set.prototype.has", "collection_table"],
  ["Set.prototype.delete", "collection_table"],
  ["Proxy.get", "proxy_trap"],
  ["Proxy.set", "proxy_trap"],
  ["Proxy.has", "proxy_trap"],
  ["Proxy.ownKeys", "proxy_trap"],
  ["Proxy.getOwnPropertyDescriptor", "proxy_trap"],
  ["Proxy.defineProperty", "proxy_trap"],
  ["Proxy.deleteProperty", "proxy_trap"],
  ["Bitwise.and", "int_bitwise"],
  ["Bitwise.or", "int_bitwise"],
  ["Bitwise.xor", "int_bitwise"],
  ["Bitwise.not", "int_bitwise"],
  ["Shift.left", "int_bitwise"],
  ["Shift.right", "int_bitwise"],
  ["Shift.unsignedRight", "int_bitwise"],
  ["String.fromCharCode", "string_decode"],
  ["String.fromCodePoint", "string_decode"],
  ["String.prototype.charAt", "string_decode"],
  ["String.prototype.charCodeAt", "string_decode"],
  ["String.prototype.concat", "string_transform"],
  ["StringAdd", "string_transform"],
  ["StringAdd.constant_lhs", "string_transform"],
  ["StringAdd.constant_rhs", "string_transform"],
  ["String.prototype.substr", "string_transform"],
  ["String.prototype.slice", "string_transform"],
  ["String.prototype.substring", "string_transform"],
  ["String.prototype.padStart", "string_transform"],
  ["String.prototype.padEnd", "string_transform"],
  ["Number.prototype.toString", "string_transform"],
  ["BigInt.prototype.toString", "string_transform"],
  ["String.prototype.indexOf", "string_transform"],
  ["String.prototype.includes", "string_transform"],
  ["String.prototype.replace", "string_transform"],
  ["String.prototype.split", "string_transform"],
  ["String.prototype.toLowerCase", "string_transform"],
  ["String.prototype.toUpperCase", "string_transform"],
  ["RegExp.prototype.test", "regexp_probe"],
  ["RegExp.prototype.exec", "regexp_probe"],
  ["encodeURI", "url_encoding"],
  ["encodeURIComponent", "url_encoding"],
  ["decodeURI", "url_encoding"],
  ["decodeURIComponent", "url_encoding"],
  ["URLSearchParams.toString", "url_encoding"],
  ["URLSearchParams.sort", "url_encoding"],
  ["Math.imul", "int_arithmetic"],
  ["Performance.now", "anti_debug_timing"],
  ["Date.now", "anti_debug_timing"],
  ["console.debug", "anti_debug_timing"],
  ["console.clear", "anti_debug_timing"],
  ["debugger.statement", "anti_debug_timing"],
  ["Function.prototype.toString", "source_probe"],
  ["Error.captureStackTrace", "stack_probe"],
  ["Error.stack.get", "stack_probe"],
  ["Error.constructor", "exception_probe"],
  ["Exception.throw", "exception_probe"]
]);
const SIGNATURE_TERMS = ["X-Signature", "X-Secondary-Signature"];
const SENSITIVE_PARAM_TERMS = [...SIGNATURE_TERMS, "token"];
const SIGNATURE_PARAM_MATERIALIZATION_APIS = new Set([
  "String.fromCharCode",
  "String.fromCodePoint",
  "String.prototype.charAt",
  "String.prototype.charCodeAt",
  "String.prototype.codePointAt",
  "String.prototype.concat",
  "String.prototype.slice",
  "String.prototype.substring",
  "String.prototype.substr",
  "String.prototype.padStart",
  "String.prototype.padEnd",
  "String.prototype.replace",
  "String.prototype.split",
  "String.prototype.toLowerCase",
  "String.prototype.toUpperCase",
  "StringAdd",
  "StringAdd.constant_lhs",
  "StringAdd.constant_rhs",
  "Array.prototype.join",
  "TypedArray.join",
  "Number.prototype.toString",
  "BigInt.prototype.toString",
  "encodeURI",
  "encodeURIComponent",
  "decodeURI",
  "decodeURIComponent",
  "URLSearchParams.append",
  "URLSearchParams.set",
  "URLSearchParams.toString",
  "URL.href.set",
  "URL.search.set",
  "Headers.append",
  "Headers.set",
  "XMLHttpRequest.setRequestHeader",
  "FormData.append",
  "FormData.set"
]);
const SIGNATURE_CONTEXT_LOOKBACK = 20000;
const AUTO_TARGETED_SIGNATURE_LOOKBACK = 5000;
const AUTO_TARGETED_SIGNATURE_LOOKAHEAD = 1000;
const SIGNATURE_VMP_LOOKBACK = 5000;
const SIGNATURE_VMP_NEARBY_LOOKBACK = 160;
const SIGNATURE_VMP_EVENT_LIMIT = 12;
const SIGNATURE_TIMELINE_EVENT_LIMIT = 48;
const SIGNATURE_REQUEST_MATERIAL_TRACE_RADIUS = 80;
const SIGNATURE_REQUEST_MATERIAL_EVENT_LIMIT = 16;
const SIGNATURE_REQUEST_AMBIENT_INPUT_EVENT_LIMIT = 48;
const VMP_SAMPLE_LIMIT = 8;
const VMP_ANALYSIS_POINT_LIMIT = 16;
const VMP_HOTSPOT_LIMIT = 12;
const VMP_EXECUTION_PROFILE_LIMIT = 12;
const VMP_EXECUTION_PROFILE_SAMPLE_LIMIT = 6;
const VMP_CLUSTER_GAP = 32;
const SOURCE_CONTEXT_RADIUS = 2;
const SOURCE_CONTEXT_MAX_CHARS = 1200;
const AGENT_SOURCE_PREVIEW_MAX_CHARS = 240;
const SOURCE_CONTEXTS_PER_WINDOW = 3;
const STACK_CLUSTER_LIMIT = 8;
const VMP_LINKING_CANDIDATE_LIMIT = 8;
const VMP_LINKING_CONTEXT_RADIUS = 2;
const VMP_LINKING_NEAREST_FLOW_LIMIT = 3;
const VMP_RELATION_PRIORITY = {
  between_unsigned_signed: 0,
  signed_stack: 1,
  unsigned_stack: 2,
  same_frame: 3,
  same_origin: 4,
  nearby: 5
};
const VMP_HOOK_ANALYSIS_GOALS = {
  vmp_string_decoder: "trace decoded strings, parameter names, and base64 material",
  vmp_bytecode_or_register_access: "trace VM bytecode/register reads and typed-array register movement",
  vmp_array_table: "trace VM array tables, opcode tables, and string table mutation",
  vmp_dynamic_dispatch: "trace VM handler dispatch and indirect function invocation",
  vmp_collection_table: "trace Map/Set opcode tables and memoized VM state",
  vmp_proxy_trap: "trace Proxy-based property indirection and guarded VM state access",
  vmp_json_serialization: "trace JSON canonicalization and request material serialization",
  vmp_hash_or_signature_pipeline: "trace JSON serialization, encoding, WebCrypto digest/sign/importKey, and arithmetic material used by request signing",
  vmp_int_bitwise_pipeline: "trace integer bitwise and shift rounds used by VM/signature mixing",
  vmp_anti_debug_timing_gate: "trace VMP anti-debug checks, timing gates, and console probes",
  vmp_source_integrity_probe: "trace source/native-code probes used for anti-hook and VMP integrity checks",
  vmp_stack_trace_probe: "trace Error stack capture/read probes used for stack-shape checks and guarded VMP paths",
  vmp_exception_control_flow: "trace thrown exceptions and Error construction used for guarded VMP control flow",
  vmp_string_transform: "trace string slicing, searching, and normalization around VM material",
  vmp_regexp_probe: "trace regular-expression probes used to parse or classify VM/request material",
  vmp_url_encoding_boundary: "trace URL and query-string encoding boundaries before request material enters signing or VM mixing"
};
const VMP_HOOK_POINT_SPECS = [
  {
    type: "vmp_string_decoder",
    families: ["string_decode", "base64"],
    priority: "medium",
    reason: "string/base64 decode hooks are missing in one or more signature flows",
    suggested_hooks: [
      "String.fromCharCode",
      "String.fromCodePoint",
      "String.prototype.charCodeAt",
      "atob",
      "btoa"
    ]
  },
  {
    type: "vmp_bytecode_or_register_access",
    families: ["byte_buffer", "typed_array"],
    priority: "medium",
    reason: "bytecode/register access hooks are missing in one or more signature flows",
    suggested_hooks: [
      "ArrayBuffer.constructor",
      "DataView.getUint8",
      "DataView.getUint16",
      "DataView.getUint32",
      "TypedArray.at",
      "TypedArray.slice"
    ]
  },
  {
    type: "vmp_array_table",
    families: ["array_table"],
    priority: "medium",
    reason: "array table hooks are missing in one or more signature flows",
    suggested_hooks: [
      "Array.prototype.push",
      "Array.prototype.slice",
      "Array.prototype.join",
      "Array.prototype.shift",
      "TypedArray.join"
    ]
  },
  {
    type: "vmp_dynamic_dispatch",
    families: ["dynamic_dispatch"],
    priority: "medium",
    reason: "dynamic dispatch hooks are missing in one or more signature flows",
    suggested_hooks: [
      "Reflect.apply",
      "Function.prototype.call",
      "Function.prototype.apply",
      "Object.keys",
      "Reflect.ownKeys"
    ]
  },
  {
    type: "vmp_collection_table",
    families: ["collection_table"],
    priority: "medium",
    reason: "Map/Set table hooks are missing in one or more signature flows",
    suggested_hooks: [
      "Map.prototype.get",
      "Map.prototype.set",
      "Map.prototype.has",
      "Set.prototype.add",
      "Set.prototype.has"
    ]
  },
  {
    type: "vmp_proxy_trap",
    families: ["proxy_trap"],
    priority: "medium",
    reason: "Proxy trap hooks are missing in one or more signature flows",
    suggested_hooks: [
      "Proxy.get",
      "Proxy.set",
      "Proxy.has",
      "Proxy.ownKeys",
      "Proxy.getOwnPropertyDescriptor"
    ]
  },
  {
    type: "vmp_json_serialization",
    families: ["json_serialization"],
    priority: "high",
    reason: "JSON serialization hooks are missing in one or more signature flows",
    suggested_hooks: [
      "JSON.stringify",
      "JSON.parse"
    ]
  },
  {
    type: "vmp_hash_or_signature_pipeline",
    families: ["json_serialization", "text_codec", "hash_crypto", "int_arithmetic"],
    priority: "high",
    reason: "JSON serialization, encoding, WebCrypto digest/sign/importKey, or integer arithmetic hooks are missing in one or more signature flows",
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
    ]
  },
  {
    type: "vmp_int_bitwise_pipeline",
    families: ["int_bitwise"],
    priority: "medium",
    reason: "bitwise/shift integer mixing hooks are missing in one or more signature flows",
    suggested_hooks: [
      "Bitwise.and",
      "Bitwise.or",
      "Bitwise.xor",
      "Bitwise.not",
      "Shift.left",
      "Shift.right",
      "Shift.unsignedRight"
    ]
  },
  {
    type: "vmp_anti_debug_timing_gate",
    families: ["anti_debug_timing"],
    priority: "high",
    reason: "timing and console/debugger probes are missing in one or more signature flows",
    suggested_hooks: [
      "Performance.now",
      "Date.now",
      "console.debug",
      "console.clear",
      "debugger.statement"
    ]
  },
  {
    type: "vmp_source_integrity_probe",
    families: ["source_probe"],
    priority: "high",
    reason: "source and native-code probes are missing in one or more signature flows",
    suggested_hooks: [
      "Function.prototype.toString"
    ]
  },
  {
    type: "vmp_stack_trace_probe",
    families: ["stack_probe"],
    priority: "high",
    reason: "stack trace probes are missing in one or more signature flows",
    suggested_hooks: [
      "Error.captureStackTrace",
      "Error.stack.get"
    ]
  },
  {
    type: "vmp_exception_control_flow",
    families: ["exception_probe"],
    priority: "high",
    reason: "exception control-flow hooks are missing in one or more signature flows",
    suggested_hooks: [
      "Error.constructor",
      "Exception.throw"
    ]
  },
  {
    type: "vmp_string_transform",
    families: ["string_transform"],
    priority: "medium",
    reason: "string transform hooks are missing in one or more signature flows",
    suggested_hooks: [
      "StringAdd",
      "StringAdd.constant_lhs",
      "StringAdd.constant_rhs",
      "String.prototype.slice",
      "String.prototype.substring",
      "String.prototype.indexOf",
      "String.prototype.includes"
    ]
  },
  {
    type: "vmp_regexp_probe",
    families: ["regexp_probe"],
    priority: "medium",
    reason: "regular-expression probe hooks are missing in one or more signature flows",
    suggested_hooks: [
      "RegExp.prototype.test",
      "RegExp.prototype.exec"
    ]
  },
  {
    type: "vmp_url_encoding_boundary",
    families: ["url_encoding"],
    priority: "high",
    reason: "URL encoding and query serialization hooks are missing in one or more signature flows",
    suggested_hooks: [
      "encodeURIComponent",
      "decodeURIComponent",
      "encodeURI",
      "decodeURI",
      "URLSearchParams.toString"
    ]
  }
];
const VMP_HOOK_POINT_IMPORTANCE = new Map([
  ["vmp_runtime_cluster", 0],
  ["vmp_hash_or_signature_pipeline", 1],
  ["vmp_json_serialization", 2],
  ["vmp_url_encoding_boundary", 3],
  ["vmp_bytecode_or_register_access", 4],
  ["vmp_dynamic_dispatch", 5],
  ["vmp_int_bitwise_pipeline", 6],
  ["vmp_anti_debug_timing_gate", 7],
  ["vmp_source_integrity_probe", 8],
  ["vmp_stack_trace_probe", 9],
  ["vmp_exception_control_flow", 10],
  ["vmp_string_transform", 11],
  ["vmp_regexp_probe", 12],
  ["vmp_proxy_trap", 13],
  ["vmp_string_decoder", 14],
  ["vmp_array_table", 15],
  ["vmp_collection_table", 16]
]);
const VMP_EXECUTION_HOOK_POINT_SPECS = [
  {
    type: "bytecode_or_register_access",
    families: ["byte_buffer", "typed_array"],
    analysis_hint: "inspect bytecode cursor, register reads/writes, and DataView/TypedArray offsets"
  },
  {
    type: "integer_mixing",
    families: ["int_bitwise", "int_arithmetic"],
    analysis_hint: "inspect 32-bit arithmetic, bitwise mixing, and checksum/signature rounds"
  },
  {
    type: "handler_dispatch",
    families: ["dynamic_dispatch", "proxy_trap"],
    analysis_hint: "inspect handler table dispatch, Reflect/Function calls, and guarded property access"
  },
  {
    type: "table_lookup",
    families: ["array_table", "collection_table"],
    analysis_hint: "inspect string tables, opcode maps, and memoized VM state"
  },
  {
    type: "string_material",
    families: ["string_decode", "base64", "json_serialization", "text_codec"],
    analysis_hint: "inspect decoded parameter names, JSON material, canonical strings, and encoded request material"
  },
  {
    type: "hash_material",
    families: ["hash_crypto"],
    analysis_hint: "inspect digest inputs and hash material preparation"
  },
  {
    type: "url_encoding",
    families: ["url_encoding"],
    analysis_hint: "inspect URL/query canonicalization, percent encoding, and serialized request material"
  },
  {
    type: "anti_debug_timing_gate",
    families: ["anti_debug_timing"],
    analysis_hint: "inspect timing deltas, debugger probes, and console-based analysis gates"
  },
  {
    type: "source_integrity_probe",
    families: ["source_probe"],
    analysis_hint: "inspect Function.prototype.toString probes for native-code checks, hook detection, or guarded VM paths"
  },
  {
    type: "stack_trace_probe",
    families: ["stack_probe"],
    analysis_hint: "inspect Error stack capture/read probes for anti-debug gates, stack-shape checks, and guarded VM paths"
  },
  {
    type: "exception_control_flow",
    families: ["exception_probe"],
    analysis_hint: "inspect Error construction and thrown exceptions for opaque predicates, VM branch gates, and anti-debug flow"
  },
  {
    type: "string_transform",
    families: ["string_transform"],
    analysis_hint: "inspect string slicing/searching for parameter extraction, canonicalization, and token assembly"
  },
  {
    type: "regexp_probe",
    families: ["regexp_probe"],
    analysis_hint: "inspect regular-expression tests and exec calls for token extraction and guarded request parsing"
  }
];
const VMP_EXECUTION_HOOK_POINT_ORDER = new Map(
  VMP_EXECUTION_HOOK_POINT_SPECS.map((spec, index) => [spec.type, index])
);
const SIGNATURE_ABSENT_NETWORK_ANCHOR_LIMIT = 12;
const SIGNATURE_ABSENT_NEARBY_VMP_LIMIT = 6;
const SIGNATURE_ABSENT_NEARBY_VMP_TRACE_RADIUS = 4000;
const SIGNATURE_ABSENT_RENDERER_REQUEST_TRACE_RADIUS = 6000;
const SIGNATURE_ABSENT_NETWORK_SIGNAL_WEIGHTS = new Map([
  ["script_request_api", 40],
  ["state_changing_method", 30],
  ["browser_fetch_like_request", 18],
  ["application_endpoint", 12],
  ["nearby_vmp:hash_crypto", 16],
  ["nearby_vmp:json_serialization", 14],
  ["nearby_vmp:int_bitwise", 12],
  ["nearby_vmp:base64", 10],
  ["nearby_vmp:text_codec", 10],
  ["nearby_vmp:byte_buffer", 8],
  ["nearby_vmp:array_table", 6],
  ["nearby_vmp:dynamic_dispatch", 6],
  ["nearby_vmp:anti_debug_timing", 6],
  ["nearby_vmp:source_probe", 8],
  ["nearby_vmp:stack_probe", 8],
  ["nearby_vmp:exception_probe", 8],
  ["nearby_vmp:string_transform", 7],
  ["nearby_vmp:regexp_probe", 7],
  ["nearby_vmp:url_encoding", 12],
  ["query_params_present", 8],
  ["nearby_obfuscated_asset", 12],
  ["deprioritized:static_resource_request", -80],
  ["deprioritized:telemetry_endpoint", -100],
  ["deprioritized:document_request", -60]
]);
const SIGNATURE_ABSENT_NETWORK_VMP_FAMILY_SIGNAL_ORDER = [
  "json_serialization",
  "text_codec",
  "hash_crypto",
  "url_encoding",
  "base64",
  "int_bitwise",
  "byte_buffer",
  "array_table",
  "dynamic_dispatch",
  "collection_table",
  "proxy_trap",
  "anti_debug_timing",
  "source_probe",
  "stack_probe",
  "exception_probe",
  "string_transform",
  "regexp_probe",
  "typed_array"
];
const SIGNATURE_TIMELINE_APIS = new Set([
  "URL.constructor",
  "URL.href.set",
  "URL.href.get",
  "URL.search.set",
  "URL.search.get",
  "URLSearchParams.append",
  "URLSearchParams.set",
  "URLSearchParams.delete",
  "URLSearchParams.sort",
  "URLSearchParams.toString",
  "URLSearchParams.get",
  "URLSearchParams.getAll",
  "URLSearchParams.has",
  "Headers.constructor",
  "Headers.append",
  "Headers.set",
  "Headers.delete",
  "Request.constructor",
  "fetch",
  "XMLHttpRequest.open",
  "XMLHttpRequest.send",
  "XMLHttpRequest.setRequestHeader"
]);

function traceBaseName(tracePath) {
  return path.basename(tracePath).replace(/\.ndjson$/i, "");
}

function reportDirectoryForTrace(tracePath) {
  return path.join(path.dirname(tracePath), "reports", traceBaseName(tracePath));
}

function sha1Hex(value) {
  return crypto.createHash("sha1").update(String(value)).digest("hex");
}

function externalScriptAssetId(url) {
  return `external-script:${sha1Hex(url).slice(0, 16)}`;
}

function isRetrievableScriptUrl(value) {
  if (!value || typeof value !== "string") return false;
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
  const pathname = parsed.pathname.toLowerCase();
  return pathname.endsWith(".js") || pathname.includes(".js/");
}

function existingAssetUrlsWithContent(assets) {
  const urls = new Set();
  for (const asset of assets || []) {
    if (!asset?.url) continue;
    if (asset.content || asset.source || asset.source_preview || asset.content_path) {
      urls.add(asset.url);
    }
  }
  return urls;
}

function collectExternalScriptUrls(events, assets, options = {}) {
  const limit = options.externalScriptLimit || DEFAULT_EXTERNAL_SCRIPT_LIMIT;
  const existingUrls = existingAssetUrlsWithContent(assets);
  const priorityUrls = [];
  const normalUrls = [];
  const seen = new Set(existingUrls);

  function addUrl(value, priority = false) {
    if (!isRetrievableScriptUrl(value) || seen.has(value)) return;
    seen.add(value);
    if (priority) {
      priorityUrls.push(value);
    } else {
      normalUrls.push(value);
    }
  }

  for (const event of events || []) {
    if (event.script_url) addUrl(event.script_url, isCoreSignatureAsset({stack_url: event.script_url}));
    for (const {parsed} of urlsFromEvent(event)) {
      const url = parsed.href;
      if (isCoreSignatureAsset({stack_url: url})) {
        addUrl(url, true);
      }
    }
    for (const frame of event.stack || []) {
      if (frame?.asset_id) continue;
      addUrl(frame?.url, isCoreSignatureAsset({stack_url: frame?.url}));
    }
  }
  return [...priorityUrls, ...normalUrls].slice(0, limit);
}

function sanitizeAssetFilename(assetId) {
  return assetId.replace(/[^a-zA-Z0-9._-]/g, "_");
}

function relativePathFromTrace(tracePath, filePath) {
  return path.relative(path.dirname(tracePath), filePath);
}

function retrieveExternalScriptSync(url, options = {}) {
  if (typeof options.retrieveExternalScript === "function") {
    return options.retrieveExternalScript(url);
  }
  const maxBytes = options.externalScriptMaxBytes || DEFAULT_EXTERNAL_SCRIPT_MAX_BYTES;
  const timeoutMs = options.externalScriptTimeoutMs || DEFAULT_EXTERNAL_SCRIPT_TIMEOUT_MS;
  const output = childProcess.execFileSync("curl", [
    "--silent",
    "--show-error",
    "--location",
    "--max-time",
    String(Math.max(1, Math.ceil(timeoutMs / 1000))),
    "--range",
    `0-${Math.max(0, maxBytes - 1)}`,
    url
  ], {
    encoding: "utf8",
    maxBuffer: maxBytes + 64 * 1024,
    stdio: ["ignore", "pipe", "ignore"]
  });
  return output;
}

function retrieveExternalScriptAssets(tracePath, events, assets, options = {}) {
  const shouldRetrieve = options.retrieveExternalScripts || typeof options.retrieveExternalScript === "function";
  if (!shouldRetrieve) return [];

  const urls = collectExternalScriptUrls(events, assets, options);
  if (!urls.length) return [];

  const maxBytes = options.externalScriptMaxBytes || DEFAULT_EXTERNAL_SCRIPT_MAX_BYTES;
  const assetDir = path.join(reportDirectoryForTrace(tracePath), "assets");
  fs.mkdirSync(assetDir, {recursive: true});
  const retrieved = [];

  for (const url of urls) {
    const assetId = externalScriptAssetId(url);
    const contentPath = path.join(assetDir, `${sanitizeAssetFilename(assetId)}.js`);
    let content = "";
    let retrievalStatus = "missing";

    if (fs.existsSync(contentPath)) {
      content = fs.readFileSync(contentPath, "utf8").slice(0, maxBytes);
      retrievalStatus = "cached";
    } else if (options.externalScriptCacheOnly) {
      retrieved.push({
        asset_id: assetId,
        kind: "external-script",
        url,
        retrieval_status: "skipped_cache_only"
      });
      continue;
    } else {
      try {
        content = String(retrieveExternalScriptSync(url, options) || "").slice(0, maxBytes);
        if (!content) {
          retrievalStatus = "empty";
        } else {
          fs.writeFileSync(contentPath, content, "utf8");
          retrievalStatus = "fetched";
        }
      } catch (error) {
        retrieved.push({
          asset_id: assetId,
          kind: "external-script",
          url,
          retrieval_status: "error",
          retrieval_error: String(error.message || error)
        });
        continue;
      }
    }

    retrieved.push({
      asset_id: assetId,
      kind: "external-script",
      url,
      content_path: relativePathFromTrace(tracePath, contentPath),
      sha1: sha1Hex(content),
      size: Buffer.byteLength(content, "utf8"),
      truncated: Buffer.byteLength(content, "utf8") >= maxBytes,
      retrieval_status: retrievalStatus,
      content
    });
  }

  return retrieved;
}

function attachStackAssetIds(events, assets) {
  const assetByUrl = new Map();
  for (const asset of assets || []) {
    if (!asset?.url || !asset?.asset_id) continue;
    if (!(asset.content || asset.source || asset.source_preview || asset.content_path)) continue;
    assetByUrl.set(asset.url, asset);
  }
  if (!assetByUrl.size) return events;

  return (events || []).map((event) => {
    if (!Array.isArray(event.stack) || !event.stack.length) return event;
    let changed = false;
    const stack = event.stack.map((frame) => {
      if (!frame || frame.asset_id || !frame.url) return frame;
      const asset = assetByUrl.get(frame.url);
      if (!asset) return frame;
      changed = true;
      return {
        ...frame,
        asset_id: asset.asset_id,
        asset_path: asset.content_path || frame.asset_path || ""
      };
    });
    return changed ? {...event, stack} : event;
  });
}

function countMatches(source, pattern) {
  return source.match(pattern)?.length || 0;
}

function analyzeJavaScriptSource(source) {
  const text = String(source || "");
  const signals = [];
  let score = 0;
  const addSignal = (signal, weight) => {
    if (!signals.includes(signal)) signals.push(signal);
    score += weight;
  };

  const escapeCount = countMatches(text, /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g);
  if (escapeCount >= 2 || /_0x[0-9a-f]+/i.test(text)) {
    addSignal("hex_or_unicode_escape_density", 2);
  }

  const bracketPropertyCount = countMatches(text, /\[[^\]\n]{1,80}\]/g);
  if (bracketPropertyCount >= 2) {
    addSignal("bracket_property_access", 1);
  }

  if (/(?:var|let|const)\s+[$_\w]+\s*=\s*\[(?:(?:"[^"]*"|'[^']*'|`[^`]*`)\s*,?\s*){4,}\]/.test(text)) {
    addSignal("string_array", 2);
  }

  if (/\b(?:eval|Function)\s*\(/.test(text) || /\bset(?:Timeout|Interval)\s*\(\s*["'`]/.test(text)) {
    addSignal("dynamic_execution", 2);
  }

  const caseCount = countMatches(text, /\bcase\b/g);
  if (/\bwhile\s*\(\s*(?:true|!!\[\])\s*\)/.test(text) && /\bswitch\s*\(/.test(text) && caseCount >= 1) {
    addSignal("control_flow_flattening", 2);
  }

  if (/\bdebugger\b/.test(text) || /Function\s*\(\s*["'`]debugger/.test(text)) {
    addSignal("anti_debug", 2);
  }

  const bytecodeArrayCount = countMatches(
    text,
    /\[(?:\s*(?:0x[0-9a-fA-F]+|\d{1,5})\s*,){24,}\s*(?:0x[0-9a-fA-F]+|\d{1,5})?\s*\]/g
  );
  if (bytecodeArrayCount > 0) {
    addSignal("vmp_bytecode_array", 2);
  }

  const handlerFunctionCount = countMatches(text, /(?:^|[,[{]\s*)function\s*\([^)]*\)\s*\{/g);
  const handlerTableAccessCount = countMatches(
    text,
    /\b(?:handlers?|dispatchers?|opHandlers?|opcodeHandlers?|ops)\s*\[[^\]\n]{1,120}\]/gi
  );
  if (handlerFunctionCount >= 2 || handlerTableAccessCount >= 2) {
    addSignal("vmp_handler_table", 2);
  }

  const minifiedVmHelperCallCount = countMatches(
    text,
    /\b[A-Z]\(\s*[A-Za-z_$][\w$]*(?:\s*,[^)]{0,80})?\)/g
  );
  const minifiedCursorUpdateCount = countMatches(
    text,
    /\b[A-Za-z_$][\w$]*\.[A-Z]\s*(?:=|\+\+|--|<|>|<=|>=)/g
  );
  const minifiedBytecodeCursor = handlerFunctionCount >= 2 &&
    minifiedVmHelperCallCount >= 6 &&
    minifiedCursorUpdateCount >= 1;
  if (minifiedBytecodeCursor) {
    addSignal("vmp_bytecode_cursor", 2);
  }

  if (
    /\bwhile\s*\([^)]*(?:\.length|true|!!\[\])[^)]*\)/.test(text) &&
    /\bswitch\s*\(/.test(text) &&
    /\[[^\]\n]{1,80}\+\+\]/.test(text)
  ) {
    addSignal("vmp_dispatch_loop", 3);
  }

  const compactDispatchLoop = /\b(?:for|while)\s*\(/.test(text) &&
    handlerTableAccessCount >= 1 &&
    /(?:\b|\.)(?:pc|offset|opcode|ip)\b/.test(text);
  if (compactDispatchLoop) {
    addSignal("vmp_dispatch_loop", 3);
  }
  if (minifiedBytecodeCursor && /\b(?:while|for)\s*\(/.test(text)) {
    addSignal("vmp_dispatch_loop", 3);
  }

  if (/\.(?:call|apply)\s*\(/.test(text) || /\bReflect\.apply\s*\(/.test(text)) {
    addSignal("vmp_dynamic_dispatch", 1);
  }

  const registerStateAccessCount = countMatches(
    text,
    /(?:\b(?:vm|state|ctx|context)\s*\.\s*(?:reg|regs|registers?|stack|pc|offset|opcode|ip)\b|\[[^\]\n]{0,80}\b(?:pc|offset|opcode|ip)\b[^\]\n]{0,80}\])/g
  );
  if (registerStateAccessCount >= 2 || (registerStateAccessCount >= 1 && compactDispatchLoop)) {
    addSignal("vmp_register_state", 1);
  }

  if (/\bString\.fromCharCode\b|\bcharCodeAt\s*\(|\batob\s*\(|\bbtoa\s*\(|\bTextDecoder\b|\bTextEncoder\b/.test(text)) {
    addSignal("vmp_string_decode_refs", 1);
  }

  const fingerprintRefs = [
    "navigator.webdriver",
    "navigator.plugins",
    "navigator.languages",
    "getImageData",
    "toDataURL",
    "getParameter",
    "enumerateDevices",
    "RTCPeerConnection",
    "AudioContext"
  ].filter((needle) => text.includes(needle));
  if (fingerprintRefs.length) {
    addSignal("fingerprint_api_refs", Math.min(3, fingerprintRefs.length));
  }

  return {
    size: Buffer.byteLength(text),
    score,
    signals,
    metrics: {
      escape_count: escapeCount,
      bracket_property_count: bracketPropertyCount,
      case_count: caseCount,
      bytecode_array_count: bytecodeArrayCount,
      handler_function_count: handlerFunctionCount,
      handler_table_access_count: handlerTableAccessCount,
      minified_vm_helper_call_count: minifiedVmHelperCallCount,
      minified_cursor_update_count: minifiedCursorUpdateCount,
      register_state_access_count: registerStateAccessCount,
      fingerprint_refs: fingerprintRefs
    }
  };
}

function apiIsFingerprint(api) {
  return FINGERPRINT_API_PREFIXES.some((prefix) => String(api || "").startsWith(prefix));
}

function preserveSignatureText(value) {
  return String(value || "");
}

function preserveSignatureValues(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((item) => preserveSignatureValues(item));
  if (value && typeof value === "object") {
    const preserved = {};
    for (const [key, item] of Object.entries(value)) {
      preserved[key] = preserveSignatureValues(item);
    }
    return preserved;
  }
  return value;
}

function signatureTermsInEvent(event) {
  const text = JSON.stringify([event.args, event.result, event.error]);
  return SIGNATURE_TERMS.filter((term) => text.includes(term));
}

function signatureTermsInText(text) {
  return sortParamNames(SIGNATURE_TERMS.filter((term) => String(text || "").includes(term)));
}

function isSupportingTokenParamName(name) {
  return /token/i.test(String(name || ""));
}

function isSensitiveParamName(name) {
  return SIGNATURE_TERMS.includes(name) || isSupportingTokenParamName(name);
}

function summarizeStackFrame(frame, assetByUrl) {
  const asset = assetByUrl.get(frame.url || "");
  return {
    function: frame.function || "",
    url: frame.url || "",
    line: frame.line ?? null,
    column: frame.column ?? null,
    script_id: frame.script_id ?? null,
    asset_id: asset?.asset_id || "",
    asset_path: asset?.content_path || "",
    asset_score: asset?.score || 0,
    asset_signals: asset?.signals || []
  };
}

function summarizeSignatureEvent(event, assetByUrl) {
  const traceIndex = explicitTraceIndexValue(event);
  return {
    ...(Number.isFinite(traceIndex) ? {trace_index: traceIndex} : {}),
    seq: event.seq ?? null,
    event_id: event.event_id || "",
    api: event.api || "",
    category: event.category || "",
    phase: event.phase || event.t || "",
    frame_url: event.frame_url || "",
    origin: event.origin || "",
    terms: signatureTermsInEvent(event),
    args: preserveSignatureValues(event.args || []),
    stack: (event.stack || []).slice(0, 16).map((frame) => summarizeStackFrame(frame, assetByUrl))
  };
}

function summarizeFlowEvent(event, assetByUrl, extra = {}) {
  const traceIndex = explicitTraceIndexValue(event);
  return {
    ...(Number.isFinite(traceIndex) ? {trace_index: traceIndex} : {}),
    seq: event.seq ?? null,
    event_id: event.event_id || "",
    api: event.api || "",
    category: event.category || "",
    phase: event.phase || event.t || "",
    frame_url: event.frame_url || "",
    origin: event.origin || "",
    terms: signatureTermsInEvent(event),
    args: preserveSignatureValues(event.args || []),
    stack: (event.stack || []).slice(0, 8).map((frame) => summarizeStackFrame(frame, assetByUrl)),
    ...extra
  };
}

function collectStrings(value, output = [], depth = 0) {
  if (depth > 6 || value === undefined || value === null) return output;
  if (typeof value === "string") {
    output.push(value);
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, output, depth + 1);
    return output;
  }
  if (typeof value === "object") {
    for (const item of Object.values(value)) collectStrings(item, output, depth + 1);
  }
  return output;
}

function parseUrlCandidate(value) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return parsed;
    }
  } catch {
    return null;
  }
  return null;
}

function urlsFromEvent(event) {
  if (event && typeof event === "object" && URLS_FROM_EVENT_CACHE.has(event)) {
    return URLS_FROM_EVENT_CACHE.get(event).slice();
  }
  const strings = collectStrings([event.args, event.result, event.error]);
  const urls = [];
  const seen = new Set();

  for (const value of strings) {
    const directParsed = parseUrlCandidate(value);
    if (directParsed) {
      const key = directParsed.href;
      if (!seen.has(key)) {
        seen.add(key);
        urls.push({raw: value, parsed: directParsed});
      }
      continue;
    }

    const candidates = [];
    for (const match of value.matchAll(/https?:\/\/[^\s"'<>\\)}\]]+/g)) {
      candidates.push(match[0]);
    }

    for (const candidate of candidates) {
      const parsed = parseUrlCandidate(candidate);
      if (!parsed) continue;
      const key = parsed.href;
      if (seen.has(key)) continue;
      seen.add(key);
      urls.push({raw: candidate, parsed});
    }
  }

  if (event && typeof event === "object") {
    URLS_FROM_EVENT_CACHE.set(event, urls);
  }
  return urls.slice();
}

function cachedUrlsFromEvent(events, index, cache) {
  if (!cache) return urlsFromEvent(events[index]);
  if (cache[index] === undefined) {
    cache[index] = urlsFromEvent(events[index]);
  }
  return cache[index];
}

function endpointForUrl(parsed) {
  return `${parsed.origin}${parsed.pathname}`;
}

function paramNameRank(name) {
  const signatureIndex = SIGNATURE_TERMS.indexOf(name);
  if (signatureIndex !== -1) return signatureIndex;
  if (isSupportingTokenParamName(name)) return SIGNATURE_TERMS.length;
  return SIGNATURE_TERMS.length + 1;
}

function sortParamNames(names) {
  return [...names].sort((a, b) => paramNameRank(a) - paramNameRank(b) || a.localeCompare(b));
}

function runtimeHintQueryKeys(names, limit = 24) {
  const unique = uniqueLimited(names || [], Number.MAX_SAFE_INTEGER);
  const priority = sortParamNames(unique.filter((name) => isSensitiveParamName(name)));
  const rest = unique.filter((name) => !priority.includes(name));
  return uniqueLimited([...priority, ...rest], limit);
}

function sortCountEntries(entries, keyName) {
  return [...entries]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .map(([key, count]) => ({[keyName]: key, count}));
}

function countBy(items, keyFn) {
  const counts = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (!key) continue;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return counts;
}

function uniqueLimited(values, limit = 12) {
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

function regexMatches(source, pattern, mapper = (match) => match[0], limit = 24) {
  const values = [];
  for (const match of String(source || "").matchAll(pattern)) {
    values.push(mapper(match));
    if (values.length >= limit * 2) break;
  }
  return uniqueLimited(values, limit);
}

function stripStringLiterals(source) {
  return String(source || "").replace(/(['"])(?:(?!\1)[^\\]|\\.)*\1/g, "\"\"");
}

function vmpFamilyForApi(api) {
  return VMP_API_FAMILY.get(api || "") || "";
}

function isVmpRuntimeEvent(event) {
  return VMP_RUNTIME_APIS.has(event?.api || "");
}

function firstStackUrl(event) {
  return (event?.stack || []).find((frame) => frame.url)?.url || "";
}

function stackLocationKey(event) {
  return firstStackUrl(event) || event?.frame_url || event?.origin || "unknown";
}

function sequenceValue(event, fallbackIndex) {
  return Number.isFinite(event?.seq) ? event.seq : fallbackIndex;
}

function traceIndexValue(event, fallbackIndex = 0) {
  if (Number.isFinite(event?._trace_index)) return event._trace_index;
  if (Number.isFinite(event?._file_index)) return event._file_index;
  if (Number.isFinite(event?.trace_index)) return event.trace_index;
  if (Number.isFinite(event?.global_seq)) return event.global_seq;
  return fallbackIndex;
}

function summarizeDynamicDispatchArgs(event) {
  if (vmpFamilyForApi(event?.api) !== "dynamic_dispatch") return null;
  const args = Array.isArray(event?.args) ? event.args[0] : null;
  if (!args || typeof args !== "object") return null;

  const fields = [
    "target_function",
    "target_type",
    "this_type",
    "arg_count",
    "arguments_list_type",
    "subject_id",
    "target_id",
    "this_id",
    "arguments_list_id"
  ];
  const summary = {};
  for (const field of fields) {
    if (Object.prototype.hasOwnProperty.call(args, field)) {
      summary[field] = args[field];
    }
  }
  return Object.keys(summary).length ? summary : null;
}

function summarizeVmpHookEvent(event, index, assetByUrl, extra = {}) {
  const stackUrl = firstStackUrl(event);
  const asset = stackUrl ? assetByUrl.get(stackUrl) : null;
  const dispatch = summarizeDynamicDispatchArgs(event);
  return {
    ...(Number.isFinite(event?._trace_index) ? {trace_index: event._trace_index} : {}),
    seq: event.seq ?? null,
    api: event.api || "",
    family: vmpFamilyForApi(event.api),
    stack_url: stackUrl,
    frame_url: event.frame_url || "",
    origin: event.origin || "",
    asset_id: asset?.asset_id || "",
    asset_path: asset?.content_path || "",
    index,
    ...(dispatch ? {dispatch} : {}),
    ...extra
  };
}

function summarizeVmpHookPoint(type, eventsWithIndex, assetByUrl, extra = {}) {
  if (!eventsWithIndex.length) return null;
  const plainEvents = eventsWithIndex.map(({event}) => event);
  let seqStart = null;
  let seqEnd = null;
  for (const {event, index} of eventsWithIndex) {
    const seq = sequenceValue(event, index);
    seqStart = seqStart === null ? seq : Math.min(seqStart, seq);
    seqEnd = seqEnd === null ? seq : Math.max(seqEnd, seq);
  }
  const families = [...new Set(plainEvents.map((event) => vmpFamilyForApi(event.api)).filter(Boolean))].sort();
  const stackUrlCounts = sortCountEntries(countBy(plainEvents, stackLocationKey), "stack_url").slice(0, 5);
  const apiCounts = sortCountEntries(countBy(plainEvents, (event) => event.api || ""), "api").slice(0, 12);
  const assets = new Map();
  for (const event of plainEvents) {
    const asset = assetByUrl.get(firstStackUrl(event));
    if (asset && !assets.has(asset.asset_id)) {
      assets.set(asset.asset_id, {
        asset_id: asset.asset_id,
        url: asset.url,
        content_path: asset.content_path,
        score: asset.score,
        signals: asset.signals
      });
    }
  }

  return {
    type,
    seq_start: seqStart,
    seq_end: seqEnd,
    event_count: eventsWithIndex.length,
    families,
    apis: apiCounts,
    stack_urls: stackUrlCounts,
    assets: [...assets.values()],
    sample_events: eventsWithIndex
      .slice(0, 8)
      .map(({event, index}) => summarizeVmpHookEvent(event, index, assetByUrl)),
    ...extra
  };
}

function firstVmpStackFrame(event) {
  return (event?.stack || []).find((frame) => frame?.url || frame?.function) || {};
}

function vmpExecutionProfileKey(event) {
  const frame = firstVmpStackFrame(event);
  const stackUrl = frame.url || event?.frame_url || event?.origin || "unknown";
  const functionName = frame.function || "(anonymous)";
  return `${functionName}\u0000${stackUrl}`;
}

function hookSpecForVmpFamily(family) {
  return VMP_EXECUTION_HOOK_POINT_SPECS.find((spec) => spec.families.includes(family)) || null;
}

function updateSeqRange(target, seq) {
  if (!Number.isFinite(seq)) return;
  target.seq_start = target.seq_start === null ? seq : Math.min(target.seq_start, seq);
  target.seq_end = target.seq_end === null ? seq : Math.max(target.seq_end, seq);
}

function confidenceForVmpExecutionProfile(profile) {
  const hookCount = profile.hookBuckets.size;
  if (hookCount >= 5 && profile.event_count >= 8) return "high";
  if (hookCount >= 3 && profile.event_count >= 4) return "medium";
  if (profile.event_count >= 32 && profile.familySet.size >= 2) return "medium";
  return "low";
}

function materializeVmpExecutionHookPoint(bucket) {
  return {
    type: bucket.type,
    event_count: bucket.event_count,
    seq_start: bucket.seq_start,
    seq_end: bucket.seq_end,
    families: [...bucket.familySet].sort(),
    apis: sortCountEntries(bucket.apiCounts, "api").slice(0, 8),
    analysis_hint: bucket.analysis_hint,
    sample_events: bucket.sampleEvents
  };
}

function buildVmpExecutionProfiles(eventsWithIndex, assetByUrl) {
  const profiles = new Map();

  for (const {event, index} of eventsWithIndex) {
    const family = vmpFamilyForApi(event.api);
    if (!family) continue;

    const frame = firstVmpStackFrame(event);
    const stackUrl = frame.url || event.frame_url || event.origin || "unknown";
    const functionName = frame.function || "(anonymous)";
    const asset = assetByUrl.get(stackUrl);
    const key = vmpExecutionProfileKey(event);
    const seq = sequenceValue(event, index);
    const profile = profiles.get(key) || {
      function: functionName,
      stack_url: stackUrl,
      frame_url: event.frame_url || "",
      origin: event.origin || "",
      asset,
      event_count: 0,
      seq_start: null,
      seq_end: null,
      apiCounts: new Map(),
      familySet: new Set(),
      hookBuckets: new Map(),
      sampleEvents: []
    };

    profile.event_count += 1;
    updateSeqRange(profile, seq);
    profile.apiCounts.set(event.api || "unknown", (profile.apiCounts.get(event.api || "unknown") || 0) + 1);
    profile.familySet.add(family);
    if (!profile.asset && asset) profile.asset = asset;
    if (profile.sampleEvents.length < VMP_EXECUTION_PROFILE_SAMPLE_LIMIT) {
      profile.sampleEvents.push(summarizeVmpHookEvent(event, index, assetByUrl));
    }

    const spec = hookSpecForVmpFamily(family);
    if (spec) {
      const bucket = profile.hookBuckets.get(spec.type) || {
        type: spec.type,
        analysis_hint: spec.analysis_hint,
        event_count: 0,
        seq_start: null,
        seq_end: null,
        apiCounts: new Map(),
        familySet: new Set(),
        sampleEvents: []
      };
      bucket.event_count += 1;
      updateSeqRange(bucket, seq);
      bucket.apiCounts.set(event.api || "unknown", (bucket.apiCounts.get(event.api || "unknown") || 0) + 1);
      bucket.familySet.add(family);
      if (bucket.sampleEvents.length < VMP_EXECUTION_PROFILE_SAMPLE_LIMIT) {
        bucket.sampleEvents.push(summarizeVmpHookEvent(event, index, assetByUrl));
      }
      profile.hookBuckets.set(spec.type, bucket);
    }

    profiles.set(key, profile);
  }

  return [...profiles.values()]
    .map((profile) => {
      const hookPoints = [...profile.hookBuckets.values()]
        .sort((a, b) =>
          (VMP_EXECUTION_HOOK_POINT_ORDER.get(a.type) ?? 99) -
            (VMP_EXECUTION_HOOK_POINT_ORDER.get(b.type) ?? 99) ||
          a.seq_start - b.seq_start)
        .map(materializeVmpExecutionHookPoint);
      const confidence = confidenceForVmpExecutionProfile(profile);
      const densityScore = Math.min(
        100,
        profile.event_count + profile.familySet.size * 3 + hookPoints.length * 6
      );
      return {
        function: profile.function,
        stack_url: profile.stack_url,
        frame_url: profile.frame_url,
        origin: profile.origin,
        asset_id: profile.asset?.asset_id || "",
        asset_path: profile.asset?.content_path || "",
        asset_score: profile.asset?.score || 0,
        asset_signals: profile.asset?.signals || [],
        confidence,
        density_score: densityScore,
        event_count: profile.event_count,
        seq_start: profile.seq_start,
        seq_end: profile.seq_end,
        families: [...profile.familySet].sort(),
        apis: sortCountEntries(profile.apiCounts, "api").slice(0, 12),
        hook_points: hookPoints,
        sample_events: profile.sampleEvents
      };
    })
    .sort((a, b) => {
      const confidenceRank = {high: 0, medium: 1, low: 2};
      return (confidenceRank[a.confidence] ?? 99) - (confidenceRank[b.confidence] ?? 99) ||
        b.density_score - a.density_score ||
        b.event_count - a.event_count ||
        (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
        String(a.function).localeCompare(String(b.function)) ||
        String(a.stack_url).localeCompare(String(b.stack_url));
    })
    .slice(0, VMP_EXECUTION_PROFILE_LIMIT);
}

function buildVmpClusters(eventsWithIndex) {
  const clusters = [];
  let current = [];
  let lastSeq = null;

  for (const item of eventsWithIndex) {
    const seq = sequenceValue(item.event, item.index);
    if (current.length && lastSeq !== null && seq - lastSeq > VMP_CLUSTER_GAP) {
      clusters.push(current);
      current = [];
    }
    current.push(item);
    lastSeq = seq;
  }
  if (current.length) clusters.push(current);

  return clusters
    .filter((cluster) => cluster.length >= 3)
    .sort((a, b) => b.length - a.length ||
      sequenceValue(a[0].event, a[0].index) - sequenceValue(b[0].event, b[0].index));
}

function buildVmpHookAnalysis(events, assetFindings) {
  const assetByUrl = new Map(assetFindings.filter((asset) => asset.url).map((asset) => [asset.url, asset]));
  const eventsWithIndex = [];
  const familyCounts = new Map();
  const hotspots = new Map();

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (!isVmpRuntimeEvent(event)) continue;
    const family = vmpFamilyForApi(event.api);
    eventsWithIndex.push({event, index});
    if (family) familyCounts.set(family, (familyCounts.get(family) || 0) + 1);

    const location = stackLocationKey(event);
    const hotspot = hotspots.get(location) || {
      stack_url: location,
      count: 0,
      seq_start: sequenceValue(event, index),
      seq_end: sequenceValue(event, index),
      apiCounts: new Map(),
      families: new Set(),
      asset: null
    };
    hotspot.count += 1;
    hotspot.seq_start = Math.min(hotspot.seq_start, sequenceValue(event, index));
    hotspot.seq_end = Math.max(hotspot.seq_end, sequenceValue(event, index));
    hotspot.apiCounts.set(event.api || "unknown", (hotspot.apiCounts.get(event.api || "unknown") || 0) + 1);
    if (family) hotspot.families.add(family);
    const asset = assetByUrl.get(firstStackUrl(event));
    if (asset) hotspot.asset = asset;
    hotspots.set(location, hotspot);
  }

  const byFamily = (families) => eventsWithIndex.filter(({event}) => families.includes(vmpFamilyForApi(event.api)));
  const points = [
    summarizeVmpHookPoint("vmp_string_decoder", byFamily(["string_decode", "base64"]), assetByUrl, {
      reason: "runtime string/base64 reconstruction hooks"
    }),
    summarizeVmpHookPoint("vmp_bytecode_or_register_access", byFamily(["byte_buffer", "typed_array"]), assetByUrl, {
      reason: "ArrayBuffer/DataView/TypedArray byte reads or writes often used as VM bytecode/register access"
    }),
    summarizeVmpHookPoint("vmp_array_table", byFamily(["array_table"]), assetByUrl, {
      reason: "Array table mutation or serialization hooks often used for VM handler tables and string tables"
    }),
    summarizeVmpHookPoint("vmp_dynamic_dispatch", byFamily(["dynamic_dispatch"]), assetByUrl, {
      reason: "Reflect/Object/Function dispatch hooks often mark VM handler invocation or table discovery"
    }),
    summarizeVmpHookPoint("vmp_collection_table", byFamily(["collection_table"]), assetByUrl, {
      reason: "Map/Set hooks often mark VM handler maps, opcode lookup tables, and memoized dispatch state"
    }),
    summarizeVmpHookPoint("vmp_proxy_trap", byFamily(["proxy_trap"]), assetByUrl, {
      reason: "Proxy traps often mark obfuscated property indirection, guarded state access, or VM dispatch interception"
    }),
    summarizeVmpHookPoint("vmp_json_serialization", byFamily(["json_serialization"]), assetByUrl, {
      reason: "JSON parse/stringify hooks often mark canonical request material before encoding or hashing"
    }),
    summarizeVmpHookPoint("vmp_hash_or_signature_pipeline", byFamily(["json_serialization", "text_codec", "hash_crypto", "int_arithmetic"]), assetByUrl, {
      reason: "JSON serialization, encoding, WebCrypto digest/sign/importKey, and 32-bit arithmetic hooks commonly surround request-signature preparation"
    }),
    summarizeVmpHookPoint("vmp_url_encoding_boundary", byFamily(["url_encoding"]), assetByUrl, {
      reason: "URL encoding hooks often mark request canonicalization before signature or VMP integer mixing"
    }),
    summarizeVmpHookPoint("vmp_int_bitwise_pipeline", byFamily(["int_bitwise"]), assetByUrl, {
      reason: "bitwise and shift hooks often mark integer mixing in VM and request-signature pipelines"
    }),
    summarizeVmpHookPoint("vmp_anti_debug_timing_gate", byFamily(["anti_debug_timing"]), assetByUrl, {
      reason: "timing and console/debugger probes often gate VMP execution or detect analysis"
    }),
    summarizeVmpHookPoint("vmp_source_integrity_probe", byFamily(["source_probe"]), assetByUrl, {
      reason: "source and native-code probes often detect JS hooks or guard VMP execution paths"
    }),
    summarizeVmpHookPoint("vmp_stack_trace_probe", byFamily(["stack_probe"]), assetByUrl, {
      reason: "stack trace probes often detect call-stack shape, debugger state, or guarded VM execution paths"
    }),
    summarizeVmpHookPoint("vmp_exception_control_flow", byFamily(["exception_probe"]), assetByUrl, {
      reason: "exception probes often mark VM branch gates, opaque predicates, or anti-debug control flow"
    }),
    summarizeVmpHookPoint("vmp_string_transform", byFamily(["string_transform"]), assetByUrl, {
      reason: "string transform hooks often mark parameter extraction, canonicalization, and VM token assembly"
    }),
    summarizeVmpHookPoint("vmp_regexp_probe", byFamily(["regexp_probe"]), assetByUrl, {
      reason: "regular-expression probes often mark token extraction, branch tests, or request-material parsing"
    })
  ].filter(Boolean);

  const clusters = buildVmpClusters(eventsWithIndex);
  if (clusters.length) {
    points.push(summarizeVmpHookPoint("vmp_runtime_cluster", clusters[0], assetByUrl, {
      reason: "dense nearby VMP runtime hooks"
    }));
  }

  for (const asset of assetFindings.filter((item) => item.signals.some((signal) => signal.startsWith("vmp_"))).slice(0, 4)) {
    points.push({
      type: "vmp_obfuscated_asset",
      seq_start: asset.first_seq ?? null,
      seq_end: asset.first_seq ?? null,
      event_count: 0,
      families: [],
      apis: [],
      stack_urls: asset.url ? [{stack_url: asset.url, count: 1}] : [],
      assets: [{
        asset_id: asset.asset_id,
        url: asset.url,
        content_path: asset.content_path,
        score: asset.score,
        signals: asset.signals
      }],
      sample_events: [],
      reason: "static JS asset contains VMP-like interpreter signals"
    });
  }

  return {
    families: sortCountEntries(familyCounts, "family"),
    execution_profiles: buildVmpExecutionProfiles(eventsWithIndex, assetByUrl),
    hotspots: [...hotspots.values()]
      .sort((a, b) => b.count - a.count || String(a.stack_url).localeCompare(String(b.stack_url)))
      .slice(0, VMP_HOTSPOT_LIMIT)
      .map((hotspot) => ({
        stack_url: hotspot.stack_url,
        asset_id: hotspot.asset?.asset_id || "",
        asset_path: hotspot.asset?.content_path || "",
        asset_score: hotspot.asset?.score || 0,
        asset_signals: hotspot.asset?.signals || [],
        count: hotspot.count,
        seq_start: hotspot.seq_start,
        seq_end: hotspot.seq_end,
        families: [...hotspot.families].sort(),
        apis: sortCountEntries(hotspot.apiCounts, "api").slice(0, 12)
      })),
    hook_coverage: buildVmpHookCoverage(points),
    analysis_points: points.slice(0, VMP_ANALYSIS_POINT_LIMIT)
  };
}

function vmpRuntimeGapReason(reason) {
  return String(reason || "").replace("one or more signature flows", "the VMP runtime trace");
}

function vmpHookAnalysisGoal(type) {
  return VMP_HOOK_ANALYSIS_GOALS[type] || "trace VMP runtime behavior";
}

function vmpHookPointStatus(observedCount, missingCount = 0) {
  if (observedCount > 0 && missingCount > 0) return "partial";
  if (observedCount > 0) return "observed";
  return "missing";
}

function nextActionForTopLevelVmpHook(status) {
  return status === "observed" ? "review_observed_events" : "add_or_enable_hooks";
}

function buildTopLevelVmpHookAnalysisPoints(coverageByType, pointByType) {
  return VMP_HOOK_POINT_SPECS.map((spec) => {
    const coverage = coverageByType[spec.type] || {};
    const point = pointByType.get(spec.type);
    const observedCount = coverage.event_count || 0;
    const status = vmpHookPointStatus(observedCount);
    return {
      type: spec.type,
      status,
      priority: spec.priority,
      analysis_goal: vmpHookAnalysisGoal(spec.type),
      families: spec.families || [],
      observed_event_count: observedCount,
      observed_apis: coverage.apis || [],
      suggested_hooks: spec.suggested_hooks,
      reason: status === "observed"
        ? point?.reason || vmpRuntimeGapReason(spec.reason)
        : vmpRuntimeGapReason(spec.reason),
      next_action: nextActionForTopLevelVmpHook(status)
    };
  });
}

function buildVmpHookCoverage(points) {
  const pointByType = new Map(points.map((point) => [point.type, point]));
  const coverageByType = {};
  const observedPointTypes = [];
  const missingPointTypes = [];
  const hookGaps = [];

  for (const spec of VMP_HOOK_POINT_SPECS) {
    const point = pointByType.get(spec.type);
    if (point) {
      observedPointTypes.push(spec.type);
      coverageByType[spec.type] = {
        observed: true,
        event_count: point.event_count || 0,
        families: point.families || [],
        apis: (point.apis || []).slice(0, 8)
      };
      continue;
    }

    missingPointTypes.push(spec.type);
    coverageByType[spec.type] = {
      observed: false,
      event_count: 0,
      families: spec.families || [],
      apis: []
    };
    hookGaps.push({
      type: spec.type,
      priority: spec.priority,
      reason: vmpRuntimeGapReason(spec.reason),
      suggested_hooks: spec.suggested_hooks,
      event_count: 0
    });
  }

  return {
    observed_point_types: observedPointTypes,
    missing_point_types: missingPointTypes,
    coverage_by_type: coverageByType,
    hook_analysis_points: buildTopLevelVmpHookAnalysisPoints(coverageByType, pointByType),
    hook_gaps: hookGaps
  };
}

function paramsByName(parsed) {
  const params = new Map();
  for (const [name, value] of parsed.searchParams.entries()) {
    if (!params.has(name)) params.set(name, []);
    params.get(name).push(value);
  }
  return params;
}

function compareUrlParams(unsignedUrl, signedUrl) {
  const before = paramsByName(unsignedUrl);
  const after = paramsByName(signedUrl);
  const beforeNames = new Set(before.keys());
  const afterNames = new Set(after.keys());
  const addedNames = [...afterNames].filter((name) => !beforeNames.has(name));
  const removedNames = [...beforeNames].filter((name) => !afterNames.has(name));
  const unchangedNames = [...afterNames].filter((name) => {
    if (!before.has(name)) return false;
    return JSON.stringify(before.get(name)) === JSON.stringify(after.get(name));
  });
  const changedNames = [...afterNames].filter((name) => {
    if (!before.has(name)) return false;
    return JSON.stringify(before.get(name)) !== JSON.stringify(after.get(name));
  });

  return {
    added_params: sortParamNames(addedNames).map((name) => ({
      name,
      value: after.get(name)?.[0] ?? "",
      values: after.get(name) || [],
      is_signature: SIGNATURE_TERMS.includes(name),
      value_count: after.get(name)?.length || 0
    })),
    removed_params: sortParamNames(removedNames),
    changed_params: sortParamNames(changedNames).map((name) => ({
      name,
      before: before.get(name)?.[0] ?? "",
      after: after.get(name)?.[0] ?? "",
      before_values: before.get(name) || [],
      after_values: after.get(name) || []
    })),
    unchanged_params: sortParamNames(unchangedNames)
  };
}

function signatureParamsFromSignedUrl(signedUrl) {
  const after = paramsByName(signedUrl);
  const presentNames = [...after.keys()].filter((name) => isSensitiveParamName(name));
  return {
    added_params: sortParamNames(presentNames).map((name) => ({
      name,
      value: after.get(name)?.[0] ?? "",
      values: after.get(name) || [],
      is_signature: SIGNATURE_TERMS.includes(name),
      value_count: after.get(name)?.length || 0
    })),
    removed_params: [],
    changed_params: [],
    unchanged_params: []
  };
}

function sharedParamCount(leftUrl, rightUrl) {
  const left = paramsByName(leftUrl);
  const right = paramsByName(rightUrl);
  let count = 0;
  for (const [name, values] of left.entries()) {
    if (right.has(name) && JSON.stringify(values) === JSON.stringify(right.get(name))) {
      count += 1;
    }
  }
  return count;
}

function findBestUnsignedUrl(events, signedIndex, signedUrl, urlCandidateCache = null) {
  const endpoint = endpointForUrl(signedUrl);
  let best = null;
  const start = Math.max(0, signedIndex - SIGNATURE_CONTEXT_LOOKBACK);

  for (let index = signedIndex - 1; index >= start; index -= 1) {
    const event = events[index];
    if (signatureTermsInEvent(event).length) continue;
    for (const candidate of cachedUrlsFromEvent(events, index, urlCandidateCache)) {
      if (endpointForUrl(candidate.parsed) !== endpoint) continue;
      const shared = sharedParamCount(candidate.parsed, signedUrl);
      const score = shared * 1000 - (signedIndex - index);
      if (!best || score > best.score) {
        best = {event, index, url: candidate.parsed, score};
      }
    }
  }

  return best;
}

function collectAssetsFromEvents(events, assetByUrl) {
  const assets = new Map();
  for (const event of events) {
    for (const frame of event?.stack || []) {
      const asset = assetByUrl.get(frame.url || "");
      if (asset && !assets.has(asset.asset_id)) {
        assets.set(asset.asset_id, asset);
      }
    }
  }
  return [...assets.values()].map((asset) => ({
    asset_id: asset.asset_id,
    url: asset.url,
    content_path: asset.content_path,
    score: asset.score,
    signals: asset.signals,
    first_seq: asset.first_seq
  }));
}

function stackKeysForEvent(event) {
  const urls = new Set();
  const scriptIds = new Set();
  for (const frame of event?.stack || []) {
    if (frame.url) urls.add(frame.url);
    if (frame.script_id !== undefined && frame.script_id !== null) {
      scriptIds.add(String(frame.script_id));
    }
  }
  return {urls, scriptIds};
}

function stackKeysOverlap(left, right) {
  for (const url of left.urls) {
    if (right.urls.has(url)) return true;
  }
  for (const scriptId of left.scriptIds) {
    if (right.scriptIds.has(scriptId)) return true;
  }
  return false;
}

function classifyVmpRelation({event, index, signedEvent, signedIndex, unsignedEvent, unsignedIndex}) {
  const betweenUnsignedAndSigned = unsignedIndex !== null && unsignedIndex !== undefined &&
    index > unsignedIndex && index < signedIndex;
  if (betweenUnsignedAndSigned) return "between_unsigned_signed";

  const eventKeys = stackKeysForEvent(event);
  if (stackKeysOverlap(eventKeys, stackKeysForEvent(signedEvent))) return "signed_stack";
  if (unsignedEvent && stackKeysOverlap(eventKeys, stackKeysForEvent(unsignedEvent))) return "unsigned_stack";

  if (unsignedIndex !== null && unsignedIndex !== undefined && index < unsignedIndex) {
    return "";
  }

  if (event.frame_url && (event.frame_url === signedEvent.frame_url || event.frame_url === unsignedEvent?.frame_url)) {
    return "same_frame";
  }
  if (event.origin && (event.origin === signedEvent.origin || event.origin === unsignedEvent?.origin)) {
    return "same_origin";
  }
  if (signedIndex - index <= SIGNATURE_VMP_NEARBY_LOOKBACK) return "nearby";
  return "";
}

function precedingVmpEvents(events, signedIndex, unsignedIndex, assetByUrl) {
  const signedEvent = events[signedIndex];
  const unsignedEvent = unsignedIndex === null || unsignedIndex === undefined ? null : events[unsignedIndex];
  const start = Math.max(0, signedIndex - SIGNATURE_VMP_LOOKBACK);
  const candidates = [];

  for (let index = start; index < signedIndex; index += 1) {
    const event = events[index];
    if (!VMP_RUNTIME_APIS.has(event.api)) continue;
    const relation = classifyVmpRelation({event, index, signedEvent, signedIndex, unsignedEvent, unsignedIndex});
    if (!relation) continue;
    candidates.push({
      event,
      index,
      relation,
      distance: signedIndex - index,
      priority: VMP_RELATION_PRIORITY[relation] ?? 99
    });
  }

  return candidates
    .sort((a, b) => a.priority - b.priority || a.distance - b.distance || a.index - b.index)
    .slice(0, SIGNATURE_VMP_EVENT_LIMIT)
    .sort((a, b) => a.index - b.index)
    .map((item) => summarizeFlowEvent(item.event, assetByUrl, {
      relation: item.relation,
      distance: item.distance
    }));
}

function timelineRoleForEvent(event, index, unsignedIndex, signedIndex) {
  if (index === unsignedIndex) return "unsigned_url";
  if (index === signedIndex) return "signed_request";
  const api = event.api || "";
  if (VMP_RUNTIME_APIS.has(api)) return "vmp";
  if (api.startsWith("URLSearchParams.") || api === "URL.constructor" || api.startsWith("URL.")) {
    return "url_mutation";
  }
  if (api.startsWith("Headers.")) return "headers";
  if (api === "Request.constructor" || api === "fetch" || api.startsWith("XMLHttpRequest.")) {
    return "request";
  }
  return "";
}

function timelineKey(event, fallbackIndex) {
  const traceIndex = explicitTraceIndexValue(event);
  if (Number.isFinite(traceIndex)) return `trace:${traceIndex}`;
  return event.seq ?? event.event_id ?? `index:${fallbackIndex}`;
}

function timelineOrderValue(event, fallbackIndex = 0) {
  const traceIndex = explicitTraceIndexValue(event);
  if (Number.isFinite(traceIndex)) return traceIndex;
  return Number.isFinite(event?.seq) ? event.seq : fallbackIndex;
}

function selectTimelineEvents(events, signedEvent) {
  const sorted = [...events].sort((a, b) =>
    timelineOrderValue(a) - timelineOrderValue(b) || String(a.api).localeCompare(String(b.api))
  );
  if (sorted.length <= SIGNATURE_TIMELINE_EVENT_LIMIT) return sorted;

  const selected = new Map();
  for (const event of sorted) {
    if (event.role === "unsigned_url" || event.role === "signed_request") {
      selected.set(timelineKey(event, selected.size), event);
    }
  }

  const signedSeq = timelineOrderValue(signedEvent, Number.MAX_SAFE_INTEGER);
  const remaining = Math.max(0, SIGNATURE_TIMELINE_EVENT_LIMIT - selected.size);
  const context = sorted
    .filter((event) => !selected.has(timelineKey(event, 0)))
    .sort((a, b) => {
      const distance = Math.abs(timelineOrderValue(a) - signedSeq) - Math.abs(timelineOrderValue(b) - signedSeq);
      if (distance !== 0) return distance;
      return timelineOrderValue(a) - timelineOrderValue(b) || String(a.api).localeCompare(String(b.api));
    })
    .slice(0, remaining);

  for (const event of context) {
    selected.set(timelineKey(event, selected.size), event);
  }

  return [...selected.values()].sort((a, b) =>
    timelineOrderValue(a) - timelineOrderValue(b) || String(a.api).localeCompare(String(b.api))
  );
}

function buildSignatureTimeline(events, signedIndex, unsignedIndex, vmpEvents, assetByUrl) {
  const byKey = new Map();

  for (const event of vmpEvents) {
    byKey.set(timelineKey(event, byKey.size), {...event, role: "vmp"});
  }

  const startIndex = unsignedIndex === null || unsignedIndex === undefined
    ? Math.max(0, signedIndex - SIGNATURE_VMP_NEARBY_LOOKBACK)
    : unsignedIndex;

  for (let index = startIndex; index <= signedIndex; index += 1) {
    const event = events[index];
    if (!event) continue;
    const role = timelineRoleForEvent(event, index, unsignedIndex, signedIndex);
    if (!role && !SIGNATURE_TIMELINE_APIS.has(event.api || "")) continue;

    const summary = summarizeFlowEvent(event, assetByUrl, {role: role || "context"});
    const key = timelineKey(summary, index);
    const previous = byKey.get(key);
    byKey.set(key, previous ? {...summary, ...previous, role: previous.role || summary.role} : summary);
  }

  return selectTimelineEvents(byKey.values(), summarizeFlowEvent(events[signedIndex], assetByUrl, {role: "signed_request"}));
}

function buildNetworkRequestIndex(events) {
  const byIndex = [];
  const rendererRequestItems = [];
  const browserRequestItems = [];
  for (let index = 0; index < (events || []).length; index += 1) {
    const event = events[index];
    const info = networkRequestInfoFromEvent(event);
    if (!info) continue;
    const item = {
      event,
      index,
      traceIndex: traceIndexValue(event, index),
      info
    };
    byIndex[index] = item;
    if (isRendererRequestApi(event?.api || "")) rendererRequestItems.push(item);
    if (info.api === "BrowserNetwork.request") browserRequestItems.push(item);
  }
  rendererRequestItems.sort((a, b) => a.traceIndex - b.traceIndex);
  browserRequestItems.sort((a, b) => a.traceIndex - b.traceIndex);
  return {byIndex, rendererRequestItems, browserRequestItems};
}

function rendererRequestLinkForObservedSignedEvent(events, signedIndex, assetByUrl, networkRequestIndex = null) {
  const signedEvent = events[signedIndex];
  const signedInfo = networkRequestIndex?.byIndex?.[signedIndex]?.info || networkRequestInfoFromEvent(signedEvent);
  if (!signedInfo || signedInfo.api !== "BrowserNetwork.request") return null;

  const signedTraceIndex = traceIndexValue(signedEvent, signedIndex);
  const rendererRequestItems = networkRequestIndex?.rendererRequestItems || (events || [])
    .map((event, index) => ({
      event,
      index,
      traceIndex: traceIndexValue(event, index),
      info: networkRequestInfoFromEvent(event)
    }))
    .filter((item) => item.index !== signedIndex)
    .filter((item) => item.info && isRendererRequestApi(item.event?.api || ""))
    .sort((a, b) => a.traceIndex - b.traceIndex);
  return findRendererRequestLink(
    signedInfo,
    signedTraceIndex,
    rendererRequestItems,
    assetByUrl
  );
}

function summarizeBrowserRequestLink(browserItem, rendererInfo, rendererTraceIndex, match = "endpoint_method_trace_window") {
  const browserEvent = browserItem.event;
  const browserInfo = browserItem.info;
  const browserTraceIndex = browserItem.traceIndex;
  const traceDistance = Math.abs(browserTraceIndex - rendererTraceIndex);
  return {
    trace_index: browserTraceIndex,
    seq: browserEvent.seq ?? null,
    api: browserEvent.api || "",
    method: browserInfo.method || rendererInfo.method || "GET",
    endpoint: browserInfo.endpoint || rendererInfo.endpoint || "",
    relation: browserTraceIndex >= rendererTraceIndex ? "after_renderer_request" : "before_renderer_request",
    trace_distance: traceDistance,
    confidence: match === "network_correlation_key" ||
        (traceDistance <= 1000 && browserTraceIndex >= rendererTraceIndex)
      ? "high"
      : "medium",
    ...(match === "network_correlation_key" ? {match} : {})
  };
}

function browserRequestLinkForObservedRendererEvent(events, signedIndex, networkRequestIndex = null) {
  const signedEvent = events[signedIndex];
  const rendererInfo = networkRequestIndex?.byIndex?.[signedIndex]?.info || networkRequestInfoFromEvent(signedEvent);
  if (!rendererInfo || !isRendererRequestApi(signedEvent?.api || "")) return null;

  const rendererTraceIndex = traceIndexValue(signedEvent, signedIndex);
  const browserRequestItems = networkRequestIndex?.browserRequestItems || (events || [])
    .map((event, index) => ({
      event,
      index,
      traceIndex: traceIndexValue(event, index),
      info: networkRequestInfoFromEvent(event)
    }))
    .filter((item) => item.index !== signedIndex)
    .filter((item) => item.info?.api === "BrowserNetwork.request")
    .sort((a, b) => a.traceIndex - b.traceIndex);

  if (rendererInfo.network_correlation_key) {
    const keyedCandidates = browserRequestItems
      .filter((item) => item.info.network_correlation_key === rendererInfo.network_correlation_key)
      .filter((item) => !rendererInfo.method || !item.info.method || item.info.method === rendererInfo.method)
      .map((item) => ({
        item,
        distance: Math.abs(item.traceIndex - rendererTraceIndex),
        after: item.traceIndex >= rendererTraceIndex
      }))
      .sort((a, b) =>
        Number(b.after) - Number(a.after) ||
        a.distance - b.distance ||
        (a.item.traceIndex ?? 0) - (b.item.traceIndex ?? 0));
    if (keyedCandidates.length) {
      return summarizeBrowserRequestLink(
        keyedCandidates[0].item,
        rendererInfo,
        rendererTraceIndex,
        "network_correlation_key"
      );
    }
  }

  const candidates = browserRequestItems
    .filter((item) => item.info.endpoint === rendererInfo.endpoint)
    .filter((item) => !rendererInfo.method || !item.info.method || item.info.method === rendererInfo.method)
    .map((item) => ({
      item,
      distance: Math.abs(item.traceIndex - rendererTraceIndex),
      after: item.traceIndex >= rendererTraceIndex
    }))
    .filter((candidate) => candidate.distance <= SIGNATURE_ABSENT_RENDERER_REQUEST_TRACE_RADIUS)
    .sort((a, b) =>
      Number(b.after) - Number(a.after) ||
      a.distance - b.distance ||
      (a.item.traceIndex ?? 0) - (b.item.traceIndex ?? 0));
  if (!candidates.length) return null;
  return summarizeBrowserRequestLink(candidates[0].item, rendererInfo, rendererTraceIndex);
}

function requestLinkForObservedSignedEvent(events, signedIndex, assetByUrl, networkRequestIndex = null) {
  const signedInfo = networkRequestIndex?.byIndex?.[signedIndex]?.info || networkRequestInfoFromEvent(events[signedIndex]);
  if (!signedInfo) return null;
  if (signedInfo.api === "BrowserNetwork.request") {
    return rendererRequestLinkForObservedSignedEvent(events, signedIndex, assetByUrl, networkRequestIndex);
  }
  return browserRequestLinkForObservedRendererEvent(events, signedIndex, networkRequestIndex);
}

function signatureAnchorPriority(api) {
  if (api === "Request.constructor" || api === "fetch" || api.startsWith("XMLHttpRequest.")) return 0;
  if (api.startsWith("Headers.")) return 1;
  if (api === "URL.href.get" || api === "URL.search.get") return 2;
  if (api.startsWith("URLSearchParams.") || api.startsWith("URL.")) return 3;
  return 4;
}

function buildSignatureTransitions(events, signatureEventIndexes, assetByUrl) {
  const flows = [];
  const urlCandidateCache = [];
  const networkRequestIndex = buildNetworkRequestIndex(events);
  for (const {event, index} of signatureEventIndexes) {
    const signedUrlInfo = cachedUrlsFromEvent(events, index, urlCandidateCache).find((candidate) =>
      SIGNATURE_TERMS.some((term) => candidate.parsed.searchParams.has(term))
    );
    if (!signedUrlInfo) continue;

    const unsigned = findBestUnsignedUrl(events, index, signedUrlInfo.parsed, urlCandidateCache);
    const unsignedIndex = unsigned?.index ?? null;
    const vmpEvents = precedingVmpEvents(events, index, unsignedIndex, assetByUrl);
    const flowStart = unsignedIndex === null
      ? Math.max(0, index - SIGNATURE_VMP_NEARBY_LOOKBACK)
      : unsignedIndex;
    const flowEvents = [...events.slice(flowStart, index), event];
    const timeline = buildSignatureTimeline(events, index, unsignedIndex, vmpEvents, assetByUrl);
    const rendererRequestLink = requestLinkForObservedSignedEvent(events, index, assetByUrl, networkRequestIndex);
    flows.push({
      match: unsigned ? "unsigned_to_signed" : "signed_only",
      endpoint: endpointForUrl(signedUrlInfo.parsed),
      signed_param_names: sortParamNames([...paramsByName(signedUrlInfo.parsed).keys()]),
      unsigned_event: unsigned ? summarizeFlowEvent(unsigned.event, assetByUrl) : null,
      signed_event: summarizeFlowEvent(event, assetByUrl),
      ...(unsigned ? compareUrlParams(unsigned.url, signedUrlInfo.parsed) : signatureParamsFromSignedUrl(signedUrlInfo.parsed)),
      preceding_vmp_events: vmpEvents,
      timeline,
      ...(rendererRequestLink ? {renderer_request_link: rendererRequestLink} : {}),
      assets: collectAssetsFromEvents(flowEvents, assetByUrl)
    });
  }

  return flows
    .sort((a, b) =>
      signatureAnchorPriority(a.signed_event.api || "") - signatureAnchorPriority(b.signed_event.api || "") ||
      timelineOrderValue(a.signed_event) - timelineOrderValue(b.signed_event) ||
      String(a.endpoint).localeCompare(String(b.endpoint)))
    .slice(0, 25);
}

function phaseForAgentTimelineEvent(event) {
  if (event.role === "unsigned_url") return "unsigned_url";
  if (event.role === "signed_request") return "signed_request";
  if (event.role === "url_mutation") return "url_signature_mutation";
  if (event.role === "headers") return "request_headers";
  if (event.role === "request") return "request_construction";

  const family = vmpFamilyForApi(event.api);
  if (family === "string_decode" || family === "base64") return "vmp_string_decode";
  if (family === "byte_buffer" || family === "typed_array") return "vmp_bytecode_or_register_access";
  if (family === "array_table") return "vmp_array_table";
  if (family === "dynamic_dispatch") return "vmp_dynamic_dispatch";
  if (family === "collection_table") return "vmp_collection_table";
  if (family === "proxy_trap") return "vmp_proxy_trap";
  if (family === "int_bitwise") return "vmp_int_bitwise_pipeline";
  if (family === "anti_debug_timing") return "vmp_anti_debug_timing_gate";
  if (family === "source_probe") return "vmp_source_integrity_probe";
  if (family === "stack_probe") return "vmp_stack_trace_probe";
  if (family === "exception_probe") return "vmp_exception_control_flow";
  if (family === "string_transform") return "vmp_string_transform";
  if (family === "regexp_probe") return "vmp_regexp_probe";
  if (family === "url_encoding") return "vmp_url_encoding_boundary";
  if (family === "json_serialization") return "vmp_json_serialization";
  if (["json_serialization", "text_codec", "hash_crypto", "int_arithmetic"].includes(family)) {
    return "vmp_hash_or_signature_pipeline";
  }
  if (event.role === "vmp") return "vmp_runtime";
  return "";
}

function compactAgentPhases(timeline) {
  const phases = new Map();
  for (const event of timeline || []) {
    const phaseName = phaseForAgentTimelineEvent(event);
    if (!phaseName) continue;
    const seq = event.seq ?? null;
    const phase = phases.get(phaseName) || {
      phase: phaseName,
      seq_start: seq,
      seq_end: seq,
      event_count: 0,
      apiSet: new Set(),
      familySet: new Set(),
      roleSet: new Set()
    };
    phase.event_count += 1;
    if (seq !== null) {
      phase.seq_start = phase.seq_start === null ? seq : Math.min(phase.seq_start, seq);
      phase.seq_end = phase.seq_end === null ? seq : Math.max(phase.seq_end, seq);
    }
    if (event.api) phase.apiSet.add(event.api);
    const family = vmpFamilyForApi(event.api);
    if (family) phase.familySet.add(family);
    if (event.role) phase.roleSet.add(event.role);
    phases.set(phaseName, phase);
  }

  return [...phases.values()].map((phase) => ({
    phase: phase.phase,
    seq_start: phase.seq_start,
    seq_end: phase.seq_end,
    event_count: phase.event_count,
    apis: [...phase.apiSet].sort(),
    families: [...phase.familySet].sort(),
    roles: [...phase.roleSet].sort()
  }));
}

function stackUrlForSummaryEvent(event) {
  return (event?.stack || []).find((frame) => frame.url)?.url ||
    event?.stack_url ||
    event?.frame_url ||
    event?.origin ||
    "unknown";
}

function primaryAssetForSummaryEvent(event) {
  const stackAsset = (event?.stack || []).find((frame) => frame.asset_id);
  if (stackAsset) return stackAsset;
  if (event?.asset_id) {
    return {
      asset_id: event.asset_id,
      url: event.stack_url || event.url || "",
      content_path: event.asset_path || "",
      score: event.asset_score || 0,
      signals: event.asset_signals || []
    };
  }
  return null;
}

function primaryFrameForSummaryEvent(event) {
  return (event?.stack || []).find((frame) => frame.url || frame.function || frame.asset_id) || {
    function: event?.function || "",
    url: event?.stack_url || "",
    asset_id: event?.asset_id || ""
  };
}

function summarizeAgentVmpHookPoint(type, events, extra = {}) {
  if (!events.length) return null;

  let seqStart = null;
  let seqEnd = null;
  for (let index = 0; index < events.length; index += 1) {
    const seq = sequenceValue(events[index], index);
    seqStart = seqStart === null ? seq : Math.min(seqStart, seq);
    seqEnd = seqEnd === null ? seq : Math.max(seqEnd, seq);
  }

  const families = [...new Set(events.map((event) => vmpFamilyForApi(event.api)).filter(Boolean))].sort();
  const assets = new Map();
  for (const event of events) {
    const asset = primaryAssetForSummaryEvent(event);
    if (!asset || !asset.asset_id || assets.has(asset.asset_id)) continue;
    assets.set(asset.asset_id, {
      asset_id: asset.asset_id,
      url: asset.url,
      content_path: asset.asset_path || asset.content_path || "",
      score: asset.asset_score ?? asset.score ?? 0,
      signals: asset.asset_signals || asset.signals || []
    });
  }

  return {
    type,
    seq_start: seqStart,
    seq_end: seqEnd,
    event_count: events.length,
    families,
    apis: sortCountEntries(countBy(events, (event) => event.api || ""), "api").slice(0, 12),
    relations: sortCountEntries(countBy(events, (event) => event.relation || ""), "relation").slice(0, 8),
    stack_urls: sortCountEntries(countBy(events, stackUrlForSummaryEvent), "stack_url").slice(0, 5),
    assets: [...assets.values()].slice(0, 5),
    sample_events: events.slice(0, 8).map((event) => {
      const asset = primaryAssetForSummaryEvent(event);
      return {
        seq: event.seq ?? null,
        api: event.api || "",
        family: vmpFamilyForApi(event.api),
        relation: event.relation || "",
        stack_url: stackUrlForSummaryEvent(event),
        asset_id: asset?.asset_id || ""
      };
    }),
    ...extra
  };
}

function dedupeVmpFlowEvents(flow) {
  const events = [];
  const seen = new Set();
  for (const event of flow.timeline || []) {
    if (!VMP_RUNTIME_APIS.has(event.api || "")) continue;
    const key = `${event.seq ?? ""}:${event.api || ""}:${event.relation || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    events.push(event);
  }
  return events.sort((a, b) => timelineOrderValue(a) - timelineOrderValue(b) || String(a.api).localeCompare(String(b.api)));
}

function buildAgentVmpClusters(events) {
  const clusters = [];
  let current = [];
  let lastSeq = null;

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const seq = sequenceValue(event, index);
    if (current.length && lastSeq !== null && seq - lastSeq > VMP_CLUSTER_GAP) {
      clusters.push(current);
      current = [];
    }
    current.push(event);
    lastSeq = seq;
  }
  if (current.length) clusters.push(current);

  return clusters
    .filter((cluster) => cluster.length >= 3)
    .sort((a, b) => b.length - a.length ||
      sequenceValue(a[0], 0) - sequenceValue(b[0], 0));
}

function vmpAnalysisPointsForEvents(vmpEvents) {
  if (!vmpEvents.length) return [];

  const byFamily = (families) => vmpEvents.filter((event) => families.includes(vmpFamilyForApi(event.api)));
  const points = [
    summarizeAgentVmpHookPoint("vmp_string_decoder", byFamily(["string_decode", "base64"]), {
      reason: "runtime string/base64 reconstruction hooks near this signature flow"
    }),
    summarizeAgentVmpHookPoint("vmp_bytecode_or_register_access", byFamily(["byte_buffer", "typed_array"]), {
      reason: "ArrayBuffer/DataView/TypedArray hooks near this flow can mark bytecode or register reads and writes"
    }),
    summarizeAgentVmpHookPoint("vmp_array_table", byFamily(["array_table"]), {
      reason: "Array table mutation or serialization hooks near this flow can mark handler/string tables"
    }),
    summarizeAgentVmpHookPoint("vmp_dynamic_dispatch", byFamily(["dynamic_dispatch"]), {
      reason: "Reflect/Object/Function dispatch hooks near this flow can mark VM handler invocation or table discovery"
    }),
    summarizeAgentVmpHookPoint("vmp_collection_table", byFamily(["collection_table"]), {
      reason: "Map/Set hooks near this flow can mark handler maps, opcode lookup tables, or memoized dispatch state"
    }),
    summarizeAgentVmpHookPoint("vmp_proxy_trap", byFamily(["proxy_trap"]), {
      reason: "Proxy traps near this flow can mark obfuscated property indirection or guarded VM state access"
    }),
    summarizeAgentVmpHookPoint("vmp_json_serialization", byFamily(["json_serialization"]), {
      reason: "JSON parse/stringify hooks near this flow can mark request material canonicalization"
    }),
    summarizeAgentVmpHookPoint("vmp_hash_or_signature_pipeline", byFamily(["json_serialization", "text_codec", "hash_crypto", "int_arithmetic"]), {
      reason: "JSON serialization, encoding, WebCrypto digest/sign/importKey, and 32-bit arithmetic hooks near this flow can mark signature material preparation"
    }),
    summarizeAgentVmpHookPoint("vmp_url_encoding_boundary", byFamily(["url_encoding"]), {
      reason: "URL encoding hooks near this flow can mark request canonicalization before signing or VM mixing"
    }),
    summarizeAgentVmpHookPoint("vmp_int_bitwise_pipeline", byFamily(["int_bitwise"]), {
      reason: "bitwise and shift hooks near this flow can mark integer mixing in VM or signature pipelines"
    }),
    summarizeAgentVmpHookPoint("vmp_anti_debug_timing_gate", byFamily(["anti_debug_timing"]), {
      reason: "timing and console/debugger probes near this flow can mark VM anti-debug gates"
    }),
    summarizeAgentVmpHookPoint("vmp_source_integrity_probe", byFamily(["source_probe"]), {
      reason: "Function.prototype.toString probes near this flow can mark anti-hook checks or guarded VM paths"
    }),
    summarizeAgentVmpHookPoint("vmp_stack_trace_probe", byFamily(["stack_probe"]), {
      reason: "Error stack probes near this flow can mark stack-shape checks, debugger gates, or guarded VM paths"
    }),
    summarizeAgentVmpHookPoint("vmp_exception_control_flow", byFamily(["exception_probe"]), {
      reason: "Error and throw probes near this flow can mark exception-driven VM branches or opaque predicates"
    }),
    summarizeAgentVmpHookPoint("vmp_string_transform", byFamily(["string_transform"]), {
      reason: "string transform hooks near this flow can mark parameter extraction, canonicalization, or VM token assembly"
    }),
    summarizeAgentVmpHookPoint("vmp_regexp_probe", byFamily(["regexp_probe"]), {
      reason: "RegExp probes near this flow can mark token extraction, branch tests, or request-material parsing"
    })
  ].filter(Boolean);

  const clusters = buildAgentVmpClusters(vmpEvents);
  if (clusters.length) {
    points.push(summarizeAgentVmpHookPoint("vmp_runtime_cluster", clusters[0], {
      reason: "dense VMP runtime hook cluster near this signature flow"
    }));
  }

  return points.slice(0, VMP_ANALYSIS_POINT_LIMIT);
}

function vmpAnalysisPointsForFlow(flow) {
  return vmpAnalysisPointsForEvents(dedupeVmpFlowEvents(flow));
}

function evidenceLevelForFlow(flow) {
  if (flow.match === "unsigned_to_signed" && flow.preceding_vmp_events?.length) return "high";
  if (flow.match === "unsigned_to_signed") return "medium";
  if (flow.preceding_vmp_events?.length || flow.timeline?.some((event) => event.role === "vmp")) return "medium";
  return "low";
}

function gapsForFlow(flow) {
  const gaps = [];
  if (flow.match === "signed_only") gaps.push("unsigned_url_not_observed");
  if (!flow.preceding_vmp_events?.length && !flow.timeline?.some((event) => event.role === "vmp")) {
    gaps.push("vmp_runtime_not_observed");
  }
  return gaps;
}

function actionForUrlMutationApi(api) {
  if (api === "URLSearchParams.set") return "set";
  if (api === "URLSearchParams.append") return "append";
  if (api === "URLSearchParams.delete") return "delete";
  if (api === "URL.href.set") return "href_set";
  if (api === "URL.search.set") return "search_set";
  return "";
}

function paramNameFromMutationEvent(event) {
  for (const arg of event.args || []) {
    if (!arg || typeof arg !== "object") continue;
    const name = arg.name || arg.key || arg.param || arg.parameter;
    if (name) return String(name);
  }
  return "";
}

function signatureMutationsForFlow(flow) {
  const mutations = [];
  const seen = new Set();
  for (const event of flow.timeline || []) {
    const action = actionForUrlMutationApi(event.api || "");
    if (!action) continue;
    const param = paramNameFromMutationEvent(event);
    if (!SIGNATURE_TERMS.includes(param)) continue;
    const key = `${event.seq}:${event.api}:${param}:${action}`;
    if (seen.has(key)) continue;
    seen.add(key);
    mutations.push({
      seq: event.seq ?? null,
      api: event.api || "",
      param,
      action
    });
  }
  return mutations;
}

function addObjectLink(links, type, id, event) {
  const numericId = Number(id);
  if (!Number.isFinite(numericId) || numericId <= 0) return;
  const key = `${type}:${numericId}`;
  const link = links.get(key) || {
    type,
    id: numericId,
    seqs: [],
    apiSet: new Set()
  };
  if (event.seq !== null && event.seq !== undefined && !link.seqs.includes(event.seq)) {
    link.seqs.push(event.seq);
  }
  if (event.api) link.apiSet.add(event.api);
  links.set(key, link);
}

function objectLinksForFlow(flow) {
  const links = new Map();
  for (const event of flow.timeline || []) {
    for (const arg of event.args || []) {
      if (!arg || typeof arg !== "object") continue;
      addObjectLink(links, "url_object", arg.url_object_id, event);
      addObjectLink(links, "search_params", arg.search_params_id, event);
    }
  }
  return [...links.values()]
    .map((link) => ({
      type: link.type,
      id: link.id,
      seqs: [...link.seqs].sort((a, b) => a - b),
      apis: [...link.apiSet].sort()
    }))
    .sort((a, b) => {
      const order = {url_object: 0, search_params: 1};
      if (a.type !== b.type) return (order[a.type] ?? 99) - (order[b.type] ?? 99);
      return a.id - b.id;
    });
}

function buildAgentFlowSummary(flow, index) {
  const addedNames = (flow.added_params || []).map((param) => param.name);
  const signatureParams = sortParamNames(addedNames.filter((name) => SIGNATURE_TERMS.includes(name)));
  const supportingParams = sortParamNames(addedNames.filter((name) => !SIGNATURE_TERMS.includes(name)));
  const signatureMutations = signatureMutationsForFlow(flow);
  const inferredUnsignedParamNames = flow.match === "signed_only"
    ? sortParamNames((flow.signed_param_names || []).filter((name) => !isSensitiveParamName(name)))
    : [];
  return {
    id: `signature_flow_${index + 1}`,
    endpoint: flow.endpoint,
    match: flow.match || "unknown",
    evidence_level: evidenceLevelForFlow(flow),
    unsigned_seq: flow.unsigned_event?.seq ?? null,
    signed_seq: flow.signed_event?.seq ?? null,
    signature_params: signatureParams,
    supporting_params: supportingParams,
    inferred_unsigned_param_names: inferredUnsignedParamNames,
    signature_mutations: signatureMutations,
    object_links: objectLinksForFlow(flow),
    renderer_request_link: flow.renderer_request_link || null,
    phases: compactAgentPhases(flow.timeline || []),
    vmp_analysis_points: vmpAnalysisPointsForFlow(flow),
    vmp_evidence: (flow.preceding_vmp_events || []).map((event) => ({
      seq: event.seq ?? null,
      api: event.api || "",
      family: vmpFamilyForApi(event.api),
      relation: event.relation || "",
      distance: event.distance ?? null
    })),
    assets: (flow.assets || []).slice(0, 8).map((asset) => ({
      asset_id: asset.asset_id,
      url: asset.url,
      content_path: asset.content_path,
      score: asset.score,
      signals: asset.signals
    })),
    gaps: gapsForFlow(flow)
  };
}

function buildSignatureAgentBrief(flows) {
  const unsignedToSignedCount = flows.filter((flow) => flow.match === "unsigned_to_signed").length;
  const signedOnlyCount = flows.filter((flow) => flow.match === "signed_only").length;
  return {
    version: 1,
    target_terms: SIGNATURE_TERMS,
    summary: {
      flow_count: flows.length,
      unsigned_to_signed_count: unsignedToSignedCount,
      signed_only_count: signedOnlyCount,
      signature_event_count: flows.length
    },
    flows: flows.map((flow, index) => buildAgentFlowSummary(flow, index))
  };
}

function sourcePreviewAroundColumn(line, column) {
  const text = String(line || "");
  const numericColumn = Number(column);
  if (!Number.isFinite(numericColumn) || numericColumn <= 0 || text.length <= SOURCE_CONTEXT_MAX_CHARS) {
    const preview = preserveSignatureText(text);
    return {
      preview: preview.length > SOURCE_CONTEXT_MAX_CHARS
        ? `${preview.slice(0, SOURCE_CONTEXT_MAX_CHARS)}...`
        : preview
    };
  }

  const anchor = Math.max(0, Math.min(text.length, Math.floor(numericColumn) - 1));
  const half = Math.floor(SOURCE_CONTEXT_MAX_CHARS / 2);
  let start = Math.max(0, anchor - half);
  let end = Math.min(text.length, start + SOURCE_CONTEXT_MAX_CHARS);
  if (end - start < SOURCE_CONTEXT_MAX_CHARS) {
    start = Math.max(0, end - SOURCE_CONTEXT_MAX_CHARS);
  }

  const prefix = start > 0 ? "..." : "";
  const suffix = end < text.length ? "..." : "";
  return {
    column_anchor: Math.floor(numericColumn),
    column_start: start + 1,
    column_end: end,
    preview: preserveSignatureText(`${prefix}${text.slice(start, end)}${suffix}`)
  };
}

function analyzeSourceContextSnippet(source) {
  const text = String(source || "");
  const codeText = stripStringLiterals(text);
  const calls = regexMatches(codeText, /(?:[A-Za-z_$][\w$]*\.){0,4}[A-Za-z_$][\w$]*\s*\(/g, (match) => {
    const name = match[0].replace(/\s*\($/, "");
    const prefix = codeText.slice(Math.max(0, (match.index || 0) - 10), match.index || 0);
    if (/function\s*$/.test(prefix)) return "";
    if (/^(if|for|while|switch|catch|return)$/.test(name)) return "";
    return name;
  });
  const properties = regexMatches(codeText, /\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){1,5}\b/g);
  const operators = uniqueLimited([
    ...(codeText.includes("^") ? ["^"] : []),
    ...(codeText.includes(">>>") ? [">>>"] : []),
    ...(/(^|[^<])<<($|[^<])/.test(codeText) ? ["<<"] : []),
    ...(/(^|[^>])>>($|[^>])/.test(codeText) ? [">>"] : []),
    ...(codeText.includes("&") ? ["&"] : []),
    ...(codeText.includes("|") ? ["|"] : []),
    ...(codeText.includes("~") ? ["~"] : [])
  ]);
  const numeric_literals = regexMatches(codeText, /\b(?:0x[0-9a-fA-F]+|\d{3,})\b/g, (match) => match[0], 12);
  const string_literals = regexMatches(text, /(['"])(?:(?!\1)[^\\]|\\.){2,80}\1/g, (match) =>
    preserveSignatureText(match[0]).slice(0, 96)
  , 8);

  const signals = [];
  const signalChecks = [
    ["byte_buffer", /DataView|ArrayBuffer|Uint(?:8|16|32)Array|Int(?:8|16|32)Array|getUint|getInt|setUint|setInt/],
    ["json_serialization", /JSON\.(?:stringify|parse)/],
    ["text_codec", /TextEncoder|TextDecoder|fromCharCode|charCodeAt|fromCodePoint|atob|btoa/],
    ["int_bitwise", /\>\>\>|\>\>|\<\<|\^|~|(?:[^|]\|[^|])|(?:[^&]&[^&])/],
    ["int_multiply", /Math\.imul|\*\s*(?:0x[0-9a-fA-F]+|\d{4,})/],
    ["hash_crypto", /SubtleCrypto|crypto\.subtle|digest|sha256|SHA256|md5|HMAC/i],
    ["url_signature", /X-Signature|X-Secondary-Signature|URLSearchParams|searchParams|encodeURIComponent/],
    ["prototype_call", /\.prototype\.[A-Za-z_$][\w$]*\.call|\.call\(/],
    ["dynamic_dispatch", /Reflect\.apply|Function\.prototype|\.apply\(/]
  ];
  for (const [signal, pattern] of signalChecks) {
    if (pattern.test(signal === "url_signature" ? text : codeText)) signals.push(signal);
  }

  return {
    signals: uniqueLimited(signals, 12),
    calls: calls.slice(0, 12),
    properties: properties.slice(0, 12),
    operators,
    numeric_literals,
    string_literals
  };
}

function sourceContextForFrame(frame, assetSourcesById) {
  if (!frame?.asset_id) return null;
  const source = assetSourcesById.get(frame.asset_id);
  if (!source?.content) return null;

  const lines = String(source.content).split(/\r?\n/);
  const frameLine = Number(frame.line);
  const requestedLine = Number.isFinite(frameLine) && frameLine > 0 ? Math.floor(frameLine) : 1;
  const lineNumber = Math.min(Math.max(requestedLine, 1), Math.max(lines.length, 1));
  const start = Math.max(1, lineNumber - SOURCE_CONTEXT_RADIUS);
  const end = Math.min(lines.length, lineNumber + SOURCE_CONTEXT_RADIUS);
  const selectedLines = lines.slice(start - 1, end);
  const columnContext = selectedLines.length === 1
    ? sourcePreviewAroundColumn(selectedLines[0], frame.column)
    : sourcePreviewAroundColumn(selectedLines.join("\n"), null);

  return {
    asset_id: frame.asset_id,
    url: frame.url || source.url || "",
    content_path: frame.asset_path || source.content_path || "",
    line_start: start,
    line_end: end,
    ...columnContext,
    analysis: analyzeSourceContextSnippet(columnContext.preview || "")
  };
}

function sourceContextForAssetLine(assetId, source, lineNumber) {
  if (!assetId || !source?.content) return null;
  const lines = String(source.content).split(/\r?\n/);
  const requestedLine = Number.isFinite(lineNumber) && lineNumber > 0 ? Math.floor(lineNumber) : 1;
  const line = Math.min(Math.max(requestedLine, 1), Math.max(lines.length, 1));
  const start = Math.max(1, line - SOURCE_CONTEXT_RADIUS);
  const end = Math.min(lines.length, line + SOURCE_CONTEXT_RADIUS);
  const preview = preserveSignatureText(lines.slice(start - 1, end).join("\n"));
  return {
    asset_id: assetId,
    url: source.url || "",
    content_path: source.content_path || "",
    line_start: start,
    line_end: end,
    preview: preview.length > SOURCE_CONTEXT_MAX_CHARS
      ? `${preview.slice(0, SOURCE_CONTEXT_MAX_CHARS)}...`
      : preview,
    analysis: analyzeSourceContextSnippet(preview)
  };
}

function dynamicDispatchSourceContextsForAssets(assetIds, assetSourcesById) {
  const contexts = [];
  const seen = new Set();
  for (const assetId of assetIds || []) {
    const source = assetSourcesById?.get(assetId);
    if (!source?.content) continue;
    const lines = String(source.content).split(/\r?\n/);
    const matchIndex = lines.findIndex((line) =>
      /Reflect\.apply|Function\.prototype\.(?:call|apply)|(?:handler|dispatch)[A-Za-z_$\w]*[^\n]{0,120}\.(?:call|apply)\s*\(/i.test(line)
    );
    if (matchIndex === -1) continue;
    const context = sourceContextForAssetLine(assetId, source, matchIndex + 1);
    if (!context) continue;
    const key = sourceContextKey(context);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    contexts.push(context);
    if (contexts.length >= SOURCE_CONTEXTS_PER_WINDOW) break;
  }
  return contexts;
}

function sourceContextsForEvent(event, assetSourcesById) {
  const contexts = [];
  const seen = new Set();
  for (const frame of event.stack || []) {
    const context = sourceContextForFrame(frame, assetSourcesById);
    if (!context) continue;
    const key = sourceContextKey(context);
    if (seen.has(key)) continue;
    seen.add(key);
    contexts.push(context);
    if (contexts.length >= SOURCE_CONTEXTS_PER_WINDOW) break;
  }
  return contexts;
}

function eventEvidenceSummary(event) {
  const asset = primaryAssetForSummaryEvent(event);
  const frame = primaryFrameForSummaryEvent(event);
  const traceIndex = explicitTraceIndexValue(event);
  return {
    ...(Number.isFinite(traceIndex) ? {trace_index: traceIndex} : {}),
    seq: event.seq ?? null,
    api: event.api || "",
    category: event.category || "",
    phase: event.phase || event.t || "",
    role: event.role || "",
    relation: event.relation || "",
    family: vmpFamilyForApi(event.api),
    function: frame?.function || "",
    line: frame?.line ?? null,
    column: frame?.column ?? null,
    stack_url: stackUrlForSummaryEvent(event),
    frame_url: event.frame_url || "",
    origin: event.origin || "",
    asset_id: asset?.asset_id || "",
    args: preserveSignatureValues(event.args || [])
  };
}

function buildAgentEventWindows(flow, assetSourcesById) {
  const windows = new Map();
  for (const event of flow.timeline || []) {
    const phase = phaseForAgentTimelineEvent(event) || event.role || "context";
    const seq = event.seq ?? null;
    const window = windows.get(phase) || {
      phase,
      seq_start: seq,
      seq_end: seq,
      event_count: 0,
      events: []
    };
    window.event_count += 1;
    if (seq !== null) {
      window.seq_start = window.seq_start === null ? seq : Math.min(window.seq_start, seq);
      window.seq_end = window.seq_end === null ? seq : Math.max(window.seq_end, seq);
    }
    addSummaryToAgentWindowEvents(window, eventEvidenceSummary(event));
    if ((window.source_contexts || []).length < SOURCE_CONTEXTS_PER_WINDOW) {
      const contexts = sourceContextsForEvent(event, assetSourcesById);
      if (contexts.length) {
        const existing = new Set((window.source_contexts || [])
          .map((context) => `${context.asset_id}:${context.line_start}:${context.line_end}`));
        for (const context of contexts) {
          const key = `${context.asset_id}:${context.line_start}:${context.line_end}`;
          if (existing.has(key)) continue;
          window.source_contexts = window.source_contexts || [];
          window.source_contexts.push(context);
          existing.add(key);
          if (window.source_contexts.length >= SOURCE_CONTEXTS_PER_WINDOW) break;
        }
      }
    }
    windows.set(phase, window);
    if (phase !== "url_signature_mutation" &&
        isSupplementalSignatureAttachmentTimelineEvent(event) &&
        targetParamsForAttachmentEvent(event).length) {
      addEventToAgentWindow(
        windows,
        "url_signature_mutation",
        eventEvidenceSummary(event),
        sourceContextsForEvent(event, assetSourcesById)
      );
    }
  }
  return [...windows.values()];
}

function rawEventForFlowSummary(summary, events) {
  if (!summary || !(events || []).length) return null;
  const traceIndex = explicitTraceIndexValue(summary);
  if (Number.isFinite(traceIndex)) {
    for (let index = 0; index < events.length; index += 1) {
      const event = events[index];
      if (traceIndexValue(event, index) === traceIndex) {
        return {event, index};
      }
    }
  }
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if ((summary.seq === null || summary.seq === undefined || event.seq === summary.seq) &&
        (!summary.api || event.api === summary.api)) {
      return {event, index};
    }
  }
  return null;
}

function requestMaterialPhaseForEvent(event) {
  const api = event?.api || "";
  if (api === "XMLHttpRequest.setRequestHeader" || api.startsWith("Headers.")) {
    return "request_headers";
  }
  if (isFormDataObjectMutationEvent(event)) return "request_body";
  if (isRequestBodyBoundaryEvent(event)) return "request_body";
  return "";
}

function networkCorrelationKeyForEvent(event) {
  const arg = networkRequestArg(event);
  return String(arg.network_correlation_key || arg.request_correlation_key || "");
}

function stackFingerprintForRequestMaterial(event) {
  const frame = (event?.stack || []).find((item) => item?.url || item?.function || item?.asset_id) || {};
  return {
    function: frame.function || event?.function || "",
    url: frame.url || event?.stack_url || event?.frame_url || event?.origin || "",
    asset_id: frame.asset_id || event?.asset_id || ""
  };
}

function requestMaterialStackMatches(left, right) {
  const leftKey = stackFingerprintForRequestMaterial(left);
  const rightKey = stackFingerprintForRequestMaterial(right);
  if (leftKey.asset_id && rightKey.asset_id && leftKey.asset_id === rightKey.asset_id) {
    return !leftKey.function || !rightKey.function || leftKey.function === rightKey.function;
  }
  if (leftKey.url && rightKey.url && leftKey.url === rightKey.url) {
    return !leftKey.function || !rightKey.function || leftKey.function === rightKey.function;
  }
  return false;
}

function methodMatches(left, right) {
  if (!left || !right) return true;
  if (!left.method || !right.method) return true;
  return left.method === right.method;
}

function requestMaterialMatchForFlowEvent(event, index, anchorEvent, anchorIndex, anchorInfo) {
  const phase = requestMaterialPhaseForEvent(event);
  if (!phase || !anchorInfo) return null;
  if (index === anchorIndex) return null;

  const traceIndex = traceIndexValue(event, index);
  const anchorTraceIndex = traceIndexValue(anchorEvent, anchorIndex);
  const traceDistance = Math.abs(traceIndex - anchorTraceIndex);
  const candidateInfo = networkRequestInfoFromEvent(event);
  const anchorKey = anchorInfo.network_correlation_key || networkCorrelationKeyForEvent(anchorEvent);
  const candidateKey = candidateInfo?.network_correlation_key || networkCorrelationKeyForEvent(event);

  if (anchorKey && candidateKey && anchorKey === candidateKey && methodMatches(anchorInfo, candidateInfo)) {
    return {phase, match: "network_correlation_key", traceDistance};
  }

  if (candidateInfo &&
      candidateInfo.endpoint === anchorInfo.endpoint &&
      methodMatches(anchorInfo, candidateInfo) &&
      traceDistance <= SIGNATURE_REQUEST_MATERIAL_TRACE_RADIUS) {
    return {phase, match: "endpoint_method_trace_window", traceDistance};
  }

  if (traceDistance <= SIGNATURE_REQUEST_MATERIAL_TRACE_RADIUS &&
      requestMaterialStackMatches(event, anchorEvent)) {
    return {phase, match: "same_stack_trace_window", traceDistance};
  }

  return null;
}

function addSourceContextsToAgentWindow(window, contexts) {
  if (!contexts.length || (window.source_contexts || []).length >= SOURCE_CONTEXTS_PER_WINDOW) return;
  const existing = new Set((window.source_contexts || [])
    .map((context) => `${context.asset_id}:${context.line_start}:${context.line_end}`));
  for (const context of contexts) {
    const key = `${context.asset_id}:${context.line_start}:${context.line_end}`;
    if (existing.has(key)) continue;
    window.source_contexts = window.source_contexts || [];
    window.source_contexts.push(context);
    existing.add(key);
    if (window.source_contexts.length >= SOURCE_CONTEXTS_PER_WINDOW) break;
  }
}

function shouldUseExpandedAgentWindowEvents(phase) {
  return String(phase || "").startsWith("vmp_");
}

function addSummaryToAgentWindowEvents(window, summary) {
  if (shouldUseExpandedAgentWindowEvents(window.phase)) {
    window.events = compactClusterEventSummaries([
      ...(window.events || []),
      summary
    ]);
    return;
  }
  if ((window.events || []).length < 8) {
    window.events = window.events || [];
    window.events.push(summary);
  }
}

function addEventToAgentWindow(windows, phase, summary, contexts) {
  const seq = summary.seq ?? null;
  const window = windows.get(phase) || {
    phase,
    seq_start: seq,
    seq_end: seq,
    event_count: 0,
    events: []
  };
  const eventKey = timelineKey(summary, window.event_count);
  const exists = (window.events || []).some((event, index) => timelineKey(event, index) === eventKey);
  if (!exists) {
    window.event_count += 1;
    if (seq !== null) {
      window.seq_start = window.seq_start === null ? seq : Math.min(window.seq_start, seq);
      window.seq_end = window.seq_end === null ? seq : Math.max(window.seq_end, seq);
    }
    addSummaryToAgentWindowEvents(window, summary);
  }
  addSourceContextsToAgentWindow(window, contexts);
  windows.set(phase, window);
}

function augmentAgentEventWindowsWithRequestMaterials(
  eventWindows,
  flow,
  allEvents,
  assetSourcesById,
  assetByUrl
) {
  const anchor = rawEventForFlowSummary(flow?.signed_event, allEvents);
  if (!anchor) return eventWindows;
  const anchorInfo = networkRequestInfoFromEvent(anchor.event);
  if (!anchorInfo) return eventWindows;

  const candidates = [];
  for (let index = 0; index < (allEvents || []).length; index += 1) {
    const event = allEvents[index];
    const match = requestMaterialMatchForFlowEvent(event, index, anchor.event, anchor.index, anchorInfo);
    if (!match) continue;
    candidates.push({event, index, ...match});
  }

  if (!candidates.length) return eventWindows;

  const windows = new Map((eventWindows || []).map((window) => [window.phase, {
    ...window,
    events: [...(window.events || [])],
    source_contexts: window.source_contexts ? [...window.source_contexts] : undefined
  }]));

  for (const candidate of candidates
    .sort((a, b) => a.traceDistance - b.traceDistance || a.index - b.index)
    .slice(0, SIGNATURE_REQUEST_MATERIAL_EVENT_LIMIT)
    .sort((a, b) => a.index - b.index)) {
    const summary = summarizeFlowEvent(candidate.event, assetByUrl, {
      role: candidate.phase === "request_headers" ? "headers" : "body",
      relation: candidate.match,
      distance: candidate.traceDistance
    });
    addEventToAgentWindow(
      windows,
      candidate.phase,
      summary,
      sourceContextsForEvent(summary, assetSourcesById)
    );
  }

  return [...windows.values()].sort((a, b) =>
    (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
    String(a.phase).localeCompare(String(b.phase)));
}

function operationIdForEvent(event) {
  const id = firstEventArgsObject(event).operation_id;
  if (typeof id === "number" && Number.isFinite(id) && id > 0) {
    return String(Math.floor(id));
  }
  if (typeof id === "string") {
    const trimmed = id.trim();
    return trimmed && trimmed !== "0" ? trimmed : "";
  }
  return "";
}

function webCryptoOperationRef(event) {
  const operationId = operationIdForEvent(event);
  return operationId ? `operation:${operationId}` : "";
}

function webCryptoArrayBufferRef(value) {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return `array_buffer:${Math.floor(value)}`;
  }
  if (typeof value === "string" && value.trim() && value.trim() !== "0") {
    return `array_buffer:${value.trim()}`;
  }
  return "";
}

function webCryptoRuntimeEventRefsForFlow(flow) {
  return new Set((flow?.stages || [])
    .filter((stage) => (stage.runtime_apis || []).some((api) => WEBCRYPTO_SIGNATURE_APIS.has(api)))
    .flatMap((stage) => stage.runtime_event_refs || [])
    .map((event) => event.event_ref || "")
    .filter(Boolean));
}

function webCryptoEventsForFlow(flow, allEvents) {
  const refs = webCryptoRuntimeEventRefsForFlow(flow);
  const matching = (allEvents || [])
    .filter((event) => WEBCRYPTO_SIGNATURE_APIS.has(event?.api || "") && refs.has(runtimeEventRefId(event)));
  if (matching.length) return matching;

  const start = Number.isFinite(flow?.seq_start) ? flow.seq_start : null;
  const end = Number.isFinite(flow?.seq_end) ? flow.seq_end : null;
  if (start === null || end === null) return [];
  return (allEvents || []).filter((event) =>
    WEBCRYPTO_SIGNATURE_APIS.has(event?.api || "") &&
    Number.isFinite(event?.seq) &&
    event.seq >= start &&
    event.seq <= end);
}

function webCryptoOperationSummary(event) {
  const args = firstEventArgsObject(event);
  const operationRef = webCryptoOperationRef(event);
  const keyRef = normalizeRuntimeValueRef(args.key_ref);
  const keyMaterialRef = normalizeRuntimeValueRef(args.key_data_ref || args.key_material_ref);
  const inputRef = normalizeRuntimeValueRef(args.input_ref);
  const resultRef = normalizeRuntimeValueRef(args.result_ref);
  const inputArrayBufferRef = webCryptoArrayBufferRef(args.array_buffer_id || args.input_array_buffer_id);
  const resultArrayBufferRef = webCryptoArrayBufferRef(args.result_array_buffer_id);
  return {
    api: event?.api || "",
    phase: event?.phase || event?.t || "",
    seq: Number.isFinite(event?.seq) ? event.seq : null,
    operation_ref: operationRef,
    algorithm: typeof args.algorithm === "string"
      ? args.algorithm
      : typeof args.key_algorithm === "string"
        ? args.key_algorithm
        : "",
    ...(keyRef ? {key_ref: keyRef} : {}),
    ...(keyMaterialRef ? {key_material_ref: keyMaterialRef} : {}),
    ...(inputRef ? {input_ref: inputRef} : {}),
    ...(resultRef ? {result_ref: resultRef} : {}),
    ...(inputArrayBufferRef ? {input_array_buffer_ref: inputArrayBufferRef} : {}),
    ...(resultArrayBufferRef ? {result_array_buffer_ref: resultArrayBufferRef} : {}),
    event_ref: runtimeEventRefId(event)
  };
}

function buildWebCryptoSignatureSummaryForFlow(flow, allEvents) {
  const events = webCryptoEventsForFlow(flow, allEvents)
    .sort((a, b) =>
      (a.seq ?? Number.MAX_SAFE_INTEGER) - (b.seq ?? Number.MAX_SAFE_INTEGER) ||
      String(a.api || "").localeCompare(String(b.api || "")) ||
      String(a.phase || a.t || "").localeCompare(String(b.phase || b.t || "")));
  if (!events.length) return null;

  const operations = events.map(webCryptoOperationSummary);
  return {
    observed: true,
    apis: uniqueLimited(operations.map((operation) => operation.api).filter(Boolean), 8),
    algorithms: uniqueLimited(operations.map((operation) => operation.algorithm).filter(Boolean), 8),
    operation_refs: uniqueLimited(operations.map((operation) => operation.operation_ref).filter(Boolean), 12),
    key_refs: uniqueLimited(operations.map((operation) => operation.key_ref).filter(Boolean), 12),
    key_material_refs: uniqueLimited(operations.map((operation) => operation.key_material_ref).filter(Boolean), 12),
    input_refs: uniqueLimited(operations.map((operation) => operation.input_ref).filter(Boolean), 12),
    result_refs: uniqueLimited(operations.map((operation) => operation.result_ref).filter(Boolean), 12),
    input_array_buffer_refs: uniqueLimited(operations.map((operation) => operation.input_array_buffer_ref).filter(Boolean), 12),
    result_array_buffer_refs: uniqueLimited(operations.map((operation) => operation.result_array_buffer_ref).filter(Boolean), 12),
    runtime_event_refs: compactRuntimeEventRefs(events, 12),
    operations: operations.slice(0, 12)
  };
}

function isWebCryptoOperationReturn(event) {
  return WEBCRYPTO_SIGNATURE_APIS.has(event?.api || "") &&
    (event?.phase || event?.t || "") === "return" &&
    Boolean(operationIdForEvent(event));
}

function augmentAgentEventWindowsWithOperationReturns(eventWindows, allEvents, assetByUrl) {
  if (!(eventWindows || []).length || !(allEvents || []).length) return eventWindows;
  const returnEventsByOperation = new Map();
  for (const event of allEvents || []) {
    if (!isWebCryptoOperationReturn(event)) continue;
    const operationId = operationIdForEvent(event);
    const bucket = returnEventsByOperation.get(operationId) || [];
    bucket.push(event);
    returnEventsByOperation.set(operationId, bucket);
  }
  if (!returnEventsByOperation.size) return eventWindows;

  const windows = new Map((eventWindows || []).map((window) => [window.phase, {
    ...window,
    events: [...(window.events || [])],
    source_contexts: window.source_contexts ? [...window.source_contexts] : undefined
  }]));

  for (const window of [...windows.values()]) {
    const operationIds = new Set((window.events || [])
      .map(operationIdForEvent)
      .filter(Boolean));
    if (!operationIds.size) continue;
    for (const operationId of operationIds) {
      for (const event of returnEventsByOperation.get(operationId) || []) {
        addEventToAgentWindow(
          windows,
          window.phase,
          summarizeFlowEvent(event, assetByUrl, {
            role: "webcrypto_result",
            relation: "operation_id"
          }),
          window.source_contexts || []
        );
      }
    }
  }

  return [...windows.values()].sort((a, b) =>
    (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
    String(a.phase).localeCompare(String(b.phase)));
}

function buildAgentFlowGraph(eventWindows) {
  const nodes = (eventWindows || []).map((window, index) => ({
    id: `n${index + 1}`,
    phase: window.phase,
    seq_start: window.seq_start ?? null,
    seq_end: window.seq_end ?? null,
    event_count: window.event_count || 0,
    apis: sortCountEntries(countBy(window.events || [], (event) => event.api || ""), "api"),
    source_context_refs: (window.source_contexts || []).map((_, sourceIndex) =>
      `${window.phase}:${sourceIndex}`
    )
  }));
  const edges = [];
  for (let index = 0; index + 1 < nodes.length; index += 1) {
    const from = nodes[index];
    const to = nodes[index + 1];
    const seqGap = Number.isFinite(from.seq_end) && Number.isFinite(to.seq_start)
      ? to.seq_start - from.seq_end
      : null;
    edges.push({
      from: from.id,
      to: to.id,
      relation: "observed_before",
      seq_gap: seqGap
    });
  }
  return {nodes, edges};
}

function buildAgentStackClusters(eventWindows) {
  const clusters = new Map();
  for (const window of eventWindows || []) {
    for (const event of window.events || []) {
      const key = `${event.function || ""}|${event.stack_url || ""}|${event.asset_id || ""}`;
      const cluster = clusters.get(key) || {
        function: event.function || "",
        stack_url: event.stack_url || "",
        asset_id: event.asset_id || "",
        event_count: 0,
        seq_start: event.seq ?? null,
        seq_end: event.seq ?? null,
        phaseSet: new Set(),
        apiCounts: new Map(),
        sourceContextRefs: new Set()
      };
      cluster.event_count += 1;
      if (event.seq !== null && event.seq !== undefined) {
        cluster.seq_start = cluster.seq_start === null ? event.seq : Math.min(cluster.seq_start, event.seq);
        cluster.seq_end = cluster.seq_end === null ? event.seq : Math.max(cluster.seq_end, event.seq);
      }
      if (window.phase) cluster.phaseSet.add(window.phase);
      if (event.api) cluster.apiCounts.set(event.api, (cluster.apiCounts.get(event.api) || 0) + 1);
      for (let index = 0; index < (window.source_contexts || []).length; index += 1) {
        const context = window.source_contexts[index];
        if (!event.asset_id || !context.asset_id || context.asset_id === event.asset_id) {
          cluster.sourceContextRefs.add(`${window.phase}:${index}`);
        }
      }
      clusters.set(key, cluster);
    }
  }

  return [...clusters.values()]
    .sort((a, b) =>
      b.event_count - a.event_count ||
      (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
      String(a.function).localeCompare(String(b.function)) ||
      String(a.stack_url).localeCompare(String(b.stack_url)))
    .slice(0, STACK_CLUSTER_LIMIT)
    .map((cluster) => ({
      function: cluster.function,
      stack_url: cluster.stack_url,
      asset_id: cluster.asset_id,
      event_count: cluster.event_count,
      seq_start: cluster.seq_start,
      seq_end: cluster.seq_end,
      phases: [...cluster.phaseSet],
      apis: sortCountEntries(cluster.apiCounts, "api"),
      source_context_refs: [...cluster.sourceContextRefs]
    }));
}

function seqRangeForFlow(flow) {
  const seqs = (flow.timeline || [])
    .map((event) => event.seq)
    .filter((seq) => Number.isFinite(seq));
  if (!seqs.length) {
    return {
      start: flow.unsigned_event?.seq ?? flow.signed_event?.seq ?? null,
      end: flow.signed_event?.seq ?? flow.unsigned_event?.seq ?? null
    };
  }
  return {
    start: Math.min(...seqs),
    end: Math.max(...seqs)
  };
}

function coverageForAgentFlow(summary) {
  const phases = new Set((summary.phases || []).map((phase) => phase.phase));
  return {
    unsigned_url: summary.unsigned_seq !== null || phases.has("unsigned_url"),
    signature_mutation: Boolean(summary.signature_mutations?.length) || phases.has("url_signature_mutation"),
    signed_request: summary.signed_seq !== null || phases.has("signed_request"),
    vmp_runtime: phases.has("vmp_runtime") || (summary.phases || []).some((phase) => phase.phase.startsWith("vmp_")),
    vmp_string_decode: phases.has("vmp_string_decode"),
    vmp_bytecode_or_register_access: phases.has("vmp_bytecode_or_register_access"),
    vmp_int_bitwise_pipeline: phases.has("vmp_int_bitwise_pipeline"),
    vmp_hash_or_signature_pipeline: phases.has("vmp_hash_or_signature_pipeline"),
    vmp_anti_debug_timing_gate: phases.has("vmp_anti_debug_timing_gate"),
    vmp_source_integrity_probe: phases.has("vmp_source_integrity_probe"),
    vmp_stack_trace_probe: phases.has("vmp_stack_trace_probe"),
    vmp_exception_control_flow: phases.has("vmp_exception_control_flow"),
    vmp_string_transform: phases.has("vmp_string_transform"),
    vmp_regexp_probe: phases.has("vmp_regexp_probe"),
    vmp_url_encoding_boundary: phases.has("vmp_url_encoding_boundary"),
    assets: Boolean(summary.assets?.length)
  };
}

function nextQuestionsForAgentFlow(summary, coverage) {
  const questions = [...(summary.gaps || [])];
  if (!coverage.signature_mutation) questions.push("signature_mutation_not_observed");
  if (!coverage.vmp_hash_or_signature_pipeline) questions.push("hash_or_signature_pipeline_not_observed");
  if (!coverage.vmp_bytecode_or_register_access) questions.push("bytecode_or_register_access_not_observed");
  if (!coverage.assets) questions.push("script_asset_not_linked");
  return [...new Set(questions)];
}

function existingEvidenceLabels(coverage) {
  const labels = [];
  if (coverage.vmp_string_decode) labels.push("vmp_string_decode");
  if (coverage.vmp_bytecode_or_register_access) labels.push("vmp_bytecode_or_register_access");
  if (coverage.vmp_int_bitwise_pipeline) labels.push("vmp_int_bitwise_pipeline");
  if (coverage.vmp_hash_or_signature_pipeline) labels.push("vmp_hash_or_signature_pipeline");
  if (coverage.vmp_anti_debug_timing_gate) labels.push("vmp_anti_debug_timing_gate");
  if (coverage.vmp_source_integrity_probe) labels.push("vmp_source_integrity_probe");
  if (coverage.vmp_stack_trace_probe) labels.push("vmp_stack_trace_probe");
  if (coverage.vmp_exception_control_flow) labels.push("vmp_exception_control_flow");
  if (coverage.vmp_string_transform) labels.push("vmp_string_transform");
  if (coverage.vmp_regexp_probe) labels.push("vmp_regexp_probe");
  if (coverage.vmp_url_encoding_boundary) labels.push("vmp_url_encoding_boundary");
  if (coverage.signature_mutation) labels.push("url_signature_mutation");
  if (coverage.assets) labels.push("asset_source_context");
  return labels;
}

function captureRecommendationsForAgentFlow(summary, coverage) {
  const existing = existingEvidenceLabels(coverage);
  const recommendations = [];

  if (!coverage.signature_mutation) {
    recommendations.push({
      id: "capture_signature_url_mutation",
      priority: "high",
      reason: "URL/query mutation evidence is missing before the signed request",
      suggested_hooks: [
        "URLSearchParams.set",
        "URLSearchParams.append",
        "URLSearchParams.sort",
        "URL.href.set",
        "URL.search.set"
      ],
      related_existing_evidence: existing
    });
  }

  if (!coverage.vmp_hash_or_signature_pipeline) {
    recommendations.push({
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
      related_existing_evidence: existing
    });
  }

  if (!coverage.vmp_bytecode_or_register_access) {
    recommendations.push({
      id: "capture_vmp_bytecode_or_register_access",
      priority: "medium",
      reason: "bytecode/register access evidence is missing near this signature flow",
      suggested_hooks: [
        "ArrayBuffer.constructor",
        "DataView.getUint8",
        "DataView.getUint16",
        "DataView.getUint32",
        "TypedArray.at",
        "TypedArray.slice"
      ],
      related_existing_evidence: existing
    });
  }

  if (!coverage.assets) {
    recommendations.push({
      id: "capture_script_assets",
      priority: "medium",
      reason: "script asset source is not linked to this flow",
      suggested_hooks: [
        "--xtrace-capture-assets=full",
        "Script.inline",
        "HTMLScriptElement.src.set",
        "HTMLScriptElement.inserted"
      ],
      related_existing_evidence: existing
    });
  }

  return recommendations;
}

function buildGlobalStackClusters(evidenceFlows) {
  const clusters = new Map();
  for (const flow of evidenceFlows || []) {
    for (const window of flow.event_windows || []) {
      for (const event of window.events || []) {
        const key = `${event.function || ""}|${event.stack_url || ""}|${event.asset_id || ""}`;
        const cluster = clusters.get(key) || {
          function: event.function || "",
          stack_url: event.stack_url || "",
          asset_id: event.asset_id || "",
          flowIds: new Set(),
          endpoints: new Set(),
          event_count: 0,
          seq_start: event.seq ?? null,
          seq_end: event.seq ?? null,
          phaseSet: new Set(),
          apiCounts: new Map(),
          sourceRefsByFlow: new Map(),
          eventKeys: new Set()
        };

        cluster.flowIds.add(flow.id);
        if (flow.endpoint) cluster.endpoints.add(flow.endpoint);
        const eventKey = `${event.seq ?? ""}:${event.api || ""}:${event.function || ""}:${event.stack_url || ""}`;
        if (!cluster.eventKeys.has(eventKey)) {
          cluster.eventKeys.add(eventKey);
          cluster.event_count += 1;
          if (event.api) {
            cluster.apiCounts.set(event.api, (cluster.apiCounts.get(event.api) || 0) + 1);
          }
        }
        if (event.seq !== null && event.seq !== undefined) {
          cluster.seq_start = cluster.seq_start === null
            ? event.seq
            : Math.min(cluster.seq_start, event.seq);
          cluster.seq_end = cluster.seq_end === null
            ? event.seq
            : Math.max(cluster.seq_end, event.seq);
        }
        if (window.phase) cluster.phaseSet.add(window.phase);
        const refs = cluster.sourceRefsByFlow.get(flow.id) || new Set();
        for (let index = 0; index < (window.source_contexts || []).length; index += 1) {
          const context = window.source_contexts[index];
          if (!event.asset_id || !context.asset_id || context.asset_id === event.asset_id) {
            refs.add(`${window.phase}:${index}`);
          }
        }
        cluster.sourceRefsByFlow.set(flow.id, refs);
        clusters.set(key, cluster);
      }
    }
  }

  return [...clusters.values()]
    .sort((a, b) =>
      b.flowIds.size - a.flowIds.size ||
      b.event_count - a.event_count ||
      (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
      String(a.function).localeCompare(String(b.function)) ||
      String(a.stack_url).localeCompare(String(b.stack_url)))
    .slice(0, STACK_CLUSTER_LIMIT)
    .map((cluster) => ({
      function: cluster.function,
      stack_url: cluster.stack_url,
      asset_id: cluster.asset_id,
      flow_count: cluster.flowIds.size,
      event_count: cluster.event_count,
      seq_start: cluster.seq_start,
      seq_end: cluster.seq_end,
      endpoints: [...cluster.endpoints].sort(),
      phases: [...cluster.phaseSet].sort(),
      apis: sortCountEntries(cluster.apiCounts, "api"),
      sample_flow_ids: [...cluster.flowIds].slice(0, 8),
      source_context_refs: [...cluster.sourceRefsByFlow.entries()]
        .slice(0, 8)
        .map(([flowId, refs]) => ({
          flow_id: flowId,
          refs: [...refs]
        }))
    }));
}

function mergeCoverage(target, coverage) {
  for (const [key, value] of Object.entries(coverage || {})) {
    target[key] = Boolean(target[key] || value);
  }
}

function eventsForPipelinePattern(flow) {
  const events = [];
  const seen = new Set();
  let unsignedSeq = null;
  let signedSeq = null;

  for (const window of flow.event_windows || []) {
    for (const event of window.events || []) {
      if (window.phase === "unsigned_url" && Number.isFinite(event.seq)) {
        unsignedSeq = unsignedSeq === null ? event.seq : Math.min(unsignedSeq, event.seq);
      }
      if (window.phase === "signed_request" && Number.isFinite(event.seq)) {
        signedSeq = signedSeq === null ? event.seq : Math.max(signedSeq, event.seq);
      }
    }
  }

  for (const window of flow.event_windows || []) {
    for (const event of window.events || []) {
      if (unsignedSeq !== null && Number.isFinite(event.seq) && event.seq < unsignedSeq) continue;
      if (signedSeq !== null && Number.isFinite(event.seq) && event.seq > signedSeq) continue;
      const key = `${window.phase}:${event.seq ?? ""}:${event.api || ""}:${event.function || ""}:${event.stack_url || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      events.push({...event, phase: window.phase});
    }
  }

  return events.sort((a, b) =>
    timelineOrderValue(a) - timelineOrderValue(b) ||
    String(a.phase).localeCompare(String(b.phase)) ||
    String(a.api).localeCompare(String(b.api)));
}

function phasePatternFromEvents(events, fallbackFlow) {
  const phases = [];
  const seen = new Set();
  for (const event of events || []) {
    if (!event.phase || seen.has(event.phase)) continue;
    seen.add(event.phase);
    phases.push(event.phase);
  }
  if (phases.length) return phases;
  return (fallbackFlow.graph?.nodes || []).map((node) => node.phase).filter(Boolean);
}

function buildPipelinePatterns(evidenceFlows) {
  const patterns = new Map();
  for (const flow of evidenceFlows || []) {
    const patternEvents = eventsForPipelinePattern(flow);
    const phases = phasePatternFromEvents(patternEvents, flow);
    if (!phases.length) continue;
    const patternKey = phases.join(" -> ");
    const pattern = patterns.get(patternKey) || {
      pattern: patternKey,
      flowIds: new Set(),
      endpoints: new Set(),
      event_count: 0,
      coverage: {},
      stackClusters: new Map()
    };
    pattern.flowIds.add(flow.id);
    if (flow.endpoint) pattern.endpoints.add(flow.endpoint);
    pattern.event_count += patternEvents.length;
    mergeCoverage(pattern.coverage, flow.coverage);

    for (const event of patternEvents) {
      const key = `${event.function || ""}|${event.stack_url || ""}|${event.asset_id || ""}`;
      const existing = pattern.stackClusters.get(key) || {
        function: event.function || "",
        stack_url: event.stack_url || "",
        asset_id: event.asset_id || "",
        flowIds: new Set(),
        event_count: 0
      };
      existing.flowIds.add(flow.id);
      existing.event_count += 1;
      pattern.stackClusters.set(key, existing);
    }

    patterns.set(patternKey, pattern);
  }

  return [...patterns.values()]
    .sort((a, b) =>
      b.flowIds.size - a.flowIds.size ||
      b.event_count - a.event_count ||
      String(a.pattern).localeCompare(String(b.pattern)))
    .slice(0, 12)
    .map((pattern) => ({
      pattern: pattern.pattern,
      flow_count: pattern.flowIds.size,
      event_count: pattern.event_count,
      endpoints: [...pattern.endpoints].sort(),
      sample_flow_ids: [...pattern.flowIds].slice(0, 8),
      coverage: pattern.coverage,
      top_stack_clusters: [...pattern.stackClusters.values()]
        .sort((a, b) =>
          b.flowIds.size - a.flowIds.size ||
          b.event_count - a.event_count ||
          String(a.function).localeCompare(String(b.function)) ||
          String(a.stack_url).localeCompare(String(b.stack_url)))
        .slice(0, 5)
        .map((cluster) => ({
          function: cluster.function,
          stack_url: cluster.stack_url,
          asset_id: cluster.asset_id,
          flow_count: cluster.flowIds.size,
          event_count: cluster.event_count
        }))
    }));
}

function mergeCountEntriesIntoMap(target, entries, keyName) {
  for (const entry of entries || []) {
    const key = entry?.[keyName];
    if (!key) continue;
    target.set(key, (target.get(key) || 0) + (entry.count || 0));
  }
}

function mergeSeqRange(target, seqStart, seqEnd) {
  if (Number.isFinite(seqStart)) {
    target.seq_start = target.seq_start === null
      ? seqStart
      : Math.min(target.seq_start, seqStart);
  }
  if (Number.isFinite(seqEnd)) {
    target.seq_end = target.seq_end === null
      ? seqEnd
      : Math.max(target.seq_end, seqEnd);
  }
}

function coverageRatio(observed, total) {
  if (!total) return 0;
  return Number((observed / total).toFixed(4));
}

function globalVmpStatsForSpec(spec, globalVmpApiCounts) {
  const apiCounts = new Map();
  let eventCount = 0;
  for (const [api, count] of globalVmpApiCounts || []) {
    if (!spec?.families?.includes(vmpFamilyForApi(api))) continue;
    apiCounts.set(api, count);
    eventCount += count;
  }
  return {
    global_event_count: eventCount,
    global_apis: sortCountEntries(apiCounts, "api").slice(0, 8)
  };
}

function keyForVmpLinkingEvent(event) {
  return `${event?.seq ?? ""}:${event?.api || ""}:${event?.stack_url || firstStackUrl(event) || ""}`;
}

function seqDistanceToRange(seq, range) {
  if (!Number.isFinite(seq) || !range) return Number.MAX_SAFE_INTEGER;
  const start = Number.isFinite(range.start) ? range.start : range.end;
  const end = Number.isFinite(range.end) ? range.end : range.start;
  if (!Number.isFinite(start) || !Number.isFinite(end)) return Number.MAX_SAFE_INTEGER;
  if (seq < start) return start - seq;
  if (seq > end) return seq - end;
  return 0;
}

function flowValues(flow, key) {
  const values = new Set();
  for (const window of flow.event_windows || []) {
    for (const event of window.events || []) {
      if (event?.[key]) values.add(event[key]);
    }
  }
  return values;
}

function relationBetweenVmpCandidateAndFlow(candidate, flow) {
  const stackUrls = flowValues(flow, "stack_url");
  const origins = flowValues(flow, "origin");
  const frameUrls = flowValues(flow, "frame_url");

  if (candidate.stack_url && stackUrls.has(candidate.stack_url)) return "same_stack_nearby";
  if (candidate.frame_url && frameUrls.has(candidate.frame_url)) return "same_frame_nearby";
  if (candidate.origin && origins.has(candidate.origin)) return "same_origin_nearby";
  return "nearest_by_seq";
}

function nearestFlowsForVmpCandidate(candidate, evidenceFlows) {
  return (evidenceFlows || [])
    .map((flow) => ({
      flow_id: flow.id,
      endpoint: flow.endpoint,
      relation: relationBetweenVmpCandidateAndFlow(candidate, flow),
      seq_distance: seqDistanceToRange(candidate.seq, flow.seq_range),
      seq_range: {
        start: flow.seq_range?.start ?? null,
        end: flow.seq_range?.end ?? null
      }
    }))
    .filter((item) => Number.isFinite(item.seq_distance))
    .sort((a, b) =>
      a.seq_distance - b.seq_distance ||
      String(a.relation).localeCompare(String(b.relation)) ||
      String(a.flow_id).localeCompare(String(b.flow_id)))
    .slice(0, VMP_LINKING_NEAREST_FLOW_LIMIT);
}

function indexOfTraceEvent(target, allEvents) {
  const directIndex = (allEvents || []).indexOf(target);
  if (directIndex !== -1) return directIndex;

  const targetKey = keyForVmpLinkingEvent(target);
  return (allEvents || []).findIndex((event) => keyForVmpLinkingEvent(event) === targetKey);
}

function appendSourceContextsForEvent(contexts, seen, event, assetSourcesById) {
  for (const context of sourceContextsForEvent(event, assetSourcesById)) {
    const key = `${context.asset_id}:${context.line_start}:${context.line_end}`;
    if (seen.has(key)) continue;
    seen.add(key);
    contexts.push(context);
    if (contexts.length >= SOURCE_CONTEXTS_PER_WINDOW) return;
  }
}

function contextWindowForVmpCandidate(event, allEvents, assetSourcesById) {
  const sources = assetSourcesById || new Map();
  const index = indexOfTraceEvent(event, allEvents);
  const contextEvents = index === -1
    ? [event]
    : allEvents.slice(
        Math.max(0, index - VMP_LINKING_CONTEXT_RADIUS),
        Math.min(allEvents.length, index + VMP_LINKING_CONTEXT_RADIUS + 1)
      );
  const candidateKey = keyForVmpLinkingEvent(event);
  const summarizedEvents = contextEvents.map((contextEvent) => ({
    ...eventEvidenceSummary(contextEvent),
    window_role: keyForVmpLinkingEvent(contextEvent) === candidateKey ? "candidate" : "nearby"
  }));
  const seqs = summarizedEvents
    .map((contextEvent) => contextEvent.seq)
    .filter((seq) => Number.isFinite(seq));
  const sourceContexts = [];
  const seen = new Set();
  appendSourceContextsForEvent(sourceContexts, seen, event, sources);
  for (const contextEvent of contextEvents) {
    if (sourceContexts.length >= SOURCE_CONTEXTS_PER_WINDOW) break;
    if (keyForVmpLinkingEvent(contextEvent) === candidateKey) continue;
    appendSourceContextsForEvent(sourceContexts, seen, contextEvent, sources);
  }

  return {
    seq_start: seqs.length ? Math.min(...seqs) : event.seq ?? null,
    seq_end: seqs.length ? Math.max(...seqs) : event.seq ?? null,
    event_count: summarizedEvents.length,
    events: summarizedEvents,
    source_contexts: sourceContexts
  };
}

function summarizeVmpLinkingCandidate(event, evidenceFlows, allEvents, assetSourcesById) {
  const asset = primaryAssetForSummaryEvent(event);
  const frame = primaryFrameForSummaryEvent(event);
  const candidate = {
    seq: event.seq ?? null,
    api: event.api || "",
    family: vmpFamilyForApi(event.api),
    function: frame?.function || "",
    stack_url: firstStackUrl(event),
    asset_id: asset?.asset_id || "",
    frame_url: event.frame_url || "",
    origin: event.origin || ""
  };
  const nearestFlows = nearestFlowsForVmpCandidate(candidate, evidenceFlows);
  if (!nearestFlows.length) return null;
  return {
    seq: candidate.seq,
    api: candidate.api,
    family: candidate.family,
    function: candidate.function,
    stack_url: candidate.stack_url,
    asset_id: candidate.asset_id,
    ...(candidate.frame_url ? {frame_url: candidate.frame_url} : {}),
    ...(candidate.origin ? {origin: candidate.origin} : {}),
    nearest_flows: nearestFlows,
    context_window: contextWindowForVmpCandidate(event, allEvents, assetSourcesById)
  };
}

function linkedVmpEventKeys(evidenceFlows) {
  const keys = new Set();
  for (const flow of evidenceFlows || []) {
    for (const event of eventsForPipelinePattern(flow)) {
      if (!VMP_RUNTIME_APIS.has(event.api || "")) continue;
      keys.add(keyForVmpLinkingEvent(event));
    }
  }
  return keys;
}

function linkingCandidatesForSpec(spec, globalVmpEvents, evidenceFlows, allEvents, assetSourcesById) {
  const linkedKeys = linkedVmpEventKeys(evidenceFlows);
  const candidates = [];
  const seen = new Set();
  for (const event of globalVmpEvents || []) {
    if (!VMP_RUNTIME_APIS.has(event.api || "")) continue;
    if (!spec?.families?.includes(vmpFamilyForApi(event.api))) continue;
    const key = keyForVmpLinkingEvent(event);
    if (linkedKeys.has(key) || seen.has(key)) continue;
    const summary = summarizeVmpLinkingCandidate(event, evidenceFlows, allEvents, assetSourcesById);
    if (!summary) continue;
    candidates.push(summary);
    seen.add(key);
  }

  return candidates
    .sort((a, b) =>
      (a.nearest_flows[0]?.seq_distance ?? Number.MAX_SAFE_INTEGER) -
        (b.nearest_flows[0]?.seq_distance ?? Number.MAX_SAFE_INTEGER) ||
      (a.seq ?? Number.MAX_SAFE_INTEGER) - (b.seq ?? Number.MAX_SAFE_INTEGER) ||
      String(a.api).localeCompare(String(b.api)))
    .slice(0, VMP_LINKING_CANDIDATE_LIMIT);
}

function gapSourceForGlobalStats(stats) {
  return stats.global_event_count > 0
    ? "captured_outside_signature_flow"
    : "not_captured_in_trace";
}

function nextStepForGapSource(gapSource) {
  return gapSource === "captured_outside_signature_flow"
    ? "improve_flow_linking"
    : "add_or_enable_hooks";
}

function nextActionForGlobalVmpHookPoint(status, coverage) {
  if (status === "observed") return "review_observed_flows";
  return nextStepForGapSource(gapSourceForGlobalStats({
    global_event_count: coverage?.global_event_count || 0
  }));
}

function buildGlobalVmpHookAnalysisPoints(coverageByType, pointMap) {
  return VMP_HOOK_POINT_SPECS.map((spec) => {
    const coverage = coverageByType[spec.type] || {};
    const point = pointMap.get(spec.type);
    const status = vmpHookPointStatus(
      coverage.observed_flows || 0,
      coverage.missing_flows || 0
    );
    return {
      type: spec.type,
      status,
      priority: spec.priority,
      analysis_goal: vmpHookAnalysisGoal(spec.type),
      families: spec.families || [],
      observed_flows: coverage.observed_flows || 0,
      missing_flows: coverage.missing_flows || 0,
      coverage_ratio: coverage.coverage_ratio || 0,
      observed_event_count: coverage.event_count || 0,
      global_event_count: coverage.global_event_count || 0,
      observed_apis: point ? sortCountEntries(point.apiCounts, "api").slice(0, 12) : [],
      global_apis: coverage.global_apis || [],
      suggested_hooks: spec.suggested_hooks,
      reason: spec.reason,
      next_action: nextActionForGlobalVmpHookPoint(status, coverage)
    };
  });
}

function buildGlobalVmpHookAnalysis(
  evidenceFlows,
  globalVmpApiCounts = new Map(),
  globalVmpEvents = [],
  allEvents = [],
  assetSourcesById = new Map()
) {
  const totalFlows = evidenceFlows?.length || 0;
  const pointMap = new Map();

  for (const flow of evidenceFlows || []) {
    const mainChainVmpEvents = eventsForPipelinePattern(flow)
      .filter((event) => VMP_RUNTIME_APIS.has(event.api || ""));
    for (const point of vmpAnalysisPointsForEvents(mainChainVmpEvents)) {
      if (!point?.type) continue;
      const aggregate = pointMap.get(point.type) || {
        type: point.type,
        flowIds: new Set(),
        endpoints: new Set(),
        event_count: 0,
        seq_start: null,
        seq_end: null,
        families: new Set(),
        apiCounts: new Map(),
        stackUrlCounts: new Map(),
        assets: new Map(),
        sampleEvents: []
      };

      aggregate.flowIds.add(flow.id);
      if (flow.endpoint) aggregate.endpoints.add(flow.endpoint);
      aggregate.event_count += point.event_count || 0;
      mergeSeqRange(aggregate, point.seq_start, point.seq_end);
      for (const family of point.families || []) {
        if (family) aggregate.families.add(family);
      }
      mergeCountEntriesIntoMap(aggregate.apiCounts, point.apis, "api");
      mergeCountEntriesIntoMap(aggregate.stackUrlCounts, point.stack_urls, "stack_url");
      for (const asset of point.assets || []) {
        if (!asset?.asset_id || aggregate.assets.has(asset.asset_id)) continue;
        aggregate.assets.set(asset.asset_id, {
          asset_id: asset.asset_id,
          url: asset.url || "",
          content_path: asset.content_path || "",
          score: asset.score || 0,
          signals: asset.signals || []
        });
      }
      if (aggregate.sampleEvents.length < 8) {
        for (const event of point.sample_events || []) {
          aggregate.sampleEvents.push({
            flow_id: flow.id,
            seq: event.seq ?? null,
            api: event.api || "",
            family: event.family || "",
            relation: event.relation || "",
            stack_url: event.stack_url || "",
            asset_id: event.asset_id || ""
          });
          if (aggregate.sampleEvents.length >= 8) break;
        }
      }
      pointMap.set(point.type, aggregate);
    }
  }

  const expectedTypes = [
    ...VMP_HOOK_POINT_SPECS.map((spec) => spec.type),
    "vmp_runtime_cluster"
  ];
  const coverageByType = {};
  const specByType = new Map(VMP_HOOK_POINT_SPECS.map((spec) => [spec.type, spec]));
  for (const type of expectedTypes) {
    const point = pointMap.get(type);
    const observedFlows = point?.flowIds.size || 0;
    const spec = specByType.get(type);
    const globalStats = spec
      ? globalVmpStatsForSpec(spec, globalVmpApiCounts)
      : {
          global_event_count: [...(globalVmpApiCounts || new Map()).values()].reduce((sum, count) => sum + count, 0),
          global_apis: sortCountEntries(globalVmpApiCounts || new Map(), "api").slice(0, 8)
        };
    coverageByType[type] = {
      observed_flows: observedFlows,
      missing_flows: Math.max(0, totalFlows - observedFlows),
      coverage_ratio: coverageRatio(observedFlows, totalFlows),
      event_count: point?.event_count || 0,
      ...globalStats
    };
  }

  const observedPointTypes = expectedTypes
    .filter((type) => (coverageByType[type]?.observed_flows || 0) > 0);
  const missingPointTypes = VMP_HOOK_POINT_SPECS
    .map((spec) => spec.type)
    .filter((type) => (coverageByType[type]?.observed_flows || 0) === 0);
  const hookGaps = VMP_HOOK_POINT_SPECS
    .map((spec, index) => ({
      ...spec,
      index,
      missing_flow_count: coverageByType[spec.type]?.missing_flows || 0,
      global_event_count: coverageByType[spec.type]?.global_event_count || 0,
      global_apis: coverageByType[spec.type]?.global_apis || [],
      linking_candidates: linkingCandidatesForSpec(spec, globalVmpEvents, evidenceFlows, allEvents, assetSourcesById)
    }))
    .filter((gap) => gap.missing_flow_count > 0)
    .sort((a, b) =>
      b.missing_flow_count - a.missing_flow_count ||
      a.index - b.index)
    .map(({index, ...gap}) => {
      const gapSource = gapSourceForGlobalStats(gap);
      return {
        ...gap,
        gap_source: gapSource,
        recommended_next_step: nextStepForGapSource(gapSource)
      };
    });

  const points = [...pointMap.values()]
    .sort((a, b) =>
      b.flowIds.size - a.flowIds.size ||
      b.event_count - a.event_count ||
      (VMP_HOOK_POINT_IMPORTANCE.get(a.type) ?? 99) - (VMP_HOOK_POINT_IMPORTANCE.get(b.type) ?? 99) ||
      (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
      String(a.type).localeCompare(String(b.type)))
    .slice(0, VMP_ANALYSIS_POINT_LIMIT)
    .map((point) => ({
      type: point.type,
      flow_count: point.flowIds.size,
      event_count: point.event_count,
      seq_start: point.seq_start,
      seq_end: point.seq_end,
      families: [...point.families].sort(),
      apis: sortCountEntries(point.apiCounts, "api").slice(0, 12),
      stack_urls: sortCountEntries(point.stackUrlCounts, "stack_url").slice(0, 8),
      assets: [...point.assets.values()].slice(0, 8),
      endpoints: [...point.endpoints].sort(),
      sample_flow_ids: [...point.flowIds].slice(0, 8),
      sample_events: point.sampleEvents
    }));

  return {
    total_flows: totalFlows,
    observed_point_types: observedPointTypes,
    missing_point_types: missingPointTypes,
    coverage_by_type: coverageByType,
    hook_analysis_points: buildGlobalVmpHookAnalysisPoints(coverageByType, pointMap),
    points,
    hook_gaps: hookGaps
  };
}

function candidateForFlowFromGapCandidate(candidate, flow) {
  const nearest = (candidate.nearest_flows || []).find((item) => item.flow_id === flow.id);
  if (!nearest) return null;
  return {
    seq: candidate.seq ?? null,
    api: candidate.api || "",
    family: candidate.family || "",
    function: candidate.function || "",
    stack_url: candidate.stack_url || "",
    asset_id: candidate.asset_id || "",
    ...(candidate.frame_url ? {frame_url: candidate.frame_url} : {}),
    ...(candidate.origin ? {origin: candidate.origin} : {}),
    relation: nearest.relation || "",
    seq_distance: nearest.seq_distance ?? null,
    seq_range: nearest.seq_range || {start: null, end: null},
    context_window: candidate.context_window
  };
}

function vmpLinkingCandidatesForFlow(flow, hookGaps) {
  const groups = [];
  for (const gap of hookGaps || []) {
    const candidates = (gap.linking_candidates || [])
      .map((candidate) => candidateForFlowFromGapCandidate(candidate, flow))
      .filter(Boolean);
    if (!candidates.length) continue;
    groups.push({
      type: gap.type,
      priority: gap.priority,
      reason: gap.reason,
      gap_source: gap.gap_source,
      recommended_next_step: gap.recommended_next_step,
      suggested_hooks: gap.suggested_hooks || [],
      candidate_count: candidates.length,
      candidates
    });
  }
  return groups;
}

function confidenceForVmpCandidate(candidate) {
  if (candidate.relation === "same_stack_nearby" && candidate.seq_distance === 0) return "high";
  if (candidate.relation === "same_stack_nearby" && candidate.seq_distance <= SIGNATURE_VMP_NEARBY_LOOKBACK) return "high";
  if ((candidate.relation === "same_frame_nearby" || candidate.relation === "same_origin_nearby") &&
      candidate.seq_distance <= SIGNATURE_VMP_NEARBY_LOOKBACK) {
    return "medium";
  }
  return "low";
}

function strongestConfidence(confidences) {
  const priority = {high: 0, medium: 1, low: 2};
  return [...confidences].sort((a, b) => (priority[a] ?? 99) - (priority[b] ?? 99))[0] || "low";
}

function vmpCandidatePhasesForFlow(candidateGroups) {
  const phases = [];
  for (const group of candidateGroups || []) {
    const candidates = (group.candidates || []).map((candidate) => ({
      ...candidate,
      confidence: confidenceForVmpCandidate(candidate)
    }));
    if (!candidates.length) continue;
    const seqs = candidates.map((candidate) => candidate.seq).filter((seq) => Number.isFinite(seq));
    const apis = sortCountEntries(countBy(candidates, (candidate) => candidate.api || ""), "api");
    phases.push({
      type: group.type,
      phase: `candidate_${group.type}`,
      evidence_status: "candidate_not_main_chain",
      confidence: strongestConfidence(candidates.map((candidate) => candidate.confidence)),
      relation: candidates[0].relation || "",
      seq_start: seqs.length ? Math.min(...seqs) : null,
      seq_end: seqs.length ? Math.max(...seqs) : null,
      candidate_count: candidates.length,
      apis,
      sample_candidates: candidates.slice(0, 4).map((candidate) => ({
        seq: candidate.seq ?? null,
        api: candidate.api || "",
        family: candidate.family || "",
        relation: candidate.relation || "",
        seq_distance: candidate.seq_distance ?? null,
        confidence: candidate.confidence
      }))
    });
  }
  return phases;
}

function nodeEndsBeforePhase(node, phase) {
  return Number.isFinite(node.seq_end) && Number.isFinite(phase.seq_start) && node.seq_end <= phase.seq_start;
}

function nodeStartsAfterPhase(node, phase) {
  return Number.isFinite(node.seq_start) && Number.isFinite(phase.seq_end) && node.seq_start >= phase.seq_end;
}

function nodeOverlapsPhase(node, phase) {
  if (!Number.isFinite(node.seq_start) || !Number.isFinite(node.seq_end) ||
      !Number.isFinite(phase.seq_start) || !Number.isFinite(phase.seq_end)) {
    return false;
  }
  return node.seq_start <= phase.seq_end && node.seq_end >= phase.seq_start;
}

function buildCandidateGraph(mainGraph, candidatePhases) {
  const mainNodes = mainGraph?.nodes || [];
  const nodes = [];
  const edges = [];
  for (const [index, phase] of (candidatePhases || []).entries()) {
    const candidateNode = {
      id: `c${index + 1}`,
      phase: phase.phase,
      type: phase.type,
      evidence_status: phase.evidence_status,
      confidence: phase.confidence,
      seq_start: phase.seq_start,
      seq_end: phase.seq_end,
      candidate_count: phase.candidate_count,
      apis: phase.apis
    };
    nodes.push(candidateNode);

    const overlapping = mainNodes.find((node) => nodeOverlapsPhase(node, phase));
    if (overlapping) {
      edges.push({from: candidateNode.id, to: overlapping.id, relation: "candidate_overlaps", seq_gap: 0});
      continue;
    }

    const previous = mainNodes
      .filter((node) => nodeEndsBeforePhase(node, phase))
      .sort((a, b) => b.seq_end - a.seq_end)[0];
    const next = mainNodes
      .filter((node) => nodeStartsAfterPhase(node, phase))
      .sort((a, b) => a.seq_start - b.seq_start)[0];

    if (previous) {
      edges.push({
        from: previous.id,
        to: candidateNode.id,
        relation: "candidate_after",
        seq_gap: phase.seq_start - previous.seq_end
      });
    }
    if (next) {
      edges.push({
        from: candidateNode.id,
        to: next.id,
        relation: "candidate_before",
        seq_gap: next.seq_start - phase.seq_end
      });
    }
  }
  return {nodes, edges};
}

function subflowKeyForParts(parts) {
  return `${parts.function || ""}|${parts.stack_url || ""}|${parts.asset_id || ""}`;
}

function ensureSubflowCluster(clusters, parts) {
  const key = subflowKeyForParts(parts);
  const cluster = clusters.get(key) || {
    function: parts.function || "",
    stack_url: parts.stack_url || "",
    asset_id: parts.asset_id || "",
    seq_start: null,
    seq_end: null,
    phaseSeq: new Map(),
    observedApiCounts: new Map(),
    candidateApiCounts: new Map(),
    candidatePhaseCount: 0,
    confidenceSet: new Set(),
    evidenceKinds: new Set(),
    sourceContexts: new Map(),
    eventSummaries: []
  };
  clusters.set(key, cluster);
  return cluster;
}

function sourceContextKey(context) {
  const lineKey = `${context.asset_id || ""}:${context.line_start ?? ""}-${context.line_end ?? ""}`;
  if (context.column_start !== undefined || context.column_end !== undefined) {
    return `${lineKey}@${context.column_start ?? ""}-${context.column_end ?? ""}`;
  }
  return lineKey;
}

function addClusterSourceContexts(cluster, contexts) {
  for (const context of contexts || []) {
    if (cluster.asset_id && context.asset_id && context.asset_id !== cluster.asset_id) continue;
    const key = sourceContextKey(context);
    if (!key || cluster.sourceContexts.has(key)) continue;
    cluster.sourceContexts.set(key, context);
    if (cluster.sourceContexts.size >= SOURCE_CONTEXTS_PER_WINDOW) return;
  }
}

function mergeClusterSeq(cluster, seqStart, seqEnd) {
  if (Number.isFinite(seqStart)) {
    cluster.seq_start = cluster.seq_start === null ? seqStart : Math.min(cluster.seq_start, seqStart);
  }
  if (Number.isFinite(seqEnd)) {
    cluster.seq_end = cluster.seq_end === null ? seqEnd : Math.max(cluster.seq_end, seqEnd);
  }
}

function addClusterPhase(cluster, phase, seqStart) {
  if (!phase) return;
  const existing = cluster.phaseSeq.get(phase);
  if (existing === undefined || (Number.isFinite(seqStart) && seqStart < existing)) {
    cluster.phaseSeq.set(phase, Number.isFinite(seqStart) ? seqStart : Number.MAX_SAFE_INTEGER);
  }
}

function addCount(map, key, count = 1) {
  if (!key) return;
  map.set(key, (map.get(key) || 0) + count);
}

const MAX_CLUSTER_EVENT_SUMMARIES = 128;
const CLUSTER_EVENT_HEAD_COUNT = 48;
const CLUSTER_EVENT_TAIL_COUNT = 48;

function clusterEventKey(event) {
  return `${event?.seq}:${event?.api}`;
}

function isHighValueClusterEvent(event) {
  if (/^(?:URLSearchParams\.|URL\.|Request\.|fetch|XMLHttpRequest\.|BrowserNetwork\.)/.test(event?.api || "")) {
    return true;
  }
  return /(?:register:|handler_arg:|handler_return:|string:length:)/.test(JSON.stringify(event?.args || []));
}

function compactClusterEventSummaries(events) {
  const uniqueEvents = [];
  const seen = new Set();
  for (const event of events || []) {
    const key = clusterEventKey(event);
    if (seen.has(key)) continue;
    seen.add(key);
    uniqueEvents.push(event);
  }
  if (uniqueEvents.length <= MAX_CLUSTER_EVENT_SUMMARIES) return uniqueEvents;

  const selected = [];
  const selectedKeys = new Set();
  const addEvent = (event) => {
    const key = clusterEventKey(event);
    if (selectedKeys.has(key)) return;
    selectedKeys.add(key);
    selected.push(event);
  };
  uniqueEvents.slice(0, CLUSTER_EVENT_HEAD_COUNT).forEach(addEvent);
  uniqueEvents.filter(isHighValueClusterEvent).forEach(addEvent);
  uniqueEvents.slice(-CLUSTER_EVENT_TAIL_COUNT).forEach(addEvent);
  return selected
    .sort((left, right) =>
      (traceIndexValue(left, 0) ?? 0) - (traceIndexValue(right, 0) ?? 0) ||
      (left?.seq ?? 0) - (right?.seq ?? 0) ||
      String(left?.api || "").localeCompare(String(right?.api || ""))
    )
    .slice(0, MAX_CLUSTER_EVENT_SUMMARIES);
}

function addClusterEventSummaries(cluster, events) {
  cluster.eventSummaries = compactClusterEventSummaries([
    ...(cluster.eventSummaries || []),
    ...(events || [])
  ]);
}

function clusterRuntimeApis(cluster) {
  return uniqueLimited([
    ...[...cluster.observedApiCounts.keys()],
    ...[...cluster.candidateApiCounts.keys()]
  ], 32);
}

function normalizeObjectRefType(key) {
  const normalized = String(key || "")
    .replace(/_id$/i, "")
    .replace(/Id$/, "")
    .replace(/[^a-zA-Z0-9_:-]/g, "_");
  if (/^(?:result_|source_|destination_)?array_buffer$/.test(normalized)) return "array_buffer";
  if (/^(?:result_|source_|destination_)?typed_array$/.test(normalized)) return "typed_array";
  return normalized;
}

function extractObjectRefsFromValue(value, output = [], depth = 0) {
  if (depth > 5 || value === null || value === undefined) return output;
  if (Array.isArray(value)) {
    for (const item of value) extractObjectRefsFromValue(item, output, depth + 1);
    return output;
  }
  if (typeof value !== "object") return output;
  for (const [key, raw] of Object.entries(value)) {
    if ((key === "network_correlation_key" || key === "request_correlation_key") &&
        (typeof raw === "number" || typeof raw === "string")) {
      const id = String(raw);
      if (id && id !== "0") output.push(`network_request:${id}`);
    }
    if (/_id$/i.test(key) || /Id$/.test(key)) {
      if (typeof raw === "number" || typeof raw === "string") {
        const id = String(raw);
        if (id && id !== "0") output.push(`${normalizeObjectRefType(key)}:${id}`);
      }
    }
    extractObjectRefsFromValue(raw, output, depth + 1);
  }
  return output;
}

function objectRefsForEvents(events, matcher) {
  return uniqueLimited(
    (events || [])
      .filter((event) => matcher(event.api || ""))
      .flatMap((event) => extractObjectRefsFromValue(event.args || [])),
    16
  );
}

function urlValueRefsForParsedUrl(parsed) {
  const queryKeys = sortParamNames([...new Set([...parsed.searchParams.keys()])]);
  if (!queryKeys.length) return [];
  const shapeHash = sha1Hex(JSON.stringify({
    endpoint: endpointForUrl(parsed),
    query_keys: queryKeys
  }));
  const targetParams = sortParamNames(queryKeys.filter((name) => SIGNATURE_TERMS.includes(name)));
  return uniqueLimited([
    `url_shape:${shapeHash}`,
    targetParams.length ? `target_params:${targetParams.join("|")}` : ""
  ].filter(Boolean), 4);
}

const STRING_LENGTH_REF_KEYS = new Set([
  "subject_length",
  "search_length",
  "input_length",
  "result_length"
]);

function extractStringLengthRefsFromValue(value, output = [], depth = 0, key = "") {
  if (depth > 5 || value === null || value === undefined) return output;
  if (STRING_LENGTH_REF_KEYS.has(String(key || "")) && typeof value === "number" && Number.isFinite(value) && value >= 0) {
    output.push(`string:length:${Math.floor(value)}`);
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) extractStringLengthRefsFromValue(item, output, depth + 1);
    return output;
  }
  if (typeof value !== "object") return output;
  for (const [childKey, childValue] of Object.entries(value)) {
    extractStringLengthRefsFromValue(childValue, output, depth + 1, childKey);
  }
  return output;
}

function semanticNumberRef(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "";
  return `number:${value.toFixed(6)}`;
}

function semanticLengthRef(prefix, value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "";
  return `${prefix}:length:${Math.floor(value)}`;
}

function semanticStringLengthRef(value) {
  if (typeof value !== "string") return "";
  return semanticLengthRef("string", value.length);
}

function semanticIndexRef(prefix, value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "";
  return `${prefix}_index:${Math.floor(value)}`;
}

function semanticByteOffsetRef(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "";
  return `byte_offset:${Math.floor(value)}`;
}

function eventSemanticArgsObject(event) {
  const args = Array.isArray(event?.args) ? event.args[0] : null;
  const result = event?.result && typeof event.result === "object" ? event.result : null;
  if (args && typeof args === "object" && result) return {...args, ...result};
  if (args && typeof args === "object") return args;
  return result || {};
}

function semanticValueRefsForEvent(event) {
  const api = event?.api || "";
  const args = eventSemanticArgsObject(event);
  if (!Object.keys(args).length) return [];
  const refs = [];

  if (api === "String.fromCharCode" || api === "String.fromCodePoint") {
    refs.push(
      semanticNumberRef(args.first_code),
      semanticLengthRef("string", args.argc),
      normalizeRuntimeValueRef(args.first_code_ref),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "String.prototype.charCodeAt" || api === "String.prototype.codePointAt") {
    refs.push(
      semanticNumberRef(args.result),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "StringAdd" || api === "StringAdd.constant_lhs" || api === "StringAdd.constant_rhs") {
    refs.push(
      semanticLengthRef("string", args.left_length),
      semanticLengthRef("string", args.right_length),
      semanticLengthRef("string", args.result_length),
      normalizeRuntimeValueRef(args.left_ref),
      normalizeRuntimeValueRef(args.right_ref),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "TextEncoder.encode") {
    refs.push(
      semanticLengthRef("string", args.input_length),
      semanticLengthRef("byte", args.result_byte_length),
      normalizeRuntimeValueRef(args.result_typed_array_ref),
      normalizeRuntimeValueRef(args.result_array_buffer_ref)
    );
  } else if (api === "TextEncoder.encodeInto") {
    refs.push(
      semanticLengthRef("string", args.input_length),
      semanticLengthRef("byte", args.written),
      normalizeRuntimeValueRef(args.destination_typed_array_ref),
      normalizeRuntimeValueRef(args.destination_array_buffer_ref)
    );
  } else if (api === "TextDecoder.decode") {
    refs.push(
      semanticLengthRef("byte", args.input_byte_length),
      semanticLengthRef("byte", args.input_length),
      semanticLengthRef("string", args.result_length),
      normalizeRuntimeValueRef(args.input_ref),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "btoa") {
    refs.push(
      semanticLengthRef("string", args.input_length),
      semanticLengthRef("base64", args.result_length),
      normalizeRuntimeValueRef(args.input_ref),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "atob") {
    refs.push(
      semanticLengthRef("base64", args.input_length),
      semanticLengthRef("string", args.result_length),
      normalizeRuntimeValueRef(args.input_ref),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "encodeURI" || api === "encodeURIComponent") {
    refs.push(
      semanticLengthRef("string", args.input_length),
      semanticLengthRef("url_encoded", args.result_length),
      normalizeRuntimeValueRef(args.input_ref),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "decodeURI" || api === "decodeURIComponent") {
    refs.push(
      semanticLengthRef("url_encoded", args.input_length),
      semanticLengthRef("string", args.result_length),
      normalizeRuntimeValueRef(args.input_ref),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (/^DataView\.get(?:Uint|Int)\d+$/.test(api)) {
    refs.push(
      semanticNumberRef(args.result),
      semanticByteOffsetRef(args.byte_offset),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (/^DataView\.set(?:Uint|Int)\d+$/.test(api)) {
    refs.push(
      semanticNumberRef(args.value),
      semanticByteOffsetRef(args.byte_offset),
      normalizeRuntimeValueRef(args.value_ref)
    );
  } else if (api === "TypedArray.at") {
    refs.push(
      semanticNumberRef(args.result),
      semanticIndexRef("typed_array", args.index),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "Math.imul" || api.startsWith("Bitwise.") || api.startsWith("Shift.")) {
    refs.push(
      semanticNumberRef(args.left),
      semanticNumberRef(args.right),
      semanticNumberRef(args.x),
      semanticNumberRef(args.y),
      semanticNumberRef(args.value),
      semanticNumberRef(args.shift),
      semanticNumberRef(args.result),
      normalizeRuntimeValueRef(args.left_ref),
      normalizeRuntimeValueRef(args.right_ref),
      normalizeRuntimeValueRef(args.x_ref),
      normalizeRuntimeValueRef(args.y_ref),
      normalizeRuntimeValueRef(args.value_ref),
      normalizeRuntimeValueRef(args.shift_ref),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "TypedArray.slice" || api === "TypedArray.subarray") {
    refs.push(
      semanticIndexRef("typed_array", args.start),
      semanticIndexRef("typed_array", args.end),
      semanticLengthRef("typed_array", args.result_length)
    );
  } else if (api === "TypedArray.join") {
    refs.push(
      semanticLengthRef("typed_array", args.length),
      semanticLengthRef("separator", args.separator_length),
      semanticLengthRef("string", args.result_length)
    );
  } else if (api === "Array.prototype.push") {
    refs.push(
      semanticLengthRef("array", args.length_after),
      semanticLengthRef("array_before", args.length_before),
      semanticNumberRef(args.first_arg),
      normalizeRuntimeValueRef(args.first_arg_ref),
      normalizeRuntimeValueRef(args.value_ref)
    );
  } else if (api === "Array.prototype.slice") {
    refs.push(
      semanticIndexRef("array", args.start),
      semanticIndexRef("array", args.end),
      semanticLengthRef("array", args.result_length)
    );
  } else if (api === "Array.prototype.join") {
    refs.push(
      semanticLengthRef("array", args.length),
      semanticLengthRef("separator", args.separator_length),
      semanticLengthRef("string", args.result_length)
    );
  } else if (api === "URLSearchParams.set" || api === "URLSearchParams.append") {
    refs.push(
      semanticStringLengthRef(args.value),
      normalizeRuntimeValueRef(args.value_ref)
    );
  } else if (api === "URLSearchParams.toString") {
    refs.push(
      semanticStringLengthRef(args.serialized),
      normalizeRuntimeValueRef(args.serialized_ref),
      normalizeRuntimeValueRef(args.result_ref)
    );
  } else if (api === "URL.href.set" || api === "URL.href.get") {
    refs.push(
      semanticStringLengthRef(args.value),
      semanticStringLengthRef(args.href),
      normalizeRuntimeValueRef(args.value_ref),
      normalizeRuntimeValueRef(args.href_ref)
    );
  } else if (api === "URL.search.set" || api === "URL.search.get") {
    refs.push(
      semanticStringLengthRef(args.value),
      semanticStringLengthRef(args.search),
      semanticStringLengthRef(args.href),
      normalizeRuntimeValueRef(args.value_ref),
      normalizeRuntimeValueRef(args.search_ref),
      normalizeRuntimeValueRef(args.href_ref)
    );
  }

  return uniqueLimited(refs.filter(Boolean), 8);
}

function valueRefsForEvents(events, matcher, options = {}) {
  return compactGenerationValueRefs(
    (events || [])
      .filter((event) => matcher(event.api || ""))
      .flatMap((event) => [
        ...urlsFromEvent(event).flatMap(({parsed}) => urlValueRefsForParsedUrl(parsed)),
        ...semanticValueRefsForEvent(event),
        ...extractStringLengthRefsFromValue(event.args || []),
        ...extractStringLengthRefsFromValue(event.result || []),
        ...extractRuntimeValueRefsFromValue(event.args || []),
        ...extractRuntimeValueRefsFromValue(event.result || []),
        ...extractRuntimeSourceRefsFromValue(event.args || []),
        ...extractRuntimeSourceRefsFromValue(event.result || [])
      ]),
    32,
    options
  );
}

function isRuntimeValueRefKey(key) {
  const normalized = String(key || "").toLowerCase();
  if (!/(?:^|_)refs?$/.test(normalized)) return false;
  if (normalized === "object_refs" || normalized === "source_refs") return false;
  if (/^(?:left|right|x|y|value|result)_(?:source|register)_ref$/.test(normalized)) return true;
  if (normalized.includes("source") || normalized.includes("asset") ||
      normalized.includes("stack") || normalized.includes("script") ||
      normalized.includes("path")) {
    return false;
  }
  return normalized === "value_refs" || normalized.endsWith("_ref") ||
    normalized.endsWith("_refs");
}

function normalizeRuntimeValueRef(value) {
  if (value === null || value === undefined) return "";
  const text = preserveSignatureText(String(value));
  if (!text || text === "0" || text === "[object Object]") return "";
  if (text.length <= MAX_RUNTIME_VALUE_REF_CHARS) return text;
  return `value_ref_sha1:${sha1Hex(text)}`;
}

function extractRuntimeValueRefsFromValue(value, output = [], depth = 0, key = "") {
  if (depth > 5 || value === null || value === undefined) return output;
  if (isRuntimeValueRefKey(key)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        const ref = normalizeRuntimeValueRef(item);
        if (ref) output.push(ref);
      }
      return output;
    }
    const ref = normalizeRuntimeValueRef(value);
    if (ref) output.push(ref);
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) extractRuntimeValueRefsFromValue(item, output, depth + 1);
    return output;
  }
  if (typeof value !== "object") return output;
  for (const [childKey, childValue] of Object.entries(value)) {
    extractRuntimeValueRefsFromValue(childValue, output, depth + 1, childKey);
  }
  return output;
}

function numericRuntimeObjectId(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

function urlMaterialRefsFromEvent(event) {
  const api = event?.api || "";
  const args = eventSemanticArgsObject(event);
  const refs = [];
  const addRefs = (...values) => {
    for (const value of values) {
      const ref = normalizeRuntimeValueRef(value);
      if (ref && isStrongRuntimeDataValueRef(ref)) refs.push(ref);
    }
  };

  if (api === "URLSearchParams.toString" ||
      api === "URLSearchParams.sort" ||
      api === "URLSearchParams.append" ||
      api === "URLSearchParams.set" ||
      api.startsWith("URLSearchParams.delete")) {
    addRefs(args.serialized_ref, args.result_ref);
  } else if (api === "URL.search.set" || api === "URL.search.get") {
    addRefs(args.search_ref, args.href_ref, args.result_ref);
  } else if (api === "URL.constructor") {
    addRefs(args.href_ref, args.url_ref, args.base_ref, args.result_ref);
  } else if (api === "URL.href.set" || api === "URL.href.get") {
    addRefs(args.href_ref, args.url_ref, args.result_ref);
  } else if (api === "Request.constructor" || api === "fetch" ||
      api === "BrowserNetwork.request" || api.startsWith("XMLHttpRequest.")) {
    addRefs(args.url_ref, args.href_ref, args.request_url_ref);
    if (Array.isArray(args.inherited_url_value_refs)) {
      addRefs(...args.inherited_url_value_refs);
    }
  }

  return uniquePrioritizedLimited(refs, 8, generationPathValueRefRank);
}

function urlObjectIdsForEvent(event) {
  const args = eventSemanticArgsObject(event);
  return {
    urlObjectId: numericRuntimeObjectId(args.url_object_id),
    searchParamsId: numericRuntimeObjectId(args.search_params_id)
  };
}

function isRequestBoundaryEvent(event) {
  const api = event?.api || "";
  return api === "Request.constructor" || api === "fetch" ||
    api === "BrowserNetwork.request" || api.startsWith("XMLHttpRequest.");
}

function cloneEventWithInheritedUrlValueRefs(event, inheritedRefs) {
  if (!inheritedRefs.length) return event;
  const args = Array.isArray(event.args) ? [...event.args] : [{}];
  const first = args[0] && typeof args[0] === "object" && !Array.isArray(args[0])
    ? {...args[0]}
    : {};
  const existingRefs = Array.isArray(first.inherited_url_value_refs)
    ? first.inherited_url_value_refs.map(normalizeRuntimeValueRef).filter(Boolean)
    : [];
  first.inherited_url_value_refs = uniquePrioritizedLimited(
    [...existingRefs, ...inheritedRefs],
    8,
    generationPathValueRefRank
  );
  args[0] = first;
  return {...event, args};
}

function eventsWithInheritedUrlMaterialRefs(events) {
  const refsByUrlObject = new Map();
  const refsBySearchParams = new Map();
  const enriched = [];

  for (const event of events || []) {
    const {urlObjectId, searchParamsId} = urlObjectIdsForEvent(event);
    const inheritedRefs = isRequestBoundaryEvent(event)
      ? uniquePrioritizedLimited([
        ...(urlObjectId ? refsByUrlObject.get(urlObjectId) || [] : []),
        ...(searchParamsId ? refsBySearchParams.get(searchParamsId) || [] : [])
      ], 8, generationPathValueRefRank)
      : [];
    const nextEvent = cloneEventWithInheritedUrlValueRefs(event, inheritedRefs);
    const materialRefs = urlMaterialRefsFromEvent(nextEvent);

    if (materialRefs.length) {
      if (urlObjectId) {
        refsByUrlObject.set(urlObjectId, uniquePrioritizedLimited([
          ...(refsByUrlObject.get(urlObjectId) || []),
          ...materialRefs
        ], 8, generationPathValueRefRank));
      }
      if (searchParamsId) {
        refsBySearchParams.set(searchParamsId, uniquePrioritizedLimited([
          ...(refsBySearchParams.get(searchParamsId) || []),
          ...materialRefs
        ], 8, generationPathValueRefRank));
      }
    }

    enriched.push(nextEvent);
  }

  return enriched;
}

function isRuntimeSourceLinkRefKey(key) {
  const normalized = String(key || "").toLowerCase();
  return /^(?:left|right|x|y|value|result)_source_ref$/.test(normalized) ||
    normalized === "handler_arg_ref";
}

function extractRuntimeSourceRefsFromValue(value, output = [], depth = 0, key = "") {
  if (depth > 5 || value === null || value === undefined) return output;
  if (isRuntimeSourceLinkRefKey(key)) {
    const ref = normalizeRuntimeValueRef(value);
    if (ref) output.push(ref);
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) extractRuntimeSourceRefsFromValue(item, output, depth + 1);
    return output;
  }
  if (typeof value !== "object") return output;
  for (const [childKey, childValue] of Object.entries(value)) {
    extractRuntimeSourceRefsFromValue(childValue, output, depth + 1, childKey);
  }
  return output;
}

function firstEventArgsObject(event) {
  const args = Array.isArray(event?.args) ? event.args[0] : null;
  return args && typeof args === "object" ? args : {};
}

function isVmpScalarRefApi(api) {
  const family = vmpFamilyForApi(api);
  return api === "Math.imul" || family === "int_bitwise" || family === "int_arithmetic";
}

function normalizeVmpScalarRef(value) {
  const ref = normalizeRuntimeValueRef(value);
  if (!ref) return "";
  if (["other", "unknown", "undefined", "null", "nan"].includes(ref.toLowerCase())) return "";
  return ref;
}

function vmpScalarSourceContextForEvent(event) {
  const frame = (event?.stack || []).find((item) => item?.asset_id && Number.isFinite(item.line));
  if (!frame) return null;
  return {
    asset_id: frame.asset_id || "",
    url: frame.url || event?.frame_url || event?.origin || "",
    function: frame.function || "",
    line_start: frame.line,
    line_end: frame.line
  };
}

function vmpScalarRefStepForEvent(event, fallbackIndex = 0) {
  if (!isVmpScalarRefApi(event?.api || "")) return null;
  const args = firstEventArgsObject(event);
  const resultRef = normalizeVmpScalarRef(args.result_ref);
  if (!resultRef) return null;
  const outputRefs = uniqueLimited([
    resultRef,
    normalizeVmpScalarRef(args.result_source_ref),
    normalizeVmpScalarRef(args.result_register_ref)
  ].filter(Boolean), 6);
  const inputRefs = uniqueLimited([
    normalizeVmpScalarRef(args.left_ref),
    normalizeVmpScalarRef(args.left_source_ref),
    normalizeVmpScalarRef(args.left_register_ref),
    normalizeVmpScalarRef(args.right_ref),
    normalizeVmpScalarRef(args.right_source_ref),
    normalizeVmpScalarRef(args.right_register_ref),
    normalizeVmpScalarRef(args.x_ref),
    normalizeVmpScalarRef(args.x_source_ref),
    normalizeVmpScalarRef(args.x_register_ref),
    normalizeVmpScalarRef(args.y_ref),
    normalizeVmpScalarRef(args.y_source_ref),
    normalizeVmpScalarRef(args.y_register_ref),
    normalizeVmpScalarRef(args.value_ref),
    normalizeVmpScalarRef(args.value_source_ref),
    normalizeVmpScalarRef(args.value_register_ref)
  ].filter(Boolean), 6);
  if (!inputRefs.length) return null;
  const sourceContext = vmpScalarSourceContextForEvent(event);
  return {
    seq: Number.isFinite(event?.seq) ? event.seq : null,
    trace_index: traceIndexValue(event, fallbackIndex),
    api: event.api || "unknown",
    input_refs: inputRefs,
    result_ref: resultRef,
    ...(outputRefs.some((ref) => ref !== resultRef) ? {output_refs: outputRefs} : {}),
    ...(sourceContext ? {
      source_context_refs: [sourceContextKey(sourceContext)],
      source_contexts: [sourceContext]
    } : {})
  };
}

const MAX_VMP_SCALAR_CHAIN_STORED_STEPS = 64;
const MAX_VMP_SCALAR_CHAIN_SCORE_STEPS = 64;
const MAX_VMP_SCALAR_TOP_CHAINS = 128;
const MAX_VMP_SCALAR_RECENT_STRUCTURED_CHAINS = 64;

function scalarChainStepCount(chain) {
  return chain?.step_count ?? (chain?.steps || []).length;
}

function scalarChainScore(chain) {
  return Math.min(scalarChainStepCount(chain), MAX_VMP_SCALAR_CHAIN_SCORE_STEPS) * 1000000 +
    (chain?.updated_at ?? 0);
}

function appendScalarChainStep(parentSteps, step) {
  const nextSteps = [...(parentSteps || []), step];
  if (nextSteps.length <= MAX_VMP_SCALAR_CHAIN_STORED_STEPS) return nextSteps;
  return nextSteps.slice(-MAX_VMP_SCALAR_CHAIN_STORED_STEPS);
}

function scalarStepKey(step) {
  return `${step.trace_index ?? "?"}:${step.seq ?? "?"}:${step.api}:${step.result_ref}`;
}

function isStrictPrefixScalarChain(chain, candidateLongerChain) {
  const steps = chain?.steps || [];
  const longerSteps = candidateLongerChain?.steps || [];
  if (!steps.length || longerSteps.length <= steps.length) return false;
  return steps.every((step, index) => scalarStepKey(step) === scalarStepKey(longerSteps[index]));
}

function numericValueForScalarRef(ref) {
  const match = /^number:([-+]?(?:\d+\.?\d*|\.\d+))/.exec(String(ref || ""));
  return match ? Number(match[1]) : null;
}

function numericPayloadForScalarRef(ref) {
  const match = /(?:^|\/)number:([-+]?(?:\d+\.?\d*|\.\d+))/.exec(String(ref || ""));
  return match ? Number(match[1]) : null;
}

function isZeroScalarCarrierRef(ref) {
  const value = numericPayloadForScalarRef(ref);
  return value === 0;
}

function scalarCarrierRefsForStep(step) {
  return uniqueLimited([
    step?.result_ref || "",
    ...(step?.output_refs || [])
  ].filter((ref) => ref && !isZeroScalarCarrierRef(ref)), 8);
}

function structuredScalarOutputRefsForStep(step) {
  return uniqueLimited((step?.output_refs || [])
    .filter((ref) => /^(?:register|handler_arg|handler_return):/.test(String(ref || ""))), 8);
}

function scalarChainStructuredOutputRefs(chain) {
  return uniqueLimited((chain?.steps || [])
    .flatMap((step) => structuredScalarOutputRefsForStep(step)), 16);
}

function sourceContextsForScalarChain(chain) {
  const contexts = [];
  const seen = new Set();
  for (const step of chain?.steps || []) {
    for (const context of step.source_contexts || []) {
      const key = sourceContextKey(context);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      contexts.push(context);
      if (contexts.length >= SOURCE_CONTEXTS_PER_WINDOW) return contexts;
    }
  }
  return contexts;
}

function qualityForVmpScalarChain(chain) {
  const steps = chain?.steps || [];
  const stepCount = scalarChainStepCount(chain);
  const apis = new Set(steps.map((step) => step.api || ""));
  const refs = uniqueLimited(steps.flatMap((step) => [
    ...(step.input_refs || []),
    step.result_ref,
    ...(step.output_refs || [])
  ]), 64);
  const structuredOutputRefs = scalarChainStructuredOutputRefs(chain);
  const numericRefs = refs
    .map(numericValueForScalarRef)
    .filter((value) => value !== null && Number.isFinite(value));
  const sourceContexts = sourceContextsForScalarChain(chain);
  const reasons = [];
  let score = Math.min(stepCount, MAX_VMP_SCALAR_CHAIN_SCORE_STEPS) * 5 + refs.length * 3;

  if (apis.has("Bitwise.xor")) {
    score += 180;
    reasons.push("xor_mixing");
  }
  if (apis.has("Math.imul")) {
    score += 220;
    reasons.push("integer_multiply");
  }
  if (apis.has("Shift.unsignedRight")) {
    score += 160;
    reasons.push("unsigned_shift");
  }
  if (apis.has("Bitwise.xor") && apis.has("Math.imul") && apis.has("Shift.unsignedRight")) {
    score += 420;
    reasons.push("multiply_xor_unsigned_shift");
  }
  const highMagnitudeCount = numericRefs.filter((value) => Math.abs(value) > 1024).length;
  if (highMagnitudeCount) {
    score += Math.min(highMagnitudeCount, 12) * 12;
    reasons.push("high_magnitude_scalar_refs");
  }
  if (sourceContexts.length) {
    score += 120;
    reasons.push("source_context");
  }
  if (sourceContexts.some((context) =>
    /(?:signature|security|risk|fingerprint|sensor|challenge|captcha|waf|sdk|vmp|vm)/i
      .test(`${context.url || ""} ${context.asset_id || ""}`))) {
    score += 120;
    reasons.push("core_security_sdk_stack");
  }
  if (structuredOutputRefs.length) {
    score += Math.min(structuredOutputRefs.length, 8) * 80;
    reasons.push("structured_output_ref");
  }
  if (structuredOutputRefs.some((ref) => /string:length:\d+/.test(ref))) {
    score += 180;
    reasons.push("string_length_register_output");
  }
  const lowConstantPalette = numericRefs.length > 0 &&
    refs.length <= 5 &&
    numericRefs.every((value) => Math.abs(value) <= 32);
  if (lowConstantPalette && !apis.has("Math.imul") && !apis.has("Bitwise.xor") && !apis.has("Shift.unsignedRight")) {
    score -= 260;
    reasons.push("low_constant_palette");
  }

  return {
    score,
    reasons: uniqueLimited(reasons, 8),
    sourceContexts
  };
}

function buildVmpScalarRefChains(events) {
  const steps = (events || [])
    .map((event, index) => vmpScalarRefStepForEvent(event, index))
    .filter(Boolean)
    .sort((a, b) =>
      (a.trace_index ?? 0) - (b.trace_index ?? 0) ||
      (a.seq ?? 0) - (b.seq ?? 0) ||
      String(a.api).localeCompare(String(b.api))
    );
  const chains = [];
  const chainsByLastRef = new Map();
  const extendedChains = new Set();

  for (const step of steps) {
    let parent = null;
    for (const ref of (step.input_refs || []).filter((inputRef) => !isZeroScalarCarrierRef(inputRef))) {
      const candidate = chainsByLastRef.get(ref);
      if (!candidate) continue;
      if (!parent || scalarChainScore(candidate) > scalarChainScore(parent)) {
        parent = candidate;
      }
    }

    const nextChain = parent ? {
      steps: appendScalarChainStep(parent.steps, step),
      updated_at: step.trace_index ?? step.seq ?? 0,
      step_count: scalarChainStepCount(parent) + 1,
      seq_start: parent.seq_start ?? parent.steps?.[0]?.seq ?? null,
      trace_start: parent.trace_start ?? parent.steps?.[0]?.trace_index ?? null,
      seq_end: step.seq ?? parent.seq_end ?? null,
      trace_end: step.trace_index ?? parent.trace_end ?? null
    } : {
      steps: [step],
      updated_at: step.trace_index ?? step.seq ?? 0,
      step_count: 1,
      seq_start: step.seq ?? null,
      trace_start: step.trace_index ?? null,
      seq_end: step.seq ?? null,
      trace_end: step.trace_index ?? null
    };
    if (parent) extendedChains.add(parent);
    chains.push(nextChain);
    for (const ref of scalarCarrierRefsForStep(step)) {
      chainsByLastRef.set(ref, nextChain);
    }
  }

  const maximalChains = chains
    .filter((chain) => scalarChainStepCount(chain) >= 2 || scalarChainStructuredOutputRefs(chain).length)
    .filter((chain) => !extendedChains.has(chain));

  const rankedChains = maximalChains.map((chain) => ({
    chain,
    quality: qualityForVmpScalarChain(chain)
  }));

  const sortedByQuality = rankedChains
    .slice()
    .sort((a, b) =>
      b.quality.score - a.quality.score ||
      scalarChainStepCount(b.chain) - scalarChainStepCount(a.chain) ||
      (a.chain.steps[0]?.trace_index ?? 0) - (b.chain.steps[0]?.trace_index ?? 0) ||
      (a.chain.steps[0]?.seq ?? 0) - (b.chain.steps[0]?.seq ?? 0)
    );
  const recentStructured = rankedChains
    .filter(({chain}) => scalarChainStructuredOutputRefs(chain).length)
    .sort((a, b) =>
      (b.chain.trace_end ?? b.chain.updated_at ?? 0) - (a.chain.trace_end ?? a.chain.updated_at ?? 0) ||
      b.quality.score - a.quality.score
    )
    .slice(0, MAX_VMP_SCALAR_RECENT_STRUCTURED_CHAINS);
  const selected = [];
  const seenSelected = new Set();
  for (const item of [
    ...sortedByQuality.slice(0, MAX_VMP_SCALAR_TOP_CHAINS),
    ...recentStructured
  ]) {
    const key = (item.chain.steps || []).map((step) => scalarStepKey(step)).join("\u0001");
    if (seenSelected.has(key)) continue;
    seenSelected.add(key);
    selected.push(item);
  }

  return selected
    .map(({chain, quality}, index) => {
      const chainSteps = chain.steps.slice(-24);
      const seqRange = {
        seq_start: chain.seq_start ?? seqRangeForEvents(chainSteps).seq_start,
        seq_end: chain.seq_end ?? seqRangeForEvents(chainSteps).seq_end
      };
      const traceRange = {
        trace_start: chain.trace_start ?? traceRangeForEvents(chainSteps).trace_start,
        trace_end: chain.trace_end ?? traceRangeForEvents(chainSteps).trace_end
      };
      const sourceContextRefs = sourceContextRefsForContexts(quality.sourceContexts);
      return {
        id: `vmp_scalar_chain_${index + 1}`,
        relation: "scalar_ref_flow",
        ...seqRange,
        ...traceRange,
        step_count: scalarChainStepCount(chain),
        quality_score: quality.score,
        quality_reasons: quality.reasons,
        source_context_refs: sourceContextRefs,
        source_contexts: sourceContextsForMaterialFlow(quality.sourceContexts),
        apis: uniqueLimited(chain.steps.map((step) => step.api), 12),
        refs: uniqueLimited(chain.steps.flatMap((step) => [
          ...(step.input_refs || []),
          step.result_ref,
          ...(step.output_refs || [])
        ]), 16),
        steps: chainSteps
      };
    });
}

function confidenceRank(confidence) {
  if (confidence === "high") return 3;
  if (confidence === "medium") return 2;
  if (confidence === "low") return 1;
  return 0;
}

function sharedValueRefs(leftRefs, rightRefs, limit = 12) {
  const right = new Set(rightRefs || []);
  return uniquePrioritizedLimited(
    (leftRefs || []).filter((ref) => right.has(ref)),
    limit,
    (ref) => {
      const value = String(ref || "");
      if (/^register:string:length:\d+/.test(value)) return 0;
      if (/^handler_(?:arg|return):/.test(value)) return 1;
      if (/^register:/.test(value)) return 2;
      return 5;
    }
  );
}

function scalarStepRefsForLink(step) {
  return [
    ...(step?.input_refs || []),
    step?.result_ref || "",
    ...(step?.output_refs || [])
  ].filter(Boolean);
}

function scalarChainRefsForLink(chain) {
  return uniqueLimited([
    ...scalarChainStructuredOutputRefs(chain),
    ...(chain?.refs || []),
    ...(chain?.steps || []).flatMap((step) => scalarStepRefsForLink(step))
  ], 64);
}

function scalarOperationTraceForChain(chain, limit = 8) {
  return (chain?.steps || [])
    .slice(-limit)
    .map((step) => {
      const resultRef = step?.result_ref || "";
      const outputRefs = uniqueLimited([
        step?.result_ref || "",
        ...(step?.output_refs || [])
      ].filter(Boolean), 6);
      return {
        seq: Number.isFinite(step?.seq) ? step.seq : null,
        trace_index: Number.isFinite(step?.trace_index) ? step.trace_index : null,
        api: step?.api || "unknown",
        input_refs: uniqueLimited(step?.input_refs || [], 6),
        result_ref: resultRef,
        ...(outputRefs.some((ref) => ref !== resultRef) ? {output_refs: outputRefs} : {}),
        source_context_refs: uniqueLimited(step?.source_context_refs || [], 4)
      };
    });
}

function scalarChainLinkForStage(stage, chain) {
  const sharedRefs = sharedValueRefs(stage?.value_refs || [], scalarChainRefsForLink(chain), 12);
  if (!sharedRefs.length) return null;
  const qualityReasons = chain?.quality_reasons || [];
  if (qualityReasons.includes("low_constant_palette") &&
      !qualityReasons.includes("multiply_xor_unsigned_shift")) {
    return null;
  }
  const confidence = stage?.stage === "integer_mixing" && sharedRefs.length >= 2 ? "high" : "medium";
  return {
    chain_id: chain.id || "",
    stage: stage?.stage || "unknown",
    relation: "shared_value_ref",
    confidence,
    shared_refs: sharedRefs,
    apis: uniqueLimited(chain.apis || [], 8),
    quality_score: chain.quality_score ?? 0,
    quality_reasons: uniqueLimited(qualityReasons, 8),
    source_context_refs: uniqueLimited(chain.source_context_refs || [], 8),
    seq_start: chain.seq_start ?? null,
    seq_end: chain.seq_end ?? null,
    trace_start: chain.trace_start ?? null,
    trace_end: chain.trace_end ?? null,
    step_count: chain.step_count ?? (chain.steps || []).length,
    operation_trace: scalarOperationTraceForChain(chain)
  };
}

function scalarChainLinkEquivalenceKey(link) {
  return [
    link?.stage || "unknown",
    [...(link?.shared_refs || [])].sort().join("\u0001")
  ].join("\u0000");
}

function structuredSharedRefScore(refs) {
  return (refs || []).reduce((score, ref) => {
    const value = String(ref || "");
    if (/^register:string:length:\d+/.test(value)) return score + 100;
    if (/^register:/.test(value)) return score + 75;
    if (/^handler_(?:arg|return):/.test(value)) return score + 50;
    return score;
  }, 0);
}

function scalarChainLinksForMaterialFlow(flow, scalarChains) {
  const stages = (flow.stages || [])
    .filter((stage) => (stage.value_refs || []).length)
    .sort((left, right) => {
      const leftPriority = left.stage === "integer_mixing" ? 0 : 1;
      const rightPriority = right.stage === "integer_mixing" ? 0 : 1;
      return leftPriority - rightPriority || String(left.stage).localeCompare(String(right.stage));
    });
  const links = [];
  const seen = new Set();
  for (const chain of scalarChains || []) {
    for (const stage of stages) {
      const link = scalarChainLinkForStage(stage, chain);
      if (!link) continue;
      const key = `${link.chain_id}\u0000${link.stage}`;
      if (seen.has(key)) continue;
      seen.add(key);
      links.push(link);
      break;
    }
  }
  const ranked = links.sort((a, b) =>
      confidenceRank(b.confidence) - confidenceRank(a.confidence) ||
      structuredSharedRefScore(b.shared_refs) - structuredSharedRefScore(a.shared_refs) ||
      (b.shared_refs || []).length - (a.shared_refs || []).length ||
      (b.quality_score || 0) - (a.quality_score || 0) ||
      String(a.chain_id).localeCompare(String(b.chain_id))
    );
  const deduped = [];
  const seenEquivalent = new Set();
  for (const link of ranked) {
    const key = scalarChainLinkEquivalenceKey(link);
    if (seenEquivalent.has(key)) continue;
    seenEquivalent.add(key);
    deduped.push(link);
  }
  return deduped.slice(0, 6);
}

function sourceAnalysesForCluster(cluster) {
  return [...cluster.sourceContexts.values()]
    .map((context) => context.analysis)
    .filter(Boolean);
}

function unionAnalysisValues(analyses, field, filterFn = () => true, limit = 12) {
  return uniqueLimited(
    analyses.flatMap((analysis) => analysis?.[field] || []).filter(filterFn),
    limit
  );
}

function apisForStage(apis, matcher) {
  return uniqueLimited((apis || []).filter(matcher), 12);
}

function apisForEvents(events) {
  return uniqueLimited((events || []).map((event) => event?.api || "").filter(Boolean), 12);
}

function callsForStage(analyses, matcher) {
  return unionAnalysisValues(analyses, "calls", matcher, 12);
}

function signalsForStage(analyses, allowed) {
  const allowedSet = new Set(allowed);
  return unionAnalysisValues(analyses, "signals", (signal) => allowedSet.has(signal), 12);
}

function isDynamicDispatchSourceCall(call) {
  return /^(?:Reflect\.apply|Function\.prototype\.(?:call|apply)(?:\.(?:call|apply))?|[A-Za-z_$][\w$]*(?:handler|dispatch)[A-Za-z_$\w]*(?:\.[A-Za-z_$][\w$]*){0,3}\.(?:call|apply))$/i.test(call);
}

function seqRangeForEvents(events) {
  const seqs = (events || [])
    .map((event) => event?.seq)
    .filter(Number.isFinite);
  if (!seqs.length) return {};
  return {
    seq_start: Math.min(...seqs),
    seq_end: Math.max(...seqs)
  };
}

function explicitTraceIndexValue(event) {
  if (Number.isFinite(event?._trace_index)) return event._trace_index;
  if (Number.isFinite(event?._file_index)) return event._file_index;
  if (Number.isFinite(event?.trace_index)) return event.trace_index;
  if (Number.isFinite(event?.global_seq)) return event.global_seq;
  return null;
}

function traceRangeForEvents(events) {
  const traceIndexes = (events || [])
    .map(explicitTraceIndexValue)
    .filter(Number.isFinite);
  if (!traceIndexes.length) return {};
  return {
    trace_start: Math.min(...traceIndexes),
    trace_end: Math.max(...traceIndexes)
  };
}

function firstStackAssetId(event) {
  const frame = (event?.stack || []).find((item) => item?.asset_id);
  return frame?.asset_id || event?.asset_id || "";
}

function runtimeEventRefId(event) {
  const api = event?.api || "unknown";
  if (Number.isFinite(event?.seq)) return `seq:${event.seq}:${api}`;
  const traceIndex = explicitTraceIndexValue(event);
  if (Number.isFinite(traceIndex)) return `trace:${traceIndex}:${api}`;
  if (event?.event_id) return `event:${event.event_id}:${api}`;
  return `event:${sha1Hex(JSON.stringify({
    api,
    category: event?.category || "",
    phase: event?.phase || "",
    stack_url: firstStackUrl(event)
  }))}:${api}`;
}

function compactRuntimeEventRef(event) {
  const traceIndex = explicitTraceIndexValue(event);
  return {
    event_ref: runtimeEventRefId(event),
    seq: Number.isFinite(event?.seq) ? event.seq : null,
    trace_index: Number.isFinite(traceIndex) ? traceIndex : null,
    api: event?.api || "unknown",
    category: event?.category || "",
    phase: event?.phase || "",
    stack_url: firstStackUrl(event) || event?.stack_url || event?.frame_url || event?.origin || "",
    asset_id: firstStackAssetId(event)
  };
}

function compareRuntimeEventRefs(left, right) {
  return (left.trace_index ?? Number.MAX_SAFE_INTEGER) - (right.trace_index ?? Number.MAX_SAFE_INTEGER) ||
    (left.seq ?? Number.MAX_SAFE_INTEGER) - (right.seq ?? Number.MAX_SAFE_INTEGER) ||
    String(left.api || "").localeCompare(String(right.api || "")) ||
    String(left.event_ref || "").localeCompare(String(right.event_ref || ""));
}

function compactRuntimeEventRefs(eventsOrRefs, limit = 12) {
  const byRef = new Map();
  for (const item of eventsOrRefs || []) {
    const ref = item?.event_ref ? item : compactRuntimeEventRef(item);
    if (!ref.event_ref || byRef.has(ref.event_ref)) continue;
    byRef.set(ref.event_ref, ref);
  }
  return [...byRef.values()].sort(compareRuntimeEventRefs).slice(0, limit);
}

function buildPipelineStage(
  stage,
  runtimeApis,
  sourceCalls,
  sourceSignals,
  sourceOperators = [],
  sourceConstants = [],
  objectRefs = [],
  sourceContextRefs = [],
  valueRefs = [],
  events = []
) {
  const seqRange = seqRangeForEvents(events);
  const traceRange = traceRangeForEvents(events);
  return {
    stage,
    ...seqRange,
    ...traceRange,
    runtime_apis: uniqueLimited(runtimeApis, 12),
    source_calls: uniqueLimited(sourceCalls, 12),
    source_signals: uniqueLimited(sourceSignals, 12),
    source_operators: uniqueLimited(sourceOperators, 12),
    source_constants: uniqueLimited(sourceConstants, 12),
    object_refs: uniqueLimited(objectRefs, 16),
    source_context_refs: uniqueLimited(sourceContextRefs, 16),
    value_refs: compactGenerationValueRefs(valueRefs, 32, {preserveVmpStateRefs: stage === "dynamic_dispatch"}),
    runtime_event_refs: compactRuntimeEventRefs(events, 12)
  };
}

function sourceOnlyDynamicDispatchStage(contexts) {
  const analyses = (contexts || [])
    .map((context) => context.analysis)
    .filter(Boolean);
  const sourceCalls = callsForStage(analyses, isDynamicDispatchSourceCall);
  const sourceSignals = signalsForStage(analyses, ["prototype_call", "dynamic_dispatch"]);
  if (!sourceCalls.length && !sourceSignals.includes("dynamic_dispatch")) return null;
  return buildPipelineStage(
    "dynamic_dispatch",
    [],
    sourceCalls,
    sourceSignals,
    [],
    [],
    [],
    sourceContextRefsForContexts(contexts),
    [],
    []
  );
}

function sourceOnlyMaterialStagesForAssets(assetIds, assetSourcesById) {
  const contexts = dynamicDispatchSourceContextsForAssets(assetIds, assetSourcesById);
  const stage = sourceOnlyDynamicDispatchStage(contexts);
  return {
    stages: stage ? [stage] : [],
    contexts
  };
}

function buildPipelineDataLinks(stages) {
  const links = [];
  for (let i = 0; i < stages.length; i += 1) {
    for (let j = i + 1; j < stages.length; j += 1) {
      const refs = (stages[i].object_refs || []).filter((ref) => (stages[j].object_refs || []).includes(ref));
      let from = stages[i].stage;
      let to = stages[j].stage;
      if (from === "byte_buffer" && to === "text_or_string_decode" &&
          refs.some((ref) => ref.startsWith("array_buffer:") || ref.startsWith("typed_array:"))) {
        from = "text_or_string_decode";
        to = "byte_buffer";
      }
      if (refs.length) {
        links.push({
          from,
          to,
          refs: uniqueLimited(refs, 8)
        });
      }
      const valueRefs = sharedRuntimeValueRefsForDataLink(
        stages[i].value_refs || [],
        stages[j].value_refs || []
      );
      if (valueRefs.length) {
        links.push({
          from,
          to,
          relation: "shared_runtime_value_ref",
          refs: valueRefs
        });
      }
    }
  }
  return limitPipelineDataLinks(links, stages);
}

function sharedRuntimeValueRefsForDataLink(leftRefs, rightRefs) {
  const right = new Set(rightRefs || []);
  return uniquePrioritizedLimited(
    (leftRefs || []).filter((ref) => right.has(ref) && isStrongRuntimeDataValueRef(ref)),
    8,
    generationPathValueRefRank
  );
}

function isStrongRuntimeDataValueRef(ref) {
  const value = String(ref || "");
  if (!value || value.startsWith("target_params:") || value.startsWith("url_shape:")) return false;
  if (/^string:length:\d+$/.test(value)) return false;
  if (/^(?:string_ref|string|url_encoded|base64):/.test(value)) return true;
  if (/^(?:register|handler_arg|handler_return):/.test(value)) return true;
  if (/^(?:byte|typed_array):length:\d+/.test(value)) return true;
  return /(?:^|:)buffer/.test(value);
}

function limitPipelineDataLinks(links, stages) {
  if ((links || []).length <= 12) return links;
  const stagePositions = new Map((stages || []).map((stage, index) => [stage.stage, index]));
  const stageOrderDistance = (link) => Math.abs(
    (MATERIAL_STAGE_ORDER.get(link.to || "") ?? 50) -
    (MATERIAL_STAGE_ORDER.get(link.from || "") ?? 50)
  );
  return [...links]
    .sort((left, right) =>
      stageOrderDistance(left) - stageOrderDistance(right) ||
      (stagePositions.get(left.from) ?? 99) - (stagePositions.get(right.from) ?? 99) ||
      (stagePositions.get(left.to) ?? 99) - (stagePositions.get(right.to) ?? 99) ||
      Number(Boolean(left.relation)) - Number(Boolean(right.relation)) ||
      String(left.from).localeCompare(String(right.from)) ||
      String(left.to).localeCompare(String(right.to)))
    .slice(0, 12);
}

function hasStrongDataLink(dataLinks, from, to) {
  return (dataLinks || []).some((link) => link.from === from && link.to === to);
}

function stageSeqEnd(stage) {
  if (Number.isFinite(stage?.seq_end)) return stage.seq_end;
  if (Number.isFinite(stage?.seq_start)) return stage.seq_start;
  return null;
}

function stageSeqStart(stage) {
  if (Number.isFinite(stage?.seq_start)) return stage.seq_start;
  if (Number.isFinite(stage?.seq_end)) return stage.seq_end;
  return null;
}

function stageSeqRelation(left, right) {
  const leftStart = stageSeqStart(left);
  const leftEnd = stageSeqEnd(left);
  const rightStart = stageSeqStart(right);
  const rightEnd = stageSeqEnd(right);
  const hasLeft = Number.isFinite(leftStart) && Number.isFinite(leftEnd);
  const hasRight = Number.isFinite(rightStart) && Number.isFinite(rightEnd);
  if (!hasLeft || !hasRight) {
    return {
      confidence: "low",
      basis: "source_only_stage",
      seq_ref: null
    };
  }
  if (leftEnd <= rightStart) {
    return {
      confidence: "medium",
      basis: "ordered_runtime_window",
      seq_ref: `seq:${leftEnd}-${rightStart}`
    };
  }
  if (leftStart <= rightEnd && rightStart <= leftEnd) {
    return {
      confidence: "low",
      basis: "overlapping_runtime_window",
      seq_ref: `seq:${leftEnd}-${rightEnd}`
    };
  }
  return null;
}

function sharedStageSourceRefs(left, right) {
  const rightRefs = new Set(right?.source_context_refs || []);
  return uniqueLimited((left?.source_context_refs || []).filter((ref) => rightRefs.has(ref)), 4);
}

function sharedStageValueRefs(left, right) {
  const rightRefs = new Set(right?.value_refs || []);
  const sharedUrlShapes = (left?.value_refs || []).filter((ref) => ref.startsWith("url_shape:") && rightRefs.has(ref));
  if (!sharedUrlShapes.length) return [];
  const sharedTargetParams = (left?.value_refs || []).filter((ref) => ref.startsWith("target_params:") && rightRefs.has(ref));
  return uniqueLimited([...sharedUrlShapes, ...sharedTargetParams], 6);
}

function confidenceRank(confidence) {
  if (confidence === "high") return 3;
  if (confidence === "medium") return 2;
  if (confidence === "low") return 1;
  return 0;
}

function strongerConfidence(left, right) {
  return confidenceRank(left) >= confidenceRank(right) ? left : right;
}

function addInferredDataLink(links, link) {
  const existing = links.find((item) => item.from === link.from && item.to === link.to);
  if (!existing) {
    links.push({
      ...link,
      basis: uniqueLimited(link.basis || [], 8),
      refs: uniqueLimited(link.refs || [], 8)
    });
    return;
  }
  existing.confidence = strongerConfidence(existing.confidence, link.confidence);
  existing.basis = uniqueLimited([...(existing.basis || []), ...(link.basis || [])], 8);
  existing.refs = uniqueLimited([...(existing.refs || []), ...(link.refs || [])], 8);
}

function isMainMaterialStage(stage) {
  return MATERIAL_STAGE_ORDER.has(stage?.stage || "");
}

function buildPipelineInferredDataLinks(stages, dataLinks = []) {
  const orderedStages = (stages || [])
    .filter(isMainMaterialStage)
    .sort((a, b) =>
      materialStageOrder(a) - materialStageOrder(b) ||
      (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
      String(a.stage).localeCompare(String(b.stage)));
  const links = [];

  for (let i = 0; i < orderedStages.length - 1; i += 1) {
    const from = orderedStages[i];
    const to = orderedStages[i + 1];
    if (hasStrongDataLink(dataLinks, from.stage, to.stage)) continue;

    const sharedSources = sharedStageSourceRefs(from, to);
    const relation = sharedSources.length ? stageSeqRelation(from, to) : null;
    if (relation) {
      addInferredDataLink(links, {
        from: from.stage,
        to: to.stage,
        confidence: relation.confidence,
        basis: ["same_source_context", relation.basis],
        refs: [
          ...sharedSources.map((ref) => `source:${ref}`),
          relation.seq_ref
        ].filter(Boolean)
      });
    }

    const sharedValues = sharedStageValueRefs(from, to);
    if (sharedValues.length) {
      addInferredDataLink(links, {
        from: from.stage,
        to: to.stage,
        confidence: "medium",
        basis: ["shared_url_shape", sharedValues.some((ref) => ref.startsWith("target_params:")) ? "target_signature_params" : ""]
          .filter(Boolean),
        refs: sharedValues
      });
    }
  }

  return links.slice(0, 12);
}

function inferredDataLinksForCandidateChain(chain, dataLinks = []) {
  const steps = chain?.steps || [];
  const request = steps.find((step) => step.phase === "request_construction");
  const signed = steps.find((step) => step.phase === "signed_request");
  if (!request || !signed) return [];
  if (hasStrongDataLink(dataLinks, "request_construction", "signed_request")) return [];
  if (!request.endpoint || !signed.endpoint || request.endpoint !== signed.endpoint) return [];
  if (request.method && signed.method && request.method !== signed.method) return [];

  const basis = uniqueLimited([
    "renderer_request_link",
    request.match || "endpoint_method_trace_window",
    request.relation || ""
  ].filter(Boolean), 6);
  const seqOrTrace = request.seq ?? request.trace_index ?? "unknown";
  return [{
    from: "request_construction",
    to: "signed_request",
    confidence: request.confidence || "medium",
    basis,
    refs: [`renderer_request:${request.api || "request"}:${seqOrTrace}`]
  }];
}

function buildCandidateSignaturePipeline(cluster) {
  const runtimeApis = clusterRuntimeApis(cluster);
  const analyses = sourceAnalysesForCluster(cluster);
  const events = cluster.eventSummaries || [];
  const sourceContextRefs = [...cluster.sourceContexts.keys()];
  const stages = [];

  const requestConstructionMatcher = (api) =>
    api === "Request.constructor" || api === "fetch" || api.startsWith("XMLHttpRequest.");
  const requestConstructionStageMatcher = (api) => api === "XMLHttpRequest.open";
  const hasExplicitRequestConstructionStage = cluster.phaseSeq.has("request_construction");
  const requestConstructionEventMatcher = hasExplicitRequestConstructionStage
    ? requestConstructionMatcher
    : requestConstructionStageMatcher;
  const requestConstructionEvents = events.filter((event) => requestConstructionEventMatcher(event.api || ""));
  const requestConstructionApis = apisForStage(runtimeApis, requestConstructionEventMatcher);
  if (hasExplicitRequestConstructionStage || requestConstructionApis.length || requestConstructionEvents.length) {
    stages.push(buildPipelineStage(
      "request_construction",
      uniqueLimited([...requestConstructionApis, ...apisForEvents(requestConstructionEvents)], 12),
      [],
      [],
      [],
      [],
      objectRefsForEvents(events, requestConstructionEventMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, requestConstructionEventMatcher),
      requestConstructionEvents
    ));
  }

  const inputMatcher = (api) => api === "URL.constructor" || api.startsWith("URL.") || api.startsWith("URLSearchParams.");
  const inputApis = apisForStage(runtimeApis, inputMatcher);
  if (inputApis.length || cluster.phaseSeq.has("unsigned_url")) {
    stages.push(buildPipelineStage(
      "input_url",
      inputApis,
      [],
      [],
      [],
      [],
      objectRefsForEvents(events, inputMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, inputMatcher),
      events.filter((event) => inputMatcher(event.api || ""))
    ));
  }

  const byteMatcher = (api) =>
    api.startsWith("DataView.") || api === "ArrayBuffer.constructor" || api.startsWith("TypedArray.");
  const byteApis = apisForStage(runtimeApis, (api) =>
    api.startsWith("DataView.") || api === "ArrayBuffer.constructor" || api.startsWith("TypedArray.")
  );
  const byteCalls = callsForStage(analyses, (call) =>
    /DataView|ArrayBuffer|Uint(?:8|16|32)Array|Int(?:8|16|32)Array|getUint|getInt|setUint|setInt/.test(call)
  );
  const byteSignals = signalsForStage(analyses, ["byte_buffer"]);
  if (byteApis.length || byteCalls.length || byteSignals.length) {
    stages.push(buildPipelineStage(
      "byte_buffer",
      byteApis,
      byteCalls,
      byteSignals,
      [],
      [],
      objectRefsForEvents(events, byteMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, byteMatcher),
      events.filter((event) => byteMatcher(event.api || ""))
    ));
  }

  const jsonMatcher = (api) => api === "JSON.stringify" || api === "JSON.parse";
  const jsonApis = apisForStage(runtimeApis, jsonMatcher);
  const jsonCalls = callsForStage(analyses, (call) => /JSON\.(?:stringify|parse)/.test(call));
  const jsonSignals = signalsForStage(analyses, ["json_serialization"]);
  if (jsonApis.length || jsonCalls.length || jsonSignals.length) {
    stages.push(buildPipelineStage(
      "json_serialization",
      jsonApis,
      jsonCalls,
      jsonSignals,
      [],
      [],
      objectRefsForEvents(events, jsonMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, jsonMatcher),
      events.filter((event) => jsonMatcher(event.api || ""))
    ));
  }

  const requestHeaderMatcher = (api) =>
    api === "XMLHttpRequest.setRequestHeader" || api.startsWith("Headers.");
  const requestHeaderApis = apisForStage(runtimeApis, requestHeaderMatcher);
  const requestHeaderCalls = callsForStage(analyses, (call) =>
    /(?:setRequestHeader|Headers\.(?:append|set|delete)|headers\.(?:append|set|delete))/i.test(call)
  );
  const requestHeaderEvents = events.filter((event) => requestHeaderMatcher(event.api || ""));
  if (requestHeaderApis.length || requestHeaderCalls.length || requestHeaderEvents.length) {
    stages.push(buildPipelineStage(
      "request_headers",
      uniqueLimited([...requestHeaderApis, ...apisForEvents(requestHeaderEvents)], 12),
      requestHeaderCalls,
      [],
      [],
      [],
      objectRefsForEvents(events, requestHeaderMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, requestHeaderMatcher),
      requestHeaderEvents
    ));
  }

  const requestBodyEvents = events.filter(isRequestBodyBoundaryEvent);
  const requestBodyApis = apisForEvents(requestBodyEvents);
  const requestBodyCalls = callsForStage(analyses, (call) =>
    /(?:XMLHttpRequest\.send|xhr\.send|request\.body|body|payload|postData)/i.test(call)
  );
  if (requestBodyApis.length || requestBodyCalls.length) {
    stages.push(buildPipelineStage(
      "request_body",
      requestBodyApis,
      requestBodyCalls,
      [],
      [],
      [],
      objectRefsForEvents(requestBodyEvents, () => true),
      sourceContextRefs,
      valueRefsForEvents(requestBodyEvents, () => true),
      requestBodyEvents
    ));
  }

  const textMatcher = (api) =>
    api === "String.fromCharCode" || api === "String.fromCodePoint" || api === "String.prototype.charCodeAt" ||
    api === "TextEncoder.encode" || api === "TextEncoder.encodeInto" || api === "TextDecoder.decode" ||
    api === "TypedArray.buffer.get" ||
    api === "atob" || api === "btoa";
  const textApis = apisForStage(runtimeApis, textMatcher);
  const textCalls = callsForStage(analyses, (call) =>
    /fromCharCode|fromCodePoint|charCodeAt|TextEncoder|TextDecoder|atob|btoa/.test(call)
  );
  const textSignals = signalsForStage(analyses, ["text_codec"]);
  if (textApis.length || textCalls.length || textSignals.length) {
    stages.push(buildPipelineStage(
      "text_or_string_decode",
      textApis,
      textCalls,
      textSignals,
      [],
      [],
      objectRefsForEvents(events, textMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, textMatcher),
      events.filter((event) => textMatcher(event.api || ""))
    ));
  }

  const stringTransformMatcher = (api) => vmpFamilyForApi(api) === "string_transform";
  const stringTransformApis = apisForStage(runtimeApis, stringTransformMatcher);
  const stringTransformCalls = callsForStage(analyses, (call) =>
    /(?:String\.prototype\.(?:slice|substring|indexOf|includes)|StringAdd|\+ mixed|\+ token)/.test(call)
  );
  const stringTransformSignals = signalsForStage(analyses, ["string_transform"]);
  if (stringTransformApis.length || stringTransformCalls.length || stringTransformSignals.length) {
    stages.push(buildPipelineStage(
      "string_transform",
      stringTransformApis,
      stringTransformCalls,
      stringTransformSignals,
      [],
      [],
      objectRefsForEvents(events, stringTransformMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, stringTransformMatcher),
      events.filter((event) => stringTransformMatcher(event.api || ""))
    ));
  }

  const dynamicDispatchMatcher = (api) => [
    "dynamic_dispatch",
    "array_table",
    "collection_table",
    "proxy_trap"
  ].includes(vmpFamilyForApi(api));
  const dynamicDispatchApis = apisForStage(runtimeApis, dynamicDispatchMatcher);
  const dynamicDispatchCalls = callsForStage(analyses, isDynamicDispatchSourceCall);
  const dynamicDispatchSignals = signalsForStage(analyses, ["prototype_call", "dynamic_dispatch"]);
  if (dynamicDispatchApis.length || dynamicDispatchCalls.length || dynamicDispatchSignals.includes("dynamic_dispatch")) {
    stages.push(buildPipelineStage(
      "dynamic_dispatch",
      dynamicDispatchApis,
      dynamicDispatchCalls,
      dynamicDispatchSignals,
      [],
      [],
      objectRefsForEvents(events, dynamicDispatchMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, dynamicDispatchMatcher, {preserveVmpStateRefs: true}),
      events.filter((event) => dynamicDispatchMatcher(event.api || ""))
    ));
  }

  const integerMatcher = (api) =>
    api === "Math.imul" || api.startsWith("Bitwise.") || api.startsWith("Shift.");
  const integerApis = apisForStage(runtimeApis, (api) =>
    api === "Math.imul" || api.startsWith("Bitwise.") || api.startsWith("Shift.")
  );
  const integerCalls = callsForStage(analyses, (call) => /Math\.imul/.test(call));
  const integerSignals = signalsForStage(analyses, ["int_bitwise", "int_multiply", "int_arithmetic"]);
  const integerOperators = unionAnalysisValues(analyses, "operators", (op) => ["^", ">>>", ">>", "<<", "&", "|", "~"].includes(op), 12);
  const integerConstants = unionAnalysisValues(analyses, "numeric_literals", () => true, 12);
  if (integerApis.length || integerCalls.length || integerSignals.length || integerOperators.length) {
    stages.push(buildPipelineStage(
      "integer_mixing",
      integerApis,
      integerCalls,
      integerSignals,
      integerOperators,
      integerConstants,
      objectRefsForEvents(events, integerMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, integerMatcher),
      events.filter((event) => integerMatcher(event.api || ""))
    ));
  }

  const hashMatcher = (api) => WEBCRYPTO_SIGNATURE_APIS.has(api);
  const hashApis = apisForStage(runtimeApis, (api) => WEBCRYPTO_SIGNATURE_APIS.has(api));
  const hashCalls = callsForStage(analyses, (call) => /digest|crypto\.subtle\.sign|SubtleCrypto\.sign|importKey|SHA256|sha256|md5|HMAC/i.test(call));
  const hashSignals = signalsForStage(analyses, ["hash_crypto"]);
  if (hashApis.length || hashCalls.length || hashSignals.length) {
    stages.push(buildPipelineStage(
      "hash_or_digest",
      hashApis,
      hashCalls,
      hashSignals,
      [],
      [],
      objectRefsForEvents(events, hashMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, hashMatcher),
      events.filter((event) => hashMatcher(event.api || ""))
    ));
  }

  const hasRequestConstructionStage = cluster.phaseSeq.has("request_construction");
  const signedMatcher = (api) =>
    api === "BrowserNetwork.request" ||
    (!hasRequestConstructionStage && requestConstructionMatcher(api));
  const signedApis = apisForStage(runtimeApis, signedMatcher);
  if (signedApis.length || cluster.phaseSeq.has("signed_request")) {
    stages.push(buildPipelineStage(
      "signed_request",
      signedApis,
      [],
      [],
      [],
      [],
      objectRefsForEvents(events, signedMatcher),
      sourceContextRefs,
      valueRefsForEvents(events, signedMatcher),
      events.filter((event) => signedMatcher(event.api || ""))
    ));
  }

  const confidence = strongestConfidence([
    cluster.confidenceSet.size ? strongestConfidence(cluster.confidenceSet) : "low",
    stages.length >= 3 ? "high" : stages.length >= 2 ? "medium" : "low"
  ]);

  return {
    confidence,
    stage_count: stages.length,
    stages,
    data_links: buildPipelineDataLinks(stages)
  };
}

function addObservedWindowToSubflows(clusters, window) {
  const events = window.events || [];
  if (!events.length) return;
  const byStack = new Map();
  const operationSubflowKeys = new Map();
  for (const event of events) {
    if ((event.phase || event.t || "") === "return") continue;
    const operationId = operationIdForEvent(event);
    if (!operationId) continue;
    operationSubflowKeys.set(operationId, subflowKeyForParts(event));
  }
  for (const event of events) {
    const operationId = operationIdForEvent(event);
    const key = operationSubflowKeys.get(operationId) || subflowKeyForParts(event);
    const bucket = byStack.get(key) || [];
    bucket.push(event);
    byStack.set(key, bucket);
  }

  for (const bucket of byStack.values()) {
    const first = bucket[0];
    const cluster = ensureSubflowCluster(clusters, first);
    mergeClusterSeq(cluster, window.seq_start, window.seq_end);
    addClusterPhase(cluster, window.phase, window.seq_start);
    cluster.evidenceKinds.add("observed");
    addClusterSourceContexts(cluster, window.source_contexts || []);
    addClusterEventSummaries(cluster, bucket);

    const uniqueApis = [...new Set(bucket.map((event) => event.api).filter(Boolean))];
    if (uniqueApis.length === 1 && bucket.length === events.length) {
      addCount(cluster.observedApiCounts, uniqueApis[0], window.event_count || bucket.length);
    } else {
      for (const event of bucket) addCount(cluster.observedApiCounts, event.api, 1);
    }
  }
}

function candidateGroupForPhase(candidateGroups, phase) {
  return (candidateGroups || []).find((group) => group.type === phase.type);
}

function addCandidatePhaseToSubflows(clusters, candidateGroups, phase) {
  const group = candidateGroupForPhase(candidateGroups, phase);
  if (!group) return;
  const candidates = group.candidates || [];
  if (!candidates.length) return;
  const byStack = new Map();
  for (const candidate of candidates) {
    const key = subflowKeyForParts(candidate);
    const bucket = byStack.get(key) || [];
    bucket.push(candidate);
    byStack.set(key, bucket);
  }

  for (const bucket of byStack.values()) {
    const first = bucket[0];
    const cluster = ensureSubflowCluster(clusters, first);
    mergeClusterSeq(cluster, phase.seq_start, phase.seq_end);
    addClusterPhase(cluster, phase.phase, phase.seq_start);
    cluster.evidenceKinds.add("candidate");
    cluster.candidatePhaseCount += 1;
    cluster.confidenceSet.add(phase.confidence || "low");
    for (const candidate of bucket) {
      addCount(cluster.candidateApiCounts, candidate.api, 1);
      addClusterSourceContexts(cluster, candidate.context_window?.source_contexts || []);
      addClusterEventSummaries(cluster, candidate.context_window?.events || []);
    }
  }
}

function evidenceStatusForSubflow(cluster) {
  const hasObserved = cluster.evidenceKinds.has("observed");
  const hasCandidate = cluster.evidenceKinds.has("candidate");
  if (hasObserved && hasCandidate) return "mixed_observed_and_candidate";
  if (hasCandidate) return "candidate_only";
  return "observed_only";
}

function buildSuspectedSignatureSubflows(flow, candidateGroups, candidatePhases) {
  const clusters = new Map();
  for (const window of flow.event_windows || []) {
    addObservedWindowToSubflows(clusters, window);
  }
  for (const phase of candidatePhases || []) {
    addCandidatePhaseToSubflows(clusters, candidateGroups, phase);
  }

  return [...clusters.values()]
    .filter((cluster) => cluster.evidenceKinds.has("candidate") || cluster.phaseSeq.size >= 3)
    .sort((a, b) =>
      Number(b.evidenceKinds.has("candidate")) - Number(a.evidenceKinds.has("candidate")) ||
      (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
      String(a.function).localeCompare(String(b.function)) ||
      String(a.stack_url).localeCompare(String(b.stack_url)))
    .slice(0, 8)
    .map((cluster, index) => ({
      id: `candidate_subflow_${index + 1}`,
      evidence_status: evidenceStatusForSubflow(cluster),
      confidence: strongestConfidence(cluster.confidenceSet.size ? [...cluster.confidenceSet] : ["low"]),
      function: cluster.function,
      stack_url: cluster.stack_url,
      asset_id: cluster.asset_id,
      seq_start: cluster.seq_start,
      seq_end: cluster.seq_end,
      phases: [...cluster.phaseSeq.entries()]
        .sort((a, b) => a[1] - b[1] || String(a[0]).localeCompare(String(b[0])))
        .map(([phase]) => phase),
      observed_apis: sortCountEntries(cluster.observedApiCounts, "api").slice(0, 8),
      candidate_apis: sortCountEntries(cluster.candidateApiCounts, "api").slice(0, 8),
      candidate_phase_count: cluster.candidatePhaseCount,
      source_context_refs: [...cluster.sourceContexts.keys()],
      source_contexts: [...cluster.sourceContexts.values()],
      candidate_signature_pipeline: buildCandidateSignaturePipeline(cluster)
    }));
}

function materialStageForWindow(window) {
  const phase = window?.phase || "";
  if (phase === "unsigned_url") return "input_url";
  if (phase === "url_signature_mutation") return "signature_mutation";
  if (phase === "signed_request") return "signed_request";
  if (phase === "vmp_string_decode") return "text_or_string_decode";
  if (phase === "vmp_bytecode_or_register_access") return "byte_buffer";
  if (phase === "vmp_dynamic_dispatch") return "dynamic_dispatch";
  if (phase === "vmp_int_bitwise_pipeline") return "integer_mixing";
  if (phase === "vmp_anti_debug_timing_gate") return "anti_debug_timing_gate";
  if (phase === "vmp_source_integrity_probe") return "source_integrity_probe";
  if (phase === "vmp_stack_trace_probe") return "stack_trace_probe";
  if (phase === "vmp_exception_control_flow") return "exception_control_flow";
  if (phase === "vmp_string_transform") return "string_transform";
  if (phase === "vmp_regexp_probe") return "regexp_probe";
  if (phase === "vmp_url_encoding_boundary") return "url_encoding";
  if (phase === "vmp_json_serialization") return "json_serialization";
  if (phase === "vmp_hash_or_signature_pipeline") {
    const apis = new Set((window.events || []).map((event) => event.api || ""));
    if ([...apis].some((api) => api === "JSON.stringify" || api === "JSON.parse")) {
      return "json_serialization";
    }
    if ([...apis].some((api) => WEBCRYPTO_SIGNATURE_APIS.has(api))) return "hash_or_digest";
    if ([...apis].some((api) => api === "Math.imul" || api.startsWith("Bitwise.") || api.startsWith("Shift."))) {
      return "integer_mixing";
    }
    return "text_or_string_decode";
  }
  return phase || "context";
}

function stageFromEventWindow(window) {
  const traceRange = traceRangeForEvents(window.events || []);
  const stage = materialStageForWindow(window);
  const keepSourceAnalysis = stage !== "input_url";
  return {
    stage,
    seq_start: window.seq_start ?? null,
    seq_end: window.seq_end ?? null,
    ...traceRange,
    event_count: window.event_count || 0,
    runtime_apis: sortCountEntries(countBy(window.events || [], (event) => event.api || ""), "api")
      .map((entry) => entry.api)
      .filter(Boolean)
      .slice(0, 12),
    source_calls: [],
    source_signals: keepSourceAnalysis ? uniqueLimited(
      (window.source_contexts || []).flatMap((context) => context.analysis?.signals || []),
      12
    ) : [],
    source_operators: keepSourceAnalysis ? uniqueLimited(
      (window.source_contexts || []).flatMap((context) => context.analysis?.operators || []),
      12
    ) : [],
    source_constants: keepSourceAnalysis ? uniqueLimited(
      (window.source_contexts || []).flatMap((context) => context.analysis?.numeric_literals || []),
      12
    ) : [],
    object_refs: objectRefsForEvents(window.events || [], () => true),
    source_context_refs: sourceContextRefsForContexts(window.source_contexts || []),
    value_refs: valueRefsForEvents(window.events || [], () => true),
    runtime_event_refs: compactRuntimeEventRefs(window.events || [], 12)
  };
}

function normalizeMaterialStage(stage) {
  const isDynamicDispatch = stage.stage === "dynamic_dispatch";
  return {
    stage: stage.stage || "unknown",
    ...(stage.seq_start !== undefined ? {seq_start: stage.seq_start} : {}),
    ...(stage.seq_end !== undefined ? {seq_end: stage.seq_end} : {}),
    ...(stage.trace_start !== undefined ? {trace_start: stage.trace_start} : {}),
    ...(stage.trace_end !== undefined ? {trace_end: stage.trace_end} : {}),
    ...(stage.event_count !== undefined ? {event_count: stage.event_count} : {}),
    runtime_apis: uniqueLimited(stage.runtime_apis || [], 12),
    source_calls: uniqueLimited(stage.source_calls || [], 12),
    source_signals: uniqueLimited(stage.source_signals || [], 12),
    source_operators: uniqueLimited(stage.source_operators || [], 12),
    source_constants: uniqueLimited(stage.source_constants || [], 12),
    object_refs: isDynamicDispatch
      ? uniquePrioritizedLimited(stage.object_refs || [], 16, generationPathObjectRefRank)
      : uniqueLimited(stage.object_refs || [], 16),
    source_context_refs: uniqueLimited(stage.source_context_refs || [], 16),
    value_refs: compactGenerationValueRefs(
      stage.value_refs || [],
      32,
      {preserveVmpStateRefs: isDynamicDispatch}
    ),
    runtime_event_refs: compactRuntimeEventRefs(stage.runtime_event_refs || [], 12)
  };
}

const MATERIAL_STAGE_ORDER = new Map([
  ["input_url", 0],
  ["request_construction", 1],
  ["json_serialization", 1.5],
  ["byte_buffer", 2],
  ["dynamic_dispatch", 2.5],
  ["text_or_string_decode", 3],
  ["integer_mixing", 4],
  ["hash_or_digest", 5],
  ["string_transform", 5.4],
  ["url_encoding", 5.7],
  ["signature_mutation", 6],
  ["request_headers", 6.2],
  ["request_body", 6.4],
  ["signed_request", 7]
]);

const GENERATION_PATH_STAGE_ORDER = new Map([
  ["input_url", 0],
  ["json_serialization", 0.5],
  ["byte_buffer", 1],
  ["dynamic_dispatch", 1.5],
  ["text_or_string_decode", 2],
  ["integer_mixing", 3],
  ["hash_or_digest", 4],
  ["string_transform", 5],
  ["url_encoding", 6],
  ["signature_mutation", 7],
  ["request_headers", 7.2],
  ["request_body", 7.4],
  ["request_construction", 8],
  ["signed_request", 9]
]);

function materialStageOrder(stage) {
  return MATERIAL_STAGE_ORDER.get(stage?.stage || "") ?? 50;
}

function generationPathStageOrder(step) {
  return GENERATION_PATH_STAGE_ORDER.get(step?.stage || "") ?? 50;
}

function finiteValues(values) {
  return values.filter(Number.isFinite);
}

function mergeMaterialStage(existing, incoming) {
  const seqStarts = finiteValues([existing.seq_start, incoming.seq_start]);
  const seqEnds = finiteValues([existing.seq_end, incoming.seq_end]);
  const traceStarts = finiteValues([existing.trace_start, incoming.trace_start]);
  const traceEnds = finiteValues([existing.trace_end, incoming.trace_end]);
  return normalizeMaterialStage({
    ...existing,
    seq_start: seqStarts.length ? Math.min(...seqStarts) : existing.seq_start ?? incoming.seq_start,
    seq_end: seqEnds.length ? Math.max(...seqEnds) : existing.seq_end ?? incoming.seq_end,
    trace_start: traceStarts.length ? Math.min(...traceStarts) : existing.trace_start ?? incoming.trace_start,
    trace_end: traceEnds.length ? Math.max(...traceEnds) : existing.trace_end ?? incoming.trace_end,
    event_count: (existing.event_count || 0) + (incoming.event_count || 0),
    runtime_apis: [...(existing.runtime_apis || []), ...(incoming.runtime_apis || [])],
    source_calls: [...(existing.source_calls || []), ...(incoming.source_calls || [])],
    source_signals: [...(existing.source_signals || []), ...(incoming.source_signals || [])],
    source_operators: [...(existing.source_operators || []), ...(incoming.source_operators || [])],
    source_constants: [...(existing.source_constants || []), ...(incoming.source_constants || [])],
    object_refs: [...(existing.object_refs || []), ...(incoming.object_refs || [])],
    source_context_refs: [...(existing.source_context_refs || []), ...(incoming.source_context_refs || [])],
    value_refs: [...(existing.value_refs || []), ...(incoming.value_refs || [])],
    runtime_event_refs: [...(existing.runtime_event_refs || []), ...(incoming.runtime_event_refs || [])]
  });
}

function mergeMaterialStages(primaryStages, additionalStages) {
  const byStage = new Map();
  for (const stage of [...(primaryStages || []), ...(additionalStages || [])].map(normalizeMaterialStage)) {
    const existing = byStage.get(stage.stage);
    byStage.set(stage.stage, existing ? mergeMaterialStage(existing, stage) : stage);
  }
  return [...byStage.values()]
    .sort((a, b) =>
      materialStageOrder(a) - materialStageOrder(b) ||
      (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
      String(a.stage).localeCompare(String(b.stage)));
}

function observedRequestMaterialStages(flow) {
  const phases = new Set([
    "unsigned_url",
    "request_construction",
    "url_signature_mutation",
    "request_headers",
    "request_body",
    "signed_request"
  ]);
  return (flow.event_windows || [])
    .filter((window) => phases.has(window.phase || ""))
    .map(stageFromEventWindow)
    .map(normalizeMaterialStage);
}

function runtimeOnlyMaterialStage(stage) {
  const normalized = normalizeMaterialStage(stage);
  return {
    ...normalized,
    source_calls: [],
    source_signals: [],
    source_operators: [],
    source_constants: [],
    source_context_refs: []
  };
}

function observedVmpMaterialStages(flow) {
  const phases = new Set([
    "vmp_json_serialization",
    "vmp_string_decode",
    "vmp_bytecode_or_register_access",
    "vmp_dynamic_dispatch",
    "vmp_int_bitwise_pipeline",
    "vmp_string_transform",
    "vmp_regexp_probe",
    "vmp_url_encoding_boundary"
  ]);
  return (flow.event_windows || [])
    .filter((window) => phases.has(window.phase || ""))
    .map(stageFromEventWindow)
    .map(runtimeOnlyMaterialStage);
}

function siblingSubflowMaterialStages(flow, selectedSubflow) {
  return (flow.suspected_signature_subflows || [])
    .filter((subflow) => subflow !== selectedSubflow)
    .flatMap((subflow) => subflow.candidate_signature_pipeline?.stages || [])
    .filter((stage) => [
      "json_serialization",
      "byte_buffer",
      "dynamic_dispatch",
      "text_or_string_decode",
      "integer_mixing",
      "hash_or_digest",
      "string_transform",
      "regexp_probe"
    ].includes(stage.stage || ""))
    .map(runtimeOnlyMaterialStage);
}

function uniqueMaterialStages(stages) {
  return uniqueLimited((stages || []).map((stage) => stage.stage || ""), 24);
}

function hasAnyStage(stages, names) {
  const wanted = new Set(names);
  return (stages || []).some((stage) => wanted.has(stage.stage));
}

function materialSourceStageHasEvidence(stage) {
  return Boolean(
    (stage.runtime_apis || []).length ||
    (stage.object_refs || []).length ||
    (stage.value_refs || []).length ||
    (stage.source_context_refs || []).length ||
    (stage.source_calls || []).length ||
    (stage.source_signals || []).length
  );
}

function hasMaterialSourceEvidence(stages) {
  const materialStages = new Set([
    "json_serialization",
    "text_or_string_decode",
    "byte_buffer",
    "string_transform",
    "url_encoding",
    "hash_or_digest"
  ]);
  return (stages || []).some((stage) =>
    materialStages.has(stage.stage || "") && materialSourceStageHasEvidence(stage)
  );
}

function materialFlowReadiness(flow) {
  const stages = flow.stages || [];
  const observedStages = uniqueMaterialStages(stages);
  const dataLinkEvidence = [
    ...(flow.data_links || []),
    ...(flow.inferred_data_links || [])
  ];
  const missingStages = [];
  const evidenceGaps = [];
  const nextActions = [];

  const addGap = (missingStage, gap, action) => {
    if (missingStage && !missingStages.includes(missingStage)) missingStages.push(missingStage);
    if (gap && !evidenceGaps.includes(gap)) evidenceGaps.push(gap);
    if (action && !nextActions.includes(action)) nextActions.push(action);
  };

  if (flow.evidence_status === "signature_absent_candidate") {
    evidenceGaps.push("signature_terms_not_observed");
    nextActions.push("capture_signature_terms_or_mutation");
  }
  if (!hasAnyStage(stages, ["input_url", "request_construction"])) {
    addGap("input_url", "unsigned_input_not_observed", "capture_unsigned_request_construction");
  }
  if (!hasMaterialSourceEvidence(stages)) {
    addGap("material_extraction", "material_source_not_observed", "capture_text_buffer_or_storage_material");
  }
  if (!hasAnyStage(stages, ["integer_mixing", "hash_or_digest"])) {
    addGap("mix_or_hash", "mix_or_hash_not_observed", "capture_hash_or_integer_mixing");
  }
  const hasSignatureAttachment = hasAnyStage(stages, ["signature_mutation"]) ||
    (flow.signature_attachment_events || []).some((event) =>
      ["request_headers", "request_body"].includes(attachmentStageName(event.phase)) &&
      (event.target_params || []).length
    );
  if (!hasSignatureAttachment) {
    addGap("signature_mutation", "signature_mutation_not_observed", "capture_url_search_params_mutation_or_header_set");
  }
  if (!hasAnyStage(stages, ["signed_request"])) {
    addGap("signed_request", "signed_request_not_observed", "capture_browser_network_anchor");
  }
  if (!(flow.source_context_refs || []).length && !(flow.source_contexts || []).length) {
    addGap("", "source_context_not_available", "capture_or_retrieve_script_asset");
  }
  if (!dataLinkEvidence.length) {
    addGap("", "data_links_not_observed", "capture_object_ids_for_data_links");
  }

  const status = flow.evidence_status === "signature_absent_candidate"
    ? "candidate"
    : missingStages.length || evidenceGaps.length
      ? "partial"
      : "strong";

  return {
    status,
    observed_stages: observedStages,
    missing_stages: missingStages,
    evidence_gaps: evidenceGaps,
    next_actions: nextActions.length ? nextActions : ["review_material_flow_source_context"]
  };
}

function stageImpliesVmpHookPoint(stageName, type) {
  if (stageName === "integer_mixing" && type === "vmp_int_bitwise_pipeline") return true;
  return false;
}

function sourceSignalsForHookPoint(stage, type) {
  const signals = stage.source_signals || [];
  if (type === "vmp_dynamic_dispatch") {
    return uniqueLimited(signals.filter((signal) =>
      signal === "prototype_call" || signal === "dynamic_dispatch"
    ), 12);
  }
  return [];
}

function sourceCallsForHookPoint(stage, type) {
  const calls = stage.source_calls || [];
  if (type === "vmp_dynamic_dispatch") {
    return uniqueLimited(calls.filter(isDynamicDispatchSourceCall), 12);
  }
  return [];
}

function materialFlowVmpHookPoints(flow) {
  const stages = flow.stages || [];
  return VMP_HOOK_POINT_SPECS.map((spec) => {
    const observedApis = uniqueLimited(stages.flatMap((stage) =>
      (stage.runtime_apis || []).filter((api) =>
        spec.families.includes(vmpFamilyForApi(api)) ||
        stageImpliesVmpHookPoint(stage.stage, spec.type)
      )
    ), 12);
    const observedStages = uniqueLimited(stages
      .filter((stage) =>
        (stage.runtime_apis || []).some((api) => spec.families.includes(vmpFamilyForApi(api))) ||
        stageImpliesVmpHookPoint(stage.stage, spec.type)
      )
      .map((stage) => stage.stage), 12);
    const sourceStages = uniqueLimited(stages
      .filter((stage) =>
        sourceCallsForHookPoint(stage, spec.type).length ||
        sourceSignalsForHookPoint(stage, spec.type).length
      )
      .map((stage) => stage.stage), 12);
    const sourceSignals = uniqueLimited(stages.flatMap((stage) => sourceSignalsForHookPoint(stage, spec.type)), 12);
    const sourceCalls = uniqueLimited(stages.flatMap((stage) => sourceCallsForHookPoint(stage, spec.type)), 12);
    const status = observedApis.length || observedStages.length
      ? "observed"
      : sourceStages.length || sourceSignals.length || sourceCalls.length
        ? "source_observed"
        : "missing";
    const point = {
      type: spec.type,
      status,
      priority: spec.priority,
      analysis_goal: vmpHookAnalysisGoal(spec.type),
      families: spec.families || [],
      observed_stages: observedStages,
      observed_apis: observedApis,
      suggested_hooks: spec.suggested_hooks,
      reason: spec.reason,
      next_action: status === "observed"
        ? "review_observed_events"
        : status === "source_observed"
          ? "review_source_context_or_add_runtime_hook"
          : "add_or_link_hooks"
    };
    if (sourceStages.length) point.source_stages = sourceStages;
    if (sourceSignals.length) point.source_signals = sourceSignals;
    if (sourceCalls.length) point.source_calls = sourceCalls;
    return point;
  });
}

function finalizeMaterialFlow(flow) {
  const parameterAttachmentGraph = parameterAttachmentGraphForMaterialFlow(flow);
  const generationSteps = materialGenerationSteps(flow);
  const analysisReadiness = materialFlowReadiness(flow);
  const vmpHookPoints = materialFlowVmpHookPoints(flow);
  return {
    ...flow,
    generation_steps: generationSteps,
    agent_stage_trace: buildAgentStageTrace(generationSteps, flow.target_params || []),
    ...(parameterAttachmentGraph ? {parameter_attachment_graph: parameterAttachmentGraph} : {}),
    analysis_readiness: analysisReadiness,
    vmp_hook_points: vmpHookPoints,
    agent_generation_summary: buildAgentGenerationSummary(flow, generationSteps, vmpHookPoints, analysisReadiness)
  };
}

const NEXT_CAPTURE_RECOMMENDED_FLAGS = [
  "--xtrace-categories=reverse,fingerprint",
  "--xtrace-capture-values=full",
  "--xtrace-capture-assets=full",
  "--xtrace-max-value-bytes=262144"
];
const NEXT_CAPTURE_REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const NEXT_CAPTURE_DEFAULT_CHROMIUM_APP = path.join(NEXT_CAPTURE_REPO_ROOT, "chromium", "src", "out", "XTrace", "Chromium.app");
const NEXT_CAPTURE_DEFAULT_LOG_DIR = path.join(NEXT_CAPTURE_REPO_ROOT, "logs");
const NEXT_CAPTURE_DEFAULT_ASSET_MAX_BYTES = 2097152;
const CAPTURE_GAP_SPECS = new Map([
  ["signature_terms_not_observed", {
    priority: "high",
    action: "capture_signature_terms_or_mutation",
    reason: "capture the request, URL mutation, or header mutation where target signature terms first appear"
  }],
  ["unsigned_input_not_observed", {
    priority: "high",
    action: "capture_unsigned_request_construction",
    reason: "capture the unsigned URL or request material before VMP/signature processing starts"
  }],
  ["signature_mutation_not_observed", {
    priority: "high",
    action: "capture_url_search_params_mutation_or_header_set",
    reason: "capture URLSearchParams, URL.search, header, or request mutation that attaches signature output"
  }],
  ["material_source_not_observed", {
    priority: "high",
    action: "capture_text_buffer_or_storage_material",
    reason: "capture text, byte buffer, storage, or cookie material consumed by the signature pipeline"
  }],
  ["mix_or_hash_not_observed", {
    priority: "high",
    action: "capture_hash_or_integer_mixing",
    reason: "capture WebCrypto digest/sign/importKey, Math.imul, bitwise, or shift rounds that transform signature material"
  }],
  ["signed_request_not_observed", {
    priority: "high",
    action: "capture_browser_network_anchor",
    reason: "capture the final browser process network request to anchor the renderer-side chain"
  }],
  ["source_context_not_available", {
    priority: "medium",
    action: "capture_or_retrieve_script_asset",
    reason: "capture or retrieve script source around the stack frame for source-level review"
  }],
  ["data_links_not_observed", {
    priority: "medium",
    action: "capture_object_ids_for_data_links",
    reason: "capture object IDs so URL, SearchParams, DataView, ArrayBuffer, and mix state can be linked"
  }],
  ["business_api_anchor_not_captured", {
    priority: "high",
    action: "capture_business_api_anchor",
    reason: "trigger and capture a fetch/XHR business API request rather than document, telemetry, or static resource traffic"
  }]
]);
const CAPTURE_PRIORITY_RANK = {high: 0, medium: 1, low: 2};

function capturePriorityRank(priority) {
  return CAPTURE_PRIORITY_RANK[priority] ?? 99;
}

function captureGapSpec(gap) {
  return CAPTURE_GAP_SPECS.get(gap) || {
    priority: "medium",
    action: "review_capture_gap",
    reason: "review this capture gap before the next trace run"
  };
}

function sortedValues(values) {
  return [...values].sort((a, b) => String(a).localeCompare(String(b)));
}

function readinessStatusRank(status) {
  if (status === "strong") return 0;
  if (status === "partial") return 1;
  if (status === "candidate") return 2;
  return 3;
}

function flowEvidenceGaps(flow) {
  return flow.analysis_readiness?.evidence_gaps || [];
}

function compareEndpointRepresentativeFlow(left, right) {
  const leftGaps = flowEvidenceGaps(left);
  const rightGaps = flowEvidenceGaps(right);
  return leftGaps.length - rightGaps.length ||
    readinessStatusRank(left.analysis_readiness?.status) - readinessStatusRank(right.analysis_readiness?.status) ||
    (right.stage_count || 0) - (left.stage_count || 0) ||
    confidenceRank(right.confidence) - confidenceRank(left.confidence) ||
    String(left.id || "").localeCompare(String(right.id || ""));
}

function summarizeNextCaptureGaps(materialFlows) {
  const byGap = new Map();
  let order = 0;
  for (const flow of materialFlows || []) {
    for (const gap of flow.analysis_readiness?.evidence_gaps || []) {
      const spec = captureGapSpec(gap);
      const item = byGap.get(gap) || {
        gap,
        index: order++,
        priority: spec.priority,
        reason: spec.reason,
        flowIds: new Set(),
        nextActions: new Set()
      };
      item.flowIds.add(flow.id || "");
      item.nextActions.add(spec.action);
      if (capturePriorityRank(spec.priority) < capturePriorityRank(item.priority)) item.priority = spec.priority;
      byGap.set(gap, item);
    }
  }

  return [...byGap.values()]
    .sort((a, b) =>
      capturePriorityRank(a.priority) - capturePriorityRank(b.priority) ||
      b.flowIds.size - a.flowIds.size ||
      a.index - b.index)
    .map((item) => ({
      gap: item.gap,
      flow_count: item.flowIds.size,
      priority: item.priority,
      reason: item.reason,
      next_actions: sortedValues(item.nextActions)
    }));
}

function summarizeNextCaptureHookFocus(materialFlows) {
  const byType = new Map();
  for (const flow of materialFlows || []) {
    for (const point of flow.vmp_hook_points || []) {
      if (point.status !== "missing") continue;
      const item = byType.get(point.type) || {
        type: point.type,
        priority: point.priority || "medium",
        analysis_goal: point.analysis_goal || "",
        suggested_hooks: point.suggested_hooks || [],
        next_action: point.next_action || "add_or_link_hooks",
        flowIds: new Set()
      };
      item.flowIds.add(flow.id || "");
      byType.set(point.type, item);
    }
  }

  return [...byType.values()]
    .sort((a, b) =>
      VMP_HOOK_POINT_SPECS.findIndex((spec) => spec.type === a.type) -
        VMP_HOOK_POINT_SPECS.findIndex((spec) => spec.type === b.type) ||
      b.flowIds.size - a.flowIds.size ||
      String(a.type).localeCompare(String(b.type)))
    .map((item) => ({
      type: item.type,
      missing_flow_count: item.flowIds.size,
      priority: item.priority,
      next_action: item.next_action,
      analysis_goal: item.analysis_goal,
      suggested_hooks: item.suggested_hooks
    }));
}

function summarizeNextCaptureEndpoints(materialFlows) {
  const byEndpoint = new Map();
  for (const flow of materialFlows || []) {
    if (!flow.endpoint) continue;
    const item = byEndpoint.get(flow.endpoint) || {
      endpoint: flow.endpoint,
      flowIds: new Set(),
      statuses: new Set(),
      gaps: new Set(),
      resourceClasses: new Set(),
      representativeFlow: null
    };
    item.flowIds.add(flow.id || "");
    if (flow.analysis_readiness?.status) item.statuses.add(flow.analysis_readiness.status);
    for (const gap of flow.analysis_readiness?.evidence_gaps || []) item.gaps.add(gap);
    if (flow.resource_class) item.resourceClasses.add(flow.resource_class);
    if (!item.representativeFlow || compareEndpointRepresentativeFlow(flow, item.representativeFlow) < 0) {
      item.representativeFlow = flow;
    }
    byEndpoint.set(flow.endpoint, item);
  }

  return [...byEndpoint.values()]
    .filter((item) => ![...item.resourceClasses].some((resourceClass) => isLowValueNetworkResourceClass(resourceClass)))
    .sort((a, b) => b.flowIds.size - a.flowIds.size || String(a.endpoint).localeCompare(String(b.endpoint)))
    .slice(0, 8)
    .map((item) => ({
      endpoint: item.endpoint,
      flow_count: item.flowIds.size,
      readiness_statuses: item.representativeFlow?.analysis_readiness?.status
        ? [item.representativeFlow.analysis_readiness.status]
        : [],
      evidence_gaps: flowEvidenceGaps(item.representativeFlow)
    }));
}

function summarizeLowValueNextCaptureEndpoints(materialFlows) {
  const byClass = new Map();
  for (const flow of materialFlows || []) {
    if (!isLowValueNetworkResourceClass(flow.resource_class)) continue;
    const item = byClass.get(flow.resource_class) || {
      resource_class: flow.resource_class,
      endpoints: new Set(),
      flowIds: new Set(),
      examples: []
    };
    if (flow.endpoint) {
      item.endpoints.add(flow.endpoint);
      let example = flow.endpoint;
      try {
        example = endpointForUrl(new URL(flow.endpoint));
      } catch {
        example = String(flow.endpoint).split(/[?#]/)[0];
      }
      if (example && !item.examples.includes(example) && item.examples.length < 3) {
        item.examples.push(example);
      }
    }
    if (flow.id) item.flowIds.add(flow.id);
    byClass.set(flow.resource_class, item);
  }
  return [...byClass.values()]
    .sort((a, b) => String(a.resource_class).localeCompare(String(b.resource_class)))
    .map((item) => ({
      resource_class: item.resource_class,
      endpoint_count: item.endpoints.size,
      flow_count: item.flowIds.size,
      examples: item.examples
    }));
}

function fallbackStartEndpointForNextCapture(materialFlows) {
  const documentFlow = (materialFlows || []).find((flow) => flow.resource_class === "document_request" && flow.endpoint);
  if (documentFlow) return documentFlow.endpoint;
  for (const flow of materialFlows || []) {
    const context = flow.request_context || {};
    for (const value of [context.referrer, context.request_initiator]) {
      if (!value) continue;
      try {
        const parsed = new URL(value);
        if (!["http:", "https:"].includes(parsed.protocol)) continue;
        if (isLikelyStaticNetworkPath(parsed.pathname) || isLikelyTelemetryNetworkEndpoint({
          host: parsed.host,
          endpoint: endpointForUrl(parsed),
          path: parsed.pathname
        })) {
          continue;
        }
        return parsed.href;
      } catch {
        // Ignore request context values that are not URLs.
      }
    }
  }
  const firstFlow = (materialFlows || []).find((flow) => flow.endpoint);
  return firstFlow?.endpoint || "about:blank";
}

function isCoreSignatureAsset(asset) {
  const haystack = [
    asset.asset_id,
    asset.stack_url,
    asset.content_path
  ].join(" ").toLowerCase();
  const directTerms = [
    "signature",
    "security",
    "risk",
    "fingerprint",
    "sensor",
    "challenge",
    "captcha",
    "waf",
    "vmp",
    "vm"
  ];
  if (directTerms.some((needle) => haystack.includes(needle))) {
    return true;
  }
  return haystack.includes("sdk") &&
    !/(analytics|monitor|telemetry|collect|beacon|log|report|metrics|probe|privacy)/.test(haystack);
}

function summarizeNextCaptureAssets(materialFlows, assetFindings = []) {
  const byAsset = new Map();
  const endpointCoreAssets = new Map();
  const assetByUrl = new Map((assetFindings || [])
    .filter((asset) => asset.url && asset.asset_id)
    .map((asset) => [asset.url, asset]));
  for (const flow of materialFlows || []) {
    if (flow.endpoint && isCoreSignatureAsset({stack_url: flow.endpoint})) {
      const endpointAsset = assetByUrl.get(flow.endpoint) || null;
      const endpointItem = endpointCoreAssets.get(flow.endpoint) || {
        asset_id: endpointAsset?.asset_id || "",
        stack_url: flow.endpoint,
        content_path: endpointAsset?.content_path || "",
        retrieval_status: endpointAsset?.retrieval_status || "",
        retrieval_error: endpointAsset?.retrieval_error || "",
        score: endpointAsset?.score ?? null,
        signals: endpointAsset?.signals || [],
        flowIds: new Set(),
        statuses: new Set(),
        core: true
      };
      endpointItem.flowIds.add(flow.id || "");
      if (flow.analysis_readiness?.status) endpointItem.statuses.add(flow.analysis_readiness.status);
      endpointCoreAssets.set(flow.endpoint, endpointItem);
    }
    if (!flow.asset_id && !flow.stack_url) continue;
    const key = `${flow.asset_id || ""}\u0000${flow.stack_url || ""}`;
    const item = byAsset.get(key) || {
      asset_id: flow.asset_id || "",
      stack_url: flow.stack_url || "",
      flowIds: new Set(),
      statuses: new Set(),
      core: false
    };
    item.flowIds.add(flow.id || "");
    if (flow.analysis_readiness?.status) item.statuses.add(flow.analysis_readiness.status);
    if (isCoreSignatureAsset({
      asset_id: flow.asset_id || "",
      stack_url: flow.stack_url || "",
      content_path: flow.source_contexts?.[0]?.content_path || ""
    })) {
      item.core = true;
    }
    byAsset.set(key, item);
  }
  const hasCoreStackAsset = [...byAsset.values()].some((item) => item.core);
  if (!hasCoreStackAsset) {
    for (const item of endpointCoreAssets.values()) {
      byAsset.set(`endpoint\u0000${item.stack_url}`, item);
    }
  }

  for (const asset of assetFindings || []) {
    if (!isCoreSignatureAsset({
      asset_id: asset.asset_id || "",
      stack_url: asset.url || "",
      content_path: asset.content_path || ""
    })) {
      continue;
    }
    const key = `${asset.asset_id || ""}\u0000${asset.url || ""}`;
    const item = byAsset.get(key) || {
      asset_id: asset.asset_id || "",
      stack_url: asset.url || "",
      content_path: asset.content_path || "",
      retrieval_status: asset.retrieval_status || "",
      retrieval_error: asset.retrieval_error || "",
      score: asset.score ?? null,
      signals: asset.signals || [],
      flowIds: new Set(),
      statuses: new Set(),
      core: true
    };
    item.core = true;
    if (!item.content_path && asset.content_path) item.content_path = asset.content_path;
    if (!item.retrieval_status && asset.retrieval_status) item.retrieval_status = asset.retrieval_status;
    if (!item.retrieval_error && asset.retrieval_error) item.retrieval_error = asset.retrieval_error;
    if ((item.score === null || item.score === undefined) && asset.score !== undefined) item.score = asset.score;
    if (!(item.signals || []).length && (asset.signals || []).length) item.signals = asset.signals;
    byAsset.set(key, item);
  }

  return [...byAsset.values()]
    .filter((item) => item.core || !isBrowserInternalSourceCandidate({
      function: item.function || "",
      url: item.stack_url || "",
      content_path: item.content_path || ""
    }))
    .sort((a, b) =>
      Number(b.core) - Number(a.core) ||
      b.flowIds.size - a.flowIds.size ||
      String(a.stack_url).localeCompare(String(b.stack_url)) ||
      String(a.asset_id).localeCompare(String(b.asset_id)))
    .slice(0, 8)
    .map((item) => ({
      asset_id: item.asset_id,
      stack_url: item.stack_url,
      ...(item.content_path ? {content_path: item.content_path} : {}),
      ...(item.retrieval_status ? {retrieval_status: item.retrieval_status} : {}),
      ...(item.retrieval_error ? {retrieval_error: item.retrieval_error} : {}),
      ...(item.score !== null && item.score !== undefined ? {score: item.score} : {}),
      ...(item.signals?.length ? {signals: item.signals} : {}),
      flow_count: item.flowIds.size,
      readiness_statuses: [...item.statuses],
      ...(item.core ? {
        asset_focus: "core_signature_asset",
        asset_role: "security_sdk_signature_generator"
      } : {})
    }));
}

function priorityForNextCapturePlan(gapSummary, hookFocus) {
  const priorities = [
    ...(gapSummary || []).map((gap) => gap.priority),
    ...(hookFocus || []).map((hook) => hook.priority)
  ].filter(Boolean);
  return priorities.sort((a, b) => capturePriorityRank(a) - capturePriorityRank(b))[0] || "low";
}

function buildNextCaptureRerunRecipe({
  focusEndpoints = [],
  focusAssets = [],
  gapSummary = [],
  hookFocus = [],
  fallbackStartUrl = "about:blank"
} = {}) {
  const startUrl = focusEndpoints[0]?.endpoint || fallbackStartUrl || "about:blank";
  const categories = "reverse,fingerprint";
  const captureValues = "full";
  const captureAssets = "full";
  const maxValueBytes = 262144;
  const assetMaxBytes = NEXT_CAPTURE_DEFAULT_ASSET_MAX_BYTES;
  const focusGaps = focusEndpoints[0]?.evidence_gaps?.length
    ? focusEndpoints[0].evidence_gaps
    : gapSummary.map((gap) => gap.gap).slice(0, 8);

  return {
    profile: "interactive_full_capture",
    start_url: startUrl,
    gui_defaults: {
      url: startUrl,
      categories,
      captureValues,
      captureAssets,
      maxValueBytes
    },
    python_launcher_args: [
      "run",
      "--chromium",
      NEXT_CAPTURE_DEFAULT_CHROMIUM_APP,
      "--url",
      startUrl,
      "--log-dir",
      NEXT_CAPTURE_DEFAULT_LOG_DIR,
      "--xtrace-categories",
      categories,
      "--xtrace-capture-values",
      captureValues,
      "--xtrace-capture-assets",
      captureAssets,
      "--xtrace-max-value-bytes",
      String(maxValueBytes),
      "--xtrace-asset-max-bytes",
      String(assetMaxBytes)
    ],
    env: {
      XTRACE_CATEGORIES: categories,
      XTRACE_CAPTURE_VALUES: captureValues,
      XTRACE_CAPTURE_ASSETS: captureAssets,
      XTRACE_MAX_VALUE_BYTES: String(maxValueBytes),
      XTRACE_ASSET_MAX_BYTES: String(assetMaxBytes)
    },
    focus: {
      target_terms: SIGNATURE_TERMS,
      endpoints: focusEndpoints.map((endpoint) => endpoint.endpoint).filter(Boolean).slice(0, 8),
      assets: focusAssets
        .map((asset) => [asset.asset_id, asset.stack_url].filter(Boolean).join("@"))
        .filter(Boolean)
        .slice(0, 8),
      gaps: focusGaps,
      hooks: hookFocus.map((hook) => hook.type).filter(Boolean).slice(0, 3)
    }
  };
}

const BUSINESS_API_AVOID_RESOURCE_CLASSES = [
  "document_request",
  "static_resource",
  "telemetry_endpoint"
];
const BUSINESS_API_REQUIRED_RENDERER_APIS = [
  "Request.constructor",
  "fetch",
  "XMLHttpRequest.open",
  "XMLHttpRequest.send"
];
const BUSINESS_API_GATE_TAIL_APIS = [
  "BrowserNetwork.request",
  ...BUSINESS_API_REQUIRED_RENDERER_APIS
];

function focusAssetLabels(focusAssets) {
  return (focusAssets || [])
    .map((asset) => [asset.asset_id, asset.stack_url].filter(Boolean).join("@"))
    .filter(Boolean)
    .slice(0, 8);
}

function coreFocusAssetLabels(focusAssets) {
  return focusAssetLabels((focusAssets || []).filter((asset) =>
    asset.asset_focus === "core_signature_asset" ||
    asset.asset_role === "security_sdk_signature_generator" ||
    isCoreSignatureAsset({
      asset_id: asset.asset_id,
      stack_url: asset.stack_url,
      content_path: asset.content_path
    })
  ));
}

function sameOriginApiPattern(startUrl) {
  try {
    const parsed = new URL(startUrl);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return `${parsed.origin}/api/*`;
    }
  } catch {
    // Keep the fallback generic when the start URL is not parseable.
  }
  return "same-origin /api/*";
}

function parsedHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed : null;
  } catch {
    return null;
  }
}

function businessApiEndpointHints(startUrl) {
  const hints = [
    {
      kind: "same_origin_api",
      pattern: sameOriginApiPattern(startUrl),
      reason: "prefer same-origin application API traffic over document, telemetry, or static script requests"
    }
  ];

  hints.push({
    kind: "interactive_fetch_or_xhr",
    pattern: "fetch/XMLHttpRequest non-static endpoint",
    reason: "renderer request construction is needed to link URL/SearchParams mutation to the final request"
  });
  return hints;
}

function businessApiNormalUserActions() {
  return [
    "load the start URL with full reverse/fingerprint capture enabled",
    "perform normal in-page actions that request feed, search, detail, or pagination data",
    "wait until a non-static fetch/XHR BrowserNetwork.request appears"
  ];
}

function buildBusinessApiCaptureStatus({
  focusEndpoints = [],
  lowValueEndpointSummary = [],
  gapSummary = []
} = {}) {
  if (focusEndpoints.length) {
    const missingEvidence = uniqueLimited(
      focusEndpoints.flatMap((endpoint) => endpoint.evidence_gaps || []),
      12
    );
    return {
      status: "captured",
      priority: priorityForNextCapturePlan(gapSummary, []),
      actionable_endpoint_count: focusEndpoints.length,
      endpoints: focusEndpoints.slice(0, 6).map((endpoint) => ({
        endpoint: endpoint.endpoint,
        flow_count: endpoint.flow_count,
        readiness_statuses: endpoint.readiness_statuses || [],
        evidence_gaps: endpoint.evidence_gaps || []
      })),
      success_criteria_met: [
        "observed endpoint is not document_request, static_resource, or telemetry_endpoint"
      ],
      missing_evidence: missingEvidence,
      next_actions: uniqueLimited(missingEvidence.map((gap) => captureGapSpec(gap).action), 12)
    };
  }

  const spec = captureGapSpec("business_api_anchor_not_captured");
  return {
    status: "missing",
    priority: lowValueEndpointSummary.length ? spec.priority : priorityForNextCapturePlan(gapSummary, []),
    actionable_endpoint_count: 0,
    missing_evidence: ["business_api_anchor_not_captured"],
    avoid_resource_classes: BUSINESS_API_AVOID_RESOURCE_CLASSES
  };
}

function buildBusinessApiCaptureGate({
  focusEndpoints = [],
  lowValueEndpointSummary = [],
  gapSummary = [],
  fallbackStartUrl = "about:blank"
} = {}) {
  const actionableEndpoints = uniqueLimited(
    focusEndpoints.map((endpoint) => endpoint.endpoint).filter(Boolean),
    8
  );
  const remainingAnalysisGaps = uniqueLimited(
    (focusEndpoints.length
      ? focusEndpoints.flatMap((endpoint) => endpoint.evidence_gaps || [])
      : gapSummary.map((gap) => gap.gap)
    ).filter(Boolean),
    12
  );
  const status = actionableEndpoints.length ? "passed" : "pending";
  const missing = actionableEndpoints.length ? [] : ["business_api_anchor_not_captured"];
  const targetEndpointPatterns = actionableEndpoints.length
    ? actionableEndpoints
    : businessApiEndpointHints(fallbackStartUrl).map((hint) => hint.pattern);

  return {
    id: "business_api_anchor",
    status,
    priority: status === "pending" && lowValueEndpointSummary.length
      ? captureGapSpec("business_api_anchor_not_captured").priority
      : priorityForNextCapturePlan(gapSummary, []),
    required_event: "BrowserNetwork.request",
    required_renderer_apis: BUSINESS_API_REQUIRED_RENDERER_APIS,
    target_endpoint_patterns: targetEndpointPatterns,
    reject_resource_classes: BUSINESS_API_AVOID_RESOURCE_CLASSES,
    observed_actionable_endpoint_count: actionableEndpoints.length,
    matched_endpoints: actionableEndpoints,
    missing,
    remaining_analysis_gaps: status === "pending" ? missing : remainingAnalysisGaps,
    tail_filters: {
      categories: ["network"],
      apis: BUSINESS_API_GATE_TAIL_APIS,
      exclude_resource_classes: BUSINESS_API_AVOID_RESOURCE_CLASSES
    },
    stop_when: "observed_actionable_endpoint_count > 0"
  };
}

function firstLowValueExample(lowValueEndpointSummary, resourceClass) {
  return (lowValueEndpointSummary || [])
    .find((item) => item.resource_class === resourceClass)
    ?.examples?.[0] || "";
}

function lowValueSummaryLabels(lowValueEndpointSummary) {
  return (lowValueEndpointSummary || [])
    .map((item) => `${item.resource_class || "unknown"}:${item.endpoint_count ?? 0}`)
    .filter(Boolean);
}

function buildCaptureChecklist({
  captureGate,
  focusAssets = [],
  lowValueEndpointSummary = [],
  gapSummary = [],
  fallbackStartUrl = "about:blank"
} = {}) {
  if (captureGate?.status === "passed") {
    const gaps = uniqueLimited((captureGate.remaining_analysis_gaps || []).filter(Boolean), 12);
    const gateGapSummary = gaps.map((gap) => {
      const spec = captureGapSpec(gap);
      return {
        gap,
        priority: spec.priority,
        next_actions: [spec.action]
      };
    });
    const nextActions = uniqueLimited(gateGapSummary
      .flatMap((gap) => gap.next_actions || [])
      .filter(Boolean), 12);
    return [
      {
        id: "business_api_anchor",
        status: "observed",
        priority: "high",
        evidence: captureGate.matched_endpoints || [],
        next_action: "analyze_signature_material_flow"
      },
      {
        id: "complete_material_linking",
        status: gaps.length ? "pending" : "observed",
        priority: gaps.length ? priorityForNextCapturePlan(gateGapSummary, []) : "medium",
        evidence: gaps.length ? gaps : ["analysis_ready"],
        next_action: nextActions[0] || "review_agent_evidence_pack"
      }
    ];
  }

  const startEvidence = firstLowValueExample(lowValueEndpointSummary, "document_request") ||
    (fallbackStartUrl !== "about:blank" ? fallbackStartUrl : "");
  const coreAssets = coreFocusAssetLabels(focusAssets);
  return [
    {
      id: "load_start_url",
      status: startEvidence ? "observed" : "pending",
      priority: "medium",
      evidence: startEvidence ? [startEvidence] : [],
      next_action: startEvidence ? "keep_start_url" : "load_start_url"
    },
    {
      id: "confirm_core_sdk_asset",
      status: coreAssets.length ? "observed" : "pending",
      priority: "high",
      evidence: coreAssets,
      next_action: coreAssets.length ? "review_core_asset_windows" : "capture_or_retrieve_script_asset"
    },
    {
      id: "trigger_business_api_anchor",
      status: "pending",
      priority: "high",
      evidence: [],
      target_endpoint_patterns: captureGate?.target_endpoint_patterns || [
        sameOriginApiPattern(fallbackStartUrl),
        "fetch/XMLHttpRequest non-static endpoint"
      ],
      rejected_endpoint_summary: lowValueSummaryLabels(lowValueEndpointSummary),
      next_action: "perform_normal_in_page_actions_until_fetch_or_xhr_api_request"
    }
  ];
}

function buildBusinessApiCapturePlan({
  focusEndpoints = [],
  lowValueEndpointSummary = [],
  focusAssets = [],
  fallbackStartUrl = "about:blank"
} = {}) {
  if (focusEndpoints.length || !lowValueEndpointSummary.length) return null;
  return {
    status: "needs_business_api_anchor",
    priority: "high",
    start_url: fallbackStartUrl,
    reason: "current candidate anchors are document, telemetry, or static resource requests; trigger normal application XHR/fetch traffic",
    avoid_resource_classes: BUSINESS_API_AVOID_RESOURCE_CLASSES,
    core_assets: coreFocusAssetLabels(focusAssets),
    target_endpoint_hints: businessApiEndpointHints(fallbackStartUrl),
    normal_user_actions: businessApiNormalUserActions(fallbackStartUrl),
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
  };
}

function buildCaptureAttemptQuality({
  focusEndpoints = [],
  lowValueEndpointSummary = [],
  focusAssets = [],
  gapSummary = [],
  businessApiCaptureStatus = null
} = {}) {
  const coreAssetCount = coreFocusAssetLabels(focusAssets).length;
  const lowValueClasses = uniqueLimited(
    (lowValueEndpointSummary || [])
      .map((item) => item.resource_class)
      .filter(Boolean),
    8
  );
  const lowValueEndpointCount = (lowValueEndpointSummary || [])
    .reduce((sum, item) => sum + (item.endpoint_count || 0), 0);
  const missingEvidence = uniqueLimited([
    ...(businessApiCaptureStatus?.missing_evidence || []),
    ...(gapSummary || []).map((gap) => gap.gap).filter(Boolean)
  ], 12);

  if (focusEndpoints.length) {
    return {
      status: "business_api_anchor_captured",
      readiness: missingEvidence.length
        ? "partial_signature_generation_analysis"
        : "ready_for_signature_generation_analysis",
      reason: "at least one actionable business API request anchor was captured",
      actionable_endpoint_count: focusEndpoints.length,
      core_asset_count: coreAssetCount,
      low_value_endpoint_classes: lowValueClasses,
      low_value_endpoint_count: lowValueEndpointCount,
      missing_evidence: missingEvidence,
      next_action: missingEvidence.length ? "analyze_remaining_material_flow_gaps" : "review_signature_material_flow"
    };
  }

  if (coreAssetCount && lowValueEndpointSummary.length) {
    return {
      status: "core_sdk_observed_without_business_api",
      readiness: "not_ready_for_signature_generation_analysis",
      reason: "core SDK/runtime evidence is present, but captured request anchors are only document, static resource, or telemetry traffic",
      actionable_endpoint_count: 0,
      core_asset_count: coreAssetCount,
      low_value_endpoint_classes: lowValueClasses,
      low_value_endpoint_count: lowValueEndpointCount,
      missing_evidence: missingEvidence,
      next_action: "perform_normal_in_page_actions_until_business_api_request"
    };
  }

  return {
    status: lowValueEndpointSummary.length ? "low_value_requests_only" : "insufficient_runtime_evidence",
    readiness: "not_ready_for_signature_generation_analysis",
    reason: lowValueEndpointSummary.length
      ? "captured request anchors are only document, static resource, or telemetry traffic"
      : "no actionable request anchors or core SDK runtime evidence were captured",
    actionable_endpoint_count: 0,
    core_asset_count: coreAssetCount,
    low_value_endpoint_classes: lowValueClasses,
    low_value_endpoint_count: lowValueEndpointCount,
    missing_evidence: missingEvidence,
    next_action: coreAssetCount ? "trigger_business_api_anchor" : "capture_or_retrieve_core_sdk_asset"
  };
}

function buildNextCapturePlan(materialFlows, assetFindings = []) {
  const focusEndpoints = summarizeNextCaptureEndpoints(materialFlows);
  const lowValueEndpointSummary = summarizeLowValueNextCaptureEndpoints(materialFlows);
  const gapSummary = summarizeNextCaptureGaps(materialFlows);
  if (!focusEndpoints.length && lowValueEndpointSummary.length) {
    const spec = captureGapSpec("business_api_anchor_not_captured");
    gapSummary.unshift({
      gap: "business_api_anchor_not_captured",
      flow_count: lowValueEndpointSummary.reduce((sum, item) => sum + (item.flow_count || 0), 0),
      priority: spec.priority,
      reason: spec.reason,
      next_actions: [spec.action]
    });
  }
  const hookFocus = summarizeNextCaptureHookFocus(materialFlows);
  const focusAssets = summarizeNextCaptureAssets(materialFlows, assetFindings);
  const fallbackStartUrl = fallbackStartEndpointForNextCapture(materialFlows);
  const businessApiCapturePlan = buildBusinessApiCapturePlan({
    focusEndpoints,
    lowValueEndpointSummary,
    focusAssets,
    fallbackStartUrl
  });
  const businessApiCaptureStatus = buildBusinessApiCaptureStatus({
    focusEndpoints,
    lowValueEndpointSummary,
    gapSummary
  });
  const captureAttemptQuality = buildCaptureAttemptQuality({
    focusEndpoints,
    lowValueEndpointSummary,
    focusAssets,
    gapSummary,
    businessApiCaptureStatus
  });
  const captureGate = buildBusinessApiCaptureGate({
    focusEndpoints,
    lowValueEndpointSummary,
    gapSummary,
    fallbackStartUrl
  });
  const captureChecklist = buildCaptureChecklist({
    captureGate,
    focusAssets,
    lowValueEndpointSummary,
    gapSummary,
    fallbackStartUrl
  });
  return {
    priority: priorityForNextCapturePlan(gapSummary, hookFocus),
    target_terms: SIGNATURE_TERMS,
    recommended_flags: NEXT_CAPTURE_RECOMMENDED_FLAGS,
    actionable_endpoint_count: focusEndpoints.length,
    low_value_endpoint_summary: lowValueEndpointSummary,
    gap_summary: gapSummary,
    action_items: gapSummary.map((gap) => ({
      id: gap.next_actions[0] || "review_capture_gap",
      priority: gap.priority,
      flow_count: gap.flow_count,
      gaps: [gap.gap],
      reason: gap.reason
    })),
    hook_focus: hookFocus,
    focus_endpoints: focusEndpoints,
    focus_assets: focusAssets,
    capture_attempt_quality: captureAttemptQuality,
    capture_gate: captureGate,
    capture_checklist: captureChecklist,
    business_api_capture_status: businessApiCaptureStatus,
    ...(businessApiCapturePlan ? {business_api_capture_plan: businessApiCapturePlan} : {}),
    rerun_recipe: buildNextCaptureRerunRecipe({
      focusEndpoints,
      focusAssets,
      gapSummary,
      hookFocus,
      fallbackStartUrl
    })
  };
}

function sourceContextsForMaterialFlow(contexts) {
  return (contexts || []).slice(0, SOURCE_CONTEXTS_PER_WINDOW).map((context) => ({
    asset_id: context.asset_id || "",
    url: context.url || "",
    function: context.function || "",
    content_path: context.content_path || "",
    line_start: context.line_start ?? null,
    line_end: context.line_end ?? null,
    ...(context.column_anchor !== undefined ? {column_anchor: context.column_anchor} : {}),
    ...(context.column_start !== undefined ? {column_start: context.column_start} : {}),
    ...(context.column_end !== undefined ? {column_end: context.column_end} : {}),
    preview: context.preview || "",
    analysis: context.analysis || {}
  }));
}

function targetParamsForAttachmentEvent(event) {
  const params = new Set(
    requestMaterialPhaseForEvent(event) === "request_body"
      ? signatureTermsInRequestBodyEvent(event)
      : signatureTermsInEvent(event)
  );
  const mutationParam = paramNameFromMutationEvent(event);
  if (SIGNATURE_TERMS.includes(mutationParam)) params.add(mutationParam);
  return sortParamNames([...params].filter((param) => SIGNATURE_TERMS.includes(param)));
}

function signatureTermsInRequestBodyEvent(event) {
  const params = new Set();
  for (const arg of event?.args || []) {
    if (!arg || typeof arg !== "object") continue;
    for (const key of ["name", "field_name"]) {
      const value = String(arg[key] || "");
      if (SIGNATURE_TERMS.includes(value)) params.add(value);
    }
    for (const key of ["param_names", "field_names"]) {
      if (!Array.isArray(arg[key])) continue;
      for (const item of arg[key]) {
        const value = String(item || "");
        if (SIGNATURE_TERMS.includes(value)) params.add(value);
      }
    }
    for (const key of [
      "body",
      "body_preview",
      "post_data",
      "post_data_preview",
      "request_body",
      "request_body_preview",
      "upload_body",
      "upload_data",
      "payload"
    ]) {
      if (!(key in arg)) continue;
      const text = JSON.stringify(arg[key]);
      for (const term of SIGNATURE_TERMS) {
        if (text.includes(term)) params.add(term);
      }
    }
  }
  return [...params];
}

function attachmentActionForEvent(event) {
  const explicitAction = actionForUrlMutationApi(event?.api || "");
  if (explicitAction) return explicitAction;
  if (event?.api === "XMLHttpRequest.setRequestHeader") return "set_header";
  if (event?.api === "Headers.set") return "set_header";
  if (event?.api === "Headers.append") return "append_header";
  if (event?.api === "Headers.delete") return "delete_header";
  if (event?.api === "URL.constructor") return "construct_signed_url";
  if (event?.api === "URL.search.get") return "read_search";
  if (event?.api === "URL.href.get") return "read_href";
  return "observe";
}

function isSignatureAttachmentPhase(phase) {
  return [
    "url_signature_mutation",
    "request_headers",
    "request_body"
  ].includes(phase || "");
}

function isSupplementalSignatureAttachmentTimelineEvent(event) {
  const api = event?.api || "";
  if (actionForUrlMutationApi(api)) return true;
  return [
    "URLSearchParams.toString",
    "URL.href.get",
    "URL.search.get"
  ].includes(api);
}

function addSignatureAttachmentEvent(attachments, seen, event, phase) {
  const targetParams = targetParamsForAttachmentEvent(event);
  if (!targetParams.length) return false;
  const action = attachmentActionForEvent(event);
  const key = `${event.seq}:${event.api}:${action}:${targetParams.join("|")}`;
  if (seen.has(key)) return false;
  seen.add(key);
  attachments.push({
    seq: event.seq ?? null,
    api: event.api || "",
    phase,
    action,
    target_params: targetParams,
    object_refs: objectRefsForEvents([event], () => true),
    value_refs: valueRefsForEvents([event], () => true)
  });
  return true;
}

function signatureAttachmentEventsForFlow(flow) {
  const attachments = [];
  const seen = new Set();
  for (const window of flow.event_windows || []) {
    if (!isSignatureAttachmentPhase(window.phase)) continue;
    for (const event of window.events || []) {
      addSignatureAttachmentEvent(attachments, seen, event, window.phase);
      if (attachments.length >= 12) return attachments;
    }
  }
  for (const event of flow.timeline || []) {
    if (!isSupplementalSignatureAttachmentTimelineEvent(event)) continue;
    addSignatureAttachmentEvent(attachments, seen, event, "url_signature_mutation");
    if (attachments.length >= 12) return attachments;
  }
  return attachments;
}

function numericFieldFromValue(value, fields, depth = 0) {
  if (depth > 5 || value === null || value === undefined) return null;
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = numericFieldFromValue(item, fields, depth + 1);
      if (found !== null) return found;
    }
    return null;
  }
  if (typeof value !== "object") return null;
  for (const field of fields) {
    const candidate = value[field];
    if (typeof candidate === "number" && Number.isFinite(candidate) && candidate >= 0) {
      return Math.floor(candidate);
    }
  }
  for (const item of Object.values(value)) {
    const found = numericFieldFromValue(item, fields, depth + 1);
    if (found !== null) return found;
  }
  return null;
}

function runtimeRefsForFieldNames(value, fields, output = [], depth = 0, key = "") {
  if (depth > 5 || value === null || value === undefined) return output;
  if (fields.has(String(key || ""))) {
    if (Array.isArray(value)) {
      for (const item of value) {
        const ref = normalizeRuntimeValueRef(item);
        if (ref) output.push(ref);
      }
      return output;
    }
    const ref = normalizeRuntimeValueRef(value);
    if (ref) output.push(ref);
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) runtimeRefsForFieldNames(item, fields, output, depth + 1);
    return output;
  }
  if (typeof value !== "object") return output;
  for (const [childKey, childValue] of Object.entries(value)) {
    runtimeRefsForFieldNames(childValue, fields, output, depth + 1, childKey);
  }
  return output;
}

const MATERIALIZATION_INPUT_REF_KEYS = new Set([
  "subject_ref",
  "input_ref",
  "left_ref",
  "right_ref",
  "fill_ref",
  "separator_ref",
  "search_ref",
  "replace_ref",
  "value_ref",
  "base_ref"
]);
const MATERIALIZATION_RESULT_REF_KEYS = new Set([
  "result_ref",
  "serialized_ref",
  "href_ref",
  "search_ref"
]);

function signaturePreviewForEvent(event, param) {
  const preview = collectStrings([event?.args || [], event?.result || []])
    .map((value) => String(value || ""))
    .find((value) => value.includes(param));
  if (!preview) return "";
  return preserveSignatureText(preview).slice(0, 120);
}

function signatureParamMaterializationAction(api) {
  if (api.startsWith("URLSearchParams.") || api.startsWith("URL.")) return "url_materialize";
  if (api.startsWith("Headers.") || api.startsWith("XMLHttpRequest.") || api.startsWith("FormData.")) {
    return "request_field_materialize";
  }
  if (api === "encodeURI" || api === "encodeURIComponent" || api === "decodeURI" || api === "decodeURIComponent") {
    return "url_encode_material";
  }
  return "string_materialize";
}

function signatureParamMaterializationsForEvent(event, phase = "") {
  const api = event?.api || "";
  if (!SIGNATURE_PARAM_MATERIALIZATION_APIS.has(api)) return [];
  const params = signatureTermsInEvent(event);
  if (!params.length) return [];
  const objectRefs = objectRefsForEvents([event], () => true);
  const valueRefs = compactGenerationValueRefs(
    valueRefsForEvents([event], () => true),
    16,
    {preserveStringRuntimeRefs: true}
  );
  const resultLength = numericFieldFromValue([event.args || [], event.result || []], [
    "result_length",
    "serialized_length",
    "value_length",
    "output_length"
  ]);
  const resultRef = uniqueLimited(
    runtimeRefsForFieldNames([event.args || [], event.result || []], MATERIALIZATION_RESULT_REF_KEYS),
    1
  )[0] || "";
  const inputRefs = compactGenerationValueRefs(
    runtimeRefsForFieldNames([event.args || [], event.result || []], MATERIALIZATION_INPUT_REF_KEYS)
      .filter((ref) => ref && ref !== resultRef),
    8,
    {preserveStringRuntimeRefs: true}
  );
  return params.map((param) => ({
    param,
    seq: event.seq ?? null,
    trace_index: explicitTraceIndexValue(event) ?? null,
    api,
    phase: phase || event.phase || event.t || "",
    action: signatureParamMaterializationAction(api),
    ...(resultLength !== null ? {result_length: resultLength} : {}),
    ...(resultRef ? {result_ref: resultRef} : {}),
    ...(inputRefs.length ? {input_refs: inputRefs} : {}),
    ...(objectRefs.length ? {object_refs: objectRefs} : {}),
    value_refs: valueRefs,
    ...(signaturePreviewForEvent(event, param)
      ? {preview: signaturePreviewForEvent(event, param)}
      : {})
  }));
}

function compareSignatureParamMaterializations(left, right) {
  return (left.seq ?? Number.MAX_SAFE_INTEGER) - (right.seq ?? Number.MAX_SAFE_INTEGER) ||
    (left.trace_index ?? Number.MAX_SAFE_INTEGER) - (right.trace_index ?? Number.MAX_SAFE_INTEGER) ||
    String(left.param || "").localeCompare(String(right.param || "")) ||
    String(left.api || "").localeCompare(String(right.api || ""));
}

function compactSignatureParamMaterializations(materializations, param = "") {
  const seen = new Set();
  return (materializations || [])
    .filter((event) => !param || event.param === param)
    .sort(compareSignatureParamMaterializations)
    .map((event) => ({
      param: event.param || "",
      seq: event.seq ?? null,
      ...(Number.isFinite(event.trace_index) ? {trace_index: event.trace_index} : {}),
      api: event.api || "",
      phase: event.phase || "",
      action: event.action || "string_materialize",
      ...(event.result_length !== undefined ? {result_length: event.result_length} : {}),
      ...(event.result_ref ? {result_ref: event.result_ref} : {}),
      input_refs: compactGenerationValueRefs(event.input_refs || [], 8, {preserveStringRuntimeRefs: true}),
      ...(event.preview ? {preview: event.preview} : {}),
      object_refs: uniquePrioritizedLimited(event.object_refs || [], 8, generationPathObjectRefRank),
      value_refs: compactGenerationValueRefs(event.value_refs || [], 12, {preserveStringRuntimeRefs: true})
    }))
    .filter((event) => {
      const key = [
        event.param,
        event.seq,
        event.trace_index ?? "",
        event.api,
        event.action,
        (event.value_refs || []).join("|")
      ].join("\u0000");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 16);
}

function signatureParamMaterializationsForFlow(flow) {
  const materializations = [];
  for (const window of flow.event_windows || []) {
    for (const event of window.events || []) {
      materializations.push(...signatureParamMaterializationsForEvent(event, window.phase || ""));
    }
  }
  for (const event of flow.timeline || []) {
    materializations.push(...signatureParamMaterializationsForEvent(event, ""));
  }
  return compactSignatureParamMaterializations(materializations);
}

function addAttachmentGraphNode(graph, node) {
  if (!node?.id || graph._nodeIds.has(node.id)) return;
  graph._nodeIds.add(node.id);
  graph.nodes.push(node);
}

function addAttachmentGraphEdge(graph, edge) {
  if (!edge?.from || !edge?.to || !edge?.relation) return;
  const key = `${edge.from}\u0000${edge.to}\u0000${edge.relation}\u0000${edge.evidence || ""}`;
  if (graph._edgeIds.has(key)) return;
  graph._edgeIds.add(key);
  graph.edges.push(edge);
}

function stageNamesForAttachmentGraph(flow) {
  const names = new Set();
  for (const stage of flow.stages || []) {
    if ([
      "signature_mutation",
      "request_headers",
      "request_body",
      "signed_request"
    ].includes(stage.stage)) {
      names.add(stage.stage);
    }
  }
  for (const attachment of flow.signature_attachment_events || []) {
    if (attachment.phase) names.add(attachment.phase === "url_signature_mutation" ? "signature_mutation" : attachment.phase);
  }
  return ["signature_mutation", "request_headers", "request_body", "signed_request"]
    .filter((name) => names.has(name));
}

function stageNodeId(stage) {
  return `stage:${stage === "url_signature_mutation" ? "signature_mutation" : stage}`;
}

function parameterAttachmentGraphForMaterialFlow(flow) {
  const attachments = flow.signature_attachment_events || [];
  if (!attachments.length) return null;

  const graph = {
    target_params: sortParamNames(flow.target_params || []),
    nodes: [],
    edges: [],
    _nodeIds: new Set(),
    _edgeIds: new Set()
  };
  const objectRefs = [];
  const valueRefs = [];
  const objectRefsByStage = new Map();

  for (const param of graph.target_params) {
    addAttachmentGraphNode(graph, {
      id: `param:${param}`,
      kind: "target_param",
      label: param
    });
  }

  attachments.forEach((attachment, index) => {
    const attachId = `attach:${attachment.seq ?? index + 1}`;
    const evidence = `${attachment.api || "unknown"}@${attachment.seq ?? "none"}`;
    addAttachmentGraphNode(graph, {
      id: attachId,
      kind: "attachment_event",
      seq: attachment.seq ?? null,
      api: attachment.api || "",
      action: attachment.action || "observe"
    });

    for (const param of attachment.target_params || []) {
      addAttachmentGraphEdge(graph, {
        from: `param:${param}`,
        to: attachId,
        relation: "attached_by",
        evidence
      });
    }

    for (const ref of attachment.object_refs || []) {
      if (!objectRefs.includes(ref)) objectRefs.push(ref);
      const attachmentStage = attachmentStageName(attachment.phase);
      const stageRefs = objectRefsByStage.get(attachmentStage) || [];
      if (!stageRefs.includes(ref)) stageRefs.push(ref);
      objectRefsByStage.set(attachmentStage, stageRefs);
      addAttachmentGraphEdge(graph, {
        from: attachId,
        to: `ref:${ref}`,
        relation: "writes_object",
        evidence
      });
    }

    for (const ref of attachment.value_refs || []) {
      if (!valueRefs.includes(ref)) valueRefs.push(ref);
      addAttachmentGraphEdge(graph, {
        from: attachId,
        to: `value:${ref}`,
        relation: "observes_value_shape",
        evidence
      });
    }
  });

  for (const ref of objectRefs) {
    addAttachmentGraphNode(graph, {
      id: `ref:${ref}`,
      kind: "object_ref",
      ref
    });
  }
  for (const ref of valueRefs) {
    addAttachmentGraphNode(graph, {
      id: `value:${ref}`,
      kind: "value_ref",
      ref
    });
  }
  for (const stage of stageNamesForAttachmentGraph(flow)) {
    addAttachmentGraphNode(graph, {
      id: stageNodeId(stage),
      kind: "stage",
      stage
    });
  }

  for (const [stage, refs] of objectRefsByStage.entries()) {
    const to = stageNodeId(stage);
    for (const ref of refs) {
      addAttachmentGraphEdge(graph, {
        from: `ref:${ref}`,
        to,
        relation: "observed_in_stage",
        evidence: "attachment"
      });
    }
  }

  for (const link of flow.data_links || []) {
    if (link.to !== "signed_request") continue;
    const to = stageNodeId(link.to);
    for (const ref of link.refs || []) {
      if (!objectRefs.includes(ref)) continue;
      addAttachmentGraphEdge(graph, {
        from: `ref:${ref}`,
        to,
        relation: "flows_to_stage",
        evidence: "data_link"
      });
    }
  }

  for (const link of flow.inferred_data_links || []) {
    if (link.to !== "signed_request") continue;
    const to = stageNodeId(link.to);
    for (const ref of link.refs || []) {
      if (!valueRefs.includes(ref)) continue;
      addAttachmentGraphEdge(graph, {
        from: `value:${ref}`,
        to,
        relation: "inferred_to_stage",
        evidence: "inferred_data_link"
      });
    }
  }

  const {_nodeIds, _edgeIds, ...publicGraph} = graph;
  return publicGraph.nodes.length || publicGraph.edges.length ? publicGraph : null;
}

function generationRoleForStage(stage) {
  switch (stage) {
    case "input_url":
      return "input";
    case "request_construction":
      return "request_construction";
    case "request_headers":
      return "request_metadata";
    case "request_body":
      return "request_body";
    case "byte_buffer":
      return "material_read";
    case "dynamic_dispatch":
      return "control_flow";
    case "text_or_string_decode":
      return "string_material";
    case "integer_mixing":
    case "hash_or_digest":
    case "string_transform":
    case "url_encoding":
      return "transform";
    case "signature_mutation":
      return "parameter_attachment";
    case "signed_request":
      return "network_emit";
    case "anti_debug_timing_gate":
    case "source_integrity_probe":
    case "stack_trace_probe":
    case "exception_control_flow":
    case "regexp_probe":
      return "guard_or_probe";
    default:
      return "context";
  }
}

function attachmentStageName(phase) {
  return phase === "url_signature_mutation" ? "signature_mutation" : phase || "signature_mutation";
}

function generationAttachmentValueRefs(attachment) {
  return uniqueLimited([
    ...(attachment.value_refs || []),
    ...(attachment.target_params || []).map((param) => `target_params:${param}`)
  ], 8);
}

function generationAttachmentsForStage(flow, stageName) {
  return (flow.signature_attachment_events || [])
    .filter((attachment) => attachmentStageName(attachment.phase) === stageName)
    .map((attachment) => ({
      seq: attachment.seq ?? null,
      api: attachment.api || "",
      action: attachment.action || "observe",
      target_params: sortParamNames(attachment.target_params || []),
      object_refs: uniqueLimited(attachment.object_refs || [], 8),
      value_refs: generationAttachmentValueRefs(attachment)
    }));
}

function targetParamsForGenerationStage(flow, stage, attachments) {
  if (["signature_mutation", "request_headers", "request_body"].includes(stage.stage)) {
    return sortParamNames(uniqueLimited((attachments || []).flatMap((attachment) => attachment.target_params || []), 8));
  }
  if (stage.stage === "signed_request") {
    return sortParamNames(flow.target_params || []);
  }
  return [];
}

function generationRuntimeApisForStage(stage) {
  const apis = stage.runtime_apis || [];
  if (stage.stage === "input_url") {
    return uniqueLimited(apis.filter((api) => !actionForUrlMutationApi(api)), 12);
  }
  if (stage.stage === "signature_mutation") {
    return uniqueLimited(apis.filter((api) => actionForUrlMutationApi(api)), 12);
  }
  return uniqueLimited(apis, 12);
}

function runtimeEventRefsForGenerationStage(stage, runtimeApis) {
  const allowedApis = new Set(runtimeApis || []);
  if (!allowedApis.size) return [];
  return compactRuntimeEventRefs(
    (stage.runtime_event_refs || []).filter((event) => allowedApis.has(event.api || "")),
    12
  );
}

function generationSeqEndForStage(stage, runtimeApis) {
  if (stage.stage === "input_url" && runtimeApis.length !== (stage.runtime_apis || []).length) {
    return stage.seq_start ?? stage.seq_end ?? null;
  }
  return stage.seq_end ?? null;
}

function generationRelationToSignedRequest(start, end, signedPoint) {
  if (!Number.isFinite(signedPoint) || !Number.isFinite(start) || !Number.isFinite(end)) {
    return {
      relation: "unknown",
      distance: null
    };
  }
  if (start <= signedPoint && signedPoint <= end) {
    return {
      relation: "signed_request",
      distance: 0
    };
  }
  if (end < signedPoint) {
    return {
      relation: "before_signed_request",
      distance: signedPoint - end
    };
  }
  return {
    relation: "after_signed_request",
    distance: start - signedPoint
  };
}

function generationDistanceToSignedRequest(stage, seqStart, seqEnd, signedSeq, signedTrace) {
  const traceStart = stage.trace_start ?? null;
  const traceEnd = stage.trace_end ?? null;
  if (Number.isFinite(traceStart) && Number.isFinite(traceEnd) && Number.isFinite(signedTrace)) {
    const relation = generationRelationToSignedRequest(traceStart, traceEnd, signedTrace);
    return {
      relation: relation.relation,
      basis: "trace_index",
      trace_distance: relation.distance,
      seq_distance: null,
      trace_start: traceStart,
      trace_end: traceEnd
    };
  }

  const relation = generationRelationToSignedRequest(seqStart, seqEnd, signedSeq);
  return {
    relation: relation.relation,
    basis: Number.isFinite(relation.distance) ? "seq" : "unknown",
    trace_distance: null,
    seq_distance: relation.distance,
    trace_start: traceStart,
    trace_end: traceEnd
  };
}

function generationKeepsSourceDetails(role) {
  return role === "material_read" || role === "string_material" || role === "transform";
}

function generationEvidenceForStage(stage, attachmentEvents, runtimeApis, role) {
  const evidence = [];
  if ((runtimeApis || []).length) evidence.push("runtime_api");
  if ((stage.source_context_refs || []).length) evidence.push("source_context");
  if ((stage.object_refs || []).length) evidence.push("object_ref");
  if ((stage.value_refs || []).length || (attachmentEvents || []).some((event) => (event.value_refs || []).length)) {
    evidence.push("value_ref");
  }
  if (generationKeepsSourceDetails(role) && (stage.source_operators || []).length) evidence.push("source_operator");
  if (generationKeepsSourceDetails(role) && (stage.source_constants || []).length) evidence.push("source_constant");
  if ((attachmentEvents || []).length) evidence.push("attachment_event");
  return evidence;
}

function materialFlowSourceContextsByRef(flow) {
  const byRef = new Map();
  for (const context of flow.source_contexts || []) {
    const ref = sourceContextKey(context);
    if (ref && !byRef.has(ref)) byRef.set(ref, context);
  }
  return byRef;
}

function sourceLocationForGenerationStep(context, ref, flow) {
  const analysis = context?.analysis || {};
  return {
    ref,
    asset_id: context?.asset_id || "",
    url: context?.url || "",
    content_path: context?.content_path || "",
    function: flow.function || "",
    line_start: context?.line_start ?? null,
    line_end: context?.line_end ?? null,
    ...(context?.column_anchor !== undefined ? {column_anchor: context.column_anchor} : {}),
    ...(context?.column_start !== undefined ? {column_start: context.column_start} : {}),
    ...(context?.column_end !== undefined ? {column_end: context.column_end} : {}),
    signals: uniqueLimited([...(analysis.signals || [])].sort(), 8),
    calls: uniqueLimited(analysis.calls || [], 8),
    operators: uniqueLimited(analysis.operators || [], 8),
    numeric_literals: uniqueLimited(analysis.numeric_literals || [], 8)
  };
}

function sourceLocationsForGenerationStep(flow, contextByRef, sourceRefs) {
  return uniqueLimited(sourceRefs || [], 8)
    .map((ref) => {
      const context = contextByRef.get(ref);
      return context ? sourceLocationForGenerationStep(context, ref, flow) : null;
    })
    .filter(Boolean);
}

function materialGenerationSteps(flow) {
  const contextByRef = materialFlowSourceContextsByRef(flow);
  const signedStage = (flow.stages || []).find((stage) => stage.stage === "signed_request");
  const signedSeq = stageSeqStart(signedStage) ?? stageSeqEnd(signedStage);
  const signedTrace = signedStage?.trace_start ?? signedStage?.trace_end ?? null;
  return (flow.stages || []).slice(0, 12).map((stage, index) => {
    const attachmentEvents = generationAttachmentsForStage(flow, stage.stage);
    const runtimeApis = generationRuntimeApisForStage(stage);
    const runtimeEventRefs = runtimeEventRefsForGenerationStage(stage, runtimeApis);
    const role = generationRoleForStage(stage.stage);
    const seqStart = stage.seq_start ?? null;
    const seqEnd = generationSeqEndForStage(stage, runtimeApis);
    const signedRelation = generationDistanceToSignedRequest(stage, seqStart, seqEnd, signedSeq, signedTrace);
    const sourceContextRefs = uniqueLimited(stage.source_context_refs || [], 12);
    const objectRefs = uniqueLimited([
      ...(stage.object_refs || []),
      ...attachmentEvents.flatMap((event) => event.object_refs || [])
    ], 12);
    const valueRefs = compactGenerationValueRefs([
      ...(stage.value_refs || []),
      ...attachmentEvents.flatMap((event) => event.value_refs || [])
    ], 12, {preserveVmpStateRefs: stage.stage === "dynamic_dispatch"});
    const evidenceStage = {
      ...stage,
      object_refs: objectRefs,
      value_refs: valueRefs
    };
    return {
      id: `step_${index + 1}`,
      order: index + 1,
      stage: stage.stage || "unknown",
      role,
      seq_start: seqStart,
      seq_end: seqEnd,
      trace_start: signedRelation.trace_start,
      trace_end: signedRelation.trace_end,
      relation_to_signed_request: signedRelation.relation,
      distance_basis: signedRelation.basis,
      seq_distance_to_signed_request: signedRelation.seq_distance,
      trace_distance_to_signed_request: signedRelation.trace_distance,
      runtime_apis: runtimeApis,
      target_params: targetParamsForGenerationStage(flow, stage, attachmentEvents),
      evidence: generationEvidenceForStage(evidenceStage, attachmentEvents, runtimeApis, role),
      object_refs: objectRefs,
      value_refs: valueRefs,
      source_context_refs: sourceContextRefs,
      source_locations: sourceLocationsForGenerationStep(flow, contextByRef, sourceContextRefs),
      source_calls: uniqueLimited(stage.source_calls || [], 12),
      source_signals: uniqueLimited(stage.source_signals || [], 12),
      source_operators: generationKeepsSourceDetails(role) ? uniqueLimited(stage.source_operators || [], 12) : [],
      source_constants: generationKeepsSourceDetails(role) ? uniqueLimited(stage.source_constants || [], 12) : [],
      runtime_event_refs: runtimeEventRefs,
      attachment_events: attachmentEvents
    };
  });
}

function stageSourceCallsForAgentSummary(stage, step) {
  return uniqueLimited([
    ...(stage?.source_calls || []),
    ...((step?.source_locations || []).flatMap((location) => location.calls || []))
  ], 12);
}

function stageSourceSignalsForAgentSummary(stage, step) {
  return uniqueLimited([
    ...(stage?.source_signals || []),
    ...((step?.source_locations || []).flatMap((location) => location.signals || []))
  ], 12);
}

function vmpHookTypesForApi(api) {
  const family = vmpFamilyForApi(api || "");
  if (!family) return [];
  return VMP_HOOK_POINT_SPECS
    .filter((spec) => (spec.families || []).includes(family))
    .map((spec) => spec.type);
}

function sourceCallsForVmpHookRefSummary(type, stage, step, hookPoint) {
  const calls = [
    ...(stage?.source_calls || []),
    ...(step?.source_calls || []),
    ...(hookPoint?.source_calls || [])
  ];
  if (type === "vmp_dynamic_dispatch") {
    return uniqueLimited(calls.filter(isDynamicDispatchSourceCall), 8);
  }
  return uniqueLimited([
    ...stageSourceCallsForAgentSummary(stage, step),
    ...(hookPoint?.source_calls || [])
  ], 8);
}

function sourceSignalsForVmpHookRefSummary(type, stage, step, hookPoint) {
  const signals = [
    ...(stage?.source_signals || []),
    ...(step?.source_signals || []),
    ...(hookPoint?.source_signals || [])
  ];
  if (type === "vmp_dynamic_dispatch") {
    return uniqueLimited(signals.filter((signal) =>
      signal === "prototype_call" || signal === "dynamic_dispatch"
    ), 8);
  }
  return uniqueLimited([
    ...stageSourceSignalsForAgentSummary(stage, step),
    ...(hookPoint?.source_signals || [])
  ], 8);
}

function addVmpHookRefSummary(summaryByType, type, stage, step, hookPoint) {
  if (!type) return;
  if (!summaryByType.has(type)) {
    summaryByType.set(type, {
      type,
      status: hookPoint?.status || "observed",
      stages: new Set(),
      apis: new Set(),
      value_refs: [],
      object_refs: [],
      source_refs: [],
      source_calls: [],
      source_signals: []
    });
  }
  const summary = summaryByType.get(type);
  if (hookPoint?.status && summary.status !== "observed") {
    summary.status = hookPoint.status;
  }
  if (stage?.stage) summary.stages.add(stage.stage);
  for (const stageName of [
    ...(hookPoint?.observed_stages || []),
    ...(hookPoint?.source_stages || [])
  ]) {
    if (stageName) summary.stages.add(stageName);
  }
  for (const api of [
    ...(stage?.runtime_apis || []),
    ...(step?.runtime_apis || []),
    ...(hookPoint?.observed_apis || [])
  ]) {
    if (vmpHookTypesForApi(api).includes(type)) summary.apis.add(api);
  }
  summary.value_refs.push(...(stage?.value_refs || []), ...(step?.value_refs || []));
  summary.object_refs.push(...(stage?.object_refs || []), ...(step?.object_refs || []));
  summary.source_refs.push(...(stage?.source_context_refs || []), ...(step?.source_context_refs || []));
  summary.source_calls.push(...sourceCallsForVmpHookRefSummary(type, stage, step, hookPoint));
  summary.source_signals.push(...sourceSignalsForVmpHookRefSummary(type, stage, step, hookPoint));
}

function buildVmpHookRefSummary(stages, generationSteps, hookPoints) {
  const hookPointByType = new Map((hookPoints || []).map((point) => [point.type, point]));
  const summaryByType = new Map();
  for (const [index, stage] of (stages || []).entries()) {
    const step = (generationSteps || [])[index] || {};
    const types = uniqueLimited([
      ...(stage.runtime_apis || []).flatMap(vmpHookTypesForApi),
      ...(step.runtime_apis || []).flatMap(vmpHookTypesForApi),
      ...VMP_HOOK_POINT_SPECS
        .filter((spec) =>
          sourceCallsForHookPoint(stage, spec.type).length ||
          sourceSignalsForHookPoint(stage, spec.type).length ||
          stageImpliesVmpHookPoint(stage.stage, spec.type))
        .map((spec) => spec.type)
    ], VMP_HOOK_POINT_SPECS.length);
    for (const type of types) {
      addVmpHookRefSummary(summaryByType, type, stage, step, hookPointByType.get(type));
    }
  }
  return VMP_HOOK_POINT_SPECS
    .map((spec) => summaryByType.get(spec.type))
    .filter(Boolean)
    .map((summary) => ({
      type: summary.type,
      status: summary.status,
      stages: uniqueLimited([...summary.stages], 8),
      apis: uniqueLimited([...summary.apis], 8),
      value_refs: uniquePrioritizedLimited(
        summary.value_refs,
        12,
        (ref) => vmpHookValueRefRank(summary.type, ref)
      ),
      object_refs: uniquePrioritizedLimited(summary.object_refs, 12, generationPathObjectRefRank),
      source_refs: uniqueLimited(summary.source_refs, 8),
      source_calls: uniqueLimited(summary.source_calls, 8),
      source_signals: uniqueLimited(summary.source_signals, 8)
    }));
}

function vmpHookValueRefRank(type, ref) {
  const value = String(ref || "");
  if (type === "vmp_array_table") {
    if (/^(?:array|array_before|typed_array):/.test(value)) return 0;
    if (/^(?:string|separator):length:/.test(value)) return 1;
    if (value.startsWith("number:")) return 2;
    if (value.startsWith("register:")) return 20;
    if (value.startsWith("handler_return:") || value.startsWith("handler_arg:")) return 21;
    return 50;
  }
  return generationPathValueRefRank(ref);
}

function materialFlowEvidenceProfile(runtimeApis, sourceCalls, sourceSignals, generationSteps, hookPoints) {
  const hasRuntime = runtimeApis.length ||
    (hookPoints || []).some((point) => point.status === "observed" && (point.observed_apis || []).length);
  const hasSource = sourceCalls.length ||
    sourceSignals.length ||
    (generationSteps || []).some((step) => (step.source_context_refs || []).length) ||
    (hookPoints || []).some((point) => point.status === "source_observed");
  if (hasRuntime && hasSource) return "runtime_and_source";
  if (hasRuntime) return "runtime_only";
  if (hasSource) return "source_only";
  return "no_evidence";
}

function buildAgentGenerationSummary(flow, generationSteps, hookPoints, readiness) {
  const stages = (flow.stages || []).slice(0, 12);
  const runtimeApis = uniqueLimited([
    ...(generationSteps || []).flatMap((step) => step.runtime_apis || []),
    ...stages.flatMap((stage) => stage.runtime_apis || [])
  ], 24);
  const sourceCalls = uniqueLimited(stages.flatMap((stage, index) =>
    stageSourceCallsForAgentSummary(stage, (generationSteps || [])[index])), 24);
  const sourceSignals = uniqueLimited(stages.flatMap((stage, index) =>
    stageSourceSignalsForAgentSummary(stage, (generationSteps || [])[index])), 24);
  const sourceObservedHooks = uniqueLimited((hookPoints || [])
    .filter((point) => point.status === "source_observed")
    .map((point) => point.type)
    .filter(Boolean), 16);
  const runtimeObservedHooks = uniqueLimited((hookPoints || [])
    .filter((point) => point.status === "observed")
    .map((point) => point.type)
    .filter(Boolean), 16);
  const attachmentParams = sortParamNames(uniqueLimited((flow.signature_attachment_events || [])
    .flatMap((event) => event.target_params || []), 16));
  const signatureParamMaterializations = compactSignatureParamMaterializations(
    flow.signature_param_materializations || []
  );
  const stageChain = stages.map((stage) => stage.stage || "unknown");
  const vmpHookRefSummary = buildVmpHookRefSummary(stages, generationSteps || [], hookPoints || []);

  return {
    stage_chain: stageChain,
    summary_text: stageChain.join(" -> "),
    target_params: sortParamNames(flow.target_params || []),
    evidence_profile: materialFlowEvidenceProfile(runtimeApis, sourceCalls, sourceSignals, generationSteps, hookPoints),
    readiness: readiness?.status || "unknown",
    runtime_apis: runtimeApis,
    source_calls: sourceCalls,
    source_signals: sourceSignals,
    source_observed_hooks: sourceObservedHooks,
    runtime_observed_hooks: runtimeObservedHooks,
    vmp_hook_ref_summary: vmpHookRefSummary,
    attachment_params: attachmentParams,
    signature_param_materializations: signatureParamMaterializations,
    data_link_count: (flow.data_links || []).length,
    inferred_data_link_count: (flow.inferred_data_links || []).length,
    steps: (generationSteps || []).slice(0, 12).map((step, index) => ({
      order: step.order ?? index + 1,
      stage: step.stage || "unknown",
      role: step.role || "context",
      evidence: uniqueLimited(step.evidence || [], 8),
      runtime_apis: uniqueLimited(step.runtime_apis || [], 8),
      source_context_refs: uniqueLimited(step.source_context_refs || [], 8),
      source_calls: uniqueLimited(step.source_calls || [], 8),
      source_signals: uniqueLimited(step.source_signals || [], 8),
      source_operators: uniqueLimited(step.source_operators || [], 8),
      source_constants: uniqueLimited(step.source_constants || [], 8),
      runtime_event_refs: compactRuntimeEventRefs(step.runtime_event_refs || [], 8),
      target_params: sortParamNames(step.target_params || []),
      object_refs: uniquePrioritizedLimited(
        step.object_refs || [],
        step.stage === "dynamic_dispatch" ? 16 : 8,
        generationPathObjectRefRank
      ),
      value_refs: compactGenerationValueRefs(
        step.value_refs || [],
        step.stage === "dynamic_dispatch" ? 24 : 8,
        {preserveVmpStateRefs: step.stage === "dynamic_dispatch"}
      ),
      relation_to_signed_request: step.relation_to_signed_request || "unknown"
    }))
  };
}

function agentStageTraceRole(step) {
  if (step?.role === "material_read" || step?.role === "string_material") {
    return "material";
  }
  return step?.role || "context";
}

function agentStageTraceDistance(step) {
  const distance = step?.trace_distance_to_signed_request ?? step?.seq_distance_to_signed_request;
  return Number.isFinite(distance) ? distance : null;
}

function agentStageTraceParamRelation(observedParams, targetParams) {
  if (observedParams.length) return "direct_observed";
  if (targetParams.length) return "flow_target";
  return "none";
}

function buildAgentStageTrace(generationSteps, targetParams = []) {
  const flowTargetParams = sortParamNames(targetParams || []);
  return (generationSteps || []).slice(0, 12).map((step, index) => {
    const observedParams = sortParamNames(step.target_params || []);
    const stageTargetParams = observedParams.length ? observedParams : flowTargetParams;
    return {
      order: step.order ?? index + 1,
      stage: step.stage || "unknown",
      role: agentStageTraceRole(step),
      ...(step.seq_start !== undefined ? {seq_start: step.seq_start} : {}),
      ...(step.seq_end !== undefined ? {seq_end: step.seq_end} : {}),
      apis: uniqueLimited(step.runtime_apis || [], 8),
      evidence: uniqueLimited(step.evidence || [], 8),
      relation: step.relation_to_signed_request || "unknown",
      distance_to_signed_request: agentStageTraceDistance(step),
      distance_basis: step.distance_basis || "unknown",
      params: observedParams,
      target_params: stageTargetParams,
      param_relation: agentStageTraceParamRelation(observedParams, flowTargetParams),
      source_refs: uniqueLimited(step.source_context_refs || [], 6),
      source_calls: uniqueLimited(step.source_calls || [], 6),
      source_signals: uniqueLimited(step.source_signals || [], 6),
      source_operators: uniqueLimited(step.source_operators || [], 6),
      source_constants: uniqueLimited(step.source_constants || [], 6),
      runtime_event_refs: compactRuntimeEventRefs(step.runtime_event_refs || [], 8),
      object_refs: uniquePrioritizedLimited(
        step.object_refs || [],
        step.stage === "dynamic_dispatch" ? 16 : 6,
        generationPathObjectRefRank
      ),
      value_refs: compactGenerationValueRefs(
        step.value_refs || [],
        step.stage === "dynamic_dispatch" ? 24 : 6,
        {preserveVmpStateRefs: step.stage === "dynamic_dispatch"}
      )
    };
  });
}

function requestContextForMaterialFlow(flow) {
  const events = (flow.event_windows || []).flatMap((window) => window.events || []);
  const browserEvent = events.find((event) => event.api === "BrowserNetwork.request") ||
    events.find((event) => networkRequestInfoFromEvent(event)?.api === "BrowserNetwork.request");
  if (!browserEvent) return null;

  const info = networkRequestInfoFromEvent(browserEvent);
  if (!info) return null;
  const context = summarizeNetworkRequestContext(info, browserEvent, flow.renderer_request_link || null);
  const summary = summarizeCandidateChainRequestContext(context);
  return Object.keys(summary).length ? summary : null;
}

function materialFlowFromSubflow(flow, subflow, index, assetSourcesById = new Map()) {
  const resourceClass = flow.resource_class || networkResourceClassForEndpoint(flow.endpoint || "");
  const assetDerived = sourceOnlyMaterialStagesForAssets(
    uniqueLimited([subflow.asset_id, ...(flow.assets || []).map((asset) => asset.asset_id)].filter(Boolean), 8),
    assetSourcesById
  );
  const pipeline = subflow.candidate_signature_pipeline || {};
  const stages = mergeMaterialStages(
    (pipeline.stages || []).map(normalizeMaterialStage),
    [
      ...observedRequestMaterialStages(flow),
      ...observedVmpMaterialStages(flow),
      ...siblingSubflowMaterialStages(flow, subflow),
      ...assetDerived.stages
    ]
  );
  const dataLinks = buildPipelineDataLinks(stages);
  const inferredDataLinks = buildPipelineInferredDataLinks(stages, dataLinks);
  const sourceContexts = [
    ...assetDerived.contexts,
    ...(subflow.source_contexts || [])
  ];
  const requestContext = requestContextForMaterialFlow(flow);
  return {
    id: `material_flow_${index + 1}`,
    flow_id: flow.id || "",
    endpoint: flow.endpoint || "",
    match: flow.match || "",
    ...(resourceClass ? {resource_class: resourceClass} : {}),
    business_relevance: businessRelevanceForResourceClass(resourceClass),
    confidence: pipeline.confidence || subflow.confidence || flow.evidence_level || "low",
    evidence_status: subflow.evidence_status || "unknown",
    function: subflow.function || "",
    stack_url: subflow.stack_url || "",
    asset_id: subflow.asset_id || "",
    seq_start: subflow.seq_start ?? null,
    seq_end: subflow.seq_end ?? null,
    target_params: flow.signature_params || [],
    supporting_params: flow.supporting_params || [],
    stage_count: stages.length,
    stages,
    data_links: dataLinks,
    _request_input_event_windows: flow.event_windows || [],
    ...(inferredDataLinks.length ? {inferred_data_links: inferredDataLinks} : {}),
    ...(flow.renderer_request_link ? {renderer_request_link: flow.renderer_request_link} : {}),
    ...(requestContext ? {request_context: requestContext} : {}),
    signature_attachment_events: signatureAttachmentEventsForFlow(flow),
    signature_param_materializations: signatureParamMaterializationsForFlow(flow),
    source_context_refs: sourceContextRefsForContexts(sourceContexts),
    source_contexts: sourceContextsForMaterialFlow(sourceContexts),
    capture_recommendations: flow.capture_recommendations || [],
    next_questions: flow.next_questions || []
  };
}

function materialFlowFromObservedFlow(flow, index, assetSourcesById = new Map()) {
  const resourceClass = flow.resource_class || networkResourceClassForEndpoint(flow.endpoint || "");
  const assetDerived = sourceOnlyMaterialStagesForAssets(
    uniqueLimited([
      flow.stack_clusters?.[0]?.asset_id,
      ...(flow.assets || []).map((asset) => asset.asset_id)
    ].filter(Boolean), 8),
    assetSourcesById
  );
  const stages = mergeMaterialStages(
    (flow.event_windows || [])
      .map(stageFromEventWindow)
      .map(normalizeMaterialStage),
    assetDerived.stages
  );
  const inferredDataLinks = buildPipelineInferredDataLinks(stages, []);
  const seqs = (flow.event_windows || [])
    .flatMap((window) => [window.seq_start, window.seq_end])
    .filter((seq) => Number.isFinite(seq));
  const sourceContexts = [];
  const sourceContextRefs = [];
  const seen = new Set();
  for (const context of assetDerived.contexts) {
    const key = sourceContextKey(context);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    sourceContextRefs.push(key);
    sourceContexts.push(context);
  }
  for (const window of flow.event_windows || []) {
    for (const context of window.source_contexts || []) {
      const key = sourceContextKey(context);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      sourceContextRefs.push(key);
      sourceContexts.push(context);
      if (sourceContexts.length >= SOURCE_CONTEXTS_PER_WINDOW) break;
    }
    if (sourceContexts.length >= SOURCE_CONTEXTS_PER_WINDOW) break;
  }
  const requestContext = requestContextForMaterialFlow(flow);

  return {
    id: `material_flow_${index + 1}`,
    flow_id: flow.id || "",
    endpoint: flow.endpoint || "",
    match: flow.match || "",
    ...(resourceClass ? {resource_class: resourceClass} : {}),
    business_relevance: businessRelevanceForResourceClass(resourceClass),
    confidence: flow.evidence_level || "low",
    evidence_status: "observed_flow",
    function: flow.stack_clusters?.[0]?.function || "",
    stack_url: flow.stack_clusters?.[0]?.stack_url || "",
    asset_id: flow.stack_clusters?.[0]?.asset_id || "",
    seq_start: seqs.length ? Math.min(...seqs) : flow.seq_range?.start ?? null,
    seq_end: seqs.length ? Math.max(...seqs) : flow.seq_range?.end ?? null,
    target_params: flow.signature_params || [],
    supporting_params: flow.supporting_params || [],
    stage_count: stages.length,
    stages,
    data_links: [],
    _request_input_event_windows: flow.event_windows || [],
    ...(inferredDataLinks.length ? {inferred_data_links: inferredDataLinks} : {}),
    ...(flow.renderer_request_link ? {renderer_request_link: flow.renderer_request_link} : {}),
    ...(requestContext ? {request_context: requestContext} : {}),
    signature_attachment_events: signatureAttachmentEventsForFlow(flow),
    signature_param_materializations: signatureParamMaterializationsForFlow(flow),
    source_context_refs: sourceContextRefs,
    source_contexts: sourceContextsForMaterialFlow(sourceContexts),
    capture_recommendations: flow.capture_recommendations || [],
    next_questions: flow.next_questions || []
  };
}

function rendererRequestLinkFromCandidateChain(chain) {
  const renderer = (chain.steps || []).find((step) => step.phase === "request_construction");
  if (!renderer) return null;
  return {
    trace_index: renderer.trace_index ?? null,
    seq: renderer.seq ?? null,
    api: renderer.api || "",
    method: renderer.method || chain.method || "",
    endpoint: renderer.endpoint || chain.endpoint || "",
    relation: renderer.relation || "",
    trace_distance: renderer.trace_distance ?? null,
    function: renderer.function || "",
    stack_url: renderer.stack_url || "",
    asset_id: renderer.asset_id || "",
    confidence: renderer.confidence || "medium",
    match: renderer.match || "endpoint_method_trace_window"
  };
}

function materialFlowFromAbsentCandidateChain(chain, index) {
  const resourceClass = chain.resource_class || networkResourceClassForEndpoint(chain.endpoint || "", chain.method || "GET");
  const pipeline = chain.candidate_signature_pipeline || {};
  const stages = (pipeline.stages || []).map(normalizeMaterialStage);
  const inferredDataLinks = inferredDataLinksForCandidateChain(chain, pipeline.data_links || []);
  const seqs = (chain.steps || [])
    .map((step) => step.seq)
    .filter((seq) => Number.isFinite(seq));
  const stackStep = (chain.steps || []).find((step) => step.function || step.stack_url || step.asset_id) || {};
  const rendererRequestLink = rendererRequestLinkFromCandidateChain(chain);

  return {
    id: `material_flow_${index + 1}`,
    flow_id: chain.id || "",
    endpoint: chain.endpoint || "",
    match: "signature_absent_candidate",
    confidence: chain.confidence || pipeline.confidence || "low",
    evidence_status: "signature_absent_candidate",
    ...(resourceClass ? {resource_class: resourceClass} : {}),
    business_relevance: businessRelevanceForResourceClass(resourceClass),
    function: stackStep.function || "",
    stack_url: stackStep.stack_url || "",
    asset_id: stackStep.asset_id || "",
    seq_start: seqs.length ? Math.min(...seqs) : null,
    seq_end: seqs.length ? Math.max(...seqs) : null,
    target_params: SIGNATURE_TERMS,
    supporting_params: [],
    stage_count: stages.length,
    stages,
    data_links: pipeline.data_links || [],
    ...(inferredDataLinks.length ? {inferred_data_links: inferredDataLinks} : {}),
    ...(rendererRequestLink ? {renderer_request_link: rendererRequestLink} : {}),
    ...(chain.request_context ? {request_context: chain.request_context} : {}),
    source_context_refs: chain.source_context_refs || [],
    source_contexts: sourceContextsForMaterialFlow(chain.source_contexts || []),
    capture_recommendations: [],
    next_questions: ["signature_terms_not_observed"]
  };
}

function buildSignatureMaterialFlows(
  flows,
  signatureAbsent = null,
  assetSourcesById = new Map(),
  allEvents = [],
  vmpScalarRefChains = []
) {
  const materialFlows = [];
  for (const flow of flows || []) {
    const subflows = (flow.suspected_signature_subflows || [])
      .filter((subflow) => subflow.candidate_signature_pipeline?.stage_count > 0)
      .sort((a, b) =>
        (b.candidate_signature_pipeline?.stage_count || 0) - (a.candidate_signature_pipeline?.stage_count || 0) ||
        (a.seq_start ?? Number.MAX_SAFE_INTEGER) - (b.seq_start ?? Number.MAX_SAFE_INTEGER) ||
        String(a.function).localeCompare(String(b.function)));

    if (subflows.length) {
      materialFlows.push(materialFlowFromSubflow(flow, subflows[0], materialFlows.length, assetSourcesById));
      continue;
    }

    if ((flow.event_windows || []).length) {
      materialFlows.push(materialFlowFromObservedFlow(flow, materialFlows.length, assetSourcesById));
    }
  }

  const absentKeys = new Set();
  for (const chain of signatureAbsent?.candidate_trace_chains || []) {
    if (!chain.candidate_signature_pipeline?.stage_count) continue;
    const candidate = materialFlowFromAbsentCandidateChain(chain, materialFlows.length);
    const key = [
      candidate.endpoint,
      candidate.function,
      candidate.stack_url,
      candidate.asset_id
    ].join("\u0000");
    if (absentKeys.has(key)) continue;
    absentKeys.add(key);
    materialFlows.push(candidate);
  }

  return materialFlows.slice(0, 12).map((flow, index) => {
    const baseFinalized = finalizeMaterialFlow(flow);
    const requestInputBundle = buildRequestInputBundleForMaterialFlow(baseFinalized, allEvents);
    const webcryptoSignatureSummary = buildWebCryptoSignatureSummaryForFlow(baseFinalized, allEvents);
    const {_request_input_event_windows, ...publicFinalizedBase} = baseFinalized;
    const finalized = {
      ...publicFinalizedBase,
      id: `material_flow_${index + 1}`,
      ...(requestInputBundle ? {request_input_bundle: requestInputBundle} : {}),
      ...(webcryptoSignatureSummary ? {webcrypto_signature_summary: webcryptoSignatureSummary} : {})
    };
    const scalarChainLinks = scalarChainLinksForMaterialFlow(finalized, vmpScalarRefChains);
    return scalarChainLinks.length
      ? {...finalized, vmp_scalar_chain_links: scalarChainLinks}
      : finalized;
  });
}

function ensureSignatureSourceCandidate(candidates, flow, step, location) {
  const key = [
    location.function || flow.function || "",
    location.asset_id || "",
    location.ref || ""
  ].join("\u0000");
  const candidate = candidates.get(key) || {
    function: location.function || flow.function || "",
    asset_id: location.asset_id || "",
    url: location.url || "",
    content_path: location.content_path || "",
    sourceRefs: new Set(),
    flowIds: new Set(),
    endpoints: new Set(),
    stages: [],
    stageSet: new Set(),
    runtimeApis: new Set(),
    targetParams: new Set(),
    signals: new Set(),
    calls: new Set(),
    operators: new Set(),
    numericLiterals: new Set(),
    priorityReasons: new Set(),
    distanceBasisSet: new Set(),
    resourceClasses: new Set(),
    businessRelevanceSet: new Set(),
    minDistance: null,
    step_count: 0
  };
  candidates.set(key, candidate);
  return candidate;
}

function addStageToSourceCandidate(candidate, stage) {
  if (!stage || candidate.stageSet.has(stage)) return;
  candidate.stageSet.add(stage);
  candidate.stages.push(stage);
}

function addDistanceToSourceCandidate(candidate, step) {
  const distance = step.trace_distance_to_signed_request ?? step.seq_distance_to_signed_request;
  if (!Number.isFinite(distance)) return;
  candidate.minDistance = candidate.minDistance === null
    ? distance
    : Math.min(candidate.minDistance, distance);
  if (step.distance_basis) candidate.distanceBasisSet.add(step.distance_basis);
}

function sourceCandidatePriorityReasons(candidate) {
  const reasons = [];
  if (candidate.flowIds.size > 1) reasons.push("multiple_flows");
  if (candidate.targetParams.size) reasons.push("target_param_seen");
  if (candidate.stageSet.has("signature_mutation")) reasons.push("parameter_attachment");
  if (candidate.signals.size) reasons.push("source_signals");
  if (candidate.minDistance !== null && candidate.minDistance <= 2) reasons.push("near_signed_request");
  if (candidate.resourceClasses.has("telemetry_endpoint")) reasons.push("deprioritized_telemetry_endpoint");
  if (candidate.resourceClasses.has("static_resource")) reasons.push("deprioritized_static_resource");
  if (candidate.resourceClasses.has("document_request")) reasons.push("deprioritized_document_request");
  if (candidateHasOnlyLowValueEndpoints(candidate)) reasons.push("deprioritized_low_value_endpoint");
  if (isBrowserInternalSourceCandidate(candidate)) reasons.push("deprioritized_internal_runtime");
  return reasons;
}

function candidateHasOnlyLowValueEndpoints(candidate) {
  return candidate.resourceClasses.size > 0 &&
    [...candidate.resourceClasses].every((resourceClass) => isLowValueNetworkResourceClass(resourceClass));
}

function sourceCandidateBusinessRelevance(candidate) {
  if (!candidateHasOnlyLowValueEndpoints(candidate)) return "business_api_candidate";
  if (candidate.resourceClasses.has("telemetry_endpoint")) return "low_value_telemetry";
  if (candidate.resourceClasses.has("static_resource")) return "low_value_static_resource";
  if (candidate.resourceClasses.has("document_request")) return "low_value_document_request";
  return "low_value_endpoint";
}

function sourceCandidateEvidenceScore(candidate, reasons) {
  const rawScore = candidate.flowIds.size * 100 +
    candidate.step_count * 10 +
    candidate.targetParams.size * 20 +
    (reasons.includes("parameter_attachment") ? 30 : 0) +
    candidate.signals.size * 5 +
    (reasons.includes("near_signed_request") ? 10 : 0);
  const lowValuePenalty = reasons.includes("deprioritized_low_value_endpoint") ? 320 : 0;
  const internalPenalty = reasons.includes("deprioritized_internal_runtime") ? 250 : 0;
  return Math.max(0, rawScore - lowValuePenalty - internalPenalty);
}

function preferredSourceCandidateDistanceBasis(candidate) {
  if (candidate.distanceBasisSet.has("trace_index")) return "trace_index";
  if (candidate.distanceBasisSet.has("seq")) return "seq";
  return "";
}

function isBrowserInternalSourceCandidate(candidate) {
  const functionName = String(candidate.function || "");
  const url = String(candidate.url || "");
  const contentPath = String(candidate.content_path || "");
  return functionName.startsWith("mojo.internal.") ||
    url.startsWith("chrome://") ||
    url.startsWith("devtools://") ||
    contentPath.includes("/mojo/") ||
    contentPath.endsWith("/bindings.js");
}

function buildSignatureSourceCandidates(materialFlows) {
  const candidates = new Map();
  for (const flow of materialFlows || []) {
    for (const step of flow.generation_steps || []) {
      for (const location of step.source_locations || []) {
        const candidate = ensureSignatureSourceCandidate(candidates, flow, step, location);
        candidate.sourceRefs.add(location.ref || "");
        if (flow.id) candidate.flowIds.add(flow.id);
        if (flow.endpoint) candidate.endpoints.add(flow.endpoint);
        if (flow.resource_class) candidate.resourceClasses.add(flow.resource_class);
        if (flow.business_relevance) candidate.businessRelevanceSet.add(flow.business_relevance);
        candidate.step_count += 1;
        addStageToSourceCandidate(candidate, step.stage);
        addDistanceToSourceCandidate(candidate, step);
        for (const api of step.runtime_apis || []) candidate.runtimeApis.add(api);
        for (const param of step.target_params || []) candidate.targetParams.add(param);
        for (const signal of location.signals || []) candidate.signals.add(signal);
        for (const call of location.calls || []) candidate.calls.add(call);
        for (const operator of location.operators || []) candidate.operators.add(operator);
        for (const literal of location.numeric_literals || []) candidate.numericLiterals.add(literal);
      }
    }
  }

  return [...candidates.values()]
    .map((candidate) => {
      const priorityReasons = sourceCandidatePriorityReasons(candidate);
      const evidenceScore = sourceCandidateEvidenceScore(candidate, priorityReasons);
      const businessRelevance = sourceCandidateBusinessRelevance(candidate);
      return {
        function: candidate.function,
        asset_id: candidate.asset_id,
        url: candidate.url,
        content_path: candidate.content_path,
        source_refs: sortedValues(candidate.sourceRefs),
        flow_ids: sortedValues(candidate.flowIds),
        flow_count: candidate.flowIds.size,
        step_count: candidate.step_count,
        evidence_score: evidenceScore,
        target_params: sortParamNames([...candidate.targetParams]),
        endpoints: sortedValues(candidate.endpoints),
        resource_classes: sortedValues(candidate.resourceClasses),
        business_relevance: businessRelevance,
        stages: candidate.stages,
        runtime_apis: sortedValues(candidate.runtimeApis),
        signals: sortedValues(candidate.signals),
        calls: sortedValues(candidate.calls),
        operators: sortedValues(candidate.operators),
        numeric_literals: sortedValues(candidate.numericLiterals),
        min_distance_to_signed_request: candidate.minDistance,
        distance_basis: preferredSourceCandidateDistanceBasis(candidate),
        priority_reasons: priorityReasons
      };
    })
    .sort((a, b) =>
      b.evidence_score - a.evidence_score ||
      b.flow_count - a.flow_count ||
      b.step_count - a.step_count ||
      String(a.function).localeCompare(String(b.function)) ||
      String(a.asset_id).localeCompare(String(b.asset_id)) ||
      String(a.source_refs[0] || "").localeCompare(String(b.source_refs[0] || "")))
    .slice(0, 12)
    .map((candidate, index) => ({
      id: `source_candidate_${index + 1}`,
      rank: index + 1,
      ...candidate
    }));
}

function lineRangeFromSourceRef(ref, contentPath = "") {
  const parsed = parseSourceRef(ref);
  if (!parsed.asset_id || parsed.line_start === null || parsed.line_end === null) return null;
  return {
    ref,
    content_path: contentPath || "",
    line_start: parsed.line_start,
    line_end: parsed.line_end
  };
}

function compactAgentSourcePreview(value, maxChars = AGENT_SOURCE_PREVIEW_MAX_CHARS) {
  const preview = preserveSignatureText(String(value || ""))
    .replace(/\s+/g, " ")
    .trim();
  if (!preview) return "";
  return preview.length > maxChars
    ? `${preview.slice(0, maxChars)}...`
    : preview;
}

function agentSourcePreviewForRef(ref, assetSourcesById) {
  const parsed = parseSourceRef(ref);
  if (!parsed.asset_id || parsed.line_start === null || parsed.line_end === null) return "";
  const source = assetSourcesById?.get(parsed.asset_id);
  if (!source?.content) return "";
  if (parsed.char_start !== null) {
    return sourcePreviewFromTextForParsedRef(parsed, source.content);
  }
  const lines = String(source.content).split(/\r?\n/);
  if (!lines.length) return "";
  const start = Math.max(1, Math.min(parsed.line_start, lines.length));
  const end = Math.max(start, Math.min(parsed.line_end, lines.length));
  return compactAgentSourcePreview(lines.slice(start - 1, end).join("\n"));
}

function lineRangesForSourceCandidate(candidate, assetSourcesById = new Map()) {
  return (candidate.source_refs || [])
    .map((ref) => {
      const range = lineRangeFromSourceRef(ref, candidate.content_path || "");
      if (!range) return null;
      const preview = agentSourcePreviewForRef(ref, assetSourcesById);
      return preview ? {...range, preview} : range;
    })
    .filter(Boolean);
}

function nextQuestionsForSourceCandidate(candidate) {
  const questions = ["which_inputs_feed_this_source_window"];
  if ((candidate.stages || []).includes("signature_mutation")) {
    questions.push("which_runtime_step_attaches_target_params");
  } else {
    questions.push("where_are_target_params_attached");
  }
  if ((candidate.endpoints || []).length) {
    questions.push("which_request_endpoint_uses_this_candidate");
  }
  if (isBrowserInternalSourceCandidate(candidate)) {
    questions.push("which_page_script_calls_this_internal_runtime");
  }
  return uniqueLimited(questions, 6);
}

function generationPathStepSourceRefs(step) {
  return uniqueLimited([
    ...(step.source_locations || []).map((location) => location.ref || "").filter(Boolean),
    ...(step.source_context_refs || [])
  ], 8);
}

function generationPathStepLabel(step) {
  const seq = step.seq_start ?? "none";
  const api = (step.runtime_apis || [])[0] || "none";
  return `${step.stage || "unknown"}[${api}@${seq}]`;
}

function generationPathBounds(flow) {
  const steps = flow.generation_steps || [];
  const inputStep = steps.find((step) => step.stage === "input_url") || {};
  const signedStep = steps.find((step) => step.stage === "signed_request") || {};
  return {
    start_seq: inputStep.seq_start ?? inputStep.seq_end ?? null,
    signed_seq: signedStep.seq_start ?? signedStep.seq_end ?? null
  };
}

function sequenceInsideBounds(seq, bounds) {
  if (!Number.isFinite(seq)) return false;
  if (Number.isFinite(bounds.start_seq) && seq < bounds.start_seq) return false;
  if (Number.isFinite(bounds.signed_seq) && seq > bounds.signed_seq) return false;
  return true;
}

function displaySeqForGenerationStep(step, bounds) {
  const seqStart = step.seq_start ?? null;
  const seqEnd = step.seq_end ?? null;
  if (sequenceInsideBounds(seqStart, bounds)) return seqStart;
  if (sequenceInsideBounds(seqEnd, bounds)) return seqEnd;
  return seqStart ?? seqEnd;
}

function generationStepFitsPath(step, bounds) {
  if (step.distance_basis === "trace_index") return true;
  if (!Number.isFinite(bounds.start_seq) || !Number.isFinite(bounds.signed_seq)) return true;
  const displaySeq = displaySeqForGenerationStep(step, bounds);
  if (!Number.isFinite(displaySeq)) return true;
  return sequenceInsideBounds(displaySeq, bounds);
}

function generationStepRelationToSigned(step, displaySeq, bounds) {
  if (step.distance_basis === "trace_index") return step.relation_to_signed_request || "unknown";
  if (!Number.isFinite(displaySeq) || !Number.isFinite(bounds.signed_seq)) {
    return step.relation_to_signed_request || "unknown";
  }
  if (displaySeq === bounds.signed_seq) return "signed_request";
  return displaySeq < bounds.signed_seq ? "before_signed_request" : "after_signed_request";
}

function generationStepDistanceToSigned(step, displaySeq, bounds) {
  if (step.distance_basis === "trace_index") {
    return step.trace_distance_to_signed_request ?? null;
  }
  if (Number.isFinite(displaySeq) && Number.isFinite(bounds.signed_seq)) {
    return Math.abs(bounds.signed_seq - displaySeq);
  }
  return step.trace_distance_to_signed_request ?? step.seq_distance_to_signed_request ?? null;
}

function reviewGenerationStep(step, bounds) {
  const displaySeq = displaySeqForGenerationStep(step, bounds);
  const distance = generationStepDistanceToSigned(step, displaySeq, bounds);
  return {
    id: step.id || "",
    order: step.order ?? null,
    stage: step.stage || "unknown",
    role: step.role || "unknown",
    seq_start: displaySeq ?? null,
    seq_end: displaySeq ?? null,
    trace_start: step.trace_start ?? null,
    trace_end: step.trace_end ?? null,
    runtime_apis: step.runtime_apis || [],
    target_params: step.target_params || [],
    evidence: step.evidence || [],
    object_refs: step.object_refs || [],
    value_refs: step.value_refs || [],
    source_refs: generationPathStepSourceRefs(step),
    source_calls: uniqueLimited(step.source_calls || [], 8),
    source_signals: uniqueLimited(step.source_signals || [], 8),
    source_operators: step.source_operators || [],
    source_constants: step.source_constants || [],
    runtime_event_refs: compactRuntimeEventRefs(step.runtime_event_refs || [], 8),
    relation_to_signed_request: generationStepRelationToSigned(step, displaySeq, bounds),
    distance_basis: step.distance_basis || "",
    distance_to_signed_request: distance,
    attachment_events: (step.attachment_events || []).map((event) => ({
      seq: event.seq ?? null,
      api: event.api || "",
      action: event.action || "",
      target_params: event.target_params || [],
      object_refs: event.object_refs || [],
      value_refs: event.value_refs || []
    }))
  };
}

function reviewGenerationStepSortKey(step) {
  if (Number.isFinite(step?.seq_start)) return step.seq_start;
  return Number.MAX_SAFE_INTEGER;
}

function compareReviewGenerationSteps(a, b) {
  const urlSignatureOrder = compareUrlSignatureBoundaryStepsBySeq(a, b);
  if (urlSignatureOrder !== 0) return urlSignatureOrder;
  return generationPathStageOrder(a) - generationPathStageOrder(b) ||
    reviewGenerationStepSortKey(a) - reviewGenerationStepSortKey(b) ||
    String(a?.stage || "").localeCompare(String(b?.stage || ""));
}

function compareUrlSignatureBoundaryStepsBySeq(a, b) {
  const stages = new Set([a?.stage || "", b?.stage || ""]);
  if (!stages.has("url_encoding") || !stages.has("signature_mutation")) return 0;
  const leftSeq = reviewGenerationStepSortKey(a);
  const rightSeq = reviewGenerationStepSortKey(b);
  if (!Number.isFinite(leftSeq) || !Number.isFinite(rightSeq) || leftSeq === rightSeq) return 0;
  return leftSeq - rightSeq;
}

function generationPathCausality(steps) {
  const nonSignedSteps = (steps || []).filter((step) => step.stage !== "signed_request");
  const preRequestStepCount = nonSignedSteps
    .filter((step) => step.relation_to_signed_request === "before_signed_request")
    .length;
  const postRequestStepCount = nonSignedSteps
    .filter((step) => step.relation_to_signed_request === "after_signed_request")
    .length;
  const unknownRelationStepCount = nonSignedSteps
    .filter((step) => ![
      "before_signed_request",
      "after_signed_request",
      "signed_request"
    ].includes(step.relation_to_signed_request || ""))
    .length;

  let causality = "signed_or_unknown";
  if (preRequestStepCount > 0 && postRequestStepCount === 0) {
    causality = "pre_request_chain";
  } else if (preRequestStepCount > 0 && postRequestStepCount > 0) {
    causality = "mixed_pre_post_request";
  } else if (postRequestStepCount > 0) {
    causality = "post_request_activity";
  }

  const warnings = [];
  if (postRequestStepCount > 0) warnings.push("runtime_steps_after_signed_request");
  if (unknownRelationStepCount > 0) warnings.push("runtime_steps_with_unknown_request_relation");

  return {
    causality,
    warnings,
    pre_request_step_count: preRequestStepCount,
    post_request_step_count: postRequestStepCount,
    unknown_relation_step_count: unknownRelationStepCount
  };
}

function resourceWarningForMaterialFlow(flow) {
  if (flow.resource_class === "static_resource") return "network_anchor_static_resource";
  if (flow.resource_class === "telemetry_endpoint") return "network_anchor_telemetry_endpoint";
  if (flow.resource_class === "document_request") return "network_anchor_document_request";
  return "";
}

function generationPathForMaterialFlow(flow, index) {
  const bounds = generationPathBounds(flow);
  const steps = (flow.generation_steps || [])
    .filter((step) => generationStepFitsPath(step, bounds))
    .map((step) => reviewGenerationStep(step, bounds));
  const sortedSteps = steps
    .sort(compareReviewGenerationSteps)
    .slice(0, 12);
  const causality = generationPathCausality(sortedSteps);
  const resourceWarning = resourceWarningForMaterialFlow(flow);
  const warnings = resourceWarning
    ? uniqueLimited([...(causality.warnings || []), resourceWarning], 12)
    : causality.warnings;
  return {
    id: `generation_path_${index + 1}`,
    flow_id: flow.id || "",
    endpoint: flow.endpoint || "",
    confidence: flow.confidence || "low",
    evidence_status: flow.evidence_status || "unknown",
    target_params: flow.target_params || [],
    step_count: sortedSteps.length,
    ...causality,
    warnings,
    stage_summary: sortedSteps.map(generationPathStepLabel).join("->") || "none",
    steps: sortedSteps
  };
}

function generationPathsForSourceCandidate(candidate, signatureMaterialFlows) {
  const flowIds = new Set(candidate.flow_ids || []);
  return (signatureMaterialFlows || [])
    .filter((flow) => flowIds.has(flow.id || ""))
    .slice(0, 4)
    .map(generationPathForMaterialFlow);
}

function generationPathsSummary(paths) {
  return (paths || [])
    .slice(0, 4)
    .map((path) => `${path.id || "generation_path"}:${path.causality || "unknown"}:${path.stage_summary || "none"}`)
    .join(";") || "none";
}

function reviewEntryCausality(paths) {
  const causalities = new Set((paths || []).map((path) => path.causality || "").filter(Boolean));
  if (causalities.has("pre_request_chain")) return "pre_request_chain";
  if (causalities.has("mixed_pre_post_request")) return "mixed_pre_post_request";
  if (causalities.has("signed_or_unknown")) return "signed_or_unknown";
  if (causalities.has("post_request_activity")) return "post_request_activity";
  return "signed_or_unknown";
}

function reviewPriorityForCausality(causality) {
  if (causality === "pre_request_chain") return "high";
  if (causality === "mixed_pre_post_request" || causality === "signed_or_unknown") return "medium";
  return "low";
}

function reviewPriorityRank(priority) {
  if (priority === "high") return 0;
  if (priority === "medium") return 1;
  return 2;
}

function warningUnionForGenerationPaths(paths) {
  return uniqueLimited((paths || []).flatMap((path) => path.warnings || []), 12);
}

function entryCausalitySummary(entries) {
  const summary = {
    pre_request_chain: 0,
    mixed_pre_post_request: 0,
    signed_or_unknown: 0,
    post_request_activity: 0,
    prioritized_entry_count: 0,
    deprioritized_entry_count: 0
  };
  for (const entry of entries || []) {
    const causality = entry.causality || "signed_or_unknown";
    if (summary[causality] !== undefined) summary[causality] += 1;
    if (entry.review_priority === "high") summary.prioritized_entry_count += 1;
    if (entry.review_priority === "low") summary.deprioritized_entry_count += 1;
  }
  return summary;
}

function compareAgentReviewEntries(a, b) {
  return reviewPriorityRank(a.review_priority) - reviewPriorityRank(b.review_priority) ||
    b.evidence_score - a.evidence_score ||
    b.flow_count - a.flow_count ||
    b.step_count - a.step_count ||
    String(a.function).localeCompare(String(b.function)) ||
    String(a.source_candidate_id).localeCompare(String(b.source_candidate_id));
}

function buildAgentReviewPackage(signatureSourceCandidates, signatureMaterialFlows = [], assetSourcesById = new Map()) {
  const entries = (signatureSourceCandidates || []).slice(0, 8)
    .map((candidate, index) => {
      const generationPaths = generationPathsForSourceCandidate(candidate, signatureMaterialFlows);
      const causality = reviewEntryCausality(generationPaths);
      const reviewPriority = reviewPriorityForCausality(causality);
      return {
        source_candidate_id: candidate.id || "",
        rank: candidate.rank ?? index + 1,
        function: candidate.function || "",
        asset_id: candidate.asset_id || "",
        url: candidate.url || "",
        content_path: candidate.content_path || "",
        source_refs: candidate.source_refs || [],
        line_ranges: lineRangesForSourceCandidate(candidate, assetSourcesById),
        flow_ids: candidate.flow_ids || [],
        flow_count: candidate.flow_count || 0,
        step_count: candidate.step_count || 0,
        evidence_score: candidate.evidence_score || 0,
        target_params: candidate.target_params || [],
        endpoints: candidate.endpoints || [],
        stages: candidate.stages || [],
        runtime_apis: candidate.runtime_apis || [],
        signals: candidate.signals || [],
        calls: candidate.calls || [],
        operators: candidate.operators || [],
        min_distance_to_signed_request: candidate.min_distance_to_signed_request,
        distance_basis: candidate.distance_basis || "",
        review_reasons: candidate.priority_reasons || [],
        causality,
        review_priority: reviewPriority,
        warnings: warningUnionForGenerationPaths(generationPaths),
        generation_paths: generationPaths,
        next_questions: nextQuestionsForSourceCandidate(candidate)
      };
    })
    .sort(compareAgentReviewEntries)
    .map((entry, index) => ({
      id: `review_entry_${index + 1}`,
      ...entry
    }));
  return {
    version: 1,
    purpose: "agent_source_review_package",
    entry_count: entries.length,
    causality_summary: entryCausalitySummary(entries),
    entries
  };
}

function parameterStatusRank(status) {
  if (status === "attachment_observed") return 0;
  if (status === "signed_request_observed") return 1;
  return 2;
}

function parameterStatusForFlow(flow, param) {
  const hasAttachment = (flow.signature_attachment_events || []).some((event) =>
    (event.target_params || []).includes(param)) ||
    (flow.agent_stage_trace || []).some((step) =>
      step.stage === "signature_mutation" && (step.target_params || []).includes(param));
  if (hasAttachment) return "attachment_observed";
  const hasSignedRequest = (flow.agent_stage_trace || []).some((step) =>
    step.stage === "signed_request" && (step.target_params || []).includes(param));
  if (hasSignedRequest) return "signed_request_observed";
  return "candidate";
}

function flowConfidenceRank(confidence) {
  if (confidence === "high") return 0;
  if (confidence === "medium") return 1;
  return 2;
}

function minStageDistanceToSignedRequest(flow) {
  const distances = (flow.agent_stage_trace || [])
    .map((step) => step.distance_to_signed_request)
    .filter((distance) => Number.isFinite(distance));
  return distances.length ? Math.min(...distances) : Number.POSITIVE_INFINITY;
}

function compareParameterFlows(param) {
  return (left, right) => {
    const leftStatus = parameterStatusForFlow(left, param);
    const rightStatus = parameterStatusForFlow(right, param);
    return parameterStatusRank(leftStatus) - parameterStatusRank(rightStatus) ||
      flowConfidenceRank(left.confidence) - flowConfidenceRank(right.confidence) ||
      minStageDistanceToSignedRequest(left) - minStageDistanceToSignedRequest(right) ||
      String(left.id || "").localeCompare(String(right.id || ""));
  };
}

function parameterTraceForFlow(flow, param) {
  return [...(flow.agent_stage_trace || [])]
    .sort(compareReviewGenerationSteps)
    .slice(0, 12)
    .map((step, index) => {
      const directlyObserved = (step.params || []).includes(param);
      const targetsParam = (step.target_params || []).includes(param);
      return {
        order: index + 1,
        stage: step.stage || "unknown",
        role: step.role || "context",
        ...(step.seq_start !== undefined ? {seq_start: step.seq_start} : {}),
        ...(step.seq_end !== undefined ? {seq_end: step.seq_end} : {}),
        apis: uniqueLimited(step.apis || [], 6),
      target_params: targetsParam ? [param] : [],
      param_relation: directlyObserved ? "direct_observed" : (targetsParam ? "flow_target" : "none"),
      relation: step.relation || "unknown",
      distance_to_signed_request: step.distance_to_signed_request ?? null,
      distance_basis: step.distance_basis || "unknown",
      source_refs: uniqueLimited(step.source_refs || [], 4),
      source_calls: uniqueLimited(step.source_calls || [], 6),
      source_signals: uniqueLimited(step.source_signals || [], 6),
      source_operators: uniqueLimited(step.source_operators || [], 6),
      source_constants: uniqueLimited(step.source_constants || [], 6),
      runtime_event_refs: compactRuntimeEventRefs(step.runtime_event_refs || [], 8),
      object_refs: uniquePrioritizedLimited(
        step.object_refs || [],
        step.stage === "dynamic_dispatch" ? 16 : 8,
        generationPathObjectRefRank
      ),
      value_refs: compactGenerationValueRefs(
        step.value_refs || [],
        step.stage === "dynamic_dispatch" ? 24 : 8,
        {preserveVmpStateRefs: step.stage === "dynamic_dispatch"}
      )
    };
  });
}

function compactAgentDataLink(link) {
  return {
    from: link.from || "unknown",
    to: link.to || "unknown",
    relation: link.relation || "shared_object_ref",
    confidence: link.confidence || "medium",
    basis: uniqueLimited(link.basis || [], 8),
    refs: uniqueLimited(link.refs || [], 8)
  };
}

function compactAgentScalarChainLink(link) {
  return {
    chain_id: link.chain_id || "",
    stage: link.stage || "unknown",
    relation: link.relation || "related",
    confidence: link.confidence || "medium",
    shared_refs: uniqueLimited(link.shared_refs || [], 8),
    apis: uniqueLimited(link.apis || [], 8),
    quality_score: link.quality_score ?? 0,
    quality_reasons: uniqueLimited(link.quality_reasons || [], 8),
    source_context_refs: uniqueLimited(link.source_context_refs || [], 8),
    operation_trace: (link.operation_trace || [])
      .slice(0, 8)
      .map((step) => {
        const resultRef = step?.result_ref || "";
        const outputRefs = uniqueLimited([
          step?.result_ref || "",
          ...(step?.output_refs || [])
        ].filter(Boolean), 6);
        return {
          seq: Number.isFinite(step?.seq) ? step.seq : null,
          trace_index: Number.isFinite(step?.trace_index) ? step.trace_index : null,
          api: step?.api || "unknown",
          input_refs: uniqueLimited(step?.input_refs || [], 6),
          result_ref: resultRef,
          ...(outputRefs.some((ref) => ref !== resultRef) ? {output_refs: outputRefs} : {}),
          source_context_refs: uniqueLimited(step?.source_context_refs || [], 4)
        };
      })
  };
}

function vmpOperationPatternName(apis) {
  const apiSet = new Set(apis || []);
  if (apiSet.has("Bitwise.xor") && apiSet.has("Math.imul") && apiSet.has("Shift.unsignedRight")) {
    return "xor_imul_urshift_mixing";
  }
  if (apiSet.has("Bitwise.xor") && apiSet.has("Math.imul")) {
    return "xor_imul_mixing";
  }
  if ((apis || []).some((api) => /^Bitwise\./.test(api || "")) &&
      (apis || []).some((api) => /^Shift\./.test(api || ""))) {
    return "bitwise_shift_mixing";
  }
  if (apiSet.has("Math.imul")) {
    return "integer_multiply";
  }
  if ((apis || []).some((api) => /^Bitwise\./.test(api || ""))) {
    return "bitwise_mixing";
  }
  return "scalar_ref_flow";
}

function numberRangeFromSteps(steps, field) {
  const values = (steps || [])
    .map((step) => step?.[field])
    .filter((value) => Number.isFinite(value));
  if (!values.length) {
    return {start: null, end: null};
  }
  return {
    start: Math.min(...values),
    end: Math.max(...values)
  };
}

function relationToSignatureMutation(stageStep, signatureStep) {
  if (!stageStep || !signatureStep) return "unknown";
  if (Number.isFinite(stageStep.order) && Number.isFinite(signatureStep.order)) {
    if (stageStep.order < signatureStep.order) return "before_signature_mutation";
    if (stageStep.order > signatureStep.order) return "after_signature_mutation";
    return "same_as_signature_mutation";
  }
  if (stageStep.relation === "after_signed_request") return "after_signature_mutation";
  if (stageStep.relation === "before_signed_request") return "before_signature_mutation";
  return "unknown";
}

function distanceToSignatureMutation(stageStep, signatureStep) {
  if (!stageStep || !signatureStep) return null;
  const stageDistance = stageStep.distance_to_signed_request;
  const signatureDistance = signatureStep.distance_to_signed_request;
  if (Number.isFinite(stageDistance) && Number.isFinite(signatureDistance)) {
    return Math.abs(stageDistance - signatureDistance);
  }
  if (Number.isFinite(stageStep.order) && Number.isFinite(signatureStep.order)) {
    return Math.abs(stageStep.order - signatureStep.order);
  }
  return null;
}

function patternTimingForLink(link, generationPath) {
  const operationTrace = link.operation_trace || [];
  const seqRange = numberRangeFromSteps(operationTrace, "seq");
  const traceRange = numberRangeFromSteps(operationTrace, "trace_index");
  const stageStep = (generationPath || []).find((step) => step.stage === link.stage) || null;
  const signatureStep = (generationPath || []).find((step) => step.stage === "signature_mutation") || null;
  return {
    seq_start: seqRange.start,
    seq_end: seqRange.end,
    trace_start: traceRange.start,
    trace_end: traceRange.end,
    relation_to_signature_mutation: relationToSignatureMutation(stageStep, signatureStep),
    distance_to_signature_mutation: distanceToSignatureMutation(stageStep, signatureStep),
    stage_order: Number.isFinite(stageStep?.order) ? stageStep.order : null,
    signature_stage_order: Number.isFinite(signatureStep?.order) ? signatureStep.order : null,
    signature_distance_basis: stageStep?.distance_basis || signatureStep?.distance_basis || "unknown"
  };
}

function vmpOperationPatternsForLinks(links, generationPath = []) {
  return (links || [])
    .map((link) => {
      const operationTrace = link.operation_trace || [];
      const operationApis = operationTrace.map((step) => step.api || "unknown").filter(Boolean);
      const signatureApis = operationApis.length ? operationApis : (link.apis || []);
      const evidenceRefs = uniqueLimited(operationTrace.flatMap((step) => [
        ...(step.input_refs || []),
        step.result_ref,
        ...(step.output_refs || [])
      ]).filter(Boolean), 12);
      const timing = patternTimingForLink(link, generationPath);
      return {
        chain_id: link.chain_id || "",
        stage: link.stage || "unknown",
        pattern: vmpOperationPatternName(signatureApis),
        operation_signature: signatureApis.slice(0, 12).join(" -> ") || "unknown",
        operation_count: operationTrace.length || (link.step_count ?? signatureApis.length),
        ...timing,
        confidence: link.confidence || "medium",
        quality_score: link.quality_score ?? 0,
        quality_reasons: uniqueLimited(link.quality_reasons || [], 8),
        shared_refs: uniqueLimited(link.shared_refs || [], 8),
        evidence_refs: evidenceRefs,
        source_context_refs: uniqueLimited([
          ...(link.source_context_refs || []),
          ...operationTrace.flatMap((step) => step.source_context_refs || [])
        ], 8)
      };
    })
    .filter((pattern) => pattern.operation_signature !== "unknown" || pattern.shared_refs.length)
    .slice(0, 8);
}

function candidateMatchesParameter(candidate, param, flowIds) {
  if ((candidate.target_params || []).includes(param)) return true;
  return (candidate.flow_ids || []).some((id) => flowIds.has(id));
}

function reviewEntryMatchesParameter(entry, param, flowIds) {
  if ((entry.target_params || []).includes(param)) return true;
  if ((entry.generation_paths || []).some((path) => (path.target_params || []).includes(param))) return true;
  return (entry.generation_paths || []).some((path) => flowIds.has(path.flow_id));
}

function buildParameterGenerationBrief(signatureMaterialFlows = [], signatureSourceCandidates = [], agentReviewPackage = {}) {
  const params = sortParamNames(uniqueLimited(
    (signatureMaterialFlows || []).flatMap((flow) => flow.target_params || []),
    16
  ));
  const reviewEntries = agentReviewPackage.entries || [];
  const parameters = params.map((param) => {
    const paramFlows = (signatureMaterialFlows || [])
      .filter((flow) => (flow.target_params || []).includes(param));
    const flowIds = new Set(paramFlows.map((flow) => flow.id).filter(Boolean));
    const bestFlow = [...paramFlows].sort(compareParameterFlows(param))[0] || {};
    const matchingCandidates = (signatureSourceCandidates || [])
      .filter((candidate) => candidateMatchesParameter(candidate, param, flowIds));
    const matchingEntries = reviewEntries
      .filter((entry) => reviewEntryMatchesParameter(entry, param, flowIds));
    const sourceRefs = uniqueLimited([
      ...(bestFlow.source_context_refs || []),
      ...matchingCandidates.flatMap((candidate) => candidate.source_refs || []),
      ...matchingEntries.flatMap((entry) => entry.source_refs || [])
    ], 12);
    const generationTrace = parameterTraceForFlow(bestFlow, param);
    return {
      param,
      status: parameterStatusForFlow(bestFlow, param),
      best_flow_id: bestFlow.id || "",
      endpoint: bestFlow.endpoint || "",
      confidence: bestFlow.confidence || "low",
      evidence_status: bestFlow.evidence_status || "unknown",
      readiness: bestFlow.analysis_readiness?.status || "unknown",
      flow_ids: uniqueLimited([bestFlow.id, ...paramFlows.map((flow) => flow.id)].filter(Boolean), 8),
      source_candidate_ids: uniqueLimited(matchingCandidates.map((candidate) => candidate.id).filter(Boolean), 8),
      review_entry_ids: uniqueLimited(matchingEntries.map((entry) => entry.id).filter(Boolean), 8),
      source_refs: sourceRefs,
      stage_chain: uniqueLimited((bestFlow.agent_stage_trace || []).map((step) => step.stage || "unknown"), 12),
      evidence_gaps: uniqueLimited(bestFlow.analysis_readiness?.evidence_gaps || [], 8),
      next_questions: uniqueLimited(matchingEntries.flatMap((entry) => entry.next_questions || []), 12),
      data_links: (bestFlow.data_links || []).slice(0, 12).map(compactAgentDataLink),
      inferred_data_links: (bestFlow.inferred_data_links || []).slice(0, 12).map(compactAgentDataLink),
      vmp_scalar_chain_links: (bestFlow.vmp_scalar_chain_links || []).slice(0, 8).map(compactAgentScalarChainLink),
      signature_param_materializations: compactSignatureParamMaterializations(
        bestFlow.signature_param_materializations || [],
        param
      ),
      request_input_bundle: compactAgentRequestInputBundle(bestFlow.request_input_bundle),
      webcrypto_signature_summary: compactWebCryptoSignatureSummary(bestFlow.webcrypto_signature_summary),
      agent_generation_summary: compactAgentGenerationSummary(bestFlow.agent_generation_summary, generationTrace),
      generation_trace: generationTrace
    };
  });
  return {
    version: 1,
    purpose: "agent_parameter_generation_brief",
    parameter_count: parameters.length,
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    parameters
  };
}

function isCandidateSignatureAsset(asset) {
  return (asset.signals || []).some((signal) =>
    signal.startsWith("vmp_") ||
    signal === "dynamic_execution" ||
    signal === "anti_debug" ||
    signal === "fingerprint_api_refs"
  );
}

function summarizeCandidateSignatureAssets(assetFindings) {
  return (assetFindings || [])
    .filter(isCandidateSignatureAsset)
    .slice(0, 8)
    .map((asset) => ({
      asset_id: asset.asset_id,
      url: asset.url,
      content_path: asset.content_path,
      score: asset.score,
      signals: asset.signals,
      first_seq: asset.first_seq
    }));
}

function buildSignatureAbsentEntrypoints(globalVmpEvents, assetFindings) {
  const assetByUrl = new Map((assetFindings || [])
    .filter((asset) => asset.url)
    .map((asset) => [asset.url, asset]));
  const entrypoints = new Map();

  for (let index = 0; index < (globalVmpEvents || []).length; index += 1) {
    const event = globalVmpEvents[index];
    const frame = (event.stack || []).find((item) => item.url || item.function) || {};
    const stackUrl = frame.url || event.frame_url || event.origin || "unknown";
    const functionName = frame.function || "(anonymous)";
    const key = `${functionName}\u0000${stackUrl}`;
    const seq = sequenceValue(event, index);
    const entry = entrypoints.get(key) || {
      function: functionName,
      stack_url: stackUrl,
      event_count: 0,
      seq_start: seq,
      seq_end: seq,
      apiCounts: new Map(),
      familySet: new Set(),
      sampleEvents: [],
      asset: assetByUrl.get(stackUrl) || null
    };

    entry.event_count += 1;
    entry.seq_start = Math.min(entry.seq_start, seq);
    entry.seq_end = Math.max(entry.seq_end, seq);
    if (event.api) entry.apiCounts.set(event.api, (entry.apiCounts.get(event.api) || 0) + 1);
    const family = vmpFamilyForApi(event.api);
    if (family) entry.familySet.add(family);
    if (entry.sampleEvents.length < 6) {
      entry.sampleEvents.push({
        seq: event.seq ?? null,
        api: event.api || "",
        family
      });
    }
    entrypoints.set(key, entry);
  }

  return [...entrypoints.values()]
    .sort((a, b) =>
      b.event_count - a.event_count ||
      (b.asset?.score || 0) - (a.asset?.score || 0) ||
      a.seq_start - b.seq_start ||
      String(a.stack_url).localeCompare(String(b.stack_url)))
    .slice(0, 8)
    .map((entry) => ({
      function: entry.function,
      stack_url: entry.stack_url,
      event_count: entry.event_count,
      seq_start: entry.seq_start,
      seq_end: entry.seq_end,
      families: [...entry.familySet].sort(),
      apis: sortCountEntries(entry.apiCounts, "api").slice(0, 8),
      asset_id: entry.asset?.asset_id || "",
      asset_path: entry.asset?.content_path || "",
      asset_score: entry.asset?.score || 0,
      asset_signals: entry.asset?.signals || [],
      sample_events: entry.sampleEvents
    }));
}

function networkRequestInfoFromEvent(event) {
  if (event && typeof event === "object" && NETWORK_REQUEST_INFO_CACHE.has(event)) {
    return NETWORK_REQUEST_INFO_CACHE.get(event);
  }
  const api = event?.api || "";
  if (!api) return null;
  const isNetworkRequest =
    api === "BrowserNetwork.request" ||
    api === "Request.constructor" ||
    api === "fetch" ||
    api === "XMLHttpRequest.open" ||
    api === "XMLHttpRequest.send";
  if (!isNetworkRequest) {
    if (event && typeof event === "object") NETWORK_REQUEST_INFO_CACHE.set(event, null);
    return null;
  }

  const args = Array.isArray(event.args) ? event.args : [];
  const firstArg = args.find((item) => item && typeof item === "object") || {};
  const explicitUrl = typeof firstArg.url === "string" ? parseUrlCandidate(firstArg.url) : null;
  const urlInfo = explicitUrl ? {raw: firstArg.url, parsed: explicitUrl} : urlsFromEvent(event)[0];
  if (!urlInfo) {
    if (event && typeof event === "object") NETWORK_REQUEST_INFO_CACHE.set(event, null);
    return null;
  }
  const method = String(firstArg.method || event.method || (api === "XMLHttpRequest.send" ? "" : "GET") || "GET").toUpperCase();
  const networkCorrelationKey = String(firstArg.network_correlation_key || firstArg.request_correlation_key || "");
  const info = {
    trace_index: traceIndexValue(event, null),
    seq: event.seq ?? null,
    api,
    method,
    endpoint: endpointForUrl(urlInfo.parsed),
    host: urlInfo.parsed.host,
    path: urlInfo.parsed.pathname,
    ...(networkCorrelationKey ? {network_correlation_key: networkCorrelationKey} : {}),
    is_fetch_like_api: Boolean(firstArg.is_fetch_like_api || api === "fetch" || api === "Request.constructor" || api === "BrowserNetwork.request")
  };
  if (event && typeof event === "object") NETWORK_REQUEST_INFO_CACHE.set(event, info);
  return info;
}

function networkRequestArg(event) {
  const args = Array.isArray(event?.args) ? event.args : [];
  return args.find((item) => item && typeof item === "object") || {};
}

function eventHasRequestBody(event) {
  const arg = networkRequestArg(event);
  return Boolean(
    arg.has_request_body ||
    arg.body ||
    arg.post_data ||
    arg.request_body ||
    arg.upload_body ||
    arg.upload_data ||
    arg.has_body ||
    arg.body_size ||
    arg.body_byte_length ||
    arg.upload_size
  );
}

function isRequestBodyBoundaryEvent(event) {
  const api = event?.api || "";
  if (![
    "BrowserNetwork.request",
    "Request.constructor",
    "fetch",
    "XMLHttpRequest.send"
  ].includes(api)) {
    return false;
  }
  return eventHasRequestBody(event);
}

function summarizeUploadBodyMetadata(arg) {
  const upload = arg.upload_body || arg.request_body;
  if (!upload || typeof upload !== "object" || Array.isArray(upload)) return null;
  const summary = {};
  for (const key of [
    "element_count",
    "total_bytes",
    "in_memory_bytes",
    "has_file",
    "has_blob",
    "has_data_pipe",
    "has_chunked_data_pipe",
    "preview_sha256",
    "preview_size",
    "truncated"
  ]) {
    if (upload[key] !== undefined) summary[key] = upload[key];
  }
  return Object.keys(summary).length ? summary : null;
}

function summarizeNetworkRequestContext(info, event, rendererRequestLink = null, inferredInitiator = null) {
  const arg = networkRequestArg(event);
  const headers = Array.isArray(arg.headers) ? arg.headers : [];
  const headerNames = uniqueLimited(headers.map((header) => String(header?.name || "").toLowerCase()).filter(Boolean), 24);
  const sensitiveHeaderNames = uniqueLimited(headers
    .filter((header) => header?.redacted)
    .map((header) => String(header?.name || "").toLowerCase())
    .filter(Boolean), 24);
  const captureGaps = [];
  if (["POST", "PUT", "PATCH"].includes(info.method || "") && !eventHasRequestBody(event)) {
    captureGaps.push("request_body_not_captured");
  }
  if (arg.originated_from_service_worker) {
    captureGaps.push("service_worker_source_context_needed");
  }
  if ((info.api || "") === "BrowserNetwork.request" && !(event.stack || []).length && !rendererRequestLink) {
    captureGaps.push("renderer_stack_missing");
  }

  const uploadBody = summarizeUploadBodyMetadata(arg);
  return {
    request_initiator: arg.request_initiator || event.origin || "",
    referrer: arg.referrer || event.frame_url || "",
    originated_from_service_worker: Boolean(arg.originated_from_service_worker),
    has_user_gesture: Boolean(arg.has_user_gesture),
    header_names: headerNames,
    sensitive_header_names: sensitiveHeaderNames,
    ...(uploadBody ? {upload_body: uploadBody} : {}),
    ...(rendererRequestLink ? {renderer_request_link: rendererRequestLink} : {}),
    ...(!rendererRequestLink && inferredInitiator ? {inferred_initiator: inferredInitiator} : {}),
    capture_gaps: captureGaps
  };
}

function eventRefForRequestInput(kind, event) {
  return `${kind}:${event?.api || "unknown"}@${event?.seq ?? "none"}`;
}

function requestInputHeaderTargetParam(name, value = "") {
  const lowerName = String(name || "").toLowerCase();
  const lowerValue = String(value || "").toLowerCase();
  return SIGNATURE_TERMS.find((term) =>
    lowerName === term.toLowerCase() ||
    lowerValue.includes(term.toLowerCase())
  ) || "";
}

function requestInputHeaderActionForEvent(event) {
  switch (event?.api || "") {
    case "XMLHttpRequest.setRequestHeader":
    case "Headers.set":
      return "set";
    case "Headers.append":
      return "append";
    case "Headers.delete":
      return "delete";
    default:
      return "observe";
  }
}

function requestInputHeaderItemsForEvent(event) {
  const arg = networkRequestArg(event);
  const api = event?.api || "";
  const headers = Array.isArray(arg.headers) ? [...arg.headers] : [];
  if (api === "XMLHttpRequest.setRequestHeader" || api === "Headers.set" || api === "Headers.append") {
    const name = String(arg.name || arg.key || "");
    headers.push({
      name,
      value: arg.value,
      value_length: arg.value_length,
      value_ref: arg.value_ref,
      redacted: Boolean(arg.redacted)
    });
  }
  if (api === "Headers.delete") {
    headers.push({
      name: arg.name || arg.key || "",
      redacted: Boolean(arg.redacted)
    });
  }
  return headers;
}

function requestInputHeaderEventSummary(event, header) {
  const name = String(header?.name || "").toLowerCase();
  if (!name) return null;
  const targetParam = requestInputHeaderTargetParam(name, header?.value);
  const valueLength = requestInputValueLength(header, ["value_length", "value"]);
  const valueRefs = uniqueLimited([
    header.value_ref,
    header.result_ref
  ].filter(Boolean).map(String), 8);
  return {
    seq: event?.seq ?? null,
    api: event?.api || "",
    phase: event?.phase || "",
    action: requestInputHeaderActionForEvent(event),
    header_name: name,
    ...(targetParam ? {target_params: [targetParam]} : {}),
    ...(header?.redacted ? {redacted: true} : {}),
    ...(Number.isFinite(valueLength) ? {value_length: valueLength} : {}),
    ...(valueRefs.length ? {value_refs: valueRefs} : {}),
    evidence_ref: eventRefForRequestInput("headers", event)
  };
}

function requestInputHeaderSummary(events) {
  const names = [];
  const sensitiveNames = [];
  const targetParams = [];
  const evidence = [];
  const eventSummaries = [];
  const valueRefs = [];

  for (const event of events || []) {
    for (const header of requestInputHeaderItemsForEvent(event)) {
      const summary = requestInputHeaderEventSummary(event, header);
      if (!summary) continue;
      names.push(summary.header_name);
      if (summary.redacted) sensitiveNames.push(summary.header_name);
      targetParams.push(...(summary.target_params || []));
      valueRefs.push(...(summary.value_refs || []));
      evidence.push(summary.evidence_ref);
      eventSummaries.push(summary);
    }
  }

  return {
    observed: names.length > 0,
    header_names: uniqueLimited(names, 64).sort(),
    sensitive_header_names: uniqueLimited(sensitiveNames, 32).sort(),
    target_params: sortParamNames(uniqueLimited(targetParams, 16)),
    value_refs: compactGenerationValueRefs(valueRefs, 16),
    events: eventSummaries.slice(0, 24),
    evidence_refs: uniqueLimited(evidence, 16)
  };
}

function isBrowserNetworkResponseEvent(event) {
  return (event?.api || "") === "BrowserNetwork.response";
}

function requestInputResponseHeaderItemsForEvent(event) {
  const arg = networkRequestArg(event);
  return Array.isArray(arg.response_headers) ? arg.response_headers : [];
}

function requestInputResponseEventSummary(event) {
  const arg = networkRequestArg(event);
  const headerNames = uniqueLimited(requestInputResponseHeaderItemsForEvent(event)
    .map((header) => String(header?.name || "").toLowerCase())
    .filter(Boolean), 64).sort();
  const sensitiveHeaderNames = uniqueLimited(requestInputResponseHeaderItemsForEvent(event)
    .filter((header) => header?.redacted)
    .map((header) => String(header?.name || "").toLowerCase())
    .filter(Boolean), 32).sort();
  return {
    seq: event?.seq ?? null,
    api: event?.api || "",
    phase: event?.phase || "",
    ...(Number.isFinite(arg.response_code) ? {status_code: arg.response_code} : {}),
    ...(arg.status_line ? {status_line: String(arg.status_line)} : {}),
    ...(arg.mime_type ? {mime_type: String(arg.mime_type)} : {}),
    ...(Number.isFinite(arg.content_length) ? {content_length: arg.content_length} : {}),
    ...(Number.isFinite(arg.encoded_data_length) ? {encoded_data_length: arg.encoded_data_length} : {}),
    ...(arg.network_accessed !== undefined ? {network_accessed: Boolean(arg.network_accessed)} : {}),
    ...(arg.was_fetched_via_cache !== undefined ? {was_fetched_via_cache: Boolean(arg.was_fetched_via_cache)} : {}),
    ...(arg.was_fetched_via_service_worker !== undefined
      ? {was_fetched_via_service_worker: Boolean(arg.was_fetched_via_service_worker)}
      : {}),
    header_names: headerNames,
    sensitive_header_names: sensitiveHeaderNames,
    evidence_ref: eventRefForRequestInput("response", event)
  };
}

function requestInputResponseSummary(events) {
  const responseEvents = (events || []).filter(isBrowserNetworkResponseEvent);
  const eventSummaries = responseEvents.map(requestInputResponseEventSummary);
  const statusCodes = uniqueLimited(eventSummaries
    .map((event) => event.status_code)
    .filter(Number.isFinite), 8);
  const mimeTypes = uniqueLimited(eventSummaries
    .map((event) => event.mime_type)
    .filter(Boolean), 8);
  return {
    observed: responseEvents.length > 0,
    ...(statusCodes.length ? {status_code: statusCodes[0], status_codes: statusCodes} : {}),
    ...(mimeTypes.length ? {mime_type: mimeTypes[0], mime_types: mimeTypes} : {}),
    header_names: uniqueLimited(eventSummaries.flatMap((event) => event.header_names || []), 64).sort(),
    sensitive_header_names: uniqueLimited(eventSummaries.flatMap((event) => event.sensitive_header_names || []), 32).sort(),
    events: eventSummaries.slice(0, 16),
    evidence_refs: uniqueLimited(eventSummaries.map((event) => event.evidence_ref), 16)
  };
}

function requestInputUploadBodySummary(events) {
  for (const event of events || []) {
    const upload = summarizeUploadBodyMetadata(networkRequestArg(event));
    if (upload) return upload;
  }
  return null;
}

function requestInputBodySize(events) {
  for (const event of events || []) {
    const arg = networkRequestArg(event);
    for (const key of ["body_size", "body_byte_length", "upload_size", "request_body_size", "post_data_size"]) {
      if (Number.isFinite(arg[key])) return arg[key];
    }
  }
  return null;
}

function requestInputBodyPreview(events) {
  for (const event of events || []) {
    const arg = networkRequestArg(event);
    for (const key of ["body_preview", "post_data_preview", "request_body_preview", "payload_preview"]) {
      if (typeof arg[key] === "string" && arg[key]) {
        return preserveSignatureText(arg[key]).slice(0, AGENT_SOURCE_PREVIEW_MAX_CHARS);
      }
    }
  }
  return "";
}

function requestInputBodyActionForEvent(event) {
  switch (event?.api || "") {
    case "XMLHttpRequest.send":
      return "send";
    case "fetch":
      return "fetch";
    case "Request.constructor":
      return "construct";
    case "URLSearchParams.constructor":
      return "construct";
    case "URLSearchParams.append":
      return "append";
    case "URLSearchParams.set":
      return "set";
    case "URLSearchParams.delete":
      return "delete";
    case "URLSearchParams.sort":
      return "sort";
    case "URLSearchParams.toString":
      return "serialize";
    case "FormData.append":
      return "append";
    case "FormData.set":
      return "set";
    case "FormData.delete":
      return "delete";
    default:
      return "observe";
  }
}

function requestInputBodySizeForEvent(event) {
  const arg = networkRequestArg(event);
  return requestInputValueLength(arg, [
    "body_size",
    "body_byte_length",
    "upload_size",
    "request_body_size",
    "post_data_size",
    "body",
    "post_data",
    "request_body",
    "payload"
  ]);
}

function requestInputBodyPreviewForEvent(event) {
  const arg = networkRequestArg(event);
  for (const key of ["body_preview", "post_data_preview", "request_body_preview", "payload_preview"]) {
    if (typeof arg[key] === "string" && arg[key]) {
      return preserveSignatureText(arg[key]).slice(0, AGENT_SOURCE_PREVIEW_MAX_CHARS);
    }
  }
  return "";
}

function requestInputUrlencodedParamNamesForEvent(event) {
  if (!isURLSearchParamsBodyObjectEvent(event)) return [];
  const arg = networkRequestArg(event);
  const names = [];
  for (const key of ["name", "field_name"]) {
    if (arg[key]) names.push(String(arg[key]));
  }
  for (const key of ["param_names", "field_names"]) {
    if (!Array.isArray(arg[key])) continue;
    names.push(...arg[key].map(String).filter(Boolean));
  }
  return uniqueLimited(names, 64).sort();
}

function requestInputUrlencodedParamValueRefsForEvent(event) {
  if (!isURLSearchParamsBodyObjectEvent(event)) return [];
  const arg = networkRequestArg(event);
  return uniqueLimited([
    ...(Array.isArray(arg.param_value_refs) ? arg.param_value_refs : []),
    ...(Array.isArray(arg.field_value_refs) ? arg.field_value_refs : [])
  ].map(normalizeRuntimeValueRef).filter(Boolean), 64);
}

function requestInputBodyEventSummary(event) {
  const info = networkRequestInfoFromEvent(event);
  const arg = networkRequestArg(event);
  const bodySize = requestInputBodySizeForEvent(event);
  const preview = requestInputBodyPreviewForEvent(event);
  const uploadBody = summarizeUploadBodyMetadata(arg);
  const valueRefs = valueRefsForEvents([event], () => true);
  const formDataId = requestInputFormDataIdForEvent(event);
  const bodySearchParamsId =
    requestInputBodySearchParamsIdForEvent(event) ??
    (isURLSearchParamsBodyObjectEvent(event) ? requestInputSearchParamsIdForEvent(event) : null);
  const bodyFieldName = String(arg.name || arg.field_name || "");
  const urlencodedParamNames = requestInputUrlencodedParamNamesForEvent(event);
  const urlencodedParamValueRefs = requestInputUrlencodedParamValueRefsForEvent(event);
  const valueLength = requestInputValueLength(arg, ["value_length", "value"]);
  return {
    seq: event?.seq ?? null,
    api: event?.api || "",
    phase: event?.phase || "",
    action: requestInputBodyActionForEvent(event),
    method: String(arg.method || info?.method || "").toUpperCase(),
    target_params: sortParamNames(uniqueLimited(signatureTermsInRequestBodyEvent(event), 16)),
    ...(Number.isFinite(formDataId) ? {form_data_id: formDataId} : {}),
    ...(Number.isFinite(bodySearchParamsId) ? {body_search_params_id: bodySearchParamsId} : {}),
    ...(bodyFieldName && isFormDataObjectMutationEvent(event) ? {form_field_name: bodyFieldName} : {}),
    ...(bodyFieldName && isURLSearchParamsBodyObjectEvent(event) ? {urlencoded_param_name: bodyFieldName} : {}),
    ...(urlencodedParamNames.length ? {urlencoded_param_names: urlencodedParamNames} : {}),
    ...(urlencodedParamValueRefs.length ? {urlencoded_param_value_refs: urlencodedParamValueRefs} : {}),
    ...(arg.value_kind ? {value_kind: String(arg.value_kind)} : {}),
    ...(Number.isFinite(valueLength) ? {value_length: valueLength} : {}),
    ...(Number.isFinite(bodySize) ? {body_size: bodySize} : {}),
    ...(preview ? {preview} : {}),
    ...(uploadBody ? {upload_body: uploadBody} : {}),
    ...(valueRefs.length ? {value_refs: valueRefs} : {}),
    evidence_ref: eventRefForRequestInput("body", event)
  };
}

function requestInputBodySummary(events) {
  const bodySearchParamsIds = requestInputBodySearchParamsIdsForEvents(events);
  const bodyEvents = (events || []).filter((event) =>
    requestMaterialPhaseForEvent(event) === "request_body" ||
    isLinkedURLSearchParamsBodyEvent(event, bodySearchParamsIds)
  );
  const targetParams = sortParamNames(uniqueLimited(bodyEvents.flatMap(signatureTermsInRequestBodyEvent), 16));
  const formFieldNames = uniqueLimited(bodyEvents
    .map((event) => String(networkRequestArg(event).name || networkRequestArg(event).field_name || ""))
    .filter((name, index) => name && isFormDataObjectMutationEvent(bodyEvents[index])), 64).sort();
  const urlencodedParamNames = uniqueLimited(bodyEvents
    .flatMap(requestInputUrlencodedParamNamesForEvent), 64).sort();
  const uploadBody = requestInputUploadBodySummary(bodyEvents);
  const bodySize = requestInputBodySize(bodyEvents);
  const preview = requestInputBodyPreview(bodyEvents);
  return {
    observed: bodyEvents.length > 0,
    target_params: targetParams,
    ...(formFieldNames.length ? {form_field_names: formFieldNames} : {}),
    ...(urlencodedParamNames.length ? {urlencoded_param_names: urlencodedParamNames} : {}),
    ...(Number.isFinite(bodySize) ? {body_size: bodySize} : {}),
    ...(uploadBody ? {upload_body: uploadBody} : {}),
    ...(preview ? {preview} : {}),
    value_refs: valueRefsForEvents(bodyEvents, () => true),
    events: bodyEvents.map(requestInputBodyEventSummary).slice(0, 16),
    evidence_refs: uniqueLimited(bodyEvents.map((event) => eventRefForRequestInput("body", event)), 16)
  };
}

function requestInputCookieNamesFromText(value, {setter = false} = {}) {
  const names = [];
  const parts = String(value || "").split(";");
  const candidateParts = setter ? parts.slice(0, 1) : parts;
  for (const part of candidateParts) {
    const name = part.split("=")[0]?.trim();
    if (name) names.push(name);
  }
  return names;
}

function requestInputValueLength(arg, keys) {
  for (const key of keys || []) {
    const value = arg?.[key];
    if (Number.isFinite(value)) return value;
    if (typeof value === "string") return value.length;
  }
  return null;
}

function isCookieInputEvent(event) {
  return [
    "document.cookie.get",
    "Document.cookie.get",
    "document.cookie.set",
    "Document.cookie.set"
  ].includes(event?.api || "");
}

function requestInputCookieEventSummary(event) {
  const arg = networkRequestArg(event);
  const setter = (event?.api || "").endsWith(".set");
  const names = [];
  if (Array.isArray(arg.cookie_names)) names.push(...arg.cookie_names.map(String));
  if (arg.name) names.push(String(arg.name));
  if (arg.key) names.push(String(arg.key));
  if (typeof arg.value === "string") names.push(...requestInputCookieNamesFromText(arg.value, {setter}));
  if (typeof arg.cookie === "string") names.push(...requestInputCookieNamesFromText(arg.cookie, {setter}));
  const valueLength = requestInputValueLength(arg, ["value_length", "cookie_length", "value", "cookie"]);
  const valueRefs = uniqueLimited([
    arg.value_ref,
    arg.cookie_ref,
    arg.result_ref
  ].filter(Boolean).map(String), 8);
  return {
    seq: event?.seq ?? null,
    api: event?.api || "",
    phase: event?.phase || "",
    action: setter ? "set" : "get",
    names: uniqueLimited(names, 32).sort(),
    ...(Number.isFinite(valueLength) ? {value_length: valueLength} : {}),
    ...(valueRefs.length ? {value_refs: valueRefs} : {}),
    evidence_ref: eventRefForRequestInput("cookie", event)
  };
}

function requestInputCookieSummary(events) {
  const names = [];
  const evidence = [];
  const eventSummaries = [];
  for (const event of (events || []).filter(isCookieInputEvent)) {
    const summary = requestInputCookieEventSummary(event);
    names.push(...summary.names);
    evidence.push(summary.evidence_ref);
    eventSummaries.push(summary);
  }
  return {
    observed: evidence.length > 0,
    names: uniqueLimited(names, 32).sort(),
    event_count: evidence.length,
    events: eventSummaries.slice(0, 16),
    evidence_refs: uniqueLimited(evidence, 16)
  };
}

function isStorageInputEvent(event) {
  const api = event?.api || "";
  return /^(?:localStorage|sessionStorage|Storage)\.(?:getItem|setItem|removeItem|key|clear)$/.test(api);
}

function storageScopeForApi(api) {
  if (String(api || "").startsWith("sessionStorage.")) return "session";
  if (String(api || "").startsWith("localStorage.")) return "local";
  return "storage";
}

function storageScopeForEvent(event) {
  const storage = String(networkRequestArg(event).storage || "").toLowerCase();
  if (storage === "sessionstorage") return "session";
  if (storage === "localstorage") return "local";
  return storageScopeForApi(event?.api || "");
}

function storageActionForEvent(event) {
  const match = String(event?.api || "").match(/\.([^.]+)$/);
  return match ? match[1] : "observe";
}

function requestInputStorageEventSummary(event) {
  const arg = networkRequestArg(event);
  const keys = [];
  if (arg.key) keys.push(String(arg.key));
  if (arg.name) keys.push(String(arg.name));
  const valueRefs = uniqueLimited([
    arg.result_ref,
    arg.value_ref
  ].filter(Boolean).map(String), 8);
  const valueLength = requestInputValueLength(arg, [
    "value_length",
    "result_length",
    "value",
    "result"
  ]);
  return {
    seq: event?.seq ?? null,
    api: event?.api || "",
    phase: event?.phase || "",
    action: storageActionForEvent(event),
    scope: storageScopeForEvent(event),
    keys: uniqueLimited(keys, 32).sort(),
    ...(Number.isFinite(valueLength) ? {value_length: valueLength} : {}),
    ...(valueRefs.length ? {value_refs: valueRefs} : {}),
    evidence_ref: eventRefForRequestInput("storage", event)
  };
}

function requestInputStorageSummary(events) {
  const keys = [];
  const scopes = [];
  const valueRefs = [];
  const evidence = [];
  const eventSummaries = [];
  for (const event of (events || []).filter(isStorageInputEvent)) {
    const summary = requestInputStorageEventSummary(event);
    keys.push(...summary.keys);
    scopes.push(summary.scope);
    valueRefs.push(...(summary.value_refs || []));
    evidence.push(summary.evidence_ref);
    eventSummaries.push(summary);
  }
  return {
    observed: evidence.length > 0,
    keys: uniqueLimited(keys, 32).sort(),
    scopes: uniqueLimited(scopes, 8).sort(),
    value_refs: uniqueLimited(valueRefs, 16),
    event_count: evidence.length,
    events: eventSummaries.slice(0, 16),
    evidence_refs: uniqueLimited(evidence, 16)
  };
}

function urlForRequestInput(parsed) {
  const query = [...parsed.searchParams.entries()]
    .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`)
    .join("&");
  return `${parsed.origin}${parsed.pathname}${query ? `?${query}` : ""}`;
}

function requestInputUrlActionForEvent(event) {
  switch (event?.api || "") {
    case "XMLHttpRequest.open":
      return "open";
    case "XMLHttpRequest.send":
      return "send";
    case "fetch":
      return "fetch";
    case "Request.constructor":
    case "URL.constructor":
      return "construct";
    case "URLSearchParams.set":
      return "set";
    default:
      return "observe";
  }
}

function requestInputUrlIsNetworkEvent(event) {
  const api = event?.api || "";
  return api === "BrowserNetwork.request" ||
    api === "Request.constructor" ||
    api === "fetch" ||
    api === "XMLHttpRequest.open" ||
    api === "XMLHttpRequest.send";
}

function requestInputUrlMethodForEvent(event) {
  const arg = networkRequestArg(event);
  const method = arg.method || event?.method || "";
  if (method) return String(method).toUpperCase();
  const api = event?.api || "";
  if (api === "BrowserNetwork.request" || api === "Request.constructor" || api === "fetch") {
    return "GET";
  }
  return "";
}

function requestInputUrlEventSummary(event, urlInfo) {
  if (!urlInfo?.parsed) return null;
  const method = requestInputUrlMethodForEvent(event);
  const queryKeys = sortParamNames(uniqueLimited([...urlInfo.parsed.searchParams.keys()], 64));
  const targetParams = sortParamNames(queryKeys.filter((name) => SIGNATURE_TERMS.includes(name)));
  const valueRefs = uniquePrioritizedLimited(
    [
      ...urlValueRefsForParsedUrl(urlInfo.parsed),
      ...urlMaterialRefsFromEvent(event)
    ],
    16,
    generationPathValueRefRank
  );
  return {
    seq: event?.seq ?? null,
    api: event?.api || "",
    phase: event?.phase || "",
    action: requestInputUrlActionForEvent(event),
    ...(method ? {method} : {}),
    endpoint: endpointForUrl(urlInfo.parsed),
    url: urlForRequestInput(urlInfo.parsed),
    query_keys: queryKeys,
    target_params: targetParams,
    ...(valueRefs.length ? {value_refs: valueRefs} : {}),
    evidence_ref: eventRefForRequestInput("url", event)
  };
}

function requestInputUrlInfosForEvent(event) {
  const arg = networkRequestArg(event);
  const urls = urlsFromEvent(event);
  const explicitUrl = typeof arg.url === "string" ? arg.url : "";
  if (requestInputUrlIsNetworkEvent(event) && explicitUrl) {
    const matched = urls.find(({raw, parsed}) => raw === explicitUrl || parsed.href === explicitUrl);
    if (matched) return [matched];
  }
  return urls;
}

function requestInputUrlSummary(events) {
  const eventUrlItems = (events || []).map((event) => ({
    event,
    urls: requestInputUrlInfosForEvent(event)
  }));
  const urls = eventUrlItems.flatMap((item) => item.urls);
  const eventSummaries = [];
  for (const item of eventUrlItems) {
    for (const urlInfo of item.urls) {
      const summary = requestInputUrlEventSummary(item.event, urlInfo);
      if (summary) eventSummaries.push(summary);
    }
  }
  const preferred = urls.find(({parsed}) => SIGNATURE_TERMS.some((term) => parsed.searchParams.has(term))) ||
    urls[0] ||
    null;
  const queryKeys = sortParamNames(uniqueLimited(urls.flatMap(({parsed}) => [...parsed.searchParams.keys()]), 64));
  const targetParams = sortParamNames(queryKeys.filter((name) => SIGNATURE_TERMS.includes(name)));
  const valueRefs = uniquePrioritizedLimited(
    [
      ...urls.flatMap(({parsed}) => urlValueRefsForParsedUrl(parsed)),
      ...eventUrlItems.flatMap(({event}) => urlMaterialRefsFromEvent(event))
    ],
    16,
    generationPathValueRefRank
  );
  return {
    observed: Boolean(preferred),
    endpoint: preferred ? endpointForUrl(preferred.parsed) : "",
    url: preferred ? urlForRequestInput(preferred.parsed) : "",
    query_keys: queryKeys,
    target_params: targetParams,
    value_refs: valueRefs,
    events: eventSummaries.slice(0, 16),
    evidence_refs: uniqueLimited(eventUrlItems
      .filter((item) => item.urls.length)
      .map((item) => eventRefForRequestInput("url", item.event)), 16)
  };
}

function requestInputNetworkAnchor(events, rendererRequestLink = null) {
  const networkEvents = (events || [])
    .map((event, index) => ({event, index, info: networkRequestInfoFromEvent(event)}))
    .filter((item) => item.info);
  const preferred = networkEvents.find((item) => item.info.api === "BrowserNetwork.request") ||
    networkEvents.find((item) => item.info.api === "Request.constructor" || item.info.api === "fetch" || item.info.api === "XMLHttpRequest.send") ||
    networkEvents[0] ||
    null;
  if (!preferred) return null;
  return {
    api: preferred.info.api || preferred.event.api || "",
    seq: preferred.event.seq ?? null,
    trace_index: traceIndexValue(preferred.event, preferred.index),
    endpoint: preferred.info.endpoint || "",
    method: preferred.info.method || "",
    ...(preferred.info.network_correlation_key ? {network_correlation_key: preferred.info.network_correlation_key} : {}),
    ...(rendererRequestLink ? {
      renderer_link: {
        api: rendererRequestLink.api || "",
        seq: rendererRequestLink.seq ?? null,
        relation: rendererRequestLink.relation || "",
        trace_distance: rendererRequestLink.trace_distance ?? null,
        confidence: rendererRequestLink.confidence || "unknown"
      }
    } : {})
  };
}

function rawEventMatchesSummary(event, summary, index) {
  if (!event || !summary) return false;
  const summaryTraceIndex = explicitTraceIndexValue(summary);
  if (Number.isFinite(summaryTraceIndex) && traceIndexValue(event, index) === summaryTraceIndex) return true;
  if (summary.event_id && event.event_id === summary.event_id) return true;
  if (summary.seq !== null && summary.seq !== undefined && event.seq === summary.seq &&
      (!summary.api || event.api === summary.api)) {
    return true;
  }
  return false;
}

function rawEventForSummaryEvent(summary, allEvents) {
  for (let index = 0; index < (allEvents || []).length; index += 1) {
    if (rawEventMatchesSummary(allEvents[index], summary, index)) return {event: allEvents[index], index};
  }
  return null;
}

function rawEventForRequestLink(link, allEvents) {
  if (!link) return null;
  for (let index = 0; index < (allEvents || []).length; index += 1) {
    const event = allEvents[index];
    const info = networkRequestInfoFromEvent(event);
    if (!info) continue;
    if (Number.isFinite(link.trace_index) && traceIndexValue(event, index) === link.trace_index) {
      return {event, index};
    }
    if (link.seq !== null && link.seq !== undefined && event.seq === link.seq &&
        (!link.api || event.api === link.api)) {
      return {event, index};
    }
    if (link.endpoint && info.endpoint === link.endpoint && link.method && info.method === link.method &&
        (!link.api || info.api === link.api)) {
      return {event, index};
    }
  }
  return null;
}

function materialFlowTraceRange(flow, selectedItems = []) {
  const traces = selectedItems
    .map((item) => item.traceIndex)
    .filter(Number.isFinite);
  const seqs = selectedItems
    .map((item) => item.event?.seq)
    .filter(Number.isFinite);
  if (Number.isFinite(flow?.seq_start)) seqs.push(flow.seq_start);
  if (Number.isFinite(flow?.seq_end)) seqs.push(flow.seq_end);
  return {
    trace_start: traces.length ? Math.min(...traces) : null,
    trace_end: traces.length ? Math.max(...traces) : null,
    seq_start: seqs.length ? Math.min(...seqs) : null,
    seq_end: seqs.length ? Math.max(...seqs) : null
  };
}

function eventWithinMaterialFlowRange(event, index, range) {
  const trace = traceIndexValue(event, index);
  if (Number.isFinite(range.trace_start) && Number.isFinite(range.trace_end) &&
      trace >= range.trace_start - SIGNATURE_REQUEST_MATERIAL_TRACE_RADIUS &&
      trace <= range.trace_end + SIGNATURE_REQUEST_MATERIAL_TRACE_RADIUS) {
    return true;
  }
  const seq = event?.seq;
  return Number.isFinite(seq) &&
    Number.isFinite(range.seq_start) &&
    Number.isFinite(range.seq_end) &&
    seq >= range.seq_start - SIGNATURE_REQUEST_MATERIAL_TRACE_RADIUS &&
    seq <= range.seq_end + SIGNATURE_REQUEST_MATERIAL_TRACE_RADIUS;
}

function stackOrOriginMatchesMaterialFlow(event, flow) {
  const flowStack = flow?.stack_url || "";
  const flowAsset = flow?.asset_id || "";
  const flowOrigin = flow?.request_context?.request_initiator || "";
  const eventStack = stackFingerprintForRequestMaterial(event);
  if (flowAsset && eventStack.asset_id && flowAsset === eventStack.asset_id) return true;
  if (flowStack && eventStack.url && flowStack === eventStack.url) return true;
  if (flowOrigin && event?.origin && flowOrigin === event.origin) return true;
  return Boolean(!flowStack && !flowAsset && event?.origin);
}

function addRequestInputEvent(selected, seen, event, index) {
  if (!event) return;
  const key = `${traceIndexValue(event, index)}:${event.seq ?? "none"}:${event.api || "unknown"}`;
  if (seen.has(key)) return;
  seen.add(key);
  selected.push({event, index, traceIndex: traceIndexValue(event, index)});
}

function requestInputSourceKeys(flow, selectedItems) {
  const urls = new Set();
  const assetIds = new Set();
  const addUrl = (value) => {
    if (value) urls.add(String(value));
  };
  const addAssetId = (value) => {
    if (value) assetIds.add(String(value));
  };

  addUrl(flow?.stack_url);
  addAssetId(flow?.asset_id);
  for (const context of flow?.source_contexts || []) {
    addUrl(context.url);
    addAssetId(context.asset_id);
  }
  for (const window of flow?._request_input_event_windows || []) {
    for (const context of window.source_contexts || []) {
      addUrl(context.url);
      addAssetId(context.asset_id);
    }
  }
  for (const item of selectedItems || []) {
    for (const frame of item.event?.stack || []) {
      addUrl(frame.url);
      addAssetId(frame.asset_id);
    }
  }
  return {urls, assetIds};
}

function eventMatchesRequestInputSource(event, sourceKeys) {
  if (!sourceKeys) return false;
  for (const frame of event?.stack || []) {
    if (frame.asset_id && sourceKeys.assetIds.has(String(frame.asset_id))) return true;
    if (frame.url && sourceKeys.urls.has(String(frame.url))) return true;
  }
  const fingerprint = stackFingerprintForRequestMaterial(event);
  if (fingerprint.asset_id && sourceKeys.assetIds.has(fingerprint.asset_id)) return true;
  return Boolean(fingerprint.url && sourceKeys.urls.has(fingerprint.url));
}

function requestInputHeadersIdForEvent(event) {
  return numericRuntimeObjectId(networkRequestArg(event).headers_id);
}

function requestInputFormDataIdForEvent(event) {
  return numericRuntimeObjectId(networkRequestArg(event).form_data_id);
}

function requestInputBodySearchParamsIdForEvent(event) {
  return numericRuntimeObjectId(networkRequestArg(event).body_search_params_id);
}

function requestInputSearchParamsIdForEvent(event) {
  return numericRuntimeObjectId(networkRequestArg(event).search_params_id);
}

function isHeadersObjectMutationEvent(event) {
  return [
    "Headers.set",
    "Headers.append",
    "Headers.delete"
  ].includes(event?.api || "");
}

function isFormDataObjectMutationEvent(event) {
  return [
    "FormData.append",
    "FormData.set",
    "FormData.delete"
  ].includes(event?.api || "");
}

function isURLSearchParamsBodyObjectEvent(event) {
  return [
    "URLSearchParams.constructor",
    "URLSearchParams.append",
    "URLSearchParams.set",
    "URLSearchParams.delete",
    "URLSearchParams.sort",
    "URLSearchParams.toString"
  ].includes(event?.api || "");
}

function requestInputBodySearchParamsIdsForEvents(events) {
  return new Set(
    (events || [])
      .map(requestInputBodySearchParamsIdForEvent)
      .filter(Number.isFinite)
  );
}

function isLinkedURLSearchParamsBodyEvent(event, bodySearchParamsIds) {
  if (!isURLSearchParamsBodyObjectEvent(event)) return false;
  const searchParamsId = requestInputSearchParamsIdForEvent(event);
  return Number.isFinite(searchParamsId) && bodySearchParamsIds?.has(searchParamsId);
}

function addLinkedHeadersObjectEvents(selected, seen, allEvents) {
  const headersIds = new Set(
    (selected || [])
      .map((item) => requestInputHeadersIdForEvent(item.event))
      .filter(Number.isFinite)
  );
  if (!headersIds.size) return;
  for (let index = 0; index < (allEvents || []).length; index += 1) {
    const event = allEvents[index];
    if (!isHeadersObjectMutationEvent(event)) continue;
    const headersId = requestInputHeadersIdForEvent(event);
    if (!headersIds.has(headersId)) continue;
    addRequestInputEvent(selected, seen, event, index);
  }
}

function addLinkedFormDataObjectEvents(selected, seen, allEvents) {
  const formDataIds = new Set(
    (selected || [])
      .map((item) => requestInputFormDataIdForEvent(item.event))
      .filter(Number.isFinite)
  );
  if (!formDataIds.size) return;
  for (let index = 0; index < (allEvents || []).length; index += 1) {
    const event = allEvents[index];
    if (!isFormDataObjectMutationEvent(event)) continue;
    const formDataId = requestInputFormDataIdForEvent(event);
    if (!formDataIds.has(formDataId)) continue;
    addRequestInputEvent(selected, seen, event, index);
  }
}

function addLinkedBodySearchParamsObjectEvents(selected, seen, allEvents) {
  const bodySearchParamsIds = new Set(
    (selected || [])
      .map((item) => requestInputBodySearchParamsIdForEvent(item.event))
      .filter(Number.isFinite)
  );
  if (!bodySearchParamsIds.size) return;
  for (let index = 0; index < (allEvents || []).length; index += 1) {
    const event = allEvents[index];
    if (!isLinkedURLSearchParamsBodyEvent(event, bodySearchParamsIds)) continue;
    addRequestInputEvent(selected, seen, event, index);
  }
}

function addLinkedBrowserRequestEventsByCorrelationKey(selected, seen, allEvents) {
  const correlationKeys = new Set(
    (selected || [])
      .map((item) => networkCorrelationKeyForEvent(item.event))
      .filter(Boolean)
  );
  if (!correlationKeys.size) return;
  for (let index = 0; index < (allEvents || []).length; index += 1) {
    const event = allEvents[index];
    if ((event?.api || "") !== "BrowserNetwork.request") continue;
    const correlationKey = networkCorrelationKeyForEvent(event);
    if (!correlationKeys.has(correlationKey)) continue;
    addRequestInputEvent(selected, seen, event, index);
  }
}

function addLinkedBrowserResponseEventsByCorrelationKey(selected, seen, allEvents) {
  const correlationKeys = new Set(
    (selected || [])
      .map((item) => networkCorrelationKeyForEvent(item.event))
      .filter(Boolean)
  );
  if (!correlationKeys.size) return;
  for (let index = 0; index < (allEvents || []).length; index += 1) {
    const event = allEvents[index];
    if (!isBrowserNetworkResponseEvent(event)) continue;
    const correlationKey = networkCorrelationKeyForEvent(event);
    if (!correlationKeys.has(correlationKey)) continue;
    addRequestInputEvent(selected, seen, event, index);
  }
}

function requestInputEventDistanceToRange(event, index, range) {
  const trace = traceIndexValue(event, index);
  const traceDistances = [];
  if (Number.isFinite(range.trace_start)) traceDistances.push(Math.abs(trace - range.trace_start));
  if (Number.isFinite(range.trace_end)) traceDistances.push(Math.abs(trace - range.trace_end));
  const seq = event?.seq;
  if (Number.isFinite(seq)) {
    if (Number.isFinite(range.seq_start)) traceDistances.push(Math.abs(seq - range.seq_start));
    if (Number.isFinite(range.seq_end)) traceDistances.push(Math.abs(seq - range.seq_end));
  }
  return traceDistances.length ? Math.min(...traceDistances) : Number.MAX_SAFE_INTEGER;
}

function requestInputEventsForMaterialFlow(flow, allEvents) {
  const selected = [];
  const seen = new Set();
  const windows = flow?.event_windows || flow?._request_input_event_windows || [];
  for (const window of windows) {
    for (const summary of window.events || []) {
      const raw = rawEventForSummaryEvent(summary, allEvents);
      if (raw) addRequestInputEvent(selected, seen, raw.event, raw.index);
    }
  }

  const linkedRequest = rawEventForRequestLink(flow?.renderer_request_link, allEvents);
  if (linkedRequest) addRequestInputEvent(selected, seen, linkedRequest.event, linkedRequest.index);

  const range = materialFlowTraceRange(flow, selected);
  const sourceKeys = requestInputSourceKeys(flow, selected);
  const ambientCandidates = [];
  for (let index = 0; index < (allEvents || []).length; index += 1) {
    const event = allEvents[index];
    const isAmbientInput = isStorageInputEvent(event) || isCookieInputEvent(event);
    const isRequestMaterial = requestMaterialPhaseForEvent(event);
    if (!isAmbientInput && !isRequestMaterial) continue;
    const inRange = eventWithinMaterialFlowRange(event, index, range);
    if (isRequestMaterial) {
      if (inRange) addRequestInputEvent(selected, seen, event, index);
      continue;
    }
    if (inRange && stackOrOriginMatchesMaterialFlow(event, flow)) {
      addRequestInputEvent(selected, seen, event, index);
      continue;
    }
    if (eventMatchesRequestInputSource(event, sourceKeys)) {
      ambientCandidates.push({
        event,
        index,
        traceIndex: traceIndexValue(event, index),
        distance: requestInputEventDistanceToRange(event, index, range)
      });
    }
  }

  for (const candidate of ambientCandidates
    .sort((left, right) =>
      left.distance - right.distance ||
      left.traceIndex - right.traceIndex ||
      (left.event.seq ?? 0) - (right.event.seq ?? 0))
    .slice(0, SIGNATURE_REQUEST_AMBIENT_INPUT_EVENT_LIMIT)) {
    addRequestInputEvent(selected, seen, candidate.event, candidate.index);
  }

  addLinkedHeadersObjectEvents(selected, seen, allEvents);
  addLinkedFormDataObjectEvents(selected, seen, allEvents);
  addLinkedBodySearchParamsObjectEvents(selected, seen, allEvents);
  addLinkedBrowserRequestEventsByCorrelationKey(selected, seen, allEvents);
  addLinkedBrowserResponseEventsByCorrelationKey(selected, seen, allEvents);

  return selected
    .sort((left, right) => left.traceIndex - right.traceIndex || (left.event.seq ?? 0) - (right.event.seq ?? 0))
    .map((item) => item.event);
}

function requestInputCaptureGaps(bundle) {
  const gaps = [];
  if (!bundle.url?.observed) gaps.push("request_url_not_captured");
  if (!bundle.headers?.observed) gaps.push("request_headers_not_captured");
  if (bundle.network_anchor?.method && ["POST", "PUT", "PATCH"].includes(bundle.network_anchor.method) && !bundle.body?.observed) {
    gaps.push("request_body_not_captured");
  }
  if (!bundle.cookies?.observed) gaps.push("cookie_material_not_observed");
  if (!bundle.storage?.observed) gaps.push("storage_material_not_observed");
  return gaps;
}

function buildRequestInputBundleForMaterialFlow(flow, allEvents = []) {
  const events = requestInputEventsForMaterialFlow(flow, allEvents);
  if (!events.length) return null;
  const requestEvents = events.filter((event) => networkRequestInfoFromEvent(event));
  const headerEvents = events.filter((event) =>
    event?.api === "XMLHttpRequest.setRequestHeader" ||
    event?.api === "Headers.set" ||
    event?.api === "Headers.append" ||
    event?.api === "Headers.delete" ||
    networkRequestInfoFromEvent(event)
  );
  const bundle = {
    version: 1,
    endpoint: flow?.endpoint || "",
    target_params: sortParamNames(flow?.target_params || []),
    network_anchor: requestInputNetworkAnchor(requestEvents, flow?.renderer_request_link || null),
    url: requestInputUrlSummary(requestEvents.length ? requestEvents : events),
    headers: requestInputHeaderSummary(headerEvents),
    body: requestInputBodySummary(events),
    response: requestInputResponseSummary(events),
    cookies: requestInputCookieSummary(events),
    storage: requestInputStorageSummary(events),
    evidence_refs: uniqueLimited(events.map((event) => eventRefForRequestInput(
      isBrowserNetworkResponseEvent(event) ? "response" :
        networkRequestInfoFromEvent(event) ? "request" :
        isCookieInputEvent(event) ? "cookie" :
          isStorageInputEvent(event) ? "storage" :
            requestMaterialPhaseForEvent(event) || "event",
      event
    )), 32)
  };
  bundle.capture_gaps = requestInputCaptureGaps(bundle);
  return bundle;
}

function addNetworkRankingSignal(signals, seen, signal) {
  if (seen.has(signal)) return 0;
  seen.add(signal);
  signals.push(signal);
  return SIGNATURE_ABSENT_NETWORK_SIGNAL_WEIGHTS.get(signal) || 0;
}

function isLikelyStaticNetworkPath(pathname) {
  return /\.(?:js|mjs|css|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|map|json)$/i.test(pathname || "");
}

function isLikelyStaticNetworkResource(info, event = null) {
  if (isLikelyStaticNetworkPath(info?.path || "")) return true;
  const arg = event ? networkRequestArg(event) : {};
  const destination = String(
    arg.request_destination ||
    arg.destination ||
    arg.resource_type ||
    arg.resourceType ||
    ""
  ).toLowerCase();
  return [
    "script",
    "stylesheet",
    "style",
    "image",
    "font",
    "media",
    "object",
    "embed",
    "manifest",
    "favicon"
  ].includes(destination);
}

function isLikelyDocumentNetworkRequest(info, event = null) {
  const arg = event ? networkRequestArg(event) : {};
  const destination = String(
    arg.request_destination ||
    arg.destination ||
    arg.resource_type ||
    arg.resourceType ||
    ""
  ).toLowerCase();
  if (["document", "main_frame", "sub_frame", "iframe"].includes(destination)) return true;
  const pathName = String(info?.path || "");
  return (info?.method || "GET") === "GET" && (pathName === "/" || /\.html?$/i.test(pathName));
}

function isLikelyTelemetryNetworkEndpoint(info) {
  const host = String(info.host || "").toLowerCase();
  const endpoint = String(info.endpoint || "").toLowerCase();
  const pathName = String(info.path || "").toLowerCase();
  return (
    host.startsWith("mon.") ||
    host.includes("monitor") ||
    host.includes("analytics") ||
    endpoint.includes("/monitor_") ||
    endpoint.includes("/monitor/") ||
    pathName.includes("/collect") ||
    pathName.includes("/analytics") ||
    pathName.includes("/telemetry") ||
    pathName.includes("browser-settings")
  );
}

function networkResourceClass(info, event = null) {
  if (isLikelyTelemetryNetworkEndpoint(info)) return "telemetry_endpoint";
  if (isLikelyStaticNetworkResource(info, event)) return "static_resource";
  if (isLikelyDocumentNetworkRequest(info, event)) return "document_request";
  return "";
}

function networkInfoFromEndpoint(endpoint, method = "GET") {
  const cacheKey = `${method || "GET"}\u0000${endpoint || ""}`;
  if (NETWORK_INFO_FROM_ENDPOINT_CACHE.has(cacheKey)) {
    return NETWORK_INFO_FROM_ENDPOINT_CACHE.get(cacheKey);
  }
  let info;
  try {
    const parsed = new URL(endpoint);
    info = {
      endpoint: endpointForUrl(parsed),
      method: method || "GET",
      host: parsed.hostname,
      path: parsed.pathname || "/"
    };
  } catch {
    info = {
      endpoint: endpoint || "",
      method: method || "GET",
      host: "",
      path: ""
    };
  }
  NETWORK_INFO_FROM_ENDPOINT_CACHE.set(cacheKey, info);
  return info;
}

function networkResourceClassForEndpoint(endpoint, method = "GET") {
  return networkResourceClass(networkInfoFromEndpoint(endpoint, method));
}

function businessRelevanceForResourceClass(resourceClass) {
  if (resourceClass === "telemetry_endpoint") return "low_value_telemetry";
  if (resourceClass === "static_resource") return "low_value_static_resource";
  if (resourceClass === "document_request") return "low_value_document_request";
  return "business_api_candidate";
}

function isBusinessApiEndpoint(endpoint) {
  const info = networkInfoFromEndpoint(endpoint);
  if (!info.endpoint || isLowValueNetworkResourceClass(networkResourceClass(info))) return false;
  return /(?:^|\/)api(?:\/|$)/i.test(info.path || "");
}

function eventHasTruncatedUrlPreview(event) {
  const values = [event.args, event.result, event.error];
  const stack = [...values];
  const seen = new Set();
  while (stack.length) {
    const value = stack.pop();
    if (!value || typeof value !== "object") continue;
    if (seen.has(value)) continue;
    seen.add(value);
    if (Array.isArray(value)) {
      stack.push(...value);
      continue;
    }
    if (
      value.input_truncated ||
      value.result_truncated ||
      value.url_truncated ||
      value.truncated
    ) {
      return true;
    }
    for (const [key, child] of Object.entries(value)) {
      if (/_length$/.test(key)) {
        const previewKey = key.replace(/_length$/, "_preview");
        if (
          typeof value[previewKey] === "string" &&
          Number.isFinite(value[key]) &&
          value[key] > value[previewKey].length
        ) {
          return true;
        }
      }
      if (child && typeof child === "object") stack.push(child);
    }
  }
  return false;
}

function isFullUrlValueFieldName(name) {
  return [
    "input",
    "result",
    "url",
    "href",
    "request_url",
    "before_url",
    "after_url",
    "signed_url"
  ].includes(name || "");
}

function eventHasFullUrlValueForEndpoint(value, endpoint, depth = 0, seen = new Set()) {
  if (depth > 6 || value === undefined || value === null) return false;
  if (Array.isArray(value)) {
    return value.some((item) => eventHasFullUrlValueForEndpoint(item, endpoint, depth + 1, seen));
  }
  if (typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);

  for (const [key, child] of Object.entries(value)) {
    if (typeof child === "string" && isFullUrlValueFieldName(key)) {
      const parsed = parseUrlCandidate(child);
      if (parsed && endpointForUrl(parsed) === endpoint) {
        return value[`${key}_truncated`] !== true && value[`${key}_value_truncated`] !== true;
      }
    }
    if (child && typeof child === "object" &&
        eventHasFullUrlValueForEndpoint(child, endpoint, depth + 1, seen)) {
      return true;
    }
  }
  return false;
}

function sourceRoleForRuntimeHintFrame(frame, assetByUrl) {
  const asset = assetByUrl.get(frame.url || "");
  if (isCoreSignatureAsset({
    asset_id: frame.asset_id || asset?.asset_id || "",
    stack_url: frame.url || "",
    content_path: frame.asset_path || asset?.content_path || ""
  })) {
    return "core_signature_asset";
  }
  if (frame.url) return "application_caller";
  return "";
}

function buildBusinessApiRuntimeHints(events, assetFindings = []) {
  const assetByUrl = new Map((assetFindings || [])
    .filter((asset) => asset.url)
    .map((asset) => [asset.url, asset]));
  const hints = [];
  const seen = new Set();

  for (const event of events || []) {
    if (!BUSINESS_API_RUNTIME_APIS.has(event.api || "")) continue;
    const urls = urlsFromEvent(event)
      .sort((left, right) =>
        [...right.parsed.searchParams.keys()].length - [...left.parsed.searchParams.keys()].length ||
        String(right.raw || "").length - String(left.raw || "").length
      );
    if (!urls.length) continue;
    const previewTruncated = eventHasTruncatedUrlPreview(event);
    for (const {parsed} of urls) {
      const endpoint = endpointForUrl(parsed);
      if (!isBusinessApiEndpoint(endpoint)) continue;
      const key = `${event.seq ?? "none"}:${event.api || ""}:${endpoint}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const resourceClass = networkResourceClassForEndpoint(endpoint);
      const queryKeys = runtimeHintQueryKeys([...parsed.searchParams.keys()], 24);
      const hasFullValue = eventHasFullUrlValueForEndpoint([event.args, event.result, event.error], endpoint);
      const evidenceGaps = uniqueLimited([
        ...(!hasFullValue && previewTruncated ? ["full_url_value_truncated", "query_keys_incomplete"] : []),
        ...(!queryKeys.length ? ["query_keys_not_observed"] : [])
      ], 8);
      const sourceStackUrls = uniqueLimited((event.stack || [])
        .map((frame) => frame.url || "")
        .filter(Boolean), 8);
      const sourceRoles = uniqueLimited((event.stack || [])
        .map((frame) => sourceRoleForRuntimeHintFrame(frame, assetByUrl))
        .filter(Boolean), 4);
      hints.push({
        endpoint,
        api: event.api || "",
        seq: event.seq ?? null,
        event_id: event.event_id || "",
        business_relevance: businessRelevanceForResourceClass(resourceClass),
        resource_class: resourceClass || "",
        value_status: hasFullValue ? "full_value" : previewTruncated ? "truncated_preview" : "full_preview",
        query_keys: queryKeys,
        source_roles: sourceRoles,
        source_stack_urls: sourceStackUrls,
        source_functions: uniqueLimited((event.stack || [])
          .map((frame) => frame.function || "")
          .filter(Boolean), 8),
        source_assets: uniqueLimited((event.stack || [])
          .map((frame) => frame.asset_id || assetByUrl.get(frame.url || "")?.asset_id || "")
          .filter(Boolean), 8),
        evidence_gaps: evidenceGaps,
        next_actions: uniqueLimited([
          ...(!hasFullValue && previewTruncated ? ["capture_full_url_value"] : []),
          "capture_network_anchor_for_endpoint",
          ...(!sourceStackUrls.length ? ["capture_source_stack"] : [])
        ], 8)
      });
    }
  }

  return hints
    .sort((a, b) => (a.seq ?? Number.MAX_SAFE_INTEGER) - (b.seq ?? Number.MAX_SAFE_INTEGER))
    .slice(0, 24);
}

function isLowValueNetworkResourceClass(resourceClass) {
  return [
    "static_resource",
    "telemetry_endpoint",
    "document_request"
  ].includes(resourceClass || "");
}

function scoreSignatureAbsentNetworkAnchor(info, event, nearbyVmpCandidates, assetByUrl) {
  const signals = [];
  const seen = new Set();
  let evidenceScore = 0;
  const api = info.api || "";
  const method = info.method || "GET";
  const urlInfo = urlsFromEvent(event)[0];
  const resourceClass = networkResourceClass(info, event);

  if (api === "fetch" || api === "Request.constructor" || api.startsWith("XMLHttpRequest.")) {
    evidenceScore += addNetworkRankingSignal(signals, seen, "script_request_api");
  } else if (info.is_fetch_like_api) {
    evidenceScore += addNetworkRankingSignal(signals, seen, "browser_fetch_like_request");
  }
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    evidenceScore += addNetworkRankingSignal(signals, seen, "state_changing_method");
  }
  if (info.path && info.path !== "/" && !isLikelyStaticNetworkPath(info.path)) {
    evidenceScore += addNetworkRankingSignal(signals, seen, "application_endpoint");
  }
  if (urlInfo?.parsed?.searchParams && [...urlInfo.parsed.searchParams.keys()].length > 0) {
    evidenceScore += addNetworkRankingSignal(signals, seen, "query_params_present");
  }
  if (resourceClass === "static_resource") {
    evidenceScore += addNetworkRankingSignal(signals, seen, "deprioritized:static_resource_request");
  } else if (resourceClass === "telemetry_endpoint") {
    evidenceScore += addNetworkRankingSignal(signals, seen, "deprioritized:telemetry_endpoint");
  } else if (resourceClass === "document_request") {
    evidenceScore += addNetworkRankingSignal(signals, seen, "deprioritized:document_request");
  }

  const nearbyFamilies = new Set((nearbyVmpCandidates || [])
    .map((candidate) => candidate.family)
    .filter(Boolean));
  for (const family of SIGNATURE_ABSENT_NETWORK_VMP_FAMILY_SIGNAL_ORDER) {
    if (!nearbyFamilies.has(family)) continue;
    const signal = `nearby_vmp:${family}`;
    evidenceScore += addNetworkRankingSignal(signals, seen, signal);
  }
  for (const family of [...nearbyFamilies].sort()) {
    const signal = `nearby_vmp:${family}`;
    evidenceScore += addNetworkRankingSignal(signals, seen, signal);
  }

  const hasObfuscatedAsset = (nearbyVmpCandidates || []).some((candidate) => {
    const asset = assetByUrl.get(candidate.stack_url || "");
    return asset && (asset.score > 0 || (asset.signals || []).length > 0);
  });
  if (hasObfuscatedAsset) {
    evidenceScore += addNetworkRankingSignal(signals, seen, "nearby_obfuscated_asset");
  }

  return {
    evidence_score: evidenceScore,
    ranking_signals: signals,
    ...(resourceClass ? {resource_class: resourceClass} : {})
  };
}

function compareNearbyVmpCandidate(a, b) {
  if (a.trace_distance !== b.trace_distance) return a.trace_distance - b.trace_distance;
  if (a.relation !== b.relation) return a.relation === "before_request" ? -1 : 1;
  return (a.trace_index ?? 0) - (b.trace_index ?? 0) || String(a.api).localeCompare(String(b.api));
}

function compareSignatureAbsentNetworkAnchor(a, b) {
  if (a.evidence_score !== b.evidence_score) return b.evidence_score - a.evidence_score;
  const aPost = ["POST", "PUT", "PATCH", "DELETE"].includes(a.method || "") ? 1 : 0;
  const bPost = ["POST", "PUT", "PATCH", "DELETE"].includes(b.method || "") ? 1 : 0;
  if (aPost !== bPost) return bPost - aPost;
  return (a.trace_index ?? 0) - (b.trace_index ?? 0) || String(a.endpoint).localeCompare(String(b.endpoint));
}

function isRendererRequestApi(api) {
  return api === "Request.constructor" || api === "fetch" || api.startsWith("XMLHttpRequest.");
}

function summarizeRendererRequestLink(rendererItem, browserInfo, browserTraceIndex, assetByUrl, match = "endpoint_method_trace_window") {
  const rendererEvent = rendererItem.event;
  const rendererInfo = rendererItem.info;
  const rendererTraceIndex = rendererItem.traceIndex;
  const frame = (rendererEvent.stack || []).find((item) => item?.url || item?.function) || {};
  const stackUrl = frame.url || rendererEvent.frame_url || rendererEvent.origin || "";
  const asset = stackUrl ? assetByUrl.get(stackUrl) : null;
  const traceDistance = Math.abs(browserTraceIndex - rendererTraceIndex);
  return {
    trace_index: rendererTraceIndex,
    seq: rendererEvent.seq ?? null,
    api: rendererEvent.api || "",
    method: rendererInfo.method || browserInfo.method || "GET",
    endpoint: rendererInfo.endpoint || browserInfo.endpoint || "",
    relation: rendererTraceIndex <= browserTraceIndex ? "before_browser_request" : "after_browser_request",
    trace_distance: traceDistance,
    function: frame.function || "(anonymous)",
    stack_url: stackUrl,
    asset_id: asset?.asset_id || "",
    confidence: match === "network_correlation_key" ||
        (traceDistance <= 1000 && rendererTraceIndex <= browserTraceIndex)
      ? "high"
      : "medium",
    ...(match === "network_correlation_key" ? {match} : {})
  };
}

function findRendererRequestLink(info, traceIndex, rendererRequestItems, assetByUrl) {
  if ((info.api || "") !== "BrowserNetwork.request") return null;
  if (info.network_correlation_key) {
    const keyedCandidates = (rendererRequestItems || [])
      .filter((item) => item.info.network_correlation_key === info.network_correlation_key)
      .filter((item) => !info.method || !item.info.method || item.info.method === info.method)
      .map((item) => ({
        item,
        distance: Math.abs(traceIndex - item.traceIndex),
        before: item.traceIndex <= traceIndex
      }))
      .sort((a, b) =>
        Number(b.before) - Number(a.before) ||
        a.distance - b.distance ||
        (a.item.traceIndex ?? 0) - (b.item.traceIndex ?? 0));
    if (keyedCandidates.length) {
      return summarizeRendererRequestLink(
        keyedCandidates[0].item,
        info,
        traceIndex,
        assetByUrl,
        "network_correlation_key"
      );
    }
  }
  const candidates = (rendererRequestItems || [])
    .filter((item) => item.info.endpoint === info.endpoint)
    .filter((item) => !info.method || !item.info.method || item.info.method === info.method)
    .map((item) => ({
      item,
      distance: Math.abs(traceIndex - item.traceIndex),
      before: item.traceIndex <= traceIndex
    }))
    .filter((candidate) => candidate.distance <= SIGNATURE_ABSENT_RENDERER_REQUEST_TRACE_RADIUS)
    .sort((a, b) =>
      Number(b.before) - Number(a.before) ||
      a.distance - b.distance ||
      (a.item.traceIndex ?? 0) - (b.item.traceIndex ?? 0));
  if (!candidates.length) return null;
  return summarizeRendererRequestLink(candidates[0].item, info, traceIndex, assetByUrl);
}

function summarizeInferredInitiatorFromNearbyVmp(info, rendererRequestLink, nearbyVmpCandidates) {
  if ((info?.api || "") !== "BrowserNetwork.request" || rendererRequestLink) return null;
  const groups = new Map();
  for (const candidate of nearbyVmpCandidates || []) {
    const stackUrl = candidate.stack_url || "";
    const functionName = candidate.function || "(anonymous)";
    if (!stackUrl && !functionName) continue;
    const key = `${functionName}\u0000${stackUrl}`;
    const group = groups.get(key) || {
      relation: "nearby_vmp_stack",
      confidence: "low",
      function: functionName,
      stack_url: stackUrl,
      asset_id: candidate.asset_id || "",
      event_count: 0,
      seq_start: null,
      seq_end: null,
      trace_distance_min: null,
      trace_distance_max: null,
      apiCounts: new Map(),
      familySet: new Set()
    };
    group.event_count += 1;
    if (!group.asset_id && candidate.asset_id) group.asset_id = candidate.asset_id;
    if (Number.isFinite(candidate.seq)) {
      group.seq_start = group.seq_start === null ? candidate.seq : Math.min(group.seq_start, candidate.seq);
      group.seq_end = group.seq_end === null ? candidate.seq : Math.max(group.seq_end, candidate.seq);
    }
    if (Number.isFinite(candidate.trace_distance)) {
      group.trace_distance_min = group.trace_distance_min === null
        ? candidate.trace_distance
        : Math.min(group.trace_distance_min, candidate.trace_distance);
      group.trace_distance_max = group.trace_distance_max === null
        ? candidate.trace_distance
        : Math.max(group.trace_distance_max, candidate.trace_distance);
    }
    if (candidate.api) group.apiCounts.set(candidate.api, (group.apiCounts.get(candidate.api) || 0) + 1);
    if (candidate.family) group.familySet.add(candidate.family);
    groups.set(key, group);
  }

  const candidates = [...groups.values()]
    .filter((group) => group.event_count >= 2)
    .map((group) => {
      const families = [...group.familySet].sort();
      const confidence = group.event_count >= 4 || families.length >= 3 ? "medium" : "low";
      return {
        relation: group.relation,
        confidence,
        function: group.function,
        stack_url: group.stack_url,
        asset_id: group.asset_id,
        event_count: group.event_count,
        seq_start: group.seq_start,
        seq_end: group.seq_end,
        trace_distance_min: group.trace_distance_min,
        trace_distance_max: group.trace_distance_max,
        families,
        apis: sortCountEntries(group.apiCounts, "api").slice(0, 8)
      };
    })
    .sort((a, b) => {
      const confidenceRank = {medium: 0, low: 1};
      return (confidenceRank[a.confidence] ?? 99) - (confidenceRank[b.confidence] ?? 99) ||
        b.event_count - a.event_count ||
        (a.trace_distance_min ?? Number.MAX_SAFE_INTEGER) - (b.trace_distance_min ?? Number.MAX_SAFE_INTEGER) ||
        String(a.function).localeCompare(String(b.function)) ||
        String(a.stack_url).localeCompare(String(b.stack_url));
    });
  return candidates[0] || null;
}

function buildSignatureAbsentAnchorPipeline(info, event, nearbyVmpItems, rendererRequestEvent = null) {
  const traceIndex = traceIndexValue(event, Number.MAX_SAFE_INTEGER);
  const cluster = {
    phaseSeq: new Map([["signed_request", traceIndex]]),
    observedApiCounts: new Map(),
    candidateApiCounts: new Map(),
    confidenceSet: new Set(["medium"]),
    sourceContexts: new Map(),
    eventSummaries: [],
    candidatePhaseCount: 0
  };
  addCount(cluster.observedApiCounts, info.api || event?.api || "", 1);
  if (rendererRequestEvent) {
    addCount(cluster.observedApiCounts, rendererRequestEvent.api || "", 1);
    cluster.eventSummaries.push(rendererRequestEvent);
    addClusterPhase(cluster, "request_construction", traceIndexValue(rendererRequestEvent, rendererRequestEvent.seq ?? null));
  }
  const chronological = [...(nearbyVmpItems || [])]
    .sort((a, b) => traceIndexValue(a.event) - traceIndexValue(b.event) || String(a.event?.api).localeCompare(String(b.event?.api)));
  for (const item of chronological) {
    addCount(cluster.candidateApiCounts, item.event?.api || "", 1);
    cluster.eventSummaries.push(item.event);
    addClusterSourceContexts(cluster, item.candidate?.context_window?.source_contexts || []);
  }
  cluster.eventSummaries.push(event);
  return buildCandidateSignaturePipeline(cluster);
}

function phaseForNearbyVmpCandidate(candidate) {
  return phaseForAgentTimelineEvent({api: candidate?.api || "", role: "vmp"}) || "vmp_runtime";
}

function candidateChainConfidence(anchor) {
  const context = anchor.request_context || {};
  const hasRendererLink = Boolean(context.renderer_request_link);
  const hasUploadMetadata = Boolean(context.upload_body);
  const hookTypes = new Set((anchor.vmp_analysis_points || []).map((point) => point.type));
  const hasHashOrInt = hookTypes.has("vmp_hash_or_signature_pipeline") ||
    hookTypes.has("vmp_int_bitwise_pipeline");
  const hasBytecodeOrRuntime = hookTypes.has("vmp_bytecode_or_register_access") ||
    hookTypes.has("vmp_runtime_cluster");

  if (hasRendererLink && hasUploadMetadata && hasHashOrInt) return "high";
  if (hasRendererLink && (hasHashOrInt || hasBytecodeOrRuntime)) return "high";
  if ((anchor.nearby_vmp_candidates || []).length >= 3 && (hasHashOrInt || hasBytecodeOrRuntime)) return "medium";
  if ((anchor.vmp_analysis_points || []).length) return "medium";
  return "low";
}

function summarizeCandidateChainRequestContext(context) {
  const upload = context?.upload_body
    ? {
        element_count: context.upload_body.element_count,
        total_bytes: context.upload_body.total_bytes,
        in_memory_bytes: context.upload_body.in_memory_bytes
      }
    : null;
  const renderer = context?.renderer_request_link || null;
  return {
    request_initiator: context?.request_initiator || "",
    referrer: context?.referrer || "",
    ...(upload ? {upload} : {}),
    renderer_link: renderer
      ? `${renderer.api}@${renderer.seq ?? "none"}:${renderer.relation}:${renderer.trace_distance}`
      : "none",
    ...(context?.inferred_initiator ? {inferred_initiator: context.inferred_initiator} : {}),
    capture_gaps: context?.capture_gaps || []
  };
}

function sourceContextsFromNearbyCandidates(candidates) {
  const sourceContexts = [];
  const seen = new Set();
  for (const candidate of candidates || []) {
    for (const context of candidate.context_window?.source_contexts || []) {
      const key = sourceContextKey(context);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      sourceContexts.push(context);
      if (sourceContexts.length >= SOURCE_CONTEXTS_PER_WINDOW) {
        return sourceContexts;
      }
    }
  }
  return sourceContexts;
}

function sourceContextRefsForContexts(contexts) {
  return (contexts || [])
    .map(sourceContextKey)
    .filter(Boolean);
}

function buildCandidateTraceChain(anchor, index) {
  const chainSourceContexts = sourceContextsFromNearbyCandidates(anchor.nearby_vmp_candidates);
  const chainSourceContextRefs = sourceContextRefsForContexts(chainSourceContexts);
  const steps = [];
  const renderer = anchor.request_context?.renderer_request_link;
  if (renderer) {
    steps.push({
      phase: "request_construction",
      api: renderer.api || "",
      seq: renderer.seq ?? null,
      trace_index: renderer.trace_index ?? null,
      relation: renderer.relation || "",
      trace_distance: renderer.trace_distance ?? null,
      method: renderer.method || anchor.method || "",
      endpoint: renderer.endpoint || anchor.endpoint || "",
      function: renderer.function || "",
      stack_url: renderer.stack_url || "",
      asset_id: renderer.asset_id || "",
      confidence: renderer.confidence || "medium",
      match: renderer.match || "endpoint_method_trace_window"
    });
  }

  for (const candidate of [...(anchor.nearby_vmp_candidates || [])]
    .sort((a, b) => (a.trace_index ?? Number.MAX_SAFE_INTEGER) - (b.trace_index ?? Number.MAX_SAFE_INTEGER) ||
      (a.seq ?? Number.MAX_SAFE_INTEGER) - (b.seq ?? Number.MAX_SAFE_INTEGER) ||
      String(a.api).localeCompare(String(b.api)))) {
    steps.push({
      phase: phaseForNearbyVmpCandidate(candidate),
      api: candidate.api || "",
      family: candidate.family || "",
      seq: candidate.seq ?? null,
      trace_index: candidate.trace_index ?? null,
      relation: candidate.relation || "",
      trace_distance: candidate.trace_distance ?? null,
      function: candidate.function || "",
      stack_url: candidate.stack_url || "",
      asset_id: candidate.asset_id || ""
    });
  }

  steps.push({
    phase: "signed_request",
    api: anchor.api || "",
    seq: anchor.seq ?? null,
    trace_index: anchor.trace_index ?? null,
    relation: "anchor",
    trace_distance: 0,
    method: anchor.method || "GET",
    endpoint: anchor.endpoint || ""
  });

  return {
    id: `absent_candidate_chain_${index + 1}`,
    endpoint: anchor.endpoint || "",
    method: anchor.method || "GET",
    anchor_api: anchor.api || "",
    confidence: candidateChainConfidence(anchor),
    evidence_score: anchor.evidence_score ?? 0,
    ...(anchor.resource_class ? {resource_class: anchor.resource_class} : {}),
    ranking_signals: anchor.ranking_signals || [],
    hook_points: (anchor.vmp_analysis_points || []).slice(0, VMP_ANALYSIS_POINT_LIMIT).map((point) => ({
      type: point.type,
      seq_start: point.seq_start,
      seq_end: point.seq_end,
      event_count: point.event_count,
      families: point.families || [],
      apis: point.apis || []
    })),
    request_context: summarizeCandidateChainRequestContext(anchor.request_context || {}),
    ...(anchor.request_context?.inferred_initiator ? {inferred_initiator: anchor.request_context.inferred_initiator} : {}),
    candidate_signature_pipeline: anchor.candidate_signature_pipeline || null,
    source_context_refs: chainSourceContextRefs,
    source_contexts: sourceContextsForMaterialFlow(chainSourceContexts),
    steps
  };
}

function compareCandidateTraceChain(a, b) {
  const confidenceRank = {high: 0, medium: 1, low: 2};
  const aBrowser = a.anchor_api === "BrowserNetwork.request" ? 1 : 0;
  const bBrowser = b.anchor_api === "BrowserNetwork.request" ? 1 : 0;
  return (confidenceRank[a.confidence] ?? 99) - (confidenceRank[b.confidence] ?? 99) ||
    bBrowser - aBrowser ||
    b.evidence_score - a.evidence_score ||
    String(a.endpoint).localeCompare(String(b.endpoint));
}

function buildSignatureAbsentCandidateTraceChains(networkAnchors) {
  return (networkAnchors || [])
    .filter((anchor) => (anchor.nearby_vmp_candidates || []).length || anchor.request_context?.renderer_request_link)
    .map(buildCandidateTraceChain)
    .sort(compareCandidateTraceChain)
    .slice(0, 8)
    .map((chain, index) => ({
      ...chain,
      id: `absent_candidate_chain_${index + 1}`
    }));
}

function summarizeNearbyVmpCandidate(event, networkTraceIndex, assetByUrl) {
  const candidateTraceIndex = traceIndexValue(event, null);
  if (!Number.isFinite(candidateTraceIndex) || !Number.isFinite(networkTraceIndex)) return null;
  const traceDistance = Math.abs(candidateTraceIndex - networkTraceIndex);
  if (traceDistance > SIGNATURE_ABSENT_NEARBY_VMP_TRACE_RADIUS) return null;

  const frame = (event.stack || []).find((item) => item?.url || item?.function) || {};
  const stackUrl = frame.url || event.frame_url || event.origin || "";
  const asset = stackUrl ? assetByUrl.get(stackUrl) : null;
  return {
    trace_index: candidateTraceIndex,
    seq: event.seq ?? null,
    api: event.api || "",
    family: vmpFamilyForApi(event.api),
    relation: candidateTraceIndex <= networkTraceIndex ? "before_request" : "after_request",
    trace_distance: traceDistance,
    function: frame.function || "(anonymous)",
    stack_url: stackUrl,
    asset_id: asset?.asset_id || ""
  };
}

function enrichNearbyVmpItemsWithSourceContexts(nearbyVmpItems, allEvents, assetSourcesById) {
  return (nearbyVmpItems || []).map((item) => ({
    ...item,
    candidate: {
      ...item.candidate,
      context_window: contextWindowForVmpCandidate(item.event, allEvents, assetSourcesById)
    }
  }));
}

function finalizeSignatureAbsentNetworkAnchor(anchor, allEvents, assetSourcesById) {
  const nearbyVmpItems = enrichNearbyVmpItemsWithSourceContexts(
    anchor._nearby_vmp_items || [],
    allEvents,
    assetSourcesById
  );
  const nearbyVmpCandidates = nearbyVmpItems.map((item) => item.candidate);
  const vmpAnalysisPoints = vmpAnalysisPointsForEvents(nearbyVmpCandidates);
  const {_nearby_vmp_items, _event, _info, _renderer_request_event, ...publicAnchor} = anchor;
  return {
    ...publicAnchor,
    candidate_signature_pipeline: buildSignatureAbsentAnchorPipeline(_info || anchor, _event, nearbyVmpItems, _renderer_request_event),
    ...(vmpAnalysisPoints.length ? {vmp_analysis_points: vmpAnalysisPoints} : {}),
    nearby_vmp_candidates: nearbyVmpCandidates
  };
}

function buildSignatureAbsentNetworkAnchors(allEvents, assetFindings, assetSourcesById = new Map()) {
  const assetByUrl = new Map((assetFindings || [])
    .filter((asset) => asset.url)
    .map((asset) => [asset.url, asset]));
  const eventsWithTrace = (allEvents || [])
    .map((event, index) => ({event, index, traceIndex: traceIndexValue(event, index)}));
  const vmpEvents = eventsWithTrace
    .filter(({event}) => isVmpRuntimeEvent(event))
    .sort((a, b) => a.traceIndex - b.traceIndex);
  const rendererRequestItems = eventsWithTrace
    .filter(({event}) => isRendererRequestApi(event?.api || ""))
    .map(({event, traceIndex}) => ({event, traceIndex, info: networkRequestInfoFromEvent(event)}))
    .filter((item) => item.info)
    .sort((a, b) => a.traceIndex - b.traceIndex);
  const anchors = [];

  for (const {event, traceIndex} of eventsWithTrace) {
    const info = networkRequestInfoFromEvent(event);
    if (!info) continue;
    const nearbyVmpItems = vmpEvents
      .map(({event: vmpEvent}) => ({
        event: vmpEvent,
        candidate: summarizeNearbyVmpCandidate(vmpEvent, traceIndex, assetByUrl)
      }))
      .filter((item) => item.candidate)
      .sort((a, b) => compareNearbyVmpCandidate(a.candidate, b.candidate))
      .slice(0, SIGNATURE_ABSENT_NEARBY_VMP_LIMIT);
    const nearbyVmpCandidates = nearbyVmpItems.map((item) => item.candidate);
    const rendererRequestLink = findRendererRequestLink(
      info,
      traceIndex,
      rendererRequestItems,
      assetByUrl
    );
    const rendererRequestEvent = rendererRequestLink
      ? rendererRequestItems.find((item) =>
        item.traceIndex === rendererRequestLink.trace_index &&
        item.event?.seq === rendererRequestLink.seq &&
        item.event?.api === rendererRequestLink.api
      )?.event || null
      : null;
    const inferredInitiator = summarizeInferredInitiatorFromNearbyVmp(
      info,
      rendererRequestLink,
      nearbyVmpCandidates
    );

    anchors.push({
      ...info,
      trace_index: Number.isFinite(info.trace_index) ? info.trace_index : traceIndex,
      request_context: summarizeNetworkRequestContext(info, event, rendererRequestLink, inferredInitiator),
      ...scoreSignatureAbsentNetworkAnchor(info, event, nearbyVmpCandidates, assetByUrl),
      nearby_vmp_candidates: nearbyVmpCandidates,
      _event: event,
      _info: info,
      _renderer_request_event: rendererRequestEvent,
      _nearby_vmp_items: nearbyVmpItems
    });
  }

  return anchors
    .sort(compareSignatureAbsentNetworkAnchor)
    .slice(0, SIGNATURE_ABSENT_NETWORK_ANCHOR_LIMIT)
    .map((anchor) => finalizeSignatureAbsentNetworkAnchor(anchor, allEvents, assetSourcesById));
}

function sanitizeSignatureAbsentNetworkAnchor(anchor) {
  return {
    ...anchor,
    nearby_vmp_candidates: (anchor.nearby_vmp_candidates || []).map((candidate) => {
      const {context_window, ...summary} = candidate;
      return summary;
    })
  };
}

function buildSignatureAbsentEvidence(assetFindings, globalVmpApiCounts, globalVmpEvents, allEvents = [], assetSourcesById = new Map()) {
  const candidateAssets = summarizeCandidateSignatureAssets(assetFindings);
  const candidateEntrypoints = buildSignatureAbsentEntrypoints(globalVmpEvents, assetFindings);
  const networkAnchors = buildSignatureAbsentNetworkAnchors(allEvents, assetFindings, assetSourcesById);
  const publicNetworkAnchors = networkAnchors.map(sanitizeSignatureAbsentNetworkAnchor);
  const vmpEventCount = (globalVmpEvents || []).length;
  if (!vmpEventCount && !candidateAssets.length && !networkAnchors.length) return null;

  return {
    reason: "signature_terms_not_observed",
    target_terms: SIGNATURE_TERMS,
    vmp_runtime_event_count: vmpEventCount,
    top_vmp_apis: sortCountEntries(globalVmpApiCounts || new Map(), "api").slice(0, 15),
    candidate_entrypoints: candidateEntrypoints,
    candidate_assets: candidateAssets,
    network_anchors: publicNetworkAnchors,
    candidate_trace_chains: buildSignatureAbsentCandidateTraceChains(networkAnchors),
    capture_recommendations: [
      {
        id: "trigger_signed_request_paths",
        priority: "high",
        reason: "the trace contains VMP and obfuscated-code evidence, but no observed request or URL mutation carried target signature parameters"
      },
      {
        id: "rerun_with_interactive_profile",
        priority: "medium",
        reason: "headless or first-load capture may not reach the user action that creates signed API requests"
      },
      {
        id: "inspect_candidate_entrypoints",
        priority: "medium",
        reason: "candidate VMP entrypoints and assets identify where to focus source-context review before the next capture"
      }
    ],
    next_questions: [
      "signature_terms_not_observed",
      "which_user_action_triggers_signed_api",
      "which_candidate_entrypoint_runs_before_network_request"
    ]
  };
}

const CORE_ASSET_REVIEW_WINDOW_SPECS = [
  {
    focus: "url_signature_boundary",
    priority: "high",
    pattern: /X-Signature|X-Secondary-Signature|URLSearchParams|searchParams|encodeURIComponent|decodeURIComponent/
  },
  {
    focus: "vmp_runtime_surface",
    priority: "high",
    pattern: /bytecode|handlers|switch\s*\(|\bcase\b|\.call\s*\(|\.apply\s*\(|Reflect\.apply/
  },
  {
    focus: "fingerprint_collection",
    priority: "medium",
    pattern: /navigator\.|screen\.|Intl\.|Canvas|WebGL|AudioContext|RTCPeerConnection|plugins|languages/
  },
  {
    focus: "dynamic_code_boundary",
    priority: "medium",
    pattern: /\beval\s*\(|\bFunction\s*\(|set(?:Timeout|Interval)\s*\(\s*["'`]/
  },
  {
    focus: "encoding_or_hash_boundary",
    priority: "high",
    pattern: /TextEncoder|TextDecoder|crypto\.subtle|SubtleCrypto|digest|Math\.imul|charCodeAt|fromCharCode|atob|btoa/
  },
  {
    focus: "anti_debug_or_integrity_probe",
    priority: "medium",
    pattern: /debugger|Function\.prototype\.toString|\.toString\s*\(|Error\.stack|performance\.now|Date\.now/
  }
];

function buildCoreAssetSourceWindow(asset, source, spec) {
  const lines = String(source?.content || "").split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const match = spec.pattern.exec(line);
    if (!match) continue;
    spec.pattern.lastIndex = 0;
    const preview = sourcePreviewAroundColumn(line, (match.index || 0) + 1);
    return {
      focus: spec.focus,
      priority: spec.priority,
      asset_id: asset.asset_id,
      url: asset.url || source.url || "",
      content_path: asset.content_path || source.content_path || "",
      line_start: index + 1,
      line_end: index + 1,
      ...preview,
      analysis: analyzeSourceContextSnippet(preview.preview || "")
    };
  }
  spec.pattern.lastIndex = 0;
  return null;
}

function buildCoreAssetReviewPackage(assetFindings, assetSourcesById) {
  const entries = [];
  for (const asset of (assetFindings || [])
    .filter((item) => isCoreSignatureAsset({
      asset_id: item.asset_id,
      stack_url: item.url,
      content_path: item.content_path
    }))
    .sort((a, b) => b.score - a.score || String(a.url).localeCompare(String(b.url)))
    .slice(0, 4)) {
    const source = assetSourcesById.get(asset.asset_id);
    const windows = source?.content
      ? CORE_ASSET_REVIEW_WINDOW_SPECS
        .map((spec) => buildCoreAssetSourceWindow(asset, source, spec))
        .filter(Boolean)
        .slice(0, 8)
      : [];
    entries.push({
      asset_id: asset.asset_id,
      url: asset.url,
      content_path: asset.content_path,
      retrieval_status: asset.retrieval_status || "",
      score: asset.score,
      signals: asset.signals || [],
      asset_focus: "core_signature_asset",
      asset_role: "security_sdk_signature_generator",
      source_status: source?.content ? "available" : "missing",
      review_focus: windows.map((window) => window.focus),
      source_windows: windows,
      next_questions: [
        "which_runtime_step_enters_this_sdk_window",
        "which_request_endpoint_uses_this_core_asset",
        "which_inputs_feed_the_url_signature_boundary"
      ]
    });
  }

  return {
    version: 1,
    purpose: "agent_core_asset_source_review",
    entry_count: entries.length,
    entries
  };
}

function buildAgentEvidencePack(
  flows,
  assetSourcesById,
  globalVmpApiCounts = new Map(),
  globalVmpEvents = [],
  allEvents = [],
  signatureAbsent = null,
  assetFindings = []
) {
  const assetByUrl = new Map((assetFindings || []).filter((asset) => asset.url).map((asset) => [asset.url, asset]));
  const summaries = flows.map((flow, index) => buildAgentFlowSummary(flow, index));
  const evidenceFlows = flows.map((flow, index) => {
    const summary = summaries[index];
    const coverage = coverageForAgentFlow(summary);
    let eventWindows = augmentAgentEventWindowsWithRequestMaterials(
      buildAgentEventWindows(flow, assetSourcesById),
      flow,
      allEvents,
      assetSourcesById,
      assetByUrl
    );
    eventWindows = augmentAgentEventWindowsWithOperationReturns(
      eventWindows,
      allEvents,
      assetByUrl
    );
    return {
      id: summary.id,
      endpoint: summary.endpoint,
      match: summary.match,
      evidence_level: summary.evidence_level,
      seq_range: seqRangeForFlow(flow),
      signature_params: summary.signature_params,
      supporting_params: summary.supporting_params,
      coverage,
      event_windows: eventWindows,
      graph: buildAgentFlowGraph(eventWindows),
      stack_clusters: buildAgentStackClusters(eventWindows),
      vmp_analysis_points: summary.vmp_analysis_points,
      signature_mutations: summary.signature_mutations,
      object_links: summary.object_links,
      renderer_request_link: summary.renderer_request_link,
      assets: summary.assets,
      capture_recommendations: captureRecommendationsForAgentFlow(summary, coverage),
      next_questions: nextQuestionsForAgentFlow(summary, coverage)
    };
  });
  const vmpHookAnalysis = buildGlobalVmpHookAnalysis(
    evidenceFlows,
    globalVmpApiCounts,
    globalVmpEvents,
    allEvents,
    assetSourcesById
  );
  const flowsWithVmpCandidates = evidenceFlows.map((flow) => {
    const vmpLinkingCandidates = vmpLinkingCandidatesForFlow(flow, vmpHookAnalysis.hook_gaps);
    const vmpCandidatePhases = vmpCandidatePhasesForFlow(vmpLinkingCandidates);
    const candidateGraph = buildCandidateGraph(flow.graph, vmpCandidatePhases);
    return {
      ...flow,
      vmp_linking_candidates: vmpLinkingCandidates,
      vmp_candidate_phases: vmpCandidatePhases,
      candidate_graph: candidateGraph,
      suspected_signature_subflows: buildSuspectedSignatureSubflows(
        flow,
        vmpLinkingCandidates,
        vmpCandidatePhases
      )
    };
  });
  const vmpScalarRefChains = buildVmpScalarRefChains(allEvents);
  const signatureMaterialFlows = buildSignatureMaterialFlows(
    flowsWithVmpCandidates,
    signatureAbsent,
    assetSourcesById,
    allEvents,
    vmpScalarRefChains
  );
  const signatureSourceCandidates = buildSignatureSourceCandidates(signatureMaterialFlows);
  const coreAssetReviewPackage = buildCoreAssetReviewPackage(assetFindings, assetSourcesById);
  const businessApiRuntimeHints = buildBusinessApiRuntimeHints(allEvents, assetFindings);
  const agentReviewPackage = buildAgentReviewPackage(signatureSourceCandidates, signatureMaterialFlows, assetSourcesById);
  const parameterGenerationBrief = buildParameterGenerationBrief(
    signatureMaterialFlows,
    signatureSourceCandidates,
    agentReviewPackage
  );
  return {
    version: 1,
    purpose: "agent_signature_flow_evidence",
    target_terms: SIGNATURE_TERMS,
    redaction: {
      sensitive_terms: SENSITIVE_PARAM_TERMS,
      values_redacted: false
    },
    global_stack_clusters: buildGlobalStackClusters(evidenceFlows),
    pipeline_patterns: buildPipelinePatterns(evidenceFlows),
    vmp_hook_analysis: vmpHookAnalysis,
    vmp_scalar_ref_chains: vmpScalarRefChains,
    signature_material_flows: signatureMaterialFlows,
    signature_source_candidates: signatureSourceCandidates,
    business_api_runtime_hints: businessApiRuntimeHints,
    parameter_generation_brief: parameterGenerationBrief,
    agent_review_package: agentReviewPackage,
    core_asset_review_package: coreAssetReviewPackage,
    next_capture_plan: buildNextCapturePlan(signatureMaterialFlows, assetFindings),
    signature_absent: signatureAbsent,
    flows: flowsWithVmpCandidates
  };
}

function buildSignatureFlow(
  events,
  assetFindings,
  assetSourcesById = new Map(),
  globalVmpApiCounts = new Map(),
  globalVmpEvents = []
) {
  const assetByUrl = new Map(assetFindings.filter((asset) => asset.url).map((asset) => [asset.url, asset]));
  const byApi = new Map();
  const byStackUrl = new Map();
  const involvedAssets = new Map();
  const signatureEvents = [];
  const signatureEventIndexes = [];

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const terms = signatureTermsInEvent(event);
    if (!terms.length) continue;

    byApi.set(event.api || "unknown", (byApi.get(event.api || "unknown") || 0) + 1);
    for (const frame of event.stack || []) {
      if (!frame.url) continue;
      byStackUrl.set(frame.url, (byStackUrl.get(frame.url) || 0) + 1);
      const asset = assetByUrl.get(frame.url);
      if (asset && !involvedAssets.has(asset.asset_id)) {
        involvedAssets.set(asset.asset_id, asset);
      }
    }

    const summary = summarizeSignatureEvent(event, assetByUrl);
    summary.terms = terms;
    if (index > 0) {
      summary.previous_event = summarizeSignatureEvent(events[index - 1], assetByUrl);
    }
    if (index + 1 < events.length) {
      summary.next_event = summarizeSignatureEvent(events[index + 1], assetByUrl);
    }
    summary.context = {
      previous: events
        .slice(Math.max(0, index - 8), index)
        .map((contextEvent) => summarizeSignatureEvent(contextEvent, assetByUrl)),
      next: events
        .slice(index + 1, Math.min(events.length, index + 5))
        .map((contextEvent) => summarizeSignatureEvent(contextEvent, assetByUrl))
    };
    signatureEvents.push(summary);
    signatureEventIndexes.push({event, index});
  }

  const flows = buildSignatureTransitions(events, signatureEventIndexes, assetByUrl);
  const signatureAbsent = signatureEvents.length
    ? null
    : buildSignatureAbsentEvidence(assetFindings, globalVmpApiCounts, globalVmpEvents, events, assetSourcesById);

  return {
    terms: SIGNATURE_TERMS,
    event_count: signatureEvents.length,
    api_counts: [...byApi.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([api, count]) => ({api, count})),
    stack_url_counts: [...byStackUrl.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 25)
      .map(([url, count]) => ({url, count})),
    involved_assets: [...involvedAssets.values()]
      .sort((a, b) => b.score - a.score || String(a.asset_id).localeCompare(String(b.asset_id)))
      .map((asset) => ({
        asset_id: asset.asset_id,
        url: asset.url,
        content_path: asset.content_path,
        score: asset.score,
        signals: asset.signals,
        first_seq: asset.first_seq
      })),
    first_events: signatureEvents.slice(0, 12),
    flows,
    agent_brief: buildSignatureAgentBrief(flows),
    agent_evidence_pack: buildAgentEvidencePack(
      flows,
      assetSourcesById,
      globalVmpApiCounts,
      globalVmpEvents,
      events,
      signatureAbsent,
      assetFindings
    )
  };
}

function buildAssetSourcesById(assets) {
  const sources = new Map();
  for (const asset of assets || []) {
    const content = asset.content || asset.source || asset.source_preview || "";
    if (!asset.asset_id || !content) continue;
    sources.set(asset.asset_id, {
      content: String(content),
      url: asset.url || "",
      content_path: asset.content_path || ""
    });
  }
  return sources;
}

function buildLocalReport({tracePath, events = [], assets = []}) {
  const byCategory = new Map();
  const byApi = new Map();
  const byVmpApi = new Map();
  const byVmpSample = new Map();
  const fingerprintApis = new Set();
  let dynamicExecutionCount = 0;
  let vmpRuntimeEventCount = 0;
  const globalVmpEvents = [];

  for (const event of events) {
    const category = event.category || "unknown";
    byCategory.set(category, (byCategory.get(category) || 0) + 1);
    if (event.api) {
      byApi.set(event.api, (byApi.get(event.api) || 0) + 1);
      if (event.category === "fingerprint" || apiIsFingerprint(event.api)) {
        fingerprintApis.add(event.api);
      }
      if (DYNAMIC_EXECUTION_APIS.has(event.api)) {
        dynamicExecutionCount += 1;
      }
      if (VMP_RUNTIME_APIS.has(event.api)) {
        vmpRuntimeEventCount += 1;
        globalVmpEvents.push(event);
        byVmpApi.set(event.api, (byVmpApi.get(event.api) || 0) + 1);
        const samples = byVmpSample.get(event.api) || [];
        if (samples.length < VMP_SAMPLE_LIMIT && Array.isArray(event.args) && event.args.length) {
          samples.push({
            seq: event.seq ?? null,
            args: preserveSignatureValues(event.args)
          });
          byVmpSample.set(event.api, samples);
        }
      }
    }
  }

  const assetFindings = assets
    .filter((asset) => asset.asset_id !== "xtrace.asset_parse_error")
    .map((asset) => {
      const analysis = analyzeJavaScriptSource(asset.content || asset.source || asset.source_preview || "");
      return {
        asset_id: asset.asset_id,
        kind: asset.kind || "unknown",
        url: asset.url || "",
        content_path: asset.content_path || "",
        sha1: asset.sha1 || asset.source_hash || "",
        size: asset.size || analysis.size,
        truncated: Boolean(asset.truncated),
        retrieval_status: asset.retrieval_status || "",
        retrieval_error: asset.retrieval_error || "",
        first_seq: asset.first_seq ?? null,
        score: analysis.score,
        signals: analysis.signals,
        metrics: analysis.metrics
      };
    })
    .sort((a, b) => b.score - a.score || String(a.asset_id).localeCompare(String(b.asset_id)));
  const vmpAssets = assetFindings.filter((asset) =>
    asset.signals.some((signal) => signal.startsWith("vmp_"))
  );
  const vmpAnalysis = buildVmpHookAnalysis(events, assetFindings);
  const signatureEvents = eventsWithInheritedUrlMaterialRefs(events);
  const signature = buildSignatureFlow(signatureEvents, assetFindings, buildAssetSourcesById(assets), byVmpApi, globalVmpEvents);

  return {
    version: 1,
    generated_at: new Date().toISOString(),
    trace: {
      path: tracePath,
      event_count: events.length,
      categories: Object.fromEntries([...byCategory.entries()].sort()),
      top_apis: [...byApi.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, 25)
        .map(([api, count]) => ({api, count}))
    },
    reverse: {
      dynamic_execution_count: dynamicExecutionCount
    },
    signature,
    vmp: {
      runtime_event_count: vmpRuntimeEventCount,
      apis: [...byVmpApi.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([api, count]) => ({api, count})),
      samples: Object.fromEntries([...byVmpSample.entries()].sort()),
      families: vmpAnalysis.families,
      execution_profiles: vmpAnalysis.execution_profiles,
      hotspots: vmpAnalysis.hotspots,
      hook_coverage: vmpAnalysis.hook_coverage,
      hook_analysis_points: vmpAnalysis.hook_coverage.hook_analysis_points,
      analysis_points: vmpAnalysis.analysis_points,
      assets: vmpAssets
    },
    fingerprint: {
      api_count: fingerprintApis.size,
      apis: [...fingerprintApis].sort()
    },
    assets: assetFindings
  };
}

function sourceAnalysisSummary(analysis) {
  if (!analysis) return "";
  const signals = (analysis.signals || []).slice(0, 6).join(",") || "none";
  const calls = (analysis.calls || []).slice(0, 6).join(",") || "none";
  const props = (analysis.properties || []).slice(0, 6).join(",") || "none";
  const ops = (analysis.operators || []).slice(0, 6).join(",") || "none";
  return `signals:${signals} calls:${calls} props:${props} ops:${ops}`;
}

function candidatePipelineSummary(pipeline) {
  const stages = (pipeline?.stages || [])
    .slice(0, 8)
    .map((stage) => {
      const evidence = (stage.runtime_apis || []).slice(0, 4).join(",") ||
        (stage.source_calls || []).slice(0, 4).join(",") ||
        (stage.source_signals || []).slice(0, 4).join(",") ||
        "source";
      return `${stage.stage || "unknown"}[${evidence}]`;
    })
    .join("->") || "none";
  return `${stages} confidence=${pipeline?.confidence || "low"}`;
}

function materialStagesSummary(stages) {
  return (stages || [])
    .slice(0, 8)
    .map((stage) => {
      const evidence = (stage.runtime_apis || []).slice(0, 4).join(",") ||
        (stage.source_calls || []).slice(0, 4).join(",") ||
        (stage.source_signals || []).slice(0, 4).join(",") ||
        "source";
      return `${stage.stage || "unknown"}[${evidence}]`;
    })
    .join("->") || "none";
}

function pipelineDataLinksSummary(pipeline) {
  return (pipeline?.data_links || [])
    .slice(0, 8)
    .map((link) => `${link.from || "unknown"}->${link.to || "unknown"}:${(link.refs || []).slice(0, 6).join("|") || "none"}`)
    .join(",") || "none";
}

function pipelineInferredDataLinksSummary(pipeline) {
  return (pipeline?.inferred_data_links || [])
    .slice(0, 8)
    .map((link) => {
      const refs = (link.refs || []).slice(0, 4).join("|") || "none";
      const basis = (link.basis || []).slice(0, 4).join("|") || "inferred";
      return `${link.from || "unknown"}->${link.to || "unknown"}:${refs}:${link.confidence || "medium"}:${basis}`;
    })
    .join(",") || "none";
}

function materialFlowHookPointsSummary(points) {
  return (points || [])
    .slice(0, 8)
    .map((point) => {
      const evidence = [];
      if ((point.observed_apis || []).length) {
        evidence.push(`runtime:${point.observed_apis.join("|")}`);
      }
      if ((point.source_calls || []).length) {
        evidence.push(`source:${point.source_calls.join("|")}`);
      }
      if ((point.source_signals || []).length) {
        evidence.push(`signals:${point.source_signals.join("|")}`);
      }
      return `${point.type}:${point.status || "unknown"}[${evidence.join(" ") || "none"}]`;
    })
    .join(",") || "none";
}

function scalarOperationTraceSummary(steps) {
  return (steps || [])
    .slice(0, 4)
    .map((step) => {
      const seq = step.seq ?? step.trace_index ?? "?";
      const inputRefs = (step.input_refs || []).slice(0, 3).join("|") || "none";
      return `${seq}:${step.api || "unknown"}(${inputRefs}->${step.result_ref || "unknown"})`;
    })
    .join("->") || "none";
}

function materialFlowScalarChainLinksSummary(links) {
  return (links || [])
    .slice(0, 6)
    .map((link) => {
      const ops = scalarOperationTraceSummary(link.operation_trace || []);
      return `${link.chain_id || "unknown"}:${link.stage || "unknown"}:${link.relation || "related"}[${link.confidence || "unknown"}] ops=${ops}`;
    })
    .join(",") || "none";
}

function signatureAttachmentEventsSummary(events) {
  return (events || [])
    .slice(0, 8)
    .map((event) => {
      const params = (event.target_params || []).slice(0, 4).join("|") || "none";
      const refs = (event.object_refs || event.value_refs || []).slice(0, 4).join("|") || "none";
      return `${event.api || "unknown"}@${event.seq ?? "none"}:${event.action || "observe"}:${params}:${refs}`;
    })
    .join(",") || "none";
}

function signatureParamMaterializationsMarkdownSummary(events) {
  return (events || [])
    .slice(0, 8)
    .map((event) => `${event.param || "unknown"}:${event.api || "unknown"}@${event.seq ?? event.trace_index ?? "?"}`)
    .join("|") || "none";
}

function parameterAttachmentGraphSummary(graph) {
  return (graph?.edges || [])
    .slice(0, 10)
    .map((edge) => `${edge.from || "unknown"}->${edge.to || "unknown"}:${edge.relation || "related"}`)
    .join(",") || "none";
}

function generationStepsSummary(steps) {
  return (steps || [])
    .slice(0, 8)
    .map((step) => {
      const seq = step.seq_start ?? "none";
      const apis = (step.runtime_apis || [])
        .slice(0, 4)
        .map((api) => `${api}@${seq}`)
        .join(",") || step.role || "source";
      const params = (step.target_params || []).length
        ? ` params=${step.target_params.slice(0, 4).join("|")}`
        : "";
      const sourceRef = step.source_locations?.[0]?.ref || step.source_context_refs?.[0] || "";
      const source = sourceRef ? ` src=${sourceRef}` : "";
      const requestDistance = step.trace_distance_to_signed_request ?? step.seq_distance_to_signed_request;
      const distance = requestDistance !== undefined && requestDistance !== null
        ? ` d=${requestDistance}`
        : "";
      return `${step.stage || "unknown"}[${apis}${params}${source}${distance}]`;
    })
    .join("->") || "none";
}

function agentGenerationStepEventsSummary(steps) {
  return (steps || [])
    .slice(0, 8)
    .map((step) => {
      const events = (step.runtime_event_refs || [])
        .slice(0, 4)
        .map((event) => `${event.api || "unknown"}@${event.seq ?? event.trace_index ?? "?"}`)
        .join("|");
      return events ? `${step.stage || "unknown"}[${events}]` : "";
    })
    .filter(Boolean)
    .join("->") || "none";
}

function agentGenerationSummary(summary) {
  if (!summary) return "none";
  const chain = (summary.stage_chain || []).slice(0, 12).join("->") || "none";
  const runtime = (summary.runtime_apis || []).slice(0, 8).join("|") || "none";
  const sourceHooks = (summary.source_observed_hooks || []).slice(0, 8).join("|") || "none";
  const runtimeHooks = (summary.runtime_observed_hooks || []).slice(0, 8).join("|") || "none";
  const params = (summary.target_params || []).slice(0, 8).join("|") || "none";
  const attachments = (summary.attachment_params || []).slice(0, 8).join("|") || "none";
  const materializations = signatureParamMaterializationsMarkdownSummary(
    summary.signature_param_materializations || []
  );
  const source = (summary.source_calls || []).slice(0, 6).join("|") || "none";
  const stepEvents = agentGenerationStepEventsSummary(summary.steps || []);
  const logicTrace = candidateLogicTraceMarkdownSummary(summary.logic_hypothesis?.agent_logic_trace);
  return `chain=${chain} evidence=${summary.evidence_profile || "unknown"} runtime=${runtime} source_hooks=${sourceHooks} runtime_hooks=${runtimeHooks} params=${params} attachments=${attachments} materializations=${materializations} links=${summary.data_link_count ?? 0}/${summary.inferred_data_link_count ?? 0} source=${source} step_events=${stepEvents}${logicTrace !== "none" ? ` logic_trace=${logicTrace}` : ""}`;
}

function agentStageTraceSummary(steps) {
  return (steps || [])
    .slice(0, 12)
    .map((step, index) => {
      const order = step.order ?? index + 1;
      const apis = (step.apis || []).slice(0, 4).join("|") || "none";
      const evidence = (step.evidence || []).slice(0, 4).join("|") || "none";
      const params = (step.params || []).slice(0, 4).join("|") || "none";
      const targetParams = (step.target_params || []).slice(0, 4).join("|") || "none";
      const paramRelation = step.param_relation || "unknown";
      const sources = (step.source_refs || []).slice(0, 3).join("|") || "none";
      const refs = (step.object_refs || step.value_refs || []).slice(0, 4).join("|") || "none";
      const distance = step.distance_to_signed_request ?? "unknown";
      return `${order}:${step.stage || "unknown"}(${step.role || "context"})[${apis}] evidence=${evidence} relation=${step.relation || "unknown"} d=${distance} params=${params} target_params=${targetParams} param_relation=${paramRelation} sources=${sources} refs=${refs}`;
    })
    .join(" -> ") || "none";
}

function parameterGenerationTraceSummary(trace) {
  return (trace || [])
    .slice(0, 8)
    .map((step) => {
      const apis = (step.apis || []).slice(0, 3).join("|") || "none";
      const distance = step.distance_to_signed_request ?? "unknown";
      const target = (step.target_params || []).slice(0, 3).join("|") || "none";
      const relation = step.param_relation || "unknown";
      return `${step.stage || "unknown"}[${apis} d=${distance} target=${target} relation=${relation}]`;
    })
    .join("->") || "none";
}

function parameterDataLinksMarkdownSummary(links) {
  return (links || [])
    .slice(0, 8)
    .map((link) => {
      const refs = (link.refs || []).slice(0, 6).join("|") || "none";
      const basis = (link.basis || []).slice(0, 6).join("|");
      return `${link.from || "unknown"}->${link.to || "unknown"}[${link.confidence || "unknown"}/${link.relation || "unknown"}] refs=${refs}${basis ? ` basis=${basis}` : ""}`;
    })
    .join(";") || "none";
}

function parameterScalarChainsMarkdownSummary(links) {
  return (links || [])
    .slice(0, 6)
    .map((link) => {
      const ops = scalarOperationTraceSummary(link.operation_trace || []);
      const refs = (link.shared_refs || []).slice(0, 6).join("|") || "none";
      const sources = (link.source_context_refs || []).slice(0, 4).join("|") || "none";
      const reasons = (link.quality_reasons || []).slice(0, 4).join("|") || "none";
      return `${link.chain_id || "unknown"}:${link.stage || "unknown"}:${link.relation || "related"}[${link.confidence || "unknown"}] ops=${ops} refs=${refs} sources=${sources} reasons=${reasons}`;
    })
    .join(";") || "none";
}

function compactWebCryptoSignatureSummary(summary) {
  if (!summary?.observed) return null;
  return {
    observed: true,
    apis: uniqueLimited(summary.apis || [], 8),
    algorithms: uniqueLimited(summary.algorithms || [], 8),
    operation_refs: uniqueLimited(summary.operation_refs || [], 12),
    key_refs: uniqueLimited(summary.key_refs || [], 12),
    key_material_refs: uniqueLimited(summary.key_material_refs || [], 12),
    input_refs: uniqueLimited(summary.input_refs || [], 12),
    result_refs: uniqueLimited(summary.result_refs || [], 12),
    input_array_buffer_refs: uniqueLimited(summary.input_array_buffer_refs || [], 12),
    result_array_buffer_refs: uniqueLimited(summary.result_array_buffer_refs || [], 12),
    runtime_event_refs: compactRuntimeEventRefs(summary.runtime_event_refs || [], 12),
    operations: (summary.operations || []).slice(0, 12).map((operation) => ({
      api: operation.api || "",
      phase: operation.phase || "",
      seq: operation.seq ?? null,
      operation_ref: operation.operation_ref || "",
      algorithm: operation.algorithm || "",
      ...(operation.key_ref ? {key_ref: operation.key_ref} : {}),
      ...(operation.key_material_ref ? {key_material_ref: operation.key_material_ref} : {}),
      ...(operation.input_ref ? {input_ref: operation.input_ref} : {}),
      ...(operation.result_ref ? {result_ref: operation.result_ref} : {}),
      ...(operation.input_array_buffer_ref ? {input_array_buffer_ref: operation.input_array_buffer_ref} : {}),
      ...(operation.result_array_buffer_ref ? {result_array_buffer_ref: operation.result_array_buffer_ref} : {}),
      event_ref: operation.event_ref || ""
    }))
  };
}

const DIRECT_WEBCRYPTO_VMP_STAGES = new Set([
  "dynamic_dispatch",
  "array_table",
  "collection_table",
  "proxy_trap"
]);

const DIRECT_WEBCRYPTO_SUPPRESSED_GAPS = new Set([
  "vmp_operation_subgraph_not_observed",
  "vmp_pattern_not_ranked",
  "vmp_pattern_not_observed",
  "vmp_output_ref_to_signature_not_observed",
  "vmp_output_not_linked_to_signature",
  "vmp_handler_table_source_not_observed",
  "vmp_bytecode_pc_source_not_observed",
  "vmp_dynamic_dispatch_boundary_not_observed",
  "vmp_state_object_ref_not_observed",
  "vmp_register_ref_not_observed",
  "vmp_handler_return_ref_not_observed",
  "vmp_register_to_mixing_link_not_observed",
  "vmp_register_value_ref_to_mixing_not_observed"
]);

const DIRECT_WEBCRYPTO_SUPPRESSED_ACTIONS = new Set([
  "expand_vmp_runtime_hooks",
  "capture_vmp_register_state_refs"
]);

function hasDirectWebCryptoVmpStage(generationPath) {
  return (generationPath || []).some((step) => DIRECT_WEBCRYPTO_VMP_STAGES.has(step?.stage));
}

function isDirectWebCryptoGenerationPath(generationPath, webcryptoSignatureSummary, vmpOperationPatterns = []) {
  return Boolean(
    webcryptoSignatureSummary?.observed &&
    !hasDirectWebCryptoVmpStage(generationPath) &&
    !(vmpOperationPatterns || []).length
  );
}

function isDirectWebCryptoParameter(parameter) {
  return isDirectWebCryptoGenerationPath(
    parameter?.generation_path || [],
    compactWebCryptoSignatureSummary(parameter?.webcrypto_signature_summary),
    parameter?.vmp_operation_patterns || []
  );
}

function filterDirectWebCryptoGaps(gaps, directWebCrypto) {
  const values = gaps || [];
  if (!directWebCrypto) return uniqueLimited(values, 12);
  return uniqueLimited(values.filter((gap) => !DIRECT_WEBCRYPTO_SUPPRESSED_GAPS.has(gap)), 12);
}

function filterDirectWebCryptoActions(actions, directWebCrypto) {
  const values = actions || [];
  if (!directWebCrypto) return uniqueLimited(values, 12);
  return uniqueLimited(values.filter((action) => !DIRECT_WEBCRYPTO_SUPPRESSED_ACTIONS.has(action)), 12);
}

function directWebCryptoEvidenceRefs(summary) {
  return uniqueLimited([
    "direct_webcrypto_operation_path",
    ...(summary?.operation_refs || []).map((ref) => `webcrypto_operation_ref:${ref}`),
    ...(summary?.input_refs || []).map((ref) => `webcrypto_input_ref:${ref}`),
    ...(summary?.result_refs || []).map((ref) => `webcrypto_result_ref:${ref}`),
    ...(summary?.input_array_buffer_refs || []).map((ref) => `webcrypto_input_array_buffer_ref:${ref}`),
    ...(summary?.result_array_buffer_refs || []).map((ref) => `webcrypto_result_array_buffer_ref:${ref}`)
  ], 16);
}

function directWebCryptoAttachmentMutationObserved(parameter) {
  return (parameter?.generation_path || []).some((step) =>
    ["signature_mutation", "url_encoding"].includes(step?.stage) &&
    step.param_relation === "direct_observed" &&
    ((step.apis || []).length || (step.object_refs || []).length || (step.value_refs || []).length)
  );
}

function directWebCryptoNextActions(parameter) {
  return directWebCryptoAttachmentMutationObserved(parameter)
    ? ["review_source_refs"]
    : ["capture_url_search_params_mutation_or_header_set"];
}

function webCryptoSignatureMarkdownSummary(summary) {
  if (!summary?.observed) return "none";
  return [
    `apis=${(summary.apis || []).join("|") || "none"}`,
    `ops=${(summary.operation_refs || []).join("|") || "none"}`,
    `key_refs=${(summary.key_refs || []).join("|") || "none"}`,
    `input_refs=${(summary.input_refs || []).join("|") || "none"}`,
    `result_refs=${(summary.result_refs || []).join("|") || "none"}`,
    `key_material_refs=${(summary.key_material_refs || []).join("|") || "none"}`
  ].join(" ");
}

function parameterGenerationBriefLine(entry) {
  return `- parameter ${entry.param || "unknown"} status=${entry.status || "unknown"} flow=${entry.best_flow_id || "none"} endpoint=${entry.endpoint || "unknown"} readiness=${entry.readiness || "unknown"} agent_generation=${agentGenerationSummary(entry.agent_generation_summary)} trace=${parameterGenerationTraceSummary(entry.generation_trace)} ref_lineage=${runtimeRefLineageMarkdownSummary(entry.runtime_ref_lineage)} ref_events=${runtimeRefEventEvidenceMarkdownSummary(entry.runtime_ref_event_evidence)} data_links=${parameterDataLinksMarkdownSummary(entry.data_links)} inferred_links=${parameterDataLinksMarkdownSummary(entry.inferred_data_links)} scalar_chains=${parameterScalarChainsMarkdownSummary(entry.vmp_scalar_chain_links)} webcrypto=${webCryptoSignatureMarkdownSummary(entry.webcrypto_signature_summary)} sources=${(entry.source_refs || []).slice(0, 6).join(",") || "none"} candidates=${(entry.source_candidate_ids || []).slice(0, 6).join(",") || "none"} reviews=${(entry.review_entry_ids || []).slice(0, 6).join(",") || "none"} gaps=${(entry.evidence_gaps || []).join(",") || "none"} next=${(entry.next_questions || []).slice(0, 6).join(",") || "none"}`;
}

function compactAgentRequestInputBundle(bundle) {
  if (!bundle) return null;
  return {
    version: bundle.version || 1,
    endpoint: bundle.endpoint || "",
    target_params: sortParamNames(bundle.target_params || []),
    network_anchor: bundle.network_anchor || null,
    url: {
      observed: Boolean(bundle.url?.observed),
      endpoint: bundle.url?.endpoint || "",
      url: bundle.url?.url || "",
      query_keys: sortParamNames(bundle.url?.query_keys || []),
      target_params: sortParamNames(bundle.url?.target_params || []),
      value_refs: uniqueLimited(bundle.url?.value_refs || [], 16),
      events: (bundle.url?.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(bundle.url?.evidence_refs || [], 16)
    },
    headers: {
      observed: Boolean(bundle.headers?.observed),
      header_names: uniqueLimited(bundle.headers?.header_names || [], 64).sort(),
      sensitive_header_names: uniqueLimited(bundle.headers?.sensitive_header_names || [], 32).sort(),
      target_params: sortParamNames(bundle.headers?.target_params || []),
      value_refs: uniqueLimited(bundle.headers?.value_refs || [], 16),
      events: (bundle.headers?.events || []).slice(0, 24),
      evidence_refs: uniqueLimited(bundle.headers?.evidence_refs || [], 16)
    },
    body: {
      observed: Boolean(bundle.body?.observed),
      target_params: sortParamNames(bundle.body?.target_params || []),
      ...(bundle.body?.form_field_names?.length
        ? {form_field_names: uniqueLimited(bundle.body.form_field_names, 64).sort()}
        : {}),
      ...(bundle.body?.urlencoded_param_names?.length
        ? {urlencoded_param_names: uniqueLimited(bundle.body.urlencoded_param_names, 64).sort()}
        : {}),
      ...(Number.isFinite(bundle.body?.body_size) ? {body_size: bundle.body.body_size} : {}),
      ...(bundle.body?.upload_body ? {upload_body: bundle.body.upload_body} : {}),
      ...(bundle.body?.preview ? {preview: bundle.body.preview} : {}),
      value_refs: uniqueLimited(bundle.body?.value_refs || [], 16),
      events: (bundle.body?.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(bundle.body?.evidence_refs || [], 16)
    },
    response: {
      observed: Boolean(bundle.response?.observed),
      ...(Number.isFinite(bundle.response?.status_code) ? {status_code: bundle.response.status_code} : {}),
      ...(Array.isArray(bundle.response?.status_codes) && bundle.response.status_codes.length
        ? {status_codes: uniqueLimited(bundle.response.status_codes, 8)}
        : {}),
      ...(bundle.response?.mime_type ? {mime_type: bundle.response.mime_type} : {}),
      ...(Array.isArray(bundle.response?.mime_types) && bundle.response.mime_types.length
        ? {mime_types: uniqueLimited(bundle.response.mime_types, 8)}
        : {}),
      header_names: uniqueLimited(bundle.response?.header_names || [], 64).sort(),
      sensitive_header_names: uniqueLimited(bundle.response?.sensitive_header_names || [], 32).sort(),
      events: (bundle.response?.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(bundle.response?.evidence_refs || [], 16)
    },
    cookies: {
      observed: Boolean(bundle.cookies?.observed),
      names: uniqueLimited(bundle.cookies?.names || [], 32).sort(),
      event_count: bundle.cookies?.event_count ?? 0,
      events: (bundle.cookies?.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(bundle.cookies?.evidence_refs || [], 16)
    },
    storage: {
      observed: Boolean(bundle.storage?.observed),
      keys: uniqueLimited(bundle.storage?.keys || [], 32).sort(),
      scopes: uniqueLimited(bundle.storage?.scopes || [], 8).sort(),
      value_refs: uniqueLimited(bundle.storage?.value_refs || [], 16),
      event_count: bundle.storage?.event_count ?? 0,
      events: (bundle.storage?.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(bundle.storage?.evidence_refs || [], 16)
    },
    evidence_refs: uniqueLimited(bundle.evidence_refs || [], 32),
    capture_gaps: uniqueLimited(bundle.capture_gaps || [], 16)
  };
}

function buildCandidateRequestInputSummary(bundle) {
  const compactBundle = compactAgentRequestInputBundle(bundle);
  if (!compactBundle) return null;

  const categories = [];
  if (compactBundle.url.observed) {
    categories.push({
      category: "url_query",
      observed: true,
      endpoint: compactBundle.url.endpoint || compactBundle.endpoint || "",
      url: compactBundle.url.url || "",
      query_keys: sortParamNames(compactBundle.url.query_keys || []),
      target_params: sortParamNames(compactBundle.url.target_params || []),
      value_refs: uniqueLimited(compactBundle.url.value_refs || [], 16),
      events: (compactBundle.url.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(compactBundle.url.evidence_refs || [], 16)
    });
  }
  if (compactBundle.headers.observed) {
    categories.push({
      category: "request_headers",
      observed: true,
      header_names: uniqueLimited(compactBundle.headers.header_names || [], 64).sort(),
      sensitive_header_names: uniqueLimited(compactBundle.headers.sensitive_header_names || [], 32).sort(),
      target_params: sortParamNames(compactBundle.headers.target_params || []),
      value_refs: uniqueLimited(compactBundle.headers.value_refs || [], 16),
      events: (compactBundle.headers.events || []).slice(0, 24),
      evidence_refs: uniqueLimited(compactBundle.headers.evidence_refs || [], 16)
    });
  }
  if (compactBundle.body.observed) {
    categories.push({
      category: "request_body",
      observed: true,
      target_params: sortParamNames(compactBundle.body.target_params || []),
      ...(Number.isFinite(compactBundle.body.body_size) ? {body_size: compactBundle.body.body_size} : {}),
      ...(compactBundle.body.upload_body ? {upload_body: compactBundle.body.upload_body} : {}),
      value_refs: uniqueLimited(compactBundle.body.value_refs || [], 16),
      events: (compactBundle.body.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(compactBundle.body.evidence_refs || [], 16)
    });
  }
  if (compactBundle.response.observed) {
    categories.push({
      category: "response_metadata",
      observed: true,
      ...(Number.isFinite(compactBundle.response.status_code) ? {status_code: compactBundle.response.status_code} : {}),
      ...(compactBundle.response.mime_type ? {mime_type: compactBundle.response.mime_type} : {}),
      header_names: uniqueLimited(compactBundle.response.header_names || [], 64).sort(),
      sensitive_header_names: uniqueLimited(compactBundle.response.sensitive_header_names || [], 32).sort(),
      events: (compactBundle.response.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(compactBundle.response.evidence_refs || [], 16)
    });
  }
  if (compactBundle.cookies.observed) {
    categories.push({
      category: "cookies",
      observed: true,
      names: uniqueLimited(compactBundle.cookies.names || [], 32).sort(),
      event_count: compactBundle.cookies.event_count ?? 0,
      events: (compactBundle.cookies.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(compactBundle.cookies.evidence_refs || [], 16)
    });
  }
  if (compactBundle.storage.observed) {
    categories.push({
      category: "storage",
      observed: true,
      keys: uniqueLimited(compactBundle.storage.keys || [], 32).sort(),
      scopes: uniqueLimited(compactBundle.storage.scopes || [], 8).sort(),
      value_refs: uniqueLimited(compactBundle.storage.value_refs || [], 16),
      event_count: compactBundle.storage.event_count ?? 0,
      events: (compactBundle.storage.events || []).slice(0, 16),
      evidence_refs: uniqueLimited(compactBundle.storage.evidence_refs || [], 16)
    });
  }

  return {
    status: categories.length ? "observed" : "missing",
    endpoint: compactBundle.endpoint || "",
    target_params: sortParamNames(uniqueLimited([
      ...(compactBundle.target_params || []),
      ...categories.flatMap((category) => category.target_params || [])
    ].filter(Boolean), 16)),
    network_anchor: compactBundle.network_anchor || null,
    observed_categories: categories.map((category) => category.category),
    categories,
    evidence_refs: uniqueLimited([
      ...(compactBundle.evidence_refs || []),
      ...categories.flatMap((category) => category.evidence_refs || [])
    ], 32),
    capture_gaps: uniqueLimited(compactBundle.capture_gaps || [], 16)
  };
}

function compactAgentGenerationLogicPhaseEvidence({
  runtimeApis,
  sourceCalls,
  sourceSignals,
  sourceOperators,
  sourceConstants,
  targetParams
}) {
  return uniqueLimited([
    ...runtimeApis.map((api) => `runtime_api:${api}`),
    ...sourceCalls.map((call) => `source_call:${call}`),
    ...sourceSignals.map((signal) => `source_signal:${signal}`),
    ...sourceOperators.map((operator) => `source_operator:${operator}`),
    ...sourceConstants.map((constant) => `source_constant:${constant}`),
    ...targetParams.map((param) => `target_param:${param}`)
  ], 16);
}

function compactAgentGenerationLogicPhases(summary) {
  const phaseOrder = [];
  const phaseSteps = new Map();
  for (const step of summary?.steps || []) {
    const phase = candidateLogicPhaseIdForStage(step.stage || "");
    if (!phase) continue;
    if (!phaseSteps.has(phase)) {
      phaseSteps.set(phase, []);
      phaseOrder.push(phase);
    }
    phaseSteps.get(phase).push(step);
  }
  return phaseOrder.map((phase) => {
    const steps = phaseSteps.get(phase) || [];
    const runtimeApis = uniqueLimited(steps.flatMap((step) => step.runtime_apis || []), 12);
    const sourceCalls = uniqueLimited(steps.flatMap((step) => step.source_calls || []), 12);
    const sourceSignals = uniqueLimited(steps.flatMap((step) => step.source_signals || []), 12);
    const sourceOperators = uniqueLimited(steps.flatMap((step) => step.source_operators || []), 12);
    const sourceConstants = uniqueLimited(steps.flatMap((step) => step.source_constants || []), 12);
    const targetParams = sortParamNames(uniqueLimited(steps.flatMap((step) => step.target_params || []), 12));
    const objectRefs = uniquePrioritizedLimited(
      steps.flatMap((step) => step.object_refs || []),
      phase === "vmp_execution" ? 16 : 12,
      generationPathObjectRefRank
    );
    const valueRefs = compactGenerationValueRefs(
      steps.flatMap((step) => step.value_refs || []),
      phase === "vmp_execution" ? 24 : 12,
      {preserveVmpStateRefs: phase === "vmp_execution"}
    );
    const runtimeEvents = compactRuntimeEventRefs(steps.flatMap((step) => step.runtime_event_refs || []), 16)
      .map((event) => ({
        ...event,
        stage: (steps.find((step) =>
          (step.runtime_event_refs || []).some((candidate) => candidate.event_ref === event.event_ref)) || {}).stage || ""
      }));
    return {
      id: phase,
      status: "observed",
      confidence: runtimeApis.length ? "high" : "medium",
      stages: uniqueLimited(steps.map((step) => step.stage || "").filter(Boolean), 8),
      runtime_apis: runtimeApis,
      source_calls: sourceCalls,
      source_signals: sourceSignals,
      source_operators: sourceOperators,
      source_constants: sourceConstants,
      target_params: targetParams,
      source_refs: uniqueLimited(steps.flatMap((step) => step.source_context_refs || []), 8),
      object_refs: objectRefs,
      value_refs: valueRefs,
      runtime_events: runtimeEvents,
      evidence: compactAgentGenerationLogicPhaseEvidence({
        runtimeApis,
        sourceCalls,
        sourceSignals,
        sourceOperators,
        sourceConstants,
        targetParams
      })
    };
  });
}

function compactAgentGenerationLogicStatus(phases) {
  const observed = new Set((phases || []).map((phase) => phase.id));
  return ["input_material", "vmp_execution", "mixing_or_hash", "signature_attachment"]
    .every((phase) => observed.has(phase))
    ? "runtime_chain_observed"
    : "needs_more_evidence";
}

function compactAgentGenerationLogicClaim(param, phase) {
  const subject = param || "target parameter";
  const label = phase.id === "input_material"
    ? "input material"
    : phase.id === "vmp_execution"
      ? "VMP dispatch and handler execution"
      : phase.id === "mixing_or_hash"
        ? "integer mixing or digest"
        : phase.id === "signature_attachment"
          ? "signature attachment and request send"
          : phase.id || "phase";
  const stages = (phase.stages || []).join(" -> ") || "unknown stage";
  return `${label} observed for ${subject} across ${stages}`;
}

function compactAgentGenerationFinalAttachment(summary) {
  const targetParams = sortParamNames(summary?.attachment_params || []);
  const steps = summary?.steps || [];
  const directAttachmentSteps = steps.filter((step) =>
    ["signature_mutation", "url_encoding", "request_headers", "request_body"].includes(step.stage));
  const attachmentSteps = directAttachmentSteps.length
    ? directAttachmentSteps
    : steps.filter((step) => step.stage === "signed_request");
  return {
    observed: targetParams.length > 0,
    target_params: targetParams,
    apis: uniqueLimited(attachmentSteps.flatMap((step) => step.runtime_apis || []), 8),
    evidence_mode: targetParams.length ? "direct_runtime_api" : "unknown"
  };
}

function compactAgentGenerationStepSourceRefs(step) {
  return uniqueLimited([
    ...(step?.source_context_refs || []),
    ...(step?.source_refs || [])
  ], 8);
}

function compactAgentGenerationLogicEdge(left, right) {
  const fromPhase = candidateLogicPhaseIdForStage(left?.stage || "");
  const toPhase = candidateLogicPhaseIdForStage(right?.stage || "");
  if (!fromPhase || !toPhase) return null;
  const sharedValueRefs = intersectRefs(left?.value_refs || [], right?.value_refs || []);
  const targetRefs = sharedValueRefs.filter((ref) => String(ref).startsWith("target_params:"));
  const objectRefs = intersectRefs(left?.object_refs || [], right?.object_refs || []);
  const strongValueRefs = sharedRuntimeValueRefsForDataLink(left?.value_refs || [], right?.value_refs || []);
  const sourceRefs = intersectRefs(
    compactAgentGenerationStepSourceRefs(left),
    compactAgentGenerationStepSourceRefs(right)
  );
  const relation = targetRefs.length
    ? "target_param_ref"
    : objectRefs.length
      ? "shared_object_ref"
      : strongValueRefs.length
        ? "shared_value_ref"
        : sourceRefs.length
          ? "shared_source_ref"
          : "";
  if (!relation) return null;
  const refs = uniqueLimited([
    ...targetRefs,
    ...objectRefs,
    ...strongValueRefs
  ], 8);
  const evidence = uniqueLimited([
    ...(targetRefs.length ? ["target_param_ref"] : []),
    ...(objectRefs.length ? ["shared_object_ref"] : []),
    ...(strongValueRefs.length ? ["shared_value_ref"] : []),
    ...(sourceRefs.length ? ["shared_source_ref"] : [])
  ], 8);
  return {
    from_order: left?.order ?? null,
    to_order: right?.order ?? null,
    from_stage: left?.stage || "unknown",
    to_stage: right?.stage || "unknown",
    from_phase: fromPhase,
    to_phase: toPhase,
    scope: fromPhase === toPhase ? "intra_phase" : "cross_phase",
    relation,
    confidence: targetRefs.length ? "high" : objectRefs.length || strongValueRefs.length ? "medium" : "low",
    refs,
    source_refs: sourceRefs,
    evidence
  };
}

function compactAgentGenerationLogicEdges(summary) {
  const steps = (summary?.steps || [])
    .slice(0, 12)
    .map((step, index) => ({
      order: step.order ?? index + 1,
      stage: step.stage || "unknown",
      object_refs: uniquePrioritizedLimited(
        step.object_refs || [],
        step.stage === "dynamic_dispatch" ? 16 : 8,
        generationPathObjectRefRank
      ),
      value_refs: compactGenerationValueRefs(
        step.value_refs || [],
        step.stage === "dynamic_dispatch" ? 24 : 8,
        {preserveVmpStateRefs: step.stage === "dynamic_dispatch"}
      ),
      source_context_refs: compactAgentGenerationStepSourceRefs(step)
    }));
  const edges = [];
  const seen = new Set();
  for (let index = 0; index < steps.length - 1; index += 1) {
    const edge = compactAgentGenerationLogicEdge(steps[index], steps[index + 1]);
    if (!edge) continue;
    const key = [
      edge.from_order,
      edge.to_order,
      edge.from_stage,
      edge.to_stage,
      edge.relation,
      edge.confidence
    ].join(":");
    if (seen.has(key)) continue;
    seen.add(key);
    edges.push(edge);
  }
  return edges.slice(0, 12);
}

function compactAgentGenerationLogicEdgeSummary(edges) {
  const phaseEdges = edges || [];
  return {
    total_edge_count: phaseEdges.length,
    cross_phase_edge_count: phaseEdges.filter((edge) => edge.scope === "cross_phase").length,
    intra_phase_edge_count: phaseEdges.filter((edge) => edge.scope === "intra_phase").length,
    high_confidence_edge_count: phaseEdges.filter((edge) => edge.confidence === "high").length,
    medium_confidence_edge_count: phaseEdges.filter((edge) => edge.confidence === "medium").length,
    low_confidence_edge_count: phaseEdges.filter((edge) => edge.confidence === "low").length,
    missing_edge_count: phaseEdges.filter((edge) => edge.confidence === "missing").length
  };
}

function compactAgentGenerationLogicPathEvidence(edges) {
  return uniqueLimited((edges || []).map((edge) =>
    `phase_edge:${edge.from_phase || "unknown"}->${edge.to_phase || "unknown"}:${edge.relation || "unknown"}:${edge.confidence || "unknown"}`
  ), 16);
}

function compactAgentGenerationStrongestAttachmentEdge(edges) {
  return (edges || [])
    .filter((edge) =>
      edge.to_phase === "signature_attachment" ||
      edge.from_stage === "signature_mutation" ||
      edge.to_stage === "signed_request" ||
      (edge.refs || []).some((ref) => String(ref).startsWith("target_params:")))
    .sort(compareCandidateLogicEdges)[0] || null;
}

function compactAgentGenerationCriticalPath({status, phases, edges, finalAttachment}) {
  return {
    status,
    phase_sequence: (phases || []).map((phase) => phase.id),
    stage_sequence: uniqueLimited((phases || []).flatMap((phase) => phase.stages || []), 16),
    edge_summary: compactAgentGenerationLogicEdgeSummary(edges),
    strongest_attachment_edge: compactCandidateLogicEdge(compactAgentGenerationStrongestAttachmentEdge(edges)),
    blocking_gaps: finalAttachment?.observed ? [] : ["signature_attachment_not_observed"],
    path_evidence: compactAgentGenerationLogicPathEvidence(edges)
  };
}

function compactAgentGenerationLogicHypothesis(summary) {
  const phases = compactAgentGenerationLogicPhases(summary);
  if (!phases.length) return null;
  const edges = compactAgentGenerationLogicEdges(summary);
  const phaseSequence = phases.map((phase) => phase.id);
  const status = compactAgentGenerationLogicStatus(phases);
  const primaryParam = sortParamNames(summary?.target_params || [])[0] || "parameter";
  const finalAttachment = compactAgentGenerationFinalAttachment(summary);
  const criticalPath = compactAgentGenerationCriticalPath({
    status,
    phases,
    edges,
    finalAttachment
  });
  return {
    status,
    phases,
    phase_edges: edges,
    critical_path: criticalPath,
    agent_logic_trace: {
      summary: `${primaryParam} generation: ${phaseSequence.join(" -> ")}; status=${status}`,
      status,
      steps: phases.map((phase, index) => ({
        order: index + 1,
        phase: phase.id,
        status: phase.status,
        confidence: phase.confidence,
        stages: phase.stages,
        claim: compactAgentGenerationLogicClaim(primaryParam, phase),
        runtime_apis: phase.runtime_apis,
        source_calls: phase.source_calls,
        source_signals: phase.source_signals,
        source_operators: uniqueLimited(phase.source_operators || [], 8),
        source_constants: uniqueLimited(phase.source_constants || [], 8),
        target_params: phase.target_params,
        source_refs: phase.source_refs,
        object_refs: uniqueLimited(phase.object_refs || [], 8),
        value_refs: uniqueLimited(phase.value_refs || [], 8),
        runtime_events: compactRuntimeEventRefs(phase.runtime_events || [], 16),
        evidence: phase.evidence
      })),
      edges: edges.map(compactCandidateLogicEdge).filter(Boolean),
      final_attachment: finalAttachment
    },
    final_attachment: finalAttachment
  };
}

function compactAgentGenerationTraceStep(generationTrace, step, index) {
  const order = step?.order ?? index + 1;
  const stage = step?.stage || "unknown";
  return (generationTrace || []).find((candidate, candidateIndex) =>
    (candidate.order ?? candidateIndex + 1) === order && (candidate.stage || "unknown") === stage
  ) ||
    ((generationTrace || [])[index]?.stage === stage ? (generationTrace || [])[index] : null) ||
    (generationTrace || []).find((candidate) => (candidate.stage || "unknown") === stage) ||
    null;
}

function compactAgentGenerationSummarySteps(summary, generationTrace = []) {
  return (summary?.steps || []).slice(0, 12).map((step, index) => {
    const traceStep = compactAgentGenerationTraceStep(generationTrace, step, index);
    const runtimeEventRefs = (step.runtime_event_refs || []).length
      ? step.runtime_event_refs
      : traceStep?.runtime_event_refs || [];
    return {
      order: step.order ?? index + 1,
      stage: step.stage || "unknown",
      role: step.role || "context",
      evidence: uniqueLimited(step.evidence || [], 8),
      runtime_apis: uniqueLimited(step.runtime_apis || [], 8),
      source_context_refs: uniqueLimited(step.source_context_refs || [], 8),
      source_calls: uniqueLimited(step.source_calls || [], 8),
      source_signals: uniqueLimited(step.source_signals || [], 8),
      source_operators: uniqueLimited(step.source_operators || [], 8),
      source_constants: uniqueLimited(step.source_constants || [], 8),
      target_params: sortParamNames(step.target_params || []),
      object_refs: uniquePrioritizedLimited(
        step.object_refs || [],
        step.stage === "dynamic_dispatch" ? 16 : 8,
        generationPathObjectRefRank
      ),
      value_refs: compactGenerationValueRefs(
        step.value_refs || [],
        step.stage === "dynamic_dispatch" ? 24 : 8,
        {preserveVmpStateRefs: step.stage === "dynamic_dispatch"}
      ),
      runtime_event_refs: compactRuntimeEventRefs(runtimeEventRefs, 8),
      relation_to_signed_request: step.relation_to_signed_request || "unknown"
    };
  });
}

function compactAgentGenerationSummary(summary, generationTrace = []) {
  if (!summary) return null;
  const steps = compactAgentGenerationSummarySteps(summary, generationTrace);
  const summaryWithCompactedSteps = {
    ...summary,
    steps
  };
  const logicHypothesis = summary.logic_hypothesis || compactAgentGenerationLogicHypothesis(summaryWithCompactedSteps);
  return {
    stage_chain: uniqueLimited(summary.stage_chain || [], 12),
    summary_text: summary.summary_text || "",
    target_params: sortParamNames(summary.target_params || []),
    evidence_profile: summary.evidence_profile || "unknown",
    readiness: summary.readiness || "unknown",
    runtime_apis: uniqueLimited(summary.runtime_apis || [], 24),
    source_calls: uniqueLimited(summary.source_calls || [], 24),
    source_signals: uniqueLimited(summary.source_signals || [], 24),
    source_observed_hooks: uniqueLimited(summary.source_observed_hooks || [], 16),
    runtime_observed_hooks: uniqueLimited(summary.runtime_observed_hooks || [], 16),
    vmp_hook_ref_summary: (summary.vmp_hook_ref_summary || []).slice(0, VMP_HOOK_POINT_SPECS.length).map((item) => ({
      type: item.type || "unknown",
      status: item.status || "unknown",
      stages: uniqueLimited(item.stages || [], 8),
      apis: uniqueLimited(item.apis || [], 8),
      value_refs: uniquePrioritizedLimited(
        item.value_refs || [],
        12,
        (ref) => vmpHookValueRefRank(item.type || "unknown", ref)
      ),
      object_refs: uniquePrioritizedLimited(item.object_refs || [], 12, generationPathObjectRefRank),
      source_refs: uniqueLimited(item.source_refs || [], 8),
      source_calls: uniqueLimited(item.source_calls || [], 8),
      source_signals: uniqueLimited(item.source_signals || [], 8)
    })),
    attachment_params: sortParamNames(summary.attachment_params || []),
    signature_param_materializations: compactSignatureParamMaterializations(
      summary.signature_param_materializations || []
    ),
    data_link_count: summary.data_link_count ?? 0,
    inferred_data_link_count: summary.inferred_data_link_count ?? 0,
    steps,
    ...(logicHypothesis ? {logic_hypothesis: logicHypothesis} : {})
  };
}

function compactAgentRuntimePathSteps(entry) {
  return (entry.generation_trace || []).slice(0, 12).map((step, index) => ({
    order: step.order ?? index + 1,
    stage: step.stage || "unknown",
    apis: uniqueLimited(step.apis || [], 6),
    runtime_event_refs: compactRuntimeEventRefs(step.runtime_event_refs || [], 8),
    object_refs: uniquePrioritizedLimited(
      step.object_refs || [],
      step.stage === "dynamic_dispatch" ? 16 : 8,
      generationPathObjectRefRank
    ),
    value_refs: compactGenerationValueRefs(
      step.value_refs || [],
      step.stage === "dynamic_dispatch" ? 24 : 8,
      {
        preserveVmpStateRefs: step.stage === "dynamic_dispatch",
        preserveStringRuntimeRefs: shouldPreserveStringRuntimeRefsForStage(step.stage)
      }
    ),
    target_params: sortParamNames(step.target_params || []),
    relation_to_signed_request: step.relation || step.relation_to_signed_request || "unknown",
    distance_to_signed_request: step.distance_to_signed_request ?? null,
    distance_basis: step.distance_basis || "unknown",
    source_refs: uniqueLimited(step.source_refs || [], 4)
  }));
}

function compactAgentRuntimeRefEvidence(entry) {
  const pathSteps = compactAgentRuntimePathSteps(entry);
  const generationEdges = generationEdgesForPath(pathSteps, entry);
  const lineage = buildRuntimeRefLineage(pathSteps, generationEdges);
  const runtimeEventEvidence = buildRuntimeEventEvidence(pathSteps);
  return {
    lineage: lineage.slice(0, 8),
    ref_event_evidence: buildRuntimeRefEventEvidence(lineage, runtimeEventEvidence).slice(0, 8)
  };
}

function compactAgentParameterEntry(entry) {
  const runtimeRefEvidence = compactAgentRuntimeRefEvidence(entry);
  return {
    param: entry.param || "",
    status: entry.status || "unknown",
    best_flow_id: entry.best_flow_id || "",
    endpoint: entry.endpoint || "",
    confidence: entry.confidence || "low",
    evidence_status: entry.evidence_status || "unknown",
    readiness: entry.readiness || "unknown",
    flow_ids: uniqueLimited(entry.flow_ids || [], 8),
    source_candidate_ids: uniqueLimited(entry.source_candidate_ids || [], 8),
    review_entry_ids: uniqueLimited(entry.review_entry_ids || [], 8),
    source_refs: uniqueLimited(entry.source_refs || [], 12),
    evidence_gaps: uniqueLimited(entry.evidence_gaps || [], 8),
    next_questions: uniqueLimited(entry.next_questions || [], 12),
    data_links: (entry.data_links || []).slice(0, 12).map(compactAgentDataLink),
    inferred_data_links: (entry.inferred_data_links || []).slice(0, 12).map(compactAgentDataLink),
    vmp_scalar_chain_links: (entry.vmp_scalar_chain_links || []).slice(0, 8).map(compactAgentScalarChainLink),
    signature_param_materializations: compactSignatureParamMaterializations(
      entry.signature_param_materializations || [],
      entry.param || ""
    ),
    runtime_ref_lineage: runtimeRefEvidence.lineage,
    runtime_ref_event_evidence: runtimeRefEvidence.ref_event_evidence,
    ...(entry.request_input_bundle ? {request_input_bundle: compactAgentRequestInputBundle(entry.request_input_bundle)} : {}),
    ...(entry.webcrypto_signature_summary ? {webcrypto_signature_summary: compactWebCryptoSignatureSummary(entry.webcrypto_signature_summary)} : {}),
    agent_generation_summary: compactAgentGenerationSummary(entry.agent_generation_summary, entry.generation_trace || []),
    generation_trace: (entry.generation_trace || []).slice(0, 12).map((step, index) => ({
      order: step.order ?? index + 1,
      stage: step.stage || "unknown",
      role: step.role || "context",
      ...(step.seq_start !== undefined ? {seq_start: step.seq_start} : {}),
      ...(step.seq_end !== undefined ? {seq_end: step.seq_end} : {}),
      apis: uniqueLimited(step.apis || [], 6),
      target_params: sortParamNames(step.target_params || []),
      param_relation: step.param_relation || "unknown",
      relation: step.relation || "unknown",
      distance_to_signed_request: step.distance_to_signed_request ?? null,
      distance_basis: step.distance_basis || "unknown",
      source_refs: uniqueLimited(step.source_refs || [], 4),
      source_calls: uniqueLimited(step.source_calls || [], 6),
      source_signals: uniqueLimited(step.source_signals || [], 6),
      source_operators: uniqueLimited(step.source_operators || [], 6),
      source_constants: uniqueLimited(step.source_constants || [], 6),
      runtime_event_refs: compactRuntimeEventRefs(step.runtime_event_refs || [], 8),
      object_refs: uniquePrioritizedLimited(
        step.object_refs || [],
        step.stage === "dynamic_dispatch" ? 16 : 4,
        generationPathObjectRefRank
      ),
      value_refs: compactGenerationValueRefs(
        step.value_refs || [],
        step.stage === "dynamic_dispatch" ? 24 : 8,
        {
          preserveVmpStateRefs: step.stage === "dynamic_dispatch",
          preserveStringRuntimeRefs: shouldPreserveStringRuntimeRefsForStage(step.stage)
        }
      )
    }))
  };
}

function compactAgentReviewEntry(entry) {
  return {
    id: entry.id || "",
    source_candidate_id: entry.source_candidate_id || "",
    causality: entry.causality || "unknown",
    review_priority: entry.review_priority || "low",
    function: entry.function || "",
    asset_id: entry.asset_id || "",
    url: entry.url || "",
    content_path: entry.content_path || "",
    source_refs: uniqueLimited(entry.source_refs || [], 8),
    line_ranges: (entry.line_ranges || []).slice(0, 8).map((range) => ({
      ref: range.ref || "",
      content_path: range.content_path || "",
      line_start: range.line_start ?? null,
      line_end: range.line_end ?? null,
      ...(compactAgentSourcePreview(range.preview || "") ? {
        preview: compactAgentSourcePreview(range.preview || "")
      } : {})
    })),
    endpoints: uniqueLimited(entry.endpoints || [], 8),
    target_params: sortParamNames(entry.target_params || []),
    stages: uniqueLimited(entry.stages || [], 12),
    runtime_apis: uniqueLimited(entry.runtime_apis || [], 16),
    signals: uniqueLimited(entry.signals || [], 16),
    calls: uniqueLimited(entry.calls || [], 16),
    operators: uniqueLimited(entry.operators || [], 16),
    numeric_literals: uniqueLimited(entry.numeric_literals || [], 16),
    generation_paths: (entry.generation_paths || []).slice(0, 4).map((item) => ({
      id: item.id || "",
      flow_id: item.flow_id || "",
      endpoint: item.endpoint || "",
      causality: item.causality || "unknown",
      target_params: sortParamNames(item.target_params || []),
      stage_summary: item.stage_summary || "",
      warnings: uniqueLimited(item.warnings || [], 8)
    })),
    next_questions: uniqueLimited(entry.next_questions || [], 12)
  };
}

function compactAgentCoreAssetSourceWindow(window) {
  const preview = compactAgentSourcePreview(window.preview || "");
  return {
    focus: window.focus || "unknown",
    priority: window.priority || "medium",
    content_path: window.content_path || "",
    line_start: window.line_start ?? null,
    line_end: window.line_end ?? null,
    column_start: window.column_start ?? null,
    column_end: window.column_end ?? null,
    target_params: signatureTermsInText(preview),
    signals: uniqueLimited([
      ...(window.signals || []),
      ...(window.analysis?.signals || [])
    ], 8),
    ...(preview ? {preview} : {})
  };
}

function compactAgentCoreAssetEntry(entry, relatedParams = []) {
  const sourceWindows = (entry.source_windows || []).slice(0, 8).map(compactAgentCoreAssetSourceWindow);
  const targetParams = sortParamNames(uniqueLimited(sourceWindows.flatMap((window) => window.target_params || []), 8));
  const linkedParams = sortParamNames(uniqueLimited([
    ...(entry.related_params || []),
    ...relatedParams,
    ...targetParams
  ], 8));
  return {
    asset_id: entry.asset_id || "",
    asset_role: entry.asset_role || "",
    asset_focus: entry.asset_focus || "",
    url: entry.url || "",
    content_path: entry.content_path || "",
    retrieval_status: entry.retrieval_status || "",
    source_status: entry.source_status || "unknown",
    score: entry.score ?? 0,
    signals: uniqueLimited(entry.signals || [], 12),
    review_focus: uniqueLimited(entry.review_focus || sourceWindows.map((window) => window.focus), 8),
    target_params: targetParams,
    related_params: linkedParams,
    source_windows: sourceWindows,
    runtime_entrypoints: (entry.runtime_entrypoints || [])
      .slice(0, 8)
      .map((runtimeEntry) => compactAgentCoreAssetRuntimeEntrypoint(runtimeEntry, linkedParams)),
    next_questions: uniqueLimited(entry.next_questions || [], 8)
  };
}

function coreAssetSourceWindowRef(asset, window) {
  if (!asset?.asset_id || !String(asset.asset_id).startsWith("sha1:")) return "";
  if (!Number.isFinite(window?.line_start) || !Number.isFinite(window?.line_end)) return "";
  const base = `${asset.asset_id}:${window.line_start}-${window.line_end}`;
  if (Number.isFinite(window?.column_start) && Number.isFinite(window?.column_end)) {
    return `${base}@${Math.max(0, Math.floor(window.column_start) - 1)}-${Math.max(0, Math.floor(window.column_end))}`;
  }
  return base;
}

function stagesForCoreAssetWindowFocus(focus) {
  if (focus === "url_signature_boundary") return ["signature_mutation"];
  if (focus === "vmp_runtime_surface") return ["dynamic_dispatch", "integer_mixing"];
  if (focus === "encoding_or_hash_boundary") return ["text_or_string_decode", "integer_mixing"];
  if (focus === "dynamic_code_boundary") return ["dynamic_code"];
  if (focus === "fingerprint_collection") return ["fingerprint_collection"];
  if (focus === "anti_debug_or_integrity_probe") return ["anti_debug_or_integrity_probe"];
  return [];
}

function sourceIndexEntriesForCoreAssets(coreAssets) {
  const entries = [];
  for (const asset of coreAssets || []) {
    const relatedParams = sortParamNames([
      ...(asset.target_params || []),
      ...(asset.related_params || [])
    ]);
    for (const window of asset.source_windows || []) {
      const ref = coreAssetSourceWindowRef(asset, window);
      if (!ref) continue;
      entries.push({
      ref,
      asset_id: asset.asset_id || "",
      url: asset.url || "",
      content_path: window.content_path || asset.content_path || "",
        line_start: window.line_start ?? null,
        line_end: window.line_end ?? null,
        preview: window.preview || "",
        source_candidate_ids: [],
        review_entry_ids: [],
        target_params: sortParamNames(uniqueLimited([
          ...(window.target_params || []),
          ...relatedParams
        ], 8)),
        stages: stagesForCoreAssetWindowFocus(window.focus),
        signals: uniqueLimited([
          ...(asset.signals || []),
          ...(window.signals || [])
        ], 16)
      });
    }
  }
  return entries;
}

function coreAssetSourceRefsForParameter(coreAssets, param) {
  if (!param) return [];
  const refs = [];
  for (const asset of coreAssets || []) {
    const params = new Set([
      ...(asset.target_params || []),
      ...(asset.related_params || [])
    ]);
    if (!params.has(param)) continue;
    for (const window of asset.source_windows || []) {
      const ref = coreAssetSourceWindowRef(asset, window);
      if (ref) refs.push(ref);
    }
  }
  return uniqueLimited(refs, 12);
}

function compactAgentCoreAssetRuntimeEntrypoint(entry, relatedParams = []) {
  const targetParams = sortParamNames(entry.target_params || []);
  const linkedParams = sortParamNames(uniqueLimited([
    ...(entry.related_params || []),
    ...relatedParams,
    ...targetParams
  ], 8));
  const stages = uniqueLimited(entry.stages || [], 12);
  const runtimeApis = uniqueLimited(entry.runtime_apis || [], 16);
  const missingLinks = runtimeEntrypointMissingLinks({stages, runtime_apis: runtimeApis}, targetParams, linkedParams);
  return {
    function: entry.function || "(anonymous)",
    source_candidate_id: entry.source_candidate_id || "",
    review_entry_id: entry.review_entry_id || "",
    content_path: entry.content_path || "",
    source_refs: uniqueLimited(entry.source_refs || [], 8),
    line_ranges: (entry.line_ranges || []).slice(0, 4).map((range) => ({
      ref: range.ref || "",
      content_path: range.content_path || "",
      line_start: range.line_start ?? null,
      line_end: range.line_end ?? null
    })),
    target_params: targetParams,
    related_params: linkedParams,
    link_status: runtimeEntrypointLinkStatus(targetParams, linkedParams, missingLinks),
    missing_links: missingLinks,
    next_hooks: runtimeEntrypointNextHooks(missingLinks),
    endpoints: uniqueLimited(entry.endpoints || [], 8),
    stages,
    runtime_apis: runtimeApis,
    signals: uniqueLimited(entry.signals || [], 12),
    causality: entry.causality || "unknown",
    review_priority: entry.review_priority || "unknown",
    evidence_score: entry.evidence_score ?? 0,
    min_distance_to_signed_request: entry.min_distance_to_signed_request ?? null
  };
}

function runtimeEntrypointHasAny(entry, values, field) {
  const observed = new Set(entry[field] || []);
  return values.some((value) => observed.has(value));
}

function runtimeEntrypointMissingLinks(entry, targetParams, relatedParams) {
  if ((targetParams || []).length || !(relatedParams || []).length) return [];
  const missing = [];
  const hasDynamicDispatch = runtimeEntrypointHasAny(entry, ["dynamic_dispatch"], "stages") ||
    runtimeEntrypointHasAny(entry, [
      "Function.prototype.call",
      "Function.prototype.apply",
      "Reflect.apply"
    ], "runtime_apis");
  const hasIntegerMixing = runtimeEntrypointHasAny(entry, ["integer_mixing"], "stages") ||
    (entry.runtime_apis || []).some((api) =>
      /^Bitwise\./.test(api || "") ||
      /^Shift\./.test(api || "") ||
      api === "Math.imul"
    );
  const hasStringBoundary = runtimeEntrypointHasAny(entry, ["text_or_string_decode", "string_transform", "url_encoding"], "stages") ||
    runtimeEntrypointHasAny(entry, [
      "String.fromCharCode",
      "String.prototype.charCodeAt",
      "TextEncoder.encode",
      "TextDecoder.decode",
      "URLSearchParams.toString",
      "encodeURIComponent"
    ], "runtime_apis");

  if (hasIntegerMixing) missing.push("vmp_register_ref");
  if (hasDynamicDispatch) missing.push("dynamic_dispatch_boundary_ref");
  if (hasStringBoundary) missing.push("string_boundary_ref");
  return uniqueLimited(missing, 8);
}

function runtimeEntrypointLinkStatus(targetParams, relatedParams, missingLinks) {
  if ((targetParams || []).length) return "direct_param_runtime_entry";
  if ((relatedParams || []).length && (missingLinks || []).length) return "encoded_or_vmp_boundary_unresolved";
  if ((relatedParams || []).length) return "related_asset_entry_unresolved";
  return "unlinked_runtime_entry";
}

function runtimeEntrypointNextHooks(missingLinks) {
  const hooks = [];
  if ((missingLinks || []).includes("vmp_register_ref")) {
    hooks.push("vmp.register_ref", "vmp.handler.return_ref");
  }
  if ((missingLinks || []).includes("dynamic_dispatch_boundary_ref")) {
    hooks.push("vmp.handler.return_ref");
  }
  if ((missingLinks || []).includes("vmp_register_ref")) {
    hooks.push("Bitwise.result_ref");
  }
  if ((missingLinks || []).includes("string_boundary_ref")) {
    hooks.push("String.fromCharCode.result_ref", "TextEncoder.input_ref", "URLSearchParams.toString.result_ref");
  }
  return uniqueLimited(hooks, 12);
}

function reviewPriorityScore(priority) {
  if (priority === "high") return 0;
  if (priority === "medium") return 1;
  if (priority === "low") return 2;
  return 3;
}

function sourceEntryMatchesCoreAsset(entry, asset) {
  if (!entry || !asset) return false;
  if (entry.asset_id && asset.asset_id && entry.asset_id === asset.asset_id) return true;
  if (entry.content_path && asset.content_path && entry.content_path === asset.content_path) return true;
  return false;
}

function coreAssetRuntimeEntrypoints(asset, sourceCandidates = [], reviewEntries = []) {
  const reviewsByCandidate = new Map();
  for (const review of reviewEntries || []) {
    if (review.source_candidate_id) reviewsByCandidate.set(review.source_candidate_id, review);
  }
  return (sourceCandidates || [])
    .filter((candidate) => sourceEntryMatchesCoreAsset(candidate, asset))
    .map((candidate) => {
      const review = reviewsByCandidate.get(candidate.id || "") ||
        (reviewEntries || []).find((entry) =>
          sourceEntryMatchesCoreAsset(entry, asset) &&
          (entry.function || "") === (candidate.function || "")
        ) || {};
      return compactAgentCoreAssetRuntimeEntrypoint({
        function: candidate.function || review.function || "",
        source_candidate_id: candidate.id || "",
        review_entry_id: review.id || "",
        content_path: candidate.content_path || review.content_path || asset.content_path || "",
        source_refs: uniqueLimited([
          ...(candidate.source_refs || []),
          ...(review.source_refs || [])
        ], 8),
        line_ranges: review.line_ranges || [],
        target_params: sortParamNames(uniqueLimited([
          ...(candidate.target_params || []),
          ...(review.target_params || [])
        ], 8)),
        endpoints: uniqueLimited([
          ...(candidate.endpoints || []),
          ...(review.endpoints || [])
        ], 8),
        stages: uniqueLimited([
          ...(candidate.stages || []),
          ...(review.stages || [])
        ], 12),
        runtime_apis: uniqueLimited([
          ...(candidate.runtime_apis || []),
          ...(review.runtime_apis || [])
        ], 16),
        signals: uniqueLimited([
          ...(candidate.signals || []),
          ...(review.signals || [])
        ], 12),
        causality: review.causality || "unknown",
        review_priority: review.review_priority || "unknown",
        evidence_score: candidate.evidence_score ?? 0,
        min_distance_to_signed_request: candidate.min_distance_to_signed_request ?? null
      });
    })
    .sort((left, right) =>
      reviewPriorityScore(left.review_priority) - reviewPriorityScore(right.review_priority) ||
      (right.evidence_score || 0) - (left.evidence_score || 0) ||
      String(left.function).localeCompare(String(right.function)) ||
      String(left.source_candidate_id).localeCompare(String(right.source_candidate_id)))
    .slice(0, 8);
}

function parseSourceRef(ref) {
  const match = String(ref || "").match(/^(sha1:[^:]+):(\d+)-(\d+)(?:@(\d+)(?:-(\d+))?)?$/);
  if (!match) {
    return {
      asset_id: "",
      line_start: null,
      line_end: null,
      char_start: null,
      char_end: null
    };
  }
  return {
    asset_id: match[1],
    line_start: Number(match[2]),
    line_end: Number(match[3]),
    char_start: match[4] === undefined ? null : Number(match[4]),
    char_end: match[5] === undefined ? null : Number(match[5])
  };
}

function sourcePreviewFromTextForParsedRef(parsed, content) {
  const text = String(content || "");
  if (!text) return "";
  if (parsed?.char_start !== null && Number.isFinite(parsed?.char_start)) {
    const start = Math.max(0, Math.min(text.length, Math.floor(parsed.char_start)));
    const end = parsed.char_end !== null && Number.isFinite(parsed.char_end)
      ? Math.max(start, Math.min(text.length, Math.floor(parsed.char_end)))
      : start;
    const before = Math.min(160, start);
    const contextStart = Math.max(0, start - before);
    const contextEnd = Math.min(text.length, Math.max(end, start + SOURCE_CONTEXT_MAX_CHARS - before));
    const prefix = contextStart > 0 ? "..." : "";
    const suffix = contextEnd < text.length ? "..." : "";
    return compactAgentSourcePreview(`${prefix}${preserveSignatureText(text.slice(contextStart, contextEnd))}${suffix}`);
  }
  if (parsed?.line_start === null || parsed?.line_end === null) return "";
  const lines = text.split(/\r?\n/);
  if (!lines.length) return "";
  const start = Math.max(1, Math.min(parsed.line_start, lines.length));
  const end = Math.max(start, Math.min(parsed.line_end, lines.length));
  return compactAgentSourcePreview(lines.slice(start - 1, end).join("\n"));
}

function resolveSourceEvidenceContentPath(contentPath, tracePath = "") {
  if (!contentPath) return "";
  if (path.isAbsolute(contentPath)) return contentPath;
  const baseDir = tracePath ? path.dirname(tracePath) : process.cwd();
  return path.resolve(baseDir, contentPath);
}

function sourcePreviewFromContentPath(ref, contentPath, tracePath) {
  const filePath = resolveSourceEvidenceContentPath(contentPath, tracePath);
  if (!filePath || !fs.existsSync(filePath)) return "";
  try {
    return sourcePreviewFromTextForParsedRef(parseSourceRef(ref), fs.readFileSync(filePath, "utf8"));
  } catch {
    return "";
  }
}

function addSourceRefIndexEntry(index, ref, patch = {}) {
  if (!ref) return;
  const parsed = parseSourceRef(ref);
  const current = index.get(ref) || {
    ref,
    asset_id: parsed.asset_id,
    url: "",
    content_path: "",
    line_start: parsed.line_start,
    line_end: parsed.line_end,
    preview: "",
    source_candidate_ids: new Set(),
    review_entry_ids: new Set(),
    target_params: new Set(),
    stages: new Set(),
    signals: new Set(),
    calls: new Set(),
    operators: new Set(),
    numeric_literals: new Set()
  };
  if (!current.asset_id && patch.asset_id) current.asset_id = patch.asset_id;
  if (!current.url && patch.url) current.url = patch.url;
  if (!current.content_path && patch.content_path) current.content_path = patch.content_path;
  if (current.line_start === null && patch.line_start !== undefined) current.line_start = patch.line_start;
  if (current.line_end === null && patch.line_end !== undefined) current.line_end = patch.line_end;
  if (!current.preview && patch.preview) current.preview = compactAgentSourcePreview(patch.preview);
  for (const id of patch.source_candidate_ids || []) current.source_candidate_ids.add(id);
  for (const id of patch.review_entry_ids || []) current.review_entry_ids.add(id);
  for (const param of patch.target_params || []) current.target_params.add(param);
  for (const stage of patch.stages || []) current.stages.add(stage);
  for (const signal of patch.signals || []) current.signals.add(signal);
  for (const call of patch.calls || []) current.calls.add(call);
  for (const operator of patch.operators || []) current.operators.add(operator);
  for (const literal of patch.numeric_literals || []) current.numeric_literals.add(literal);
  index.set(ref, current);
}

function buildSourceRefIndex(parameters, sourceCandidates, reviewEntries) {
  const index = new Map();
  for (const candidate of sourceCandidates || []) {
    for (const ref of candidate.source_refs || []) {
      addSourceRefIndexEntry(index, ref, {
        asset_id: candidate.asset_id,
        url: candidate.url,
        content_path: candidate.content_path,
        source_candidate_ids: [candidate.id].filter(Boolean),
        target_params: candidate.target_params || [],
        stages: candidate.stages || [],
        signals: candidate.signals || [],
        calls: candidate.calls || [],
        operators: candidate.operators || [],
        numeric_literals: candidate.numeric_literals || []
      });
    }
  }
  for (const entry of reviewEntries || []) {
    for (const ref of entry.source_refs || []) {
      addSourceRefIndexEntry(index, ref, {
        asset_id: entry.asset_id,
        url: entry.url,
        content_path: entry.content_path,
        review_entry_ids: [entry.id].filter(Boolean),
        target_params: entry.target_params || [],
        stages: entry.stages || [],
        signals: entry.signals || [],
        calls: entry.calls || [],
        operators: entry.operators || [],
        numeric_literals: entry.numeric_literals || []
      });
    }
    for (const range of entry.line_ranges || []) {
      addSourceRefIndexEntry(index, range.ref, {
        asset_id: entry.asset_id,
        url: entry.url,
        content_path: range.content_path || entry.content_path,
        line_start: range.line_start,
        line_end: range.line_end,
        preview: range.preview || "",
        review_entry_ids: [entry.id].filter(Boolean),
        target_params: entry.target_params || [],
        stages: entry.stages || [],
        signals: entry.signals || [],
        calls: entry.calls || [],
        operators: entry.operators || [],
        numeric_literals: entry.numeric_literals || []
      });
    }
  }
  for (const parameter of parameters || []) {
    for (const ref of parameter.source_refs || []) {
      addSourceRefIndexEntry(index, ref, {
        target_params: [parameter.param].filter(Boolean),
        stages: (parameter.generation_trace || []).map((step) => step.stage).filter(Boolean)
      });
    }
  }
  return [...index.values()]
    .map((entry) => {
      const signals = uniqueLimited([...entry.signals], 16);
      const calls = uniqueLimited([...entry.calls], 16);
      const operators = uniqueLimited([...entry.operators], 16);
      const numericLiterals = uniqueLimited([...entry.numeric_literals], 16);
      return {
        ref: entry.ref,
        asset_id: entry.asset_id || "",
        ...(entry.url ? {url: entry.url} : {}),
        content_path: entry.content_path || "",
        line_start: entry.line_start,
        line_end: entry.line_end,
        ...(entry.preview ? {preview: entry.preview} : {}),
        source_candidate_ids: uniqueLimited([...entry.source_candidate_ids], 8),
        review_entry_ids: uniqueLimited([...entry.review_entry_ids], 8),
        target_params: sortParamNames([...entry.target_params]),
        stages: uniqueLimited([...entry.stages], 12),
        ...(signals.length ? {signals} : {}),
        ...(calls.length ? {calls} : {}),
        ...(operators.length ? {operators} : {}),
        ...(numericLiterals.length ? {numeric_literals: numericLiterals} : {})
      };
    })
    .sort((left, right) => String(left.ref).localeCompare(String(right.ref)));
}

function compactAgentSourceCandidate(candidate) {
  return {
    id: candidate.id || "",
    function: candidate.function || "",
    asset_id: candidate.asset_id || "",
    url: candidate.url || "",
    content_path: candidate.content_path || "",
    source_refs: uniqueLimited(candidate.source_refs || [], 8),
    target_params: sortParamNames(candidate.target_params || []),
    endpoints: uniqueLimited(candidate.endpoints || [], 8),
    stages: uniqueLimited(candidate.stages || [], 12),
    runtime_apis: uniqueLimited(candidate.runtime_apis || [], 16),
    signals: uniqueLimited(candidate.signals || [], 16),
    calls: uniqueLimited(candidate.calls || [], 16),
    operators: uniqueLimited(candidate.operators || [], 16),
    numeric_literals: uniqueLimited(candidate.numeric_literals || [], 16),
    priority_reasons: uniqueLimited(candidate.priority_reasons || [], 12),
    evidence_score: candidate.evidence_score || 0,
    min_distance_to_signed_request: candidate.min_distance_to_signed_request ?? null
  };
}

function buildAgentCaptureRecipe(nextCapturePlan) {
  if (!nextCapturePlan?.rerun_recipe) return null;
  const recipe = nextCapturePlan.rerun_recipe;
  const captureGate = nextCapturePlan.capture_gate || {};
  const guiDefaults = recipe.gui_defaults || {};
  const avoidResourceClasses = captureGate.reject_resource_classes ||
    captureGate.tail_filters?.exclude_resource_classes ||
    BUSINESS_API_AVOID_RESOURCE_CLASSES;
  return {
    profile: recipe.profile || "interactive_full_capture",
    start_url: recipe.start_url || guiDefaults.url || "about:blank",
    gui_defaults: guiDefaults,
    python_launcher_args: recipe.python_launcher_args || [],
    env: recipe.env || {},
    focus: recipe.focus || {},
    target_endpoint_patterns: captureGate.target_endpoint_patterns || recipe.focus?.endpoints || [],
    tail_filters: captureGate.tail_filters || {
      categories: ["network"],
      apis: BUSINESS_API_GATE_TAIL_APIS,
      exclude_resource_classes: avoidResourceClasses
    },
    stop_when: captureGate.stop_when || "observed_actionable_endpoint_count > 0",
    noise_reduction: {
      prefer_targeted_rerun: true,
      avoid_resource_classes: avoidResourceClasses,
      keep_capture_values: guiDefaults.captureValues || "full",
      keep_capture_assets: guiDefaults.captureAssets || "full"
    }
  };
}

function buildAgentInputPack(report) {
  const evidencePack = report.signature?.agent_evidence_pack || {};
  const parameterBrief = evidencePack.parameter_generation_brief || {};
  const reviewPackage = evidencePack.agent_review_package || {};
  const coreAssetReviewPackage = evidencePack.core_asset_review_package || {};
  const parameters = (parameterBrief.parameters || []).slice(0, 16).map(compactAgentParameterEntry);
  const sourceCandidates = (evidencePack.signature_source_candidates || []).slice(0, 12).map(compactAgentSourceCandidate);
  const reviewEntries = (reviewPackage.entries || []).slice(0, 12).map(compactAgentReviewEntry);
  const observedParams = sortParamNames(uniqueLimited(parameters.map((parameter) => parameter.param).filter(Boolean), 8));
  const coreAssets = (coreAssetReviewPackage.entries || [])
    .slice(0, 8)
    .map((entry) => compactAgentCoreAssetEntry({
      ...entry,
      runtime_entrypoints: coreAssetRuntimeEntrypoints(entry, sourceCandidates, reviewEntries)
    }, observedParams));
  const captureRecipe = buildAgentCaptureRecipe(evidencePack.next_capture_plan);
  const sourceRefIndex = buildSourceRefIndex(parameters, sourceCandidates, reviewEntries);
  return {
    version: 1,
    purpose: "codex_agent_signature_analysis_input",
    redaction: {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: {
      path: report.trace?.path || "",
      event_count: report.trace?.event_count ?? 0
    },
    signature: {
      event_count: report.signature?.event_count ?? 0,
      target_terms: evidencePack.target_terms || SIGNATURE_TERMS,
      parameter_count: parameterBrief.parameter_count ?? (parameterBrief.parameters || []).length,
      material_flow_count: (evidencePack.signature_material_flows || []).length,
      source_candidate_count: sourceCandidates.length,
      review_entry_count: reviewPackage.entry_count ?? (reviewPackage.entries || []).length,
      core_asset_count: coreAssetReviewPackage.entry_count ?? coreAssets.length
    },
    capture_recipe: captureRecipe,
    parameters,
    source_ref_index: sourceRefIndex,
    core_assets: coreAssets,
    vmp_scalar_ref_chains: (evidencePack.vmp_scalar_ref_chains || []).slice(0, 12),
    source_candidates: sourceCandidates,
    review_entries: reviewEntries,
    next_capture_plan: evidencePack.next_capture_plan ? {
      priority: evidencePack.next_capture_plan.priority || "low",
      target_terms: evidencePack.next_capture_plan.target_terms || [],
      recommended_flags: evidencePack.next_capture_plan.recommended_flags || [],
      gap_summary: (evidencePack.next_capture_plan.gap_summary || []).slice(0, 8),
      capture_gate: evidencePack.next_capture_plan.capture_gate || null,
      business_api_capture_status: evidencePack.next_capture_plan.business_api_capture_status || null
    } : null
  };
}

function renderAgentInputPackMarkdown(pack) {
  const lines = [
    "# XTrace Agent Input Pack",
    "",
    `Trace: \`${pack.trace?.path || ""}\``,
    `Events: ${pack.trace?.event_count ?? 0}`,
    `Signature events: ${pack.signature?.event_count ?? 0}`,
    `Parameters: ${pack.signature?.parameter_count ?? 0}`,
    ""
  ];
  if (pack.capture_recipe) {
    const recipe = pack.capture_recipe;
    lines.push(
      "## Capture Recipe",
      "",
      `- profile=${recipe.profile || "unknown"} start_url=${recipe.start_url || "about:blank"} stop_when=${recipe.stop_when || "none"}`,
      `- flags=${(recipe.python_launcher_args || []).join(" ") || "none"}`,
      `- target_endpoint_patterns=${(recipe.target_endpoint_patterns || []).join(",") || "none"}`,
      `- tail_filters categories=${(recipe.tail_filters?.categories || []).join(",") || "none"} apis=${(recipe.tail_filters?.apis || []).join(",") || "none"} exclude=${(recipe.tail_filters?.exclude_resource_classes || []).join(",") || "none"}`,
      `- noise_reduction prefer_targeted_rerun=${recipe.noise_reduction?.prefer_targeted_rerun ? "true" : "false"} avoid=${(recipe.noise_reduction?.avoid_resource_classes || []).join(",") || "none"}`,
      ""
    );
  }
  lines.push(
    "## Parameters",
    ""
  );
  for (const entry of pack.parameters || []) {
    lines.push(parameterGenerationBriefLine(entry));
  }
  if (!(pack.parameters || []).length) {
    lines.push("- none");
  }
  lines.push("", "## Source Candidates", "");
  for (const candidate of (pack.source_candidates || []).slice(0, 8)) {
    lines.push(
      `- ${candidate.id || "source_candidate"} function=${candidate.function || "(anonymous)"} path=${candidate.content_path || "none"} params=${(candidate.target_params || []).join(",") || "none"} stages=${(candidate.stages || []).slice(0, 8).join(",") || "none"} refs=${(candidate.source_refs || []).slice(0, 4).join(",") || "none"} reasons=${(candidate.priority_reasons || []).slice(0, 6).join(",") || "none"}`
    );
  }
  if (!(pack.source_candidates || []).length) {
    lines.push("- none");
  }
  lines.push("", "## Source Ref Index", "");
  for (const source of (pack.source_ref_index || []).slice(0, 16)) {
    lines.push(
      `- ${source.ref || "unknown"} path=${source.content_path || "none"} lines=${source.line_start ?? "none"}-${source.line_end ?? "none"} candidates=${(source.source_candidate_ids || []).join(",") || "none"} reviews=${(source.review_entry_ids || []).join(",") || "none"} params=${(source.target_params || []).join(",") || "none"} stages=${(source.stages || []).slice(0, 8).join(",") || "none"} preview=${source.preview || "none"}`
    );
  }
  if (!(pack.source_ref_index || []).length) {
    lines.push("- none");
  }
  lines.push("", "## Core Signature Assets", "");
  for (const asset of (pack.core_assets || []).slice(0, 8)) {
    lines.push(
      `- core_asset=${asset.asset_id || "none"} role=${asset.asset_role || "none"} status=${asset.source_status || "unknown"} path=${asset.content_path || "none"} params=${(asset.target_params || []).join(",") || "none"} focus=${(asset.review_focus || []).join(",") || "none"} related_params=${(asset.related_params || []).join(",") || "none"}`
    );
    for (const entry of (asset.runtime_entrypoints || []).slice(0, 4)) {
      lines.push(
        `  - runtime_entry=${entry.function || "(anonymous)"} candidate=${entry.source_candidate_id || "none"} review=${entry.review_entry_id || "none"} causality=${entry.causality || "unknown"} priority=${entry.review_priority || "unknown"} params=${(entry.target_params || []).join(",") || "none"} related_params=${(entry.related_params || []).join(",") || "none"} link_status=${entry.link_status || "unknown"} missing=${(entry.missing_links || []).join(",") || "none"} next_hooks=${(entry.next_hooks || []).join(",") || "none"} stages=${(entry.stages || []).join(",") || "none"} apis=${(entry.runtime_apis || []).slice(0, 8).join(",") || "none"} refs=${(entry.source_refs || []).join(",") || "none"} endpoints=${(entry.endpoints || []).slice(0, 4).join(",") || "none"}`
      );
    }
    for (const window of (asset.source_windows || []).slice(0, 4)) {
      lines.push(
        `  - source_window=${window.focus || "unknown"} lines=${window.line_start ?? "none"}-${window.line_end ?? "none"} params=${(window.target_params || []).join(",") || "none"} preview=${window.preview || "none"}`
      );
    }
  }
  if (!(pack.core_assets || []).length) {
    lines.push("- none");
  }
  lines.push("", "## Review Entries", "");
  for (const entry of (pack.review_entries || []).slice(0, 8)) {
    lines.push(
      `- ${entry.id || "review_entry"} candidate=${entry.source_candidate_id || "none"} causality=${entry.causality || "unknown"} priority=${entry.review_priority || "low"} function=${entry.function || "(anonymous)"} path=${entry.content_path || "none"} params=${(entry.target_params || []).join(",") || "none"} paths=${generationPathsSummary(entry.generation_paths)} next=${(entry.next_questions || []).slice(0, 6).join(",") || "none"}`
    );
  }
  if (!(pack.review_entries || []).length) {
    lines.push("- none");
  }
  lines.push("");
  return lines.join("\n");
}

function parameterConclusion(parameter) {
  if (parameter.status === "attachment_observed") return "attachment_observed_with_runtime_chain";
  if (parameter.status === "signed_request_observed") return "signed_request_observed_without_attachment";
  return "candidate_needs_more_evidence";
}

function parameterEvidenceLevel(parameter) {
  const stages = new Set((parameter.generation_trace || []).map((step) => step.stage));
  if (parameter.status === "attachment_observed" && stages.has("input_url") && stages.has("signed_request")) {
    return "high";
  }
  if (parameter.status === "signed_request_observed" || (parameter.source_refs || []).length) {
    return "medium";
  }
  return "low";
}

function recommendedActionsForParameter(parameter) {
  const actions = [];
  if ((parameter.source_refs || []).length) actions.push("review_source_refs");
  for (const gap of parameter.evidence_gaps || []) {
    if (gap === "material_source_not_observed") actions.push("capture_text_buffer_or_storage_material");
    else if (gap === "signature_mutation_not_observed") actions.push("capture_url_search_params_mutation_or_header_set");
    else if (gap === "unsigned_input_not_observed") actions.push("capture_unsigned_request_construction");
    else if (gap === "source_context_not_available") actions.push("capture_or_retrieve_script_asset");
    else if (gap === "data_links_not_observed") actions.push("capture_object_ids_for_data_links");
    else actions.push(`resolve_${gap}`);
  }
  if (!actions.length) actions.push("review_agent_pack");
  return uniqueLimited(actions, 8);
}

function sourceEvidenceForParameter(parameter, sourceRefIndex, tracePath = "") {
  const lookup = buildSourceEvidenceLookup(sourceRefIndex);
  return uniqueLimited(parameter.source_refs || [], 12)
    .map((ref) => sourceEvidenceForRef(ref, lookup, tracePath));
}

function buildSourceEvidenceLookup(sourceRefIndex) {
  const byRef = new Map();
  const byAsset = new Map();
  for (const entry of sourceRefIndex || []) {
    if (!entry?.ref) continue;
    byRef.set(entry.ref, entry);
    if (!entry.asset_id || byAsset.has(entry.asset_id)) continue;
    if (!entry.content_path && !(entry.source_candidate_ids || []).length && !(entry.review_entry_ids || []).length) continue;
    byAsset.set(entry.asset_id, entry);
  }
  return {byRef, byAsset};
}

function sourceEvidenceForRef(ref, lookup, tracePath = "") {
  const parsed = parseSourceRef(ref);
  const source = lookup.byRef.get(ref) || {};
  const fallback = (!source.content_path ||
    !(source.source_candidate_ids || []).length ||
    !(source.review_entry_ids || []).length)
    ? lookup.byAsset.get(source.asset_id || parsed.asset_id)
    : null;
  const contentPath = source.content_path || fallback?.content_path || "";
  const preview = compactAgentSourcePreview(source.preview || fallback?.preview || "") ||
    sourcePreviewFromContentPath(ref, contentPath, tracePath);
  const signals = uniqueLimited([
    ...(source.signals || []),
    ...(fallback?.signals || [])
  ], 16);
  const calls = uniqueLimited([
    ...(source.calls || []),
    ...(fallback?.calls || [])
  ], 16);
  const operators = uniqueLimited([
    ...(source.operators || []),
    ...(fallback?.operators || [])
  ], 16);
  const numericLiterals = uniqueLimited([
    ...(source.numeric_literals || []),
    ...(fallback?.numeric_literals || [])
  ], 16);
  return {
    ref,
    asset_id: source.asset_id || fallback?.asset_id || parsed.asset_id || "",
    ...(source.url || fallback?.url ? {url: source.url || fallback?.url} : {}),
    content_path: contentPath,
    line_start: source.line_start ?? parsed.line_start ?? fallback?.line_start ?? null,
    line_end: source.line_end ?? parsed.line_end ?? fallback?.line_end ?? null,
    ...(preview ? {preview} : {}),
    source_candidate_ids: uniqueLimited([
      ...(source.source_candidate_ids || []),
      ...(fallback?.source_candidate_ids || [])
    ], 8),
    review_entry_ids: uniqueLimited([
      ...(source.review_entry_ids || []),
      ...(fallback?.review_entry_ids || [])
    ], 8),
    ...(signals.length ? {signals} : {}),
    ...(calls.length ? {calls} : {}),
    ...(operators.length ? {operators} : {}),
    ...(numericLiterals.length ? {numeric_literals: numericLiterals} : {})
  };
}

function sourceEvidenceForRefs(sourceRefs, sourceRefIndex, tracePath = "") {
  const lookup = buildSourceEvidenceLookup(sourceRefIndex);
  return uniqueLimited(sourceRefs || [], 8)
    .map((ref) => sourceEvidenceForRef(ref, lookup, tracePath));
}

function candidateBufferRefRank(ref) {
  const value = String(ref || "");
  if (value.startsWith("array_buffer:")) return 0;
  if (value.startsWith("typed_array:")) return 1;
  if (value.startsWith("data_view:")) return 2;
  if (/(?:^|:)buffer/.test(value)) return 3;
  return 10;
}

function generationPathObjectRefRank(ref) {
  const value = String(ref || "");
  if (value.startsWith("state_object:")) return 0;
  if (value.startsWith("target:")) return 1;
  if (value.startsWith("arguments_list:")) return 2;
  if (value.startsWith("subject:")) return 3;
  if (value.startsWith("this:")) return 4;
  if (value.startsWith("url_object:")) return 10;
  if (value.startsWith("search_params:")) return 11;
  if (/^(?:typed_array|array_buffer|data_view):/.test(value)) return 12;
  if (value.startsWith("network_request:")) return 13;
  return 50;
}

function generationPathValueRefRank(ref) {
  const value = String(ref || "");
  if (value.startsWith("register:")) return 0;
  if (value.startsWith("handler_return:")) return 1;
  if (value.startsWith("handler_arg:")) return 1.5;
  if (value.startsWith("number:")) return 2;
  if (value.startsWith("url_shape:")) return 10;
  if (value.startsWith("target_params:")) return 11;
  if (/(?:^|:)buffer/.test(value)) return 12;
  return 50;
}

function compactGenerationValueRefs(values, limit, options = {}) {
  const prioritized = uniquePrioritizedLimited(values || [], Number.MAX_SAFE_INTEGER, generationPathValueRefRank);
  if (options.preserveStringRuntimeRefs && prioritized.length > limit) {
    const stringRefs = prioritized
      .filter((ref) => /^(?:string_ref|url_encoded_ref|base64_ref):/.test(String(ref || "")))
      .slice(0, Math.min(3, Math.max(1, Math.floor(limit / 2))));
    if (stringRefs.length) {
      const stringRefSet = new Set(stringRefs);
      const primary = prioritized
        .filter((ref) => !stringRefSet.has(ref))
        .slice(0, Math.max(0, limit - stringRefs.length));
      return uniqueLimited([...primary, ...stringRefs], limit);
    }
  }

  if (!options.preserveVmpStateRefs || prioritized.length <= limit) return prioritized.slice(0, limit);

  const handlerReturnLimit = Math.min(4, Math.max(1, Math.floor(limit / 6)));
  const handlerArgLimit = Math.min(2, Math.max(0, Math.floor(limit / 12)));
  const preserved = uniqueLimited([
    ...prioritized.filter((ref) => String(ref).startsWith("handler_return:")).slice(0, handlerReturnLimit),
    ...prioritized.filter((ref) => String(ref).startsWith("handler_arg:")).slice(0, handlerArgLimit)
  ], limit);
  if (!preserved.length) return prioritized.slice(0, limit);

  const preservedSet = new Set(preserved);
  const primary = prioritized
    .filter((ref) => !preservedSet.has(ref))
    .slice(0, Math.max(0, limit - preserved.length));
  return uniqueLimited([...primary, ...preserved], limit);
}

function shouldPreserveStringRuntimeRefsForStage(stage) {
  return [
    "input_url",
    "signature_mutation",
    "url_encoding",
    "request_construction",
    "signed_request"
  ].includes(stage || "");
}

function candidateSummaryKeyRefs(parameter) {
  const objectRefs = uniqueLimited((parameter.generation_path || [])
    .flatMap((step) => step.object_refs || []), 64);
  const valueRefs = uniqueLimited((parameter.generation_path || [])
    .flatMap((step) => step.value_refs || []), 64);
  return {
    url_objects: uniqueLimited(objectRefs.filter((ref) => String(ref).startsWith("url_object:")), 8),
    search_params: uniqueLimited(objectRefs.filter((ref) => String(ref).startsWith("search_params:")), 8),
    buffers: uniquePrioritizedLimited([
      ...objectRefs.filter((ref) => /^(?:array_buffer|typed_array|data_view):/.test(String(ref))),
      ...valueRefs.filter((ref) => /(?:^|:)buffer/.test(String(ref)))
    ], 8, candidateBufferRefRank),
    network_requests: uniqueLimited(objectRefs.filter((ref) => String(ref).startsWith("network_request:")), 8),
    target_params: sortParamNames(valueRefs
      .filter((ref) => String(ref).startsWith("target_params:"))
      .flatMap((ref) => String(ref).slice("target_params:".length).split("|"))
      .filter(Boolean)),
    url_shapes: uniqueLimited(valueRefs.filter((ref) => String(ref).startsWith("url_shape:")), 8)
  };
}

function candidateSummarySourceWindows(parameter) {
  const byRef = new Map();
  function add(source, stages = []) {
    if (!source?.ref || byRef.has(source.ref)) return;
    byRef.set(source.ref, {
      ref: source.ref,
      asset_id: source.asset_id || "",
      url: source.url || "",
      content_path: source.content_path || "",
      line_start: source.line_start ?? null,
      line_end: source.line_end ?? null,
      ...(source.preview ? {preview: source.preview} : {}),
      source_candidate_ids: uniqueLimited(source.source_candidate_ids || [], 8),
      review_entry_ids: uniqueLimited(source.review_entry_ids || [], 8),
      calls: uniqueLimited(source.calls || [], 8),
      signals: uniqueLimited(source.signals || [], 8),
      operators: uniqueLimited(source.operators || [], 8),
      numeric_literals: uniqueLimited(source.numeric_literals || [], 8),
      stages: uniqueLimited(stages, 8)
    });
  }
  for (const source of parameter.source_evidence || []) {
    add(source, parameter.confirmed_stages || []);
  }
  for (const step of parameter.generation_path || []) {
    for (const source of step.source_evidence || []) {
      add(source, [step.stage].filter(Boolean));
    }
  }
  return [...byRef.values()].slice(0, 8);
}

function candidateSummarySourceWindowRole(window) {
  if (isCoreSignatureAsset({
    asset_id: window?.asset_id || "",
    stack_url: window?.url || "",
    content_path: window?.content_path || ""
  })) {
    return "security_sdk_signature_generator";
  }
  const haystack = [
    window?.url || "",
    window?.content_path || "",
    window?.ref || ""
  ].join(" ").toLowerCase();
  if (/(?:^|[/_.-])(?:loader|runtime|bundler)(?:$|[/_.-])/.test(haystack) ||
      haystack.includes("privacy_protection_framework")) {
    return "loader_or_wrapper";
  }
  return "source_context";
}

function candidateSummarySourceWindowRank(window, index = 0) {
  const role = candidateSummarySourceWindowRole(window);
  if (role === "security_sdk_signature_generator") return index / 1000;
  if (role === "source_context") return 10 + index / 1000;
  if (role === "loader_or_wrapper") return 20 + index / 1000;
  return 30 + index / 1000;
}

function candidateSummaryHookSourceWindow(window) {
  const sourceRole = candidateSummarySourceWindowRole(window);
  return {
    ref: window.ref || "",
    asset_id: window.asset_id || "",
    url: window.url || "",
    source_role: sourceRole,
    content_path: window.content_path || "",
    line_start: window.line_start ?? null,
    line_end: window.line_end ?? null,
    ...(window.preview ? {preview: window.preview} : {}),
    source_candidate_ids: uniqueLimited(window.source_candidate_ids || [], 8),
    review_entry_ids: uniqueLimited(window.review_entry_ids || [], 8),
    calls: uniqueLimited(window.calls || [], 8),
    signals: uniqueLimited(window.signals || [], 8),
    operators: uniqueLimited(window.operators || [], 8),
    numeric_literals: uniqueLimited(window.numeric_literals || [], 8),
    stages: uniqueLimited(window.stages || [], 8)
  };
}

function candidateSummaryVmpHookRefSummary(parameter, agentSummary) {
  const windows = candidateSummarySourceWindows(parameter);
  const windowByRef = new Map(windows.map((window) => [window.ref, window]));
  return (agentSummary.vmp_hook_ref_summary || [])
    .slice(0, VMP_HOOK_POINT_SPECS.length)
    .map((hook) => ({
      ...hook,
      source_windows: uniqueLimited(hook.source_refs || [], 4)
        .map((ref, index) => ({window: windowByRef.get(ref), index}))
        .filter((item) => item.window)
        .sort((left, right) =>
          candidateSummarySourceWindowRank(left.window, left.index) -
          candidateSummarySourceWindowRank(right.window, right.index))
        .map((item) => item.window)
        .filter(Boolean)
        .map(candidateSummaryHookSourceWindow)
    }));
}

function candidateSummaryAttachment(parameter) {
  const param = parameter.param || "";
  const step = (parameter.generation_path || []).find((candidate) =>
    candidate.stage === "signature_mutation" &&
    (!param || (candidate.target_params || []).includes(param))) ||
    (parameter.generation_path || []).find((candidate) =>
      candidate.param_relation === "direct_observed" &&
      (!param || (candidate.target_params || []).includes(param))) ||
    null;
  if (!step) {
    return {
      observed: false,
      stage: "",
      apis: [],
      target_params: [],
      object_refs: [],
      value_refs: [],
      source_refs: []
    };
  }
  const directRuntimeApiObserved = Boolean((step.apis || []).length);
  const attachmentTargetParams = sortParamNames(step.target_params || []);
  const attachmentTargetRefs = (step.value_refs || [])
    .filter((ref) => String(ref).startsWith("target_params:"));
  const signedRequestStep = (parameter.generation_path || []).find((candidate) => {
    if (candidate.stage !== "signed_request") return false;
    const sharedParams = intersectRefs(attachmentTargetParams, candidate.target_params || []);
    const signedTargetRefs = (candidate.value_refs || [])
      .filter((ref) => String(ref).startsWith("target_params:"));
    const sharedTargetRefs = intersectRefs(attachmentTargetRefs, signedTargetRefs);
    return Boolean(
      sharedParams.length ||
      sharedTargetRefs.length ||
      (param && (candidate.target_params || []).includes(param)) ||
      (param && signedTargetRefs.some((ref) => String(ref).includes(param)))
    );
  }) || null;
  const requestAnchorObserved = Boolean(signedRequestStep);
  const evidenceMode = directRuntimeApiObserved
    ? "direct_runtime_api"
    : requestAnchorObserved
      ? "request_anchor_fallback"
      : "source_data_ref_only";
  return {
    observed: true,
    stage: step.stage || "unknown",
    apis: uniqueLimited(step.apis || [], 8),
    target_params: attachmentTargetParams,
    object_refs: uniqueLimited(step.object_refs || [], 8),
    value_refs: uniqueLimited(step.value_refs || [], 8),
    source_refs: generationStepSourceRefs(step),
    evidence_mode: evidenceMode,
    direct_runtime_api_observed: directRuntimeApiObserved,
    request_anchor_observed: requestAnchorObserved,
    fallback_stage: requestAnchorObserved && !directRuntimeApiObserved ? "signed_request" : "",
    request_anchor_apis: requestAnchorObserved ? uniqueLimited(signedRequestStep.apis || [], 8) : [],
    request_anchor_refs: requestAnchorObserved
      ? uniqueLimited([
        ...(signedRequestStep.object_refs || []),
        ...(signedRequestStep.value_refs || [])
      ], 8)
      : [],
    missing_runtime_hooks: directRuntimeApiObserved
      ? []
      : captureFocusHookTargets("capture_url_search_params_mutation_or_header_set", ["signature_mutation"])
  };
}

function isCaptureOrProbeAction(action) {
  return /^(?:capture_|expand_|prefer_)/.test(String(action || ""));
}

function candidateSummaryUnresolvedGaps(parameter) {
  return uniqueLimited([
    ...(parameter.unresolved_gaps || []),
    ...(parameter.generation_edge_gaps || []).map((gap) => gap.gap).filter(Boolean),
    ...(parameter.generation_graph?.dataflow_summary?.gaps || []),
    ...(parameter.analysis_readiness?.checklist || []).flatMap((item) => item.gaps || [])
  ], 12);
}

function candidateSummaryNextActions(parameter) {
  const attachment = candidateSummaryAttachment(parameter);
  const attachmentCaptureAction = attachment.evidence_mode === "request_anchor_fallback" &&
      attachment.request_anchor_observed &&
      !attachment.direct_runtime_api_observed &&
      (attachment.missing_runtime_hooks || []).length
    ? "capture_url_search_params_mutation_or_header_set"
    : "";
  const actions = uniqueLimited([
    parameter.analysis_readiness?.summary?.primary_next_action,
    parameter.analysis_readiness?.next_probe_plan?.action,
    ...(parameter.generation_graph?.dataflow_summary?.next_actions || []),
    ...(parameter.generation_edge_gaps || []).flatMap((gap) => gap.next_actions || []),
    ...(parameter.recommended_next_actions || []),
    attachmentCaptureAction
  ].filter(Boolean), 16);
  const captureActions = actions.filter(isCaptureOrProbeAction);
  return uniqueLimited(captureActions.length ? captureActions : actions, 12);
}

function candidateSummaryGenerationSteps(parameter) {
  return (parameter.generation_path || [])
    .slice(0, 16)
    .map((step) => ({
      order: step.order ?? null,
      stage: step.stage || "unknown",
      apis: uniqueLimited(step.apis || [], 8),
      source_calls: uniqueLimited(step.source_calls || [], 8),
      source_signals: uniqueLimited(step.source_signals || [], 8),
      source_operators: uniqueLimited(step.source_operators || [], 8),
      source_constants: uniqueLimited(step.source_constants || [], 8),
      target_params: sortParamNames(step.target_params || []),
      param_relation: step.param_relation || "unknown",
      relation: step.relation || "unknown",
      distance_to_signed_request: step.distance_to_signed_request ?? null,
      object_refs: uniqueLimited(step.object_refs || [], 8),
      value_refs: uniqueLimited(step.value_refs || [], 8),
      source_refs: generationStepSourceRefs(step),
      runtime_event_refs: compactRuntimeEventRefs(step.runtime_event_refs || [], 8),
      evidence_flags: uniqueLimited(step.evidence_flags || [], 8),
      evidence_gaps: uniqueLimited(step.evidence_gaps || [], 8)
    }));
}

const CANDIDATE_LOGIC_PHASE_DEFS = [
  {
    id: "input_material",
    label: "input material",
    stages: ["input_url", "request_headers", "request_body", "json_serialization", "byte_buffer", "text_or_string_decode"]
  },
  {
    id: "vmp_execution",
    label: "VMP dispatch and handler execution",
    stages: ["dynamic_dispatch", "array_table", "collection_table", "proxy_trap"]
  },
  {
    id: "mixing_or_hash",
    label: "integer mixing or digest",
    stages: ["integer_mixing", "hash_or_digest"]
  },
  {
    id: "signature_attachment",
    label: "signature attachment and request send",
    stages: ["url_encoding", "signature_mutation", "request_construction", "signed_request"]
  }
];

function candidateLogicPhaseIdForStage(stage) {
  for (const definition of CANDIDATE_LOGIC_PHASE_DEFS) {
    if ((definition.stages || []).includes(stage)) return definition.id;
  }
  return "";
}

function candidateLogicPhaseStatus(phaseSteps, evidence) {
  if (!(phaseSteps || []).length) return "missing";
  if ((evidence || []).length) return "observed";
  return "partial";
}

function candidateLogicPhaseConfidence(status, phaseSteps) {
  if (status === "missing") return "none";
  const gaps = uniqueLimited((phaseSteps || []).flatMap((step) => step.evidence_gaps || []), 16);
  if (!gaps.length) return "high";
  if ((phaseSteps || []).some((step) =>
    (step.apis || []).length ||
    (step.source_calls || []).length ||
    (step.source_signals || []).length ||
    (step.object_refs || []).length ||
    (step.value_refs || []).length)) {
    return "medium";
  }
  return "low";
}

function candidateLogicPhaseEvidence({
  runtimeApis,
  sourceCalls,
  sourceSignals,
  sourceOperators,
  sourceConstants,
  targetParams
}) {
  return uniqueLimited([
    ...runtimeApis.map((api) => `runtime_api:${api}`),
    ...sourceCalls.map((call) => `source_call:${call}`),
    ...sourceSignals.map((signal) => `source_signal:${signal}`),
    ...sourceOperators.map((operator) => `source_operator:${operator}`),
    ...sourceConstants.map((constant) => `source_constant:${constant}`),
    ...targetParams.map((param) => `target_param:${param}`)
  ], 24);
}

function buildCandidateLogicPhase(definition, generationSteps) {
  const stageSet = new Set(definition.stages || []);
  const phaseSteps = (generationSteps || []).filter((step) => stageSet.has(step.stage));
  const runtimeApis = uniqueLimited(phaseSteps.flatMap((step) => step.apis || []), 12);
  const sourceCalls = uniqueLimited(phaseSteps.flatMap((step) => step.source_calls || []), 12);
  const sourceSignals = uniqueLimited(phaseSteps.flatMap((step) => step.source_signals || []), 12);
  const sourceOperators = uniqueLimited(phaseSteps.flatMap((step) => step.source_operators || []), 12);
  const sourceConstants = uniqueLimited(phaseSteps.flatMap((step) => step.source_constants || []), 12);
  const targetParams = sortParamNames(uniqueLimited(phaseSteps.flatMap((step) => step.target_params || []), 12));
  const evidenceGaps = uniqueLimited(phaseSteps.flatMap((step) => step.evidence_gaps || []), 12);
  const runtimeEvents = compactRuntimeEventRefs(phaseSteps.flatMap((step) => step.runtime_event_refs || []), 16)
    .map((event) => ({
      ...event,
      stage: (phaseSteps.find((step) =>
        (step.runtime_event_refs || []).some((candidate) => candidate.event_ref === event.event_ref)) || {}).stage || ""
    }));
  const evidence = candidateLogicPhaseEvidence({
    runtimeApis,
    sourceCalls,
    sourceSignals,
    sourceOperators,
    sourceConstants,
    targetParams
  });
  const status = candidateLogicPhaseStatus(phaseSteps, evidence);
  return {
    id: definition.id,
    label: definition.label,
    status,
    confidence: candidateLogicPhaseConfidence(status, phaseSteps),
    stages: uniqueLimited(phaseSteps.map((step) => step.stage || "").filter(Boolean), 8),
    runtime_apis: runtimeApis,
    source_calls: sourceCalls,
    source_signals: sourceSignals,
    source_operators: sourceOperators,
    source_constants: sourceConstants,
    target_params: targetParams,
    source_refs: uniqueLimited(phaseSteps.flatMap((step) => step.source_refs || []), 12),
    object_refs: uniqueLimited(phaseSteps.flatMap((step) => step.object_refs || []), 12),
    value_refs: uniqueLimited(phaseSteps.flatMap((step) => step.value_refs || []), 12),
    runtime_events: runtimeEvents,
    evidence,
    evidence_gaps: evidenceGaps
  };
}

function candidateLogicRequestInputFocus(summary) {
  return (summary?.categories || [])
    .slice(0, 8)
    .map((category) => ({
      category: category.category || "unknown",
      target_params: sortParamNames(category.target_params || []),
      evidence_refs: uniqueLimited(category.evidence_refs || [], 8),
      value_refs: uniqueLimited(category.value_refs || [], 8),
      ...(category.query_keys?.length ? {query_keys: sortParamNames(category.query_keys)} : {}),
      ...(category.header_names?.length ? {header_names: uniqueLimited(category.header_names, 16).sort()} : {}),
      ...(category.names?.length ? {names: uniqueLimited(category.names, 16).sort()} : {}),
      ...(category.keys?.length ? {keys: uniqueLimited(category.keys, 16).sort()} : {}),
      ...(category.scopes?.length ? {scopes: uniqueLimited(category.scopes, 8).sort()} : {}),
      ...(Number.isFinite(category.body_size) ? {body_size: category.body_size} : {})
    }));
}

function enrichCandidateLogicInputPhase(phase, requestInputSummary) {
  if (phase?.id !== "input_material") return phase;
  const requestInputs = candidateLogicRequestInputFocus(requestInputSummary);
  if (!requestInputs.length) return phase;
  const evidence = uniqueLimited([
    ...(phase.evidence || []),
    ...requestInputs.map((input) => `request_input:${input.category}`),
    ...(requestInputSummary?.evidence_refs || []).map((ref) => `request_input_ref:${ref}`)
  ], 32);
  const targetParams = sortParamNames(uniqueLimited([
    ...(phase.target_params || []),
    ...(requestInputSummary?.target_params || [])
  ], 16));
  return {
    ...phase,
    status: "observed",
    confidence: phase.confidence === "high" ? "high" : "medium",
    target_params: targetParams,
    value_refs: uniqueLimited([
      ...(phase.value_refs || []),
      ...requestInputs.flatMap((input) => input.value_refs || [])
    ], 16),
    evidence,
    request_inputs: requestInputs
  };
}

function candidateLogicWebCryptoEvidence(summary) {
  if (!summary?.observed) return [];
  const operationApis = uniqueLimited([
    ...(summary.apis || []),
    ...(summary.operations || []).map((operation) => operation.api || "")
  ], 12);
  return uniqueLimited([
    ...operationApis.map((api) => `webcrypto_operation:${api}`),
    ...(summary.operation_refs || []).map((ref) => `webcrypto_operation_ref:${ref}`),
    ...(summary.key_refs || []).map((ref) => `webcrypto_key_ref:${ref}`),
    ...(summary.key_material_refs || []).map((ref) => `webcrypto_key_material_ref:${ref}`),
    ...(summary.input_refs || []).map((ref) => `webcrypto_input_ref:${ref}`),
    ...(summary.result_refs || []).map((ref) => `webcrypto_result_ref:${ref}`),
    ...(summary.input_array_buffer_refs || []).map((ref) => `webcrypto_input_array_buffer_ref:${ref}`),
    ...(summary.result_array_buffer_refs || []).map((ref) => `webcrypto_result_array_buffer_ref:${ref}`)
  ], 48);
}

function candidateLogicWebCryptoOperationRole(operation) {
  const api = operation?.api || "";
  if (api === "SubtleCrypto.importKey") {
    if (operation.key_material_ref) return "key_material_input";
    if (operation.key_ref) return "key_handle_output";
    return operation.phase === "return" ? "key_handle_output" : "key_material_input";
  }
  if (api === "SubtleCrypto.sign") {
    if (operation.result_ref || operation.result_array_buffer_ref) return "signature_output";
    if (operation.input_ref || operation.key_ref || operation.input_array_buffer_ref) return "signature_input";
    return operation.phase === "return" ? "signature_output" : "signature_input";
  }
  if (api === "SubtleCrypto.digest") {
    if (operation.result_ref || operation.result_array_buffer_ref) return "digest_output";
    if (operation.input_ref || operation.input_array_buffer_ref) return "digest_input";
    return operation.phase === "return" ? "digest_output" : "digest_input";
  }
  return operation?.phase === "return" ? "crypto_output" : "crypto_input";
}

function candidateLogicWebCryptoOperations(summary) {
  if (!summary?.observed) return [];
  return (summary.operations || [])
    .slice(0, 12)
    .map((operation) => ({
      api: operation.api || "",
      phase: operation.phase || "",
      seq: operation.seq ?? null,
      operation_ref: operation.operation_ref || "",
      algorithm: operation.algorithm || "",
      role: candidateLogicWebCryptoOperationRole(operation),
      ...(operation.key_ref ? {key_ref: operation.key_ref} : {}),
      ...(operation.key_material_ref ? {key_material_ref: operation.key_material_ref} : {}),
      ...(operation.input_ref ? {input_ref: operation.input_ref} : {}),
      ...(operation.result_ref ? {result_ref: operation.result_ref} : {}),
      ...(operation.input_array_buffer_ref ? {input_array_buffer_ref: operation.input_array_buffer_ref} : {}),
      ...(operation.result_array_buffer_ref ? {result_array_buffer_ref: operation.result_array_buffer_ref} : {}),
      ...(operation.event_ref ? {event_ref: operation.event_ref} : {})
    }));
}

function enrichCandidateLogicWebCryptoPhase(phase, webcryptoSignatureSummary) {
  if (phase?.id !== "mixing_or_hash" || !webcryptoSignatureSummary?.observed) return phase;
  const evidence = uniqueLimited([
    ...(phase.evidence || []),
    ...candidateLogicWebCryptoEvidence(webcryptoSignatureSummary)
  ], 64);
  return {
    ...phase,
    status: "observed",
    confidence: phase.confidence === "high" ? "high" : "medium",
    stages: uniqueLimited([
      ...(phase.stages || []),
      "hash_or_digest"
    ], 8),
    runtime_apis: uniqueLimited([
      ...(phase.runtime_apis || []),
      ...(webcryptoSignatureSummary.apis || [])
    ], 16),
    object_refs: uniqueLimited([
      ...(phase.object_refs || []),
      ...(webcryptoSignatureSummary.operation_refs || []),
      ...(webcryptoSignatureSummary.input_array_buffer_refs || []),
      ...(webcryptoSignatureSummary.result_array_buffer_refs || [])
    ], 24),
    value_refs: uniqueLimited([
      ...(phase.value_refs || []),
      ...(webcryptoSignatureSummary.key_refs || []),
      ...(webcryptoSignatureSummary.key_material_refs || []),
      ...(webcryptoSignatureSummary.input_refs || []),
      ...(webcryptoSignatureSummary.result_refs || [])
    ], 24),
    runtime_events: compactRuntimeEventRefs([
      ...(phase.runtime_events || []),
      ...(webcryptoSignatureSummary.runtime_event_refs || [])
    ], 24),
    webcrypto_operations: candidateLogicWebCryptoOperations(webcryptoSignatureSummary),
    evidence
  };
}

function enrichCandidateLogicDirectWebCryptoPhase(phase, webcryptoSignatureSummary) {
  if (phase?.id !== "vmp_execution" || !webcryptoSignatureSummary?.observed) return phase;
  if ((phase.stages || []).length || (phase.evidence || []).length) return phase;
  return {
    ...phase,
    status: "not_applicable",
    confidence: "not_applicable",
    evidence: uniqueLimited([
      "direct_webcrypto_operation_path",
      ...candidateLogicWebCryptoEvidence(webcryptoSignatureSummary)
    ], 24),
    evidence_gaps: []
  };
}

function webCryptoOperationRefsForApi(summary, api) {
  return uniqueLimited((summary?.operations || [])
    .filter((operation) => operation.api === api)
    .map((operation) => operation.operation_ref || ""), 8);
}

function enrichCandidateLogicPhaseEdgeWithWebCrypto(edge, webcryptoSignatureSummary) {
  if (!webcryptoSignatureSummary?.observed) return edge;
  const signOperationRefs = webCryptoOperationRefsForApi(webcryptoSignatureSummary, "SubtleCrypto.sign");
  const importKeyOperationRefs = webCryptoOperationRefsForApi(webcryptoSignatureSummary, "SubtleCrypto.importKey");
  const digestOperationRefs = webCryptoOperationRefsForApi(webcryptoSignatureSummary, "SubtleCrypto.digest");
  let refs = [];
  let evidence = [];
  if (edge?.from_phase === "input_material" && edge?.to_phase === "mixing_or_hash") {
    refs = [
      ...(webcryptoSignatureSummary.input_refs || []),
      ...(webcryptoSignatureSummary.key_material_refs || []),
      ...(webcryptoSignatureSummary.input_array_buffer_refs || []),
      ...importKeyOperationRefs,
      ...digestOperationRefs,
      ...signOperationRefs
    ];
    evidence = [
      ...(webcryptoSignatureSummary.input_refs || []).map((ref) => `webcrypto_input_ref:${ref}`),
      ...(webcryptoSignatureSummary.key_material_refs || []).map((ref) => `webcrypto_key_material_ref:${ref}`),
      ...(webcryptoSignatureSummary.input_array_buffer_refs || []).map((ref) => `webcrypto_input_array_buffer_ref:${ref}`),
      ...importKeyOperationRefs.map((ref) => `webcrypto_operation_ref:${ref}`),
      ...digestOperationRefs.map((ref) => `webcrypto_operation_ref:${ref}`),
      ...signOperationRefs.map((ref) => `webcrypto_operation_ref:${ref}`)
    ];
  } else if (edge?.from_phase === "mixing_or_hash" && edge?.to_phase === "signature_attachment") {
    refs = [
      ...(webcryptoSignatureSummary.result_refs || []),
      ...(webcryptoSignatureSummary.result_array_buffer_refs || []),
      ...digestOperationRefs,
      ...signOperationRefs
    ];
    evidence = [
      ...(webcryptoSignatureSummary.result_refs || []).map((ref) => `webcrypto_result_ref:${ref}`),
      ...(webcryptoSignatureSummary.result_array_buffer_refs || []).map((ref) => `webcrypto_result_array_buffer_ref:${ref}`),
      ...digestOperationRefs.map((ref) => `webcrypto_operation_ref:${ref}`),
      ...signOperationRefs.map((ref) => `webcrypto_operation_ref:${ref}`)
    ];
  }
  if (!refs.length && !evidence.length) return edge;
  return {
    ...edge,
    refs: uniqueLimited([
      ...(edge.refs || []),
      ...refs
    ], 16),
    evidence: uniqueLimited([
      ...(edge.evidence || []),
      ...evidence
    ], 16)
  };
}

function enrichCandidateLogicPhaseEdgesWithWebCrypto(phaseEdges, webcryptoSignatureSummary) {
  if (!webcryptoSignatureSummary?.observed) return phaseEdges || [];
  return (phaseEdges || []).map((edge) =>
    enrichCandidateLogicPhaseEdgeWithWebCrypto(edge, webcryptoSignatureSummary));
}

function candidateLogicStatus({phases, runtimeApis, sourceWindows, attachment}) {
  const phaseById = new Map((phases || []).map((phase) => [phase.id, phase]));
  const hasInput = phaseById.get("input_material")?.status === "observed";
  const vmpStatus = phaseById.get("vmp_execution")?.status || "missing";
  const hasVmp = vmpStatus === "observed";
  const directWebCrypto = vmpStatus === "not_applicable";
  const hasMixing = phaseById.get("mixing_or_hash")?.status === "observed";
  const hasRuntime = (runtimeApis || []).length > 0;
  const hasSource = (sourceWindows || []).length > 0 ||
    (phases || []).some((phase) =>
      (phase.source_refs || []).length ||
      (phase.source_calls || []).length ||
      (phase.source_signals || []).length);
  if (attachment?.observed && hasInput && directWebCrypto && hasMixing && hasRuntime && hasSource) {
    return "direct_webcrypto_chain_observed";
  }
  if (attachment?.observed && hasInput && directWebCrypto && hasMixing && hasRuntime) {
    return "direct_webcrypto_runtime_chain_observed";
  }
  if (attachment?.observed && hasInput && hasVmp && hasMixing && hasRuntime && hasSource) {
    return "runtime_and_source_chain_observed";
  }
  if (attachment?.observed && hasInput && hasVmp && hasMixing && hasRuntime) {
    return "runtime_chain_observed";
  }
  if (attachment?.observed) return "attachment_observed_chain_partial";
  if (hasVmp || hasMixing) return "candidate_chain_needs_attachment";
  return "needs_more_evidence";
}

function candidateLogicSourceFocus(sourceWindows) {
  return (sourceWindows || [])
    .map((window, index) => ({window, index}))
    .sort((left, right) =>
      candidateSummarySourceWindowRank(left.window, left.index) -
      candidateSummarySourceWindowRank(right.window, right.index))
    .slice(0, 6)
    .map(({window}) => ({
      ref: window.ref || "",
      role: candidateSummarySourceWindowRole(window),
      asset_id: window.asset_id || "",
      url: window.url || "",
      content_path: window.content_path || "",
      line_start: window.line_start ?? null,
      line_end: window.line_end ?? null,
      stages: uniqueLimited(window.stages || [], 8),
      calls: uniqueLimited(window.calls || [], 8),
      signals: uniqueLimited(window.signals || [], 8),
      operators: uniqueLimited(window.operators || [], 8),
      numeric_literals: uniqueLimited(window.numeric_literals || [], 8)
    }));
}

function candidateLogicEdgePairKey(item) {
  return [
    item.from_order ?? "",
    item.to_order ?? "",
    item.from_stage || "",
    item.to_stage || ""
  ].join("->");
}

function candidateLogicPhaseEdgeFromGap(gap) {
  const fromPhase = candidateLogicPhaseIdForStage(gap?.from_stage || "");
  const toPhase = candidateLogicPhaseIdForStage(gap?.to_stage || "");
  if (!fromPhase || !toPhase) return null;
  return {
    from_order: gap.from_order ?? null,
    to_order: gap.to_order ?? null,
    from_stage: gap.from_stage || "unknown",
    to_stage: gap.to_stage || "unknown",
    from_phase: fromPhase,
    to_phase: toPhase,
    scope: fromPhase === toPhase ? "intra_phase" : "cross_phase",
    relation: gap.gap || "missing_generation_edge",
    confidence: "missing",
    refs: [],
    source_refs: uniqueLimited(gap.source_refs || [], 8),
    object_refs: uniqueLimited(gap.object_refs || [], 8),
    value_refs: uniqueLimited(gap.value_refs || [], 8),
    evidence: [],
    gap: gap.gap || "missing_generation_edge",
    gap_reason: gap.reason || "",
    next_actions: uniqueLimited(gap.next_actions || [], 8)
  };
}

function candidateLogicPhaseEdgeFromGenerationEdge(edge, gap = null) {
  const fromPhase = candidateLogicPhaseIdForStage(edge?.from_stage || "");
  const toPhase = candidateLogicPhaseIdForStage(edge?.to_stage || "");
  if (!fromPhase || !toPhase) return null;
  return {
    from_order: edge.from_order ?? null,
    to_order: edge.to_order ?? null,
    from_stage: edge.from_stage || "unknown",
    to_stage: edge.to_stage || "unknown",
    from_phase: fromPhase,
    to_phase: toPhase,
    scope: fromPhase === toPhase ? "intra_phase" : "cross_phase",
    relation: edge.relation || "related",
    confidence: edge.confidence || "unknown",
    refs: uniqueLimited(edge.refs || [], 8),
    source_refs: uniqueLimited(edge.source_refs || [], 8),
    evidence: uniqueLimited(edge.evidence || [], 8),
    ...(edge.inferred_basis?.length ? {inferred_basis: uniqueLimited(edge.inferred_basis, 8)} : {}),
    ...(edge.temporal_basis?.length ? {temporal_basis: uniqueLimited(edge.temporal_basis, 8)} : {}),
    ...(edge.nearby_basis?.length ? {nearby_basis: uniqueLimited(edge.nearby_basis, 8)} : {}),
    ...(gap?.gap ? {gap: gap.gap} : {}),
    ...(gap?.reason ? {gap_reason: gap.reason} : {}),
    ...(gap?.next_actions?.length ? {next_actions: uniqueLimited(gap.next_actions, 8)} : {})
  };
}

function buildCandidateLogicPhaseEdges(generationEdges, generationEdgeGaps) {
  const gapByPair = new Map((generationEdgeGaps || [])
    .map((gap) => [candidateLogicEdgePairKey(gap), gap]));
  const seenPairs = new Set();
  const phaseEdges = [];
  for (const edge of generationEdges || []) {
    const pairKey = candidateLogicEdgePairKey(edge);
    const phaseEdge = candidateLogicPhaseEdgeFromGenerationEdge(edge, gapByPair.get(pairKey));
    if (!phaseEdge) continue;
    phaseEdges.push(phaseEdge);
    seenPairs.add(pairKey);
  }
  for (const gap of generationEdgeGaps || []) {
    const pairKey = candidateLogicEdgePairKey(gap);
    if (seenPairs.has(pairKey)) continue;
    const phaseEdge = candidateLogicPhaseEdgeFromGap(gap);
    if (phaseEdge) phaseEdges.push(phaseEdge);
  }
  return phaseEdges.slice(0, 24);
}

function candidateLogicConfidenceRank(confidence) {
  const ranks = {high: 0, medium: 1, low: 2, missing: 3, none: 4};
  return ranks[confidence] ?? 5;
}

function compareCandidateLogicEdges(left, right) {
  const confidenceDelta = candidateLogicConfidenceRank(left.confidence) -
    candidateLogicConfidenceRank(right.confidence);
  if (confidenceDelta) return confidenceDelta;
  const leftRefCount = (left.refs || []).length + (left.source_refs || []).length;
  const rightRefCount = (right.refs || []).length + (right.source_refs || []).length;
  if (leftRefCount !== rightRefCount) return rightRefCount - leftRefCount;
  return (left.from_order ?? 9999) - (right.from_order ?? 9999);
}

function candidateLogicStrongestAttachmentEdge(phaseEdges) {
  return (phaseEdges || [])
    .filter((edge) =>
      edge.to_phase === "signature_attachment" ||
      edge.from_stage === "signature_mutation" ||
      edge.to_stage === "signed_request" ||
      (edge.refs || []).some((ref) => String(ref).startsWith("target_params:")))
    .sort(compareCandidateLogicEdges)[0] || null;
}

function candidateLogicCriticalPathStatus({phases, phaseEdges, blockingGaps}) {
  const phaseStatuses = new Map((phases || []).map((phase) => [phase.id, phase.status]));
  const directWebCrypto = phaseStatuses.get("vmp_execution") === "not_applicable";
  const allPhasesObserved = CANDIDATE_LOGIC_PHASE_DEFS
    .every((definition) =>
      phaseStatuses.get(definition.id) === "observed" ||
      (directWebCrypto && definition.id === "vmp_execution"));
  const hasMissingEdges = (blockingGaps || []).some((gap) => gap.confidence === "missing" || gap.gap === "missing_generation_edge");
  const hasWeakEdges = (phaseEdges || []).some((edge) =>
    edge.confidence === "low" ||
    edge.gap === "source_only_edge" ||
    edge.gap === "temporal_only_edge" ||
    edge.gap === "nearby_runtime_only_edge");
  if (directWebCrypto && allPhasesObserved && !hasMissingEdges && !hasWeakEdges) return "direct_webcrypto_path_observed";
  if (directWebCrypto && allPhasesObserved && !hasMissingEdges) return "partial_direct_webcrypto_path";
  if (allPhasesObserved && !hasMissingEdges && !hasWeakEdges) return "strong_runtime_source_path";
  if (allPhasesObserved && !hasMissingEdges) return "partial_runtime_source_path";
  if (allPhasesObserved) return "observed_phases_missing_edges";
  return "needs_more_evidence";
}

function candidateLogicCriticalPathEvidence(phaseEdges) {
  return uniqueLimited((phaseEdges || []).map((edge) =>
    `phase_edge:${edge.from_phase || "unknown"}->${edge.to_phase || "unknown"}:${edge.relation || "unknown"}:${edge.confidence || "unknown"}`
  ), 24);
}

function candidateLogicCriticalPathEdgeSummary(phaseEdges) {
  const crossPhaseEdges = (phaseEdges || []).filter((edge) => edge.scope === "cross_phase");
  const intraPhaseEdges = (phaseEdges || []).filter((edge) => edge.scope === "intra_phase");
  return {
    total_edge_count: (phaseEdges || []).length,
    cross_phase_edge_count: crossPhaseEdges.length,
    intra_phase_edge_count: intraPhaseEdges.length,
    high_confidence_edge_count: (phaseEdges || []).filter((edge) => edge.confidence === "high").length,
    medium_confidence_edge_count: (phaseEdges || []).filter((edge) => edge.confidence === "medium").length,
    low_confidence_edge_count: (phaseEdges || []).filter((edge) => edge.confidence === "low").length,
    missing_edge_count: (phaseEdges || []).filter((edge) => edge.confidence === "missing").length
  };
}

function compactCandidateLogicEdge(edge) {
  if (!edge) return null;
  return {
    from_phase: edge.from_phase || "",
    to_phase: edge.to_phase || "",
    from_stage: edge.from_stage || "",
    to_stage: edge.to_stage || "",
    relation: edge.relation || "unknown",
    confidence: edge.confidence || "unknown",
    refs: uniqueLimited(edge.refs || [], 8),
    source_refs: uniqueLimited(edge.source_refs || [], 8),
    evidence: uniqueLimited(edge.evidence || [], 8),
    ...(edge.gap ? {gap: edge.gap} : {}),
    ...(edge.gap_reason ? {gap_reason: edge.gap_reason} : {})
  };
}

function targetParamsFromRef(ref) {
  const value = String(ref || "");
  if (!value.startsWith("target_params:")) return [];
  return sortParamNames(value.slice("target_params:".length).split("|").filter(Boolean));
}

function targetParamsFromLogicEvidence({phases, phaseEdges}) {
  return sortParamNames(uniqueLimited([
    ...(phases || []).flatMap((phase) => phase.target_params || []),
    ...(phaseEdges || []).flatMap((edge) =>
      (edge.refs || []).flatMap((ref) => targetParamsFromRef(ref)))
  ], 24));
}

function sharedTargetParamGroupsForEdges(phaseEdges, primaryParam) {
  const byRef = new Map();
  for (const edge of phaseEdges || []) {
    for (const ref of edge.refs || []) {
      const params = targetParamsFromRef(ref);
      if (params.length <= 1) continue;
      if (primaryParam && !params.includes(primaryParam)) continue;
      if (byRef.has(ref)) continue;
      byRef.set(ref, {
        ref,
        params,
        primary_param: primaryParam || "",
        related_params: primaryParam
          ? params.filter((param) => param !== primaryParam)
          : params
      });
    }
  }
  return [...byRef.values()].slice(0, 8);
}

function addRelatedParamStepEvidence(stageIndex, step, primaryParam) {
  const stepTargetParams = (step?.target_params || []).filter((param) => param && param !== primaryParam);
  for (const targetParam of stepTargetParams) {
    const current = stageIndex.get(targetParam) || {stages: [], apis: []};
    current.stages = uniqueLimited([...current.stages, step.stage || ""], 16);
    current.apis = uniqueLimited([...current.apis, ...(step.apis || [])], 16);
    stageIndex.set(targetParam, current);
  }
}

function relatedParamStageIndex(parameter) {
  const primaryParam = parameter?.param || "";
  const stageIndex = new Map();
  for (const step of parameter?.generation_path || []) {
    addRelatedParamStepEvidence(stageIndex, step, primaryParam);
  }
  for (const step of parameter?.candidate_generation_summary?.generation_steps || []) {
    addRelatedParamStepEvidence(stageIndex, step, primaryParam);
  }
  return stageIndex;
}

function mergeRelatedParamEvidenceBucket(existing, patch) {
  return {
    param: existing.param || patch.param || "",
    relation: existing.relation || patch.relation || "shared_generation_path",
    confidence: existing.confidence === "high" || patch.confidence === "high"
      ? "high"
      : existing.confidence || patch.confidence || "medium",
    shared_refs: uniqueLimited([
      ...(existing.shared_refs || []),
      ...(patch.shared_refs || [])
    ], 8),
    stages: uniqueLimited([
      ...(existing.stages || []),
      ...(patch.stages || [])
    ], 16),
    apis: uniqueLimited([
      ...(existing.apis || []),
      ...(patch.apis || [])
    ], 16),
    evidence: uniqueLimited([
      ...(existing.evidence || []),
      ...(patch.evidence || [])
    ], 8)
  };
}

function buildRelatedParamEvidence(parameter) {
  const primaryParam = parameter?.param || "";
  const criticalPath = parameter?.candidate_generation_summary?.logic_hypothesis?.critical_path || {};
  const stageIndex = relatedParamStageIndex(parameter);
  const byParam = new Map();

  for (const group of criticalPath.shared_target_param_groups || []) {
    for (const relatedParam of group.related_params || []) {
      if (!relatedParam || relatedParam === primaryParam) continue;
      const stageEvidence = stageIndex.get(relatedParam) || {};
      const existing = byParam.get(relatedParam) || {};
      byParam.set(relatedParam, mergeRelatedParamEvidenceBucket(existing, {
        param: relatedParam,
        relation: "shared_target_param_ref",
        confidence: "high",
        shared_refs: group.ref ? [group.ref] : [],
        stages: stageEvidence.stages || [],
        apis: stageEvidence.apis || [],
        evidence: ["shared_target_param_ref", "shared_generation_path"]
      }));
    }
  }

  for (const relatedParam of criticalPath.related_target_params || []) {
    if (!relatedParam || relatedParam === primaryParam) continue;
    const stageEvidence = stageIndex.get(relatedParam) || {};
    const existing = byParam.get(relatedParam) || {};
    byParam.set(relatedParam, mergeRelatedParamEvidenceBucket(existing, {
      param: relatedParam,
      relation: "shared_generation_path",
      confidence: "medium",
      shared_refs: [],
      stages: stageEvidence.stages || [],
      apis: stageEvidence.apis || [],
      evidence: ["shared_generation_path"]
    }));
  }

  const sortedParams = sortParamNames([...byParam.keys()]).slice(0, 8);
  return sortedParams.map((param) => byParam.get(param));
}

function buildCandidateLogicCriticalPath({param, phases, phaseEdges, stageChain}) {
  const blockingGaps = (phaseEdges || [])
    .filter((edge) =>
      edge.confidence === "missing" ||
      edge.gap === "missing_generation_edge" ||
      edge.gap === "source_only_edge" ||
      edge.gap === "temporal_only_edge" ||
      edge.gap === "nearby_runtime_only_edge")
    .map((edge) => ({
      from_phase: edge.from_phase || "",
      to_phase: edge.to_phase || "",
      from_stage: edge.from_stage || "",
      to_stage: edge.to_stage || "",
      gap: edge.gap || edge.relation || "weak_generation_edge",
      confidence: edge.confidence || "unknown",
      next_actions: uniqueLimited(edge.next_actions || [], 8)
    }));
  const strongestAttachmentEdge = candidateLogicStrongestAttachmentEdge(phaseEdges);
  const observedTargetParams = targetParamsFromLogicEvidence({phases, phaseEdges});
  const relatedTargetParams = param
    ? observedTargetParams.filter((targetParam) => targetParam !== param)
    : [];
  return {
    status: candidateLogicCriticalPathStatus({phases, phaseEdges, blockingGaps}),
    primary_target_param: param || "",
    observed_target_params: observedTargetParams,
    related_target_params: relatedTargetParams,
    shared_target_param_groups: sharedTargetParamGroupsForEdges(phaseEdges, param || ""),
    phase_sequence: CANDIDATE_LOGIC_PHASE_DEFS.map((definition) => definition.id),
    stage_sequence: uniqueLimited(stageChain || [], 16),
    edge_summary: candidateLogicCriticalPathEdgeSummary(phaseEdges),
    strongest_attachment_edge: compactCandidateLogicEdge(strongestAttachmentEdge),
    path_evidence: candidateLogicCriticalPathEvidence(phaseEdges),
    blocking_gaps: blockingGaps.slice(0, 12)
  };
}

function candidateLogicOpenQuestions(status, phases, dataflowGaps, nextActions) {
  const questions = [];
  if (![
    "runtime_and_source_chain_observed",
    "runtime_chain_observed",
    "direct_webcrypto_chain_observed",
    "direct_webcrypto_runtime_chain_observed"
  ].includes(status)) {
    questions.push("which_runtime_values_flow_between_observed_phases");
  }
  for (const phase of phases || []) {
    if (phase.status === "missing") questions.push(`missing_${phase.id}`);
    else if ((phase.evidence_gaps || []).length) questions.push(`resolve_${phase.id}_gaps`);
  }
  for (const gap of dataflowGaps || []) questions.push(`dataflow_${gap}`);
  if ((nextActions || []).includes("expand_vmp_runtime_hooks")) {
    questions.push("which_vmp_handler_produces_signature_material");
  }
  return uniqueLimited(questions, 12);
}

function candidateLogicSummaryText({param, status, stageChain, attachment, sourceFocus}) {
  const sourceRole = sourceFocus?.[0]?.role || "unknown_source";
  const attachmentText = attachment?.observed
    ? `attachment observed for ${(attachment.target_params || []).join(",") || param || "target_param"}`
    : "attachment not directly observed";
  return `${param || "parameter"}: ${status}; stages=${stageChain.join(" -> ") || "unknown"}; ${attachmentText}; primary_source=${sourceRole}`;
}

function candidateLogicTraceClaim(param, phase) {
  const subject = param || "target parameter";
  const status = phase?.status || "unknown";
  const label = phase?.label || phase?.id || "phase";
  const stages = (phase?.stages || []).join(" -> ") || "unknown stage";
  const requestInputs = (phase?.request_inputs || []).map((input) => input.category).filter(Boolean).join("|");
  const requestInputText = requestInputs ? `; request_inputs=${requestInputs}` : "";
  if (status === "observed") {
    return `${label} observed for ${subject} across ${stages}${requestInputText}`;
  }
  if (status === "partial") {
    return `${label} partially observed for ${subject} across ${stages}${requestInputText}`;
  }
  if (status === "not_applicable") {
    return `${label} not required for ${subject}; direct WebCrypto operation path observed`;
  }
  return `${label} missing for ${subject}${requestInputText}`;
}

function buildCandidateAgentLogicTrace({param, phases, phaseEdges, criticalPath, attachment}) {
  const phaseSequence = criticalPath?.phase_sequence?.length
    ? criticalPath.phase_sequence
    : CANDIDATE_LOGIC_PHASE_DEFS.map((definition) => definition.id);
  const phaseById = new Map((phases || []).map((phase) => [phase.id, phase]));
  const steps = phaseSequence
    .map((phaseId, index) => {
      const phase = phaseById.get(phaseId);
      if (!phase) return null;
      return {
        order: index + 1,
        phase: phase.id || phaseId,
        label: phase.label || phaseId,
        status: phase.status || "unknown",
        confidence: phase.confidence || "unknown",
        stages: uniqueLimited(phase.stages || [], 8),
        claim: candidateLogicTraceClaim(param, phase),
        runtime_apis: uniqueLimited(phase.runtime_apis || [], 8),
        source_calls: uniqueLimited(phase.source_calls || [], 8),
        source_signals: uniqueLimited(phase.source_signals || [], 8),
        source_operators: uniqueLimited(phase.source_operators || [], 8),
        source_constants: uniqueLimited(phase.source_constants || [], 8),
        target_params: sortParamNames(phase.target_params || []),
        source_refs: uniqueLimited(phase.source_refs || [], 8),
        object_refs: uniqueLimited(phase.object_refs || [], 8),
        value_refs: uniqueLimited(phase.value_refs || [], 8),
        runtime_events: compactRuntimeEventRefs(phase.runtime_events || [], 16),
        evidence: uniqueLimited(phase.evidence || [], 24),
        evidence_gaps: uniqueLimited(phase.evidence_gaps || [], 8),
        ...((phase.webcrypto_operations || []).length
          ? {webcrypto_operations: (phase.webcrypto_operations || []).slice(0, 12)}
          : {}),
        ...((phase.request_inputs || []).length
          ? {
            request_input_categories: (phase.request_inputs || []).map((input) => input.category).filter(Boolean),
            request_inputs: (phase.request_inputs || []).slice(0, 8)
          }
          : {})
      };
    })
    .filter(Boolean);
  return {
    summary: `${param || "parameter"} generation: ${phaseSequence.join(" -> ") || "unknown"}; status=${criticalPath?.status || "unknown"}`,
    status: criticalPath?.status || "unknown",
    steps,
    edges: (phaseEdges || [])
      .slice(0, 16)
      .map(compactCandidateLogicEdge)
      .filter(Boolean),
    final_attachment: {
      observed: Boolean(attachment?.observed),
      target_params: sortParamNames(attachment?.target_params || []),
      apis: uniqueLimited(attachment?.apis || [], 8),
      evidence_mode: attachment?.evidence_mode || "unknown"
    }
  };
}

function buildCandidateLogicHypothesis({
  param,
  stageChain,
  generationSteps,
  runtimeApis,
  sourceWindows,
  attachment,
  dataflowStatus,
  dataflowGaps,
  generationEdges,
  generationEdgeGaps,
  requestInputSummary,
  webcryptoSignatureSummary,
  nextActions
}) {
  const phases = CANDIDATE_LOGIC_PHASE_DEFS
    .map((definition) => {
      const inputEnriched = enrichCandidateLogicInputPhase(
        buildCandidateLogicPhase(definition, generationSteps),
        requestInputSummary
      );
      const webcryptoEnriched = enrichCandidateLogicWebCryptoPhase(inputEnriched, webcryptoSignatureSummary);
      return enrichCandidateLogicDirectWebCryptoPhase(webcryptoEnriched, webcryptoSignatureSummary);
    });
  const sourceFocus = candidateLogicSourceFocus(sourceWindows);
  const phaseEdges = enrichCandidateLogicPhaseEdgesWithWebCrypto(
    buildCandidateLogicPhaseEdges(generationEdges, generationEdgeGaps),
    webcryptoSignatureSummary
  );
  const criticalPath = buildCandidateLogicCriticalPath({param, phases, phaseEdges, stageChain});
  const status = candidateLogicStatus({phases, runtimeApis, sourceWindows, attachment});
  return {
    status,
    summary: candidateLogicSummaryText({param, status, stageChain, attachment, sourceFocus}),
    ordered_stage_chain: uniqueLimited(stageChain || [], 16),
    dataflow_status: dataflowStatus || "unknown",
    phases,
    phase_edges: phaseEdges,
    critical_path: criticalPath,
    agent_logic_trace: buildCandidateAgentLogicTrace({param, phases, phaseEdges, criticalPath, attachment}),
    final_attachment: {
      observed: Boolean(attachment?.observed),
      stage: attachment?.stage || "",
      apis: uniqueLimited(attachment?.apis || [], 8),
      target_params: sortParamNames(attachment?.target_params || []),
      object_refs: uniqueLimited(attachment?.object_refs || [], 8),
      value_refs: uniqueLimited(attachment?.value_refs || [], 8),
      source_refs: uniqueLimited(attachment?.source_refs || [], 8)
    },
    source_focus: sourceFocus,
    open_questions: candidateLogicOpenQuestions(status, phases, dataflowGaps, nextActions),
    next_actions: uniqueLimited(nextActions || [], 12)
  };
}

function completenessEntry(item, status, evidence = [], missing = [], nextCaptureHooks = []) {
  return {
    item,
    status,
    evidence: uniqueLimited(evidence.filter(Boolean), 12),
    missing: uniqueLimited(missing.filter(Boolean), 8),
    next_capture_hooks: uniqueLimited(nextCaptureHooks.filter(Boolean), 8)
  };
}

function candidateStepsForStages(generationSteps, stages) {
  const stageSet = new Set(stages || []);
  return (generationSteps || []).filter((step) => stageSet.has(step.stage));
}

function evidenceForRuntimeSteps(steps) {
  return uniqueLimited((steps || []).flatMap((step) => [
    ...(step.apis || []).map((api) => `runtime_api:${api}`),
    ...(step.object_refs || []).map((ref) => `object_ref:${ref}`),
    ...(step.value_refs || []).map((ref) => `value_ref:${ref}`)
  ]), 12);
}

function evidenceForSourceOnlyStep(step) {
  if (!step) return [];
  const sourceCall = (step.source_calls || [])[0];
  const sourceSignal = (step.source_signals || [])
    .find((signal) => signal === "dynamic_dispatch") ||
    (step.source_signals || [])[0];
  return uniqueLimited([
    sourceCall ? `source_call:${sourceCall}` : "",
    sourceSignal ? `source_signal:${sourceSignal}` : ""
  ], 8);
}

function captureCompletenessStatus(checklist) {
  const missingCount = (checklist || []).filter((item) => item.status === "missing").length;
  const partialCount = (checklist || []).filter((item) => item.status === "partial").length;
  if (missingCount) return "needs_more_runtime_capture";
  if (partialCount) return "partial_capture_needs_review";
  return "complete_enough_for_agent_analysis";
}

function captureCompletenessScore(checklist) {
  return {
    observed_count: (checklist || []).filter((item) => item.status === "observed").length,
    partial_count: (checklist || []).filter((item) => item.status === "partial").length,
    missing_count: (checklist || []).filter((item) => item.status === "missing").length,
    total_count: (checklist || []).length
  };
}

function buildCandidateCaptureCompleteness({generationSteps, sourceWindows, requestInputSummary, directWebCrypto = false}) {
  const inputSteps = candidateStepsForStages(generationSteps, [
    "input_url",
    "request_construction",
    "request_headers",
    "request_body"
  ]);
  const materialSteps = candidateStepsForStages(generationSteps, [
    "byte_buffer",
    "text_or_string_decode",
    "json_serialization",
    "request_headers",
    "request_body"
  ]);
  const vmpDispatchStep = candidateStepsForStages(generationSteps, ["dynamic_dispatch"])[0] || null;
  const mixingSteps = candidateStepsForStages(generationSteps, ["integer_mixing", "hash_or_digest"]);
  const attachmentSteps = candidateStepsForStages(generationSteps, ["signature_mutation", "url_encoding"]);
  const signedRequestSteps = candidateStepsForStages(generationSteps, ["signed_request", "request_construction"]);
  const checklist = [];
  const requestInputEvidence = uniqueLimited([
    ...(requestInputSummary?.observed_categories || []).map((category) => `request_input_category:${category}`),
    ...(requestInputSummary?.evidence_refs || []).map((ref) => `request_input:${ref}`)
  ], 12);

  checklist.push(inputSteps.length || requestInputEvidence.length
    ? completenessEntry(
      "input_material_observed",
      "observed",
      uniqueLimited([
        ...evidenceForRuntimeSteps(inputSteps),
        ...requestInputEvidence
      ], 12)
    )
    : completenessEntry(
      "input_material_observed",
      "missing",
      [],
      ["input_url_or_request_material"],
      ["URL.constructor", "Request.constructor", "XMLHttpRequest.open"]
    ));

  checklist.push(materialSteps.some((step) => (step.apis || []).length)
    ? completenessEntry("material_runtime_observed", "observed", evidenceForRuntimeSteps(materialSteps))
    : completenessEntry(
      "material_runtime_observed",
      materialSteps.length ? "partial" : "missing",
      materialSteps.flatMap(evidenceForSourceOnlyStep),
      ["material_runtime_api"],
      ["TextEncoder.encode", "DataView.getUint32", "TypedArray.buffer.get"]
    ));

  checklist.push(directWebCrypto
    ? completenessEntry(
      "vmp_dispatch_runtime_observed",
      "not_applicable",
      ["direct_webcrypto_operation_path"]
    )
    : vmpDispatchStep && (vmpDispatchStep.apis || []).length
    ? completenessEntry("vmp_dispatch_runtime_observed", "observed", evidenceForRuntimeSteps([vmpDispatchStep]))
    : completenessEntry(
      "vmp_dispatch_runtime_observed",
      "missing",
      evidenceForSourceOnlyStep(vmpDispatchStep),
      ["dynamic_dispatch_runtime_api"],
      ["VMP.dispatch.runtime_call", "Function.prototype.call.apply"]
    ));

  checklist.push(mixingSteps.some((step) => (step.apis || []).length)
    ? completenessEntry("mixing_runtime_observed", "observed", evidenceForRuntimeSteps(mixingSteps))
    : completenessEntry(
      "mixing_runtime_observed",
      mixingSteps.length ? "partial" : "missing",
      mixingSteps.flatMap(evidenceForSourceOnlyStep),
      ["mixing_or_hash_runtime_api"],
      ["Math.imul", "Bitwise.*", "Crypto.subtle.digest"]
    ));

  checklist.push(attachmentSteps.some((step) => (step.apis || []).length && (step.target_params || []).length)
    ? completenessEntry("signature_attachment_observed", "observed", evidenceForRuntimeSteps(attachmentSteps))
    : completenessEntry(
      "signature_attachment_observed",
      attachmentSteps.length ? "partial" : "missing",
      attachmentSteps.flatMap(evidenceForSourceOnlyStep),
      ["signature_attachment_runtime_api"],
      ["URLSearchParams.set", "URL.search.set", "XMLHttpRequest.setRequestHeader"]
    ));

  checklist.push(signedRequestSteps.some((step) => (step.apis || []).length)
    ? completenessEntry("signed_request_observed", "observed", evidenceForRuntimeSteps(signedRequestSteps))
    : completenessEntry(
      "signed_request_observed",
      signedRequestSteps.length ? "partial" : "missing",
      signedRequestSteps.flatMap(evidenceForSourceOnlyStep),
      ["signed_request_runtime_api"],
      ["BrowserNetwork.request", "fetch", "XMLHttpRequest.send"]
    ));

  checklist.push((sourceWindows || []).length
    ? completenessEntry(
      "source_assets_captured",
      "observed",
      (sourceWindows || []).slice(0, 4).map((source) => `source_ref:${source.ref || source.asset_id || "unknown"}`)
    )
    : completenessEntry(
      "source_assets_captured",
      "missing",
      [],
      ["script_source_asset"],
      ["xtrace_capture_assets_full", "retrieve_external_script_asset"]
    ));

  const score = captureCompletenessScore(checklist);
  const incompleteItems = checklist.filter((item) => item.status !== "observed");
  return {
    status: captureCompletenessStatus(checklist),
    score,
    checklist,
    missing_items: checklist.filter((item) => item.status === "missing").map((item) => item.item),
    partial_items: checklist.filter((item) => item.status === "partial").map((item) => item.item),
    next_capture_hooks: uniqueLimited(incompleteItems.flatMap((item) => item.next_capture_hooks || []), 16)
  };
}

function buildCandidateGenerationSummary(parameter, originalParameter = {}) {
  const agentSummary = originalParameter.agent_generation_summary || {};
  const stageChain = uniqueLimited(
    agentSummary.stage_chain?.length ? agentSummary.stage_chain : parameter.confirmed_stages || [],
    12
  );
  const runtimeApis = uniqueLimited([
    ...(agentSummary.runtime_apis || []),
    ...(parameter.generation_path || []).flatMap((step) => step.apis || [])
  ], 24);
  const sourceCalls = uniqueLimited([
    ...(agentSummary.source_calls || []),
    ...(parameter.generation_path || []).flatMap((step) => step.source_calls || [])
  ], 24);
  const sourceSignals = uniqueLimited([
    ...(agentSummary.source_signals || []),
    ...(parameter.generation_path || []).flatMap((step) => step.source_signals || [])
  ], 24);
  const attachment = candidateSummaryAttachment(parameter);
  const keyRefs = candidateSummaryKeyRefs(parameter);
  const generationSteps = candidateSummaryGenerationSteps(parameter);
  const sourceWindows = candidateSummarySourceWindows(parameter);
  const requestInputSummary = buildCandidateRequestInputSummary(
    parameter.request_input_bundle || originalParameter.request_input_bundle
  );
  const webcryptoSignatureSummary = compactWebCryptoSignatureSummary(
    parameter.webcrypto_signature_summary || originalParameter.webcrypto_signature_summary
  );
  const directWebCrypto = isDirectWebCryptoGenerationPath(
    generationSteps,
    webcryptoSignatureSummary,
    parameter.vmp_operation_patterns || []
  );
  const dataflowStatus = parameter.generation_graph?.dataflow_summary?.status || "unknown";
  const dataflowGaps = filterDirectWebCryptoGaps(
    parameter.generation_graph?.dataflow_summary?.gaps || [],
    directWebCrypto
  );
  const nextActions = filterDirectWebCryptoActions(candidateSummaryNextActions(parameter), directWebCrypto);
  const captureCompleteness = buildCandidateCaptureCompleteness({
    generationSteps,
    sourceWindows,
    requestInputSummary,
    directWebCrypto
  });
  const targetParams = sortParamNames(uniqueLimited([
    parameter.param,
    ...(agentSummary.target_params || []),
    ...(agentSummary.attachment_params || []),
    ...(attachment.target_params || []),
    ...(keyRefs.target_params || [])
  ].filter(Boolean), 16));
  const signatureParamMaterializations = compactSignatureParamMaterializations([
    ...(parameter.signature_param_materializations || []),
    ...(originalParameter.signature_param_materializations || []),
    ...(agentSummary.signature_param_materializations || [])
  ]).filter((event) => !targetParams.length || targetParams.includes(event.param));
  return {
    flow_id: parameter.best_flow_id || "",
    endpoint: parameter.endpoint || "",
    status: parameter.conclusion || "unknown",
    evidence_level: parameter.evidence_level || "low",
    evidence_profile: agentSummary.evidence_profile || "unknown",
    readiness: parameter.analysis_readiness?.summary?.status || agentSummary.readiness || "unknown",
    stage_chain: stageChain,
    generation_steps: generationSteps,
    summary_text: stageChain.join(" -> ") || agentSummary.summary_text || "unknown",
    target_params: targetParams,
    runtime_apis: runtimeApis,
    source_calls: sourceCalls,
    source_signals: sourceSignals,
    source_observed_hooks: uniqueLimited(agentSummary.source_observed_hooks || [], 16),
    runtime_observed_hooks: uniqueLimited(agentSummary.runtime_observed_hooks || [], 16),
    vmp_hook_ref_summary: candidateSummaryVmpHookRefSummary(parameter, agentSummary),
    vmp_patterns: (parameter.vmp_operation_patterns || []).slice(0, 6).map((pattern) => ({
      pattern: pattern.pattern || "unknown",
      confidence: pattern.confidence || "unknown",
      operation_signature: pattern.operation_signature || "unknown",
      relation_to_signature_mutation: pattern.relation_to_signature_mutation || "unknown",
      source_context_refs: uniqueLimited(pattern.source_context_refs || [], 8),
      evidence_refs: uniqueLimited(pattern.evidence_refs || [], 8)
    })),
    key_refs: keyRefs,
    attachment,
    signature_param_materializations: signatureParamMaterializations,
    ...(requestInputSummary ? {request_input_summary: requestInputSummary} : {}),
    ...(webcryptoSignatureSummary ? {webcrypto_signature_summary: webcryptoSignatureSummary} : {}),
    source_windows: sourceWindows,
    capture_completeness: captureCompleteness,
    logic_hypothesis: buildCandidateLogicHypothesis({
      param: parameter.param || "",
      stageChain,
      generationSteps,
      runtimeApis,
      sourceWindows,
      attachment,
      dataflowStatus,
      dataflowGaps,
      generationEdges: parameter.generation_edges || [],
      generationEdgeGaps: parameter.generation_edge_gaps || [],
      requestInputSummary,
      webcryptoSignatureSummary,
      nextActions
    }),
    data_link_count: agentSummary.data_link_count ?? (parameter.data_links || []).length,
    inferred_data_link_count: agentSummary.inferred_data_link_count ?? (parameter.inferred_data_links || []).length,
    dataflow_status: dataflowStatus,
    dataflow_gaps: dataflowGaps,
    unresolved_gaps: filterDirectWebCryptoGaps(candidateSummaryUnresolvedGaps(parameter), directWebCrypto),
    next_actions: nextActions
  };
}

function generationStepEvidenceFlags(step, sourceEvidence) {
  const flags = [];
  if ((step.apis || []).length) flags.push("runtime_api_observed");
  if ((sourceEvidence || []).length) flags.push("source_context_observed");
  if ((step.object_refs || []).length || (step.value_refs || []).length) flags.push("data_refs_observed");
  if (step.relation === "before_signed_request") flags.push("pre_request_observed");
  else if (step.relation === "signed_request") flags.push("signed_request_observed");
  else if (step.relation === "after_signed_request") flags.push("post_request_observed");
  if ((step.target_params || []).length && step.param_relation === "direct_observed") {
    flags.push("target_param_observed");
  }
  return flags;
}

function generationStepEvidenceGaps(step, sourceEvidence) {
  const gaps = [];
  if (!(step.apis || []).length) gaps.push("runtime_api_not_observed");
  if (!(sourceEvidence || []).length) gaps.push("source_context_not_available");
  if (!(step.object_refs || []).length && !(step.value_refs || []).length) gaps.push("data_refs_not_observed");
  if (step.relation === "after_signed_request") gaps.push("post_request_activity");
  return gaps;
}

function generationStepRecommendedActions(step, gaps) {
  const actions = [];
  if (step.stage === "signature_mutation" && gaps.length) {
    actions.push("capture_url_search_params_mutation_or_header_set");
  }
  for (const gap of gaps || []) {
    if (gap === "runtime_api_not_observed") actions.push("expand_vmp_runtime_hooks");
    else if (gap === "source_context_not_available") actions.push("capture_or_retrieve_script_asset");
    else if (gap === "data_refs_not_observed") actions.push("capture_object_ids_for_data_links");
    else if (gap === "post_request_activity") actions.push("prefer_pre_request_capture_window");
  }
  if (!actions.length) actions.push("review_step_source_context");
  return uniqueLimited(actions, 8);
}

function generationPathForParameter(parameter, sourceRefIndex, tracePath = "") {
  return (parameter.generation_trace || [])
    .slice(0, 12)
    .map((step, index) => {
      const sourceEvidence = sourceEvidenceForRefs(step.source_refs || [], sourceRefIndex, tracePath);
      const normalized = {
        order: step.order ?? index + 1,
        stage: step.stage || "unknown",
        role: step.role || "context",
        apis: uniqueLimited(step.apis || [], 6),
        target_params: sortParamNames(step.target_params || []),
        param_relation: step.param_relation || "unknown",
        relation: step.relation || "unknown",
        distance_to_signed_request: step.distance_to_signed_request ?? null,
        distance_basis: step.distance_basis || "unknown",
        source_evidence: sourceEvidence,
        source_calls: uniqueLimited(step.source_calls || [], 6),
        source_signals: uniqueLimited(step.source_signals || [], 6),
        source_operators: uniqueLimited(step.source_operators || [], 6),
        source_constants: uniqueLimited(step.source_constants || [], 6),
        object_refs: uniquePrioritizedLimited(
          step.object_refs || [],
          step.stage === "dynamic_dispatch" ? 16 : 8,
          generationPathObjectRefRank
        ),
        value_refs: compactGenerationValueRefs(
          step.value_refs || [],
          step.stage === "dynamic_dispatch" ? 24 : 8,
          {
            preserveVmpStateRefs: step.stage === "dynamic_dispatch",
            preserveStringRuntimeRefs: shouldPreserveStringRuntimeRefsForStage(step.stage)
          }
        )
      };
      const gaps = generationStepEvidenceGaps(normalized, sourceEvidence);
      return {
        order: normalized.order,
        stage: normalized.stage,
        role: normalized.role,
        ...(step.seq_start !== undefined ? {seq_start: step.seq_start} : {}),
        ...(step.seq_end !== undefined ? {seq_end: step.seq_end} : {}),
        apis: normalized.apis,
        target_params: normalized.target_params,
        param_relation: normalized.param_relation,
        relation_to_signed_request: normalized.relation,
        distance_to_signed_request: normalized.distance_to_signed_request,
        distance_basis: normalized.distance_basis,
        source_evidence: normalized.source_evidence,
        source_calls: normalized.source_calls,
        source_signals: normalized.source_signals,
        source_operators: normalized.source_operators,
        source_constants: normalized.source_constants,
        runtime_event_refs: compactRuntimeEventRefs(step.runtime_event_refs || [], 8),
        object_refs: normalized.object_refs,
        value_refs: normalized.value_refs,
        evidence_flags: generationStepEvidenceFlags(normalized, sourceEvidence),
        evidence_gaps: gaps,
        recommended_next_actions: generationStepRecommendedActions(normalized, gaps)
      };
    });
}

function generationStepSourceRefs(step) {
  return uniqueLimited((step.source_evidence || [])
    .map((source) => source.ref || "")
    .filter(Boolean), 8);
}

function intersectRefs(leftRefs, rightRefs) {
  const right = new Set(rightRefs || []);
  return uniqueLimited((leftRefs || []).filter((ref) => right.has(ref)), 8);
}

function inferredLinksForAdjacentSteps(left, right, parameter) {
  return (parameter?.inferred_data_links || [])
    .filter((link) => link.from === left.stage && link.to === right.stage)
    .slice(0, 4);
}

function inferredEdgeConfidence(links) {
  return strongestConfidence((links || []).map((link) => link.confidence || "medium")) || "medium";
}

function hasRuntimeOrDataEvidence(step) {
  return Boolean(
    (step?.apis || []).length ||
    (step?.object_refs || []).length ||
    (step?.value_refs || []).length ||
    (step?.target_params || []).length
  );
}

function temporalRuntimeOrderForAdjacentSteps(left, right) {
  if ((left?.relation_to_signed_request || "") !== "before_signed_request") return null;
  if (!["before_signed_request", "signed_request"].includes(right?.relation_to_signed_request || "")) return null;
  if (!hasRuntimeOrDataEvidence(left) || !hasRuntimeOrDataEvidence(right)) return null;
  if ((left.distance_basis || "") !== (right.distance_basis || "")) return null;
  const leftDistance = left.distance_to_signed_request;
  const rightDistance = right.distance_to_signed_request;
  if (!Number.isFinite(leftDistance) || !Number.isFinite(rightDistance)) return null;
  if (leftDistance <= rightDistance) return null;
  const basis = uniqueLimited([
    "pre_request_distance_order",
    left.distance_basis || "unknown"
  ], 4);
  const refPrefix = left.distance_basis === "trace_index" ? "trace_distance" : "seq_distance";
  return {
    confidence: "low",
    basis,
    refs: [`${refPrefix}:${leftDistance}->${rightDistance}`]
  };
}

function signatureEncodingBoundaryForAdjacentSteps(left, right) {
  const pair = `${left?.stage || "unknown"}->${right?.stage || "unknown"}`;
  if (pair !== "signature_mutation->url_encoding") return null;
  if (!hasRuntimeOrDataEvidence(left) || !hasRuntimeOrDataEvidence(right)) return null;
  if ((left.distance_basis || "") !== (right.distance_basis || "")) return null;
  const sharedTargetParams = intersectRefs(left.target_params || [], right.target_params || []);
  if (!sharedTargetParams.length) return null;
  const leftDistance = left.distance_to_signed_request;
  const rightDistance = right.distance_to_signed_request;
  if (!Number.isFinite(leftDistance) || !Number.isFinite(rightDistance)) return null;
  if ((left?.relation_to_signed_request || "") !== "before_signed_request") return null;
  if ((right?.relation_to_signed_request || "") !== "before_signed_request") return null;
  if (leftDistance <= rightDistance) return null;
  const refPrefix = left.distance_basis === "trace_index" ? "trace_distance" : "seq_distance";
  return {
    confidence: "low",
    basis: uniqueLimited([
      "signature_param_to_url_encoding",
      left.distance_basis || "unknown",
      `stage_pair:${pair}`
    ], 4),
    refs: [`${refPrefix}:${leftDistance}->${rightDistance}`]
  };
}

const SIGNATURE_MATERIAL_ATTACHMENT_EDGE_MAX_DISTANCE = 16;

function signatureMaterialAttachmentWindowForAdjacentSteps(left, right) {
  const pair = `${left?.stage || "unknown"}->${right?.stage || "unknown"}`;
  if (pair !== "string_transform->signature_mutation") return null;
  if (!hasRuntimeOrDataEvidence(left) || !hasRuntimeOrDataEvidence(right)) return null;
  if ((left.distance_basis || "") !== (right.distance_basis || "")) return null;
  const sharedTargetParams = intersectRefs(left.target_params || [], right.target_params || []);
  if (!sharedTargetParams.length) return null;
  if ((right?.param_relation || "") !== "direct_observed") return null;
  const leftDistance = left.distance_to_signed_request;
  const rightDistance = right.distance_to_signed_request;
  if (!Number.isFinite(leftDistance) || !Number.isFinite(rightDistance)) return null;
  if (Math.abs(leftDistance - rightDistance) > SIGNATURE_MATERIAL_ATTACHMENT_EDGE_MAX_DISTANCE) return null;
  const relationSet = new Set([
    left.relation_to_signed_request || "unknown",
    right.relation_to_signed_request || "unknown"
  ]);
  if (![...relationSet].some((relation) => relation === "signed_request" || relation === "before_signed_request")) {
    return null;
  }
  const refPrefix = left.distance_basis === "trace_index" ? "trace_distance" : "seq_distance";
  return {
    confidence: "low",
    basis: uniqueLimited([
      "signature_material_to_param_attachment",
      left.distance_basis || "unknown",
      `stage_pair:${pair}`
    ], 4),
    refs: [`${refPrefix}:${leftDistance}~${rightDistance}`]
  };
}

const VMP_NEARBY_RUNTIME_EDGE_MAX_DISTANCE = 128;
const VMP_NEARBY_RUNTIME_STAGE_PAIRS = new Set([
  "dynamic_dispatch->integer_mixing",
  "dynamic_dispatch->text_or_string_decode",
  "byte_buffer->dynamic_dispatch"
]);

const VMP_MATERIAL_DISPATCH_EDGE_MAX_DISTANCE = 32;

const REQUEST_BOUNDARY_RUNTIME_EDGE_MAX_DISTANCE = 16;
const REQUEST_BOUNDARY_RUNTIME_STAGE_PAIRS = new Set([
  "signed_request->string_transform",
  "signed_request->url_encoding",
  "string_transform->url_encoding",
  "url_encoding->request_construction",
  "url_encoding->regexp_probe"
]);

const SIDE_PROBE_RUNTIME_STAGE_PAIRS = new Set([
  "signed_request->regexp_probe",
  "signed_request->anti_debug_timing_gate",
  "signed_request->source_integrity_probe",
  "signed_request->stack_trace_probe",
  "signed_request->exception_control_flow"
]);

function nearbyVmpRuntimeWindowForAdjacentSteps(left, right) {
  const pair = `${left?.stage || "unknown"}->${right?.stage || "unknown"}`;
  if (!VMP_NEARBY_RUNTIME_STAGE_PAIRS.has(pair)) return null;
  if ((left?.relation_to_signed_request || "") !== "before_signed_request") return null;
  if ((right?.relation_to_signed_request || "") !== "before_signed_request") return null;
  if (!hasRuntimeOrDataEvidence(left) || !hasRuntimeOrDataEvidence(right)) return null;
  if ((left.distance_basis || "") !== (right.distance_basis || "")) return null;
  const leftDistance = left.distance_to_signed_request;
  const rightDistance = right.distance_to_signed_request;
  if (!Number.isFinite(leftDistance) || !Number.isFinite(rightDistance)) return null;
  if (Math.abs(leftDistance - rightDistance) > VMP_NEARBY_RUNTIME_EDGE_MAX_DISTANCE) return null;
  const refPrefix = left.distance_basis === "trace_index" ? "trace_distance" : "seq_distance";
  return {
    confidence: "low",
    basis: uniqueLimited([
      "same_pre_request_window",
      left.distance_basis || "unknown",
      `stage_pair:${pair}`
    ], 4),
    refs: [`${refPrefix}:${leftDistance}~${rightDistance}`]
  };
}

function stepHasByteBufferMaterialRefs(step) {
  return Boolean(
    (step?.stage || "") === "byte_buffer" &&
    (
      (step?.apis || []).some((api) => /TypedArray|ArrayBuffer|DataView/.test(String(api))) ||
      (step?.object_refs || []).some((ref) => /^(typed_array|array_buffer|data_view):/.test(String(ref))) ||
      (step?.value_refs || []).some((ref) => /^(typed_array|array_buffer|data_view|string:length|url_encoded:length):/.test(String(ref)))
    )
  );
}

function stepHasVmpDispatchRefs(step) {
  return Boolean(
    (step?.stage || "") === "dynamic_dispatch" &&
    (
      (step?.apis || []).some((api) => /Function\.prototype\.(call|apply)|Reflect\.apply|Array\.prototype|Object\.keys/.test(String(api))) ||
      (step?.object_refs || []).some((ref) => /^(state_object|target|arguments_list|receiver):/.test(String(ref))) ||
      (step?.value_refs || []).some((ref) => /^(register|handler_return|handler_arg):/.test(String(ref))) ||
      (step?.source_signals || []).includes("dynamic_dispatch")
    )
  );
}

function vmpMaterialDispatchWindowForAdjacentSteps(left, right) {
  const pair = `${left?.stage || "unknown"}->${right?.stage || "unknown"}`;
  if (pair !== "byte_buffer->dynamic_dispatch") return null;
  if (!stepHasByteBufferMaterialRefs(left) || !stepHasVmpDispatchRefs(right)) return null;
  if ((left.distance_basis || "") !== (right.distance_basis || "")) return null;
  const sharedTargetParams = intersectRefs(left.target_params || [], right.target_params || []);
  if (!sharedTargetParams.length) return null;
  const leftDistance = left.distance_to_signed_request;
  const rightDistance = right.distance_to_signed_request;
  if (!Number.isFinite(leftDistance) || !Number.isFinite(rightDistance)) return null;
  if (Math.abs(leftDistance - rightDistance) > VMP_MATERIAL_DISPATCH_EDGE_MAX_DISTANCE) return null;
  const refPrefix = left.distance_basis === "trace_index" ? "trace_distance" : "seq_distance";
  return {
    confidence: "low",
    basis: uniqueLimited([
      "vmp_material_dispatch_window",
      left.distance_basis || "unknown",
      `stage_pair:${pair}`,
      "typed_array_or_buffer_to_vmp_dispatch"
    ], 4),
    refs: [`${refPrefix}:${leftDistance}~${rightDistance}`]
  };
}

function requestBoundaryRuntimeWindowForAdjacentSteps(left, right) {
  const pair = `${left?.stage || "unknown"}->${right?.stage || "unknown"}`;
  if (!REQUEST_BOUNDARY_RUNTIME_STAGE_PAIRS.has(pair)) return null;
  if (!hasRuntimeOrDataEvidence(left) || !hasRuntimeOrDataEvidence(right)) return null;
  if ((left.distance_basis || "") !== (right.distance_basis || "")) return null;
  const sharedTargetParams = intersectRefs(left.target_params || [], right.target_params || []);
  if (!sharedTargetParams.length) return null;
  const leftDistance = left.distance_to_signed_request;
  const rightDistance = right.distance_to_signed_request;
  if (!Number.isFinite(leftDistance) || !Number.isFinite(rightDistance)) return null;
  if (Math.abs(leftDistance - rightDistance) > REQUEST_BOUNDARY_RUNTIME_EDGE_MAX_DISTANCE) return null;
  const relationSet = new Set([
    left.relation_to_signed_request || "unknown",
    right.relation_to_signed_request || "unknown"
  ]);
  if (![...relationSet].some((relation) => relation === "signed_request" || relation === "before_signed_request")) {
    return null;
  }
  const refPrefix = left.distance_basis === "trace_index" ? "trace_distance" : "seq_distance";
  return {
    confidence: "low",
    basis: uniqueLimited([
      "request_boundary_window",
      left.distance_basis || "unknown",
      `stage_pair:${pair}`
    ], 4),
    refs: [`${refPrefix}:${leftDistance}~${rightDistance}`]
  };
}

function sideProbeRuntimeWindowForAdjacentSteps(left, right) {
  const pair = `${left?.stage || "unknown"}->${right?.stage || "unknown"}`;
  if (!SIDE_PROBE_RUNTIME_STAGE_PAIRS.has(pair)) return null;
  if (!hasRuntimeOrDataEvidence(left) || !hasRuntimeOrDataEvidence(right)) return null;
  if ((left.distance_basis || "") !== (right.distance_basis || "")) return null;
  const leftDistance = left.distance_to_signed_request;
  const rightDistance = right.distance_to_signed_request;
  if (!Number.isFinite(leftDistance) || !Number.isFinite(rightDistance)) return null;
  const refPrefix = left.distance_basis === "trace_index" ? "trace_distance" : "seq_distance";
  return {
    confidence: "low",
    basis: uniqueLimited([
      "guard_or_probe_side_evidence",
      left.distance_basis || "unknown",
      `stage_pair:${pair}`
    ], 4),
    refs: [`${refPrefix}:${leftDistance}~${rightDistance}`]
  };
}

function generationEdgeForAdjacentSteps(left, right, parameter = {}) {
  const objectRefs = intersectRefs(left.object_refs || [], right.object_refs || []);
  const valueToObjectRefs = intersectRefs(left.value_refs || [], right.object_refs || []);
  const sharedValueRefs = intersectRefs(left.value_refs || [], right.value_refs || []);
  const targetRefs = sharedValueRefs.filter((ref) => String(ref).startsWith("target_params:"));
  const nonTargetValueRefs = sharedValueRefs.filter((ref) => !String(ref).startsWith("target_params:"));
  const sourceRefs = intersectRefs(generationStepSourceRefs(left), generationStepSourceRefs(right));
  const inferredLinks = inferredLinksForAdjacentSteps(left, right, parameter);
  const inferredRefs = uniqueLimited(inferredLinks.flatMap((link) => link.refs || []), 8);
  const inferredBasis = uniqueLimited(inferredLinks.flatMap((link) => link.basis || []), 8);
  const hasStrongerDataLink = Boolean(
    targetRefs.length ||
    valueToObjectRefs.length ||
    nonTargetValueRefs.length ||
    objectRefs.length ||
    inferredLinks.length
  );
  const signatureAttachment = hasStrongerDataLink ? null : signatureMaterialAttachmentWindowForAdjacentSteps(left, right);
  const signatureEncoding = hasStrongerDataLink || signatureAttachment ? null : signatureEncodingBoundaryForAdjacentSteps(left, right);
  const temporalOrder = hasStrongerDataLink || signatureAttachment || signatureEncoding ? null : temporalRuntimeOrderForAdjacentSteps(left, right);
  const nearbyRuntime = hasStrongerDataLink || signatureAttachment || signatureEncoding || temporalOrder
    ? null
    : nearbyVmpRuntimeWindowForAdjacentSteps(left, right);
  const materialDispatch = hasStrongerDataLink || signatureAttachment || signatureEncoding || temporalOrder || nearbyRuntime
    ? null
    : vmpMaterialDispatchWindowForAdjacentSteps(left, right);
  const requestBoundary = hasStrongerDataLink || signatureAttachment || signatureEncoding || temporalOrder || nearbyRuntime || materialDispatch
    ? null
    : requestBoundaryRuntimeWindowForAdjacentSteps(left, right);
  const sideProbe = hasStrongerDataLink || signatureAttachment || signatureEncoding || temporalOrder || nearbyRuntime || materialDispatch || requestBoundary
    ? null
    : sideProbeRuntimeWindowForAdjacentSteps(left, right);
  const signatureAttachmentRefs = signatureAttachment?.refs || [];
  const signatureEncodingRefs = signatureEncoding?.refs || [];
  const temporalRefs = temporalOrder?.refs || [];
  const nearbyRefs = nearbyRuntime?.refs || [];
  const materialDispatchRefs = materialDispatch?.refs || [];
  const boundaryRefs = requestBoundary?.refs || [];
  const sideProbeRefs = sideProbe?.refs || [];
  const evidence = [];
  if (targetRefs.length) evidence.push("target_param_ref");
  if (valueToObjectRefs.length) evidence.push("value_to_object_ref");
  if (nonTargetValueRefs.length) evidence.push("shared_value_ref");
  if (objectRefs.length) evidence.push("shared_object_ref");
  if (inferredLinks.length) evidence.push("inferred_data_link");
  if (signatureAttachment) evidence.push("signature_material_attachment_window");
  if (signatureEncoding) evidence.push("signature_encoding_boundary");
  if (temporalOrder) evidence.push("temporal_runtime_order");
  if (nearbyRuntime) evidence.push("vmp_nearby_runtime_window");
  if (materialDispatch) evidence.push("vmp_material_dispatch_window");
  if (requestBoundary) evidence.push("request_boundary_runtime_window");
  if (sideProbe) evidence.push("side_probe_runtime_window");
  if (sourceRefs.length) evidence.push("shared_source_ref");
  if (!evidence.length) return null;
  const relation = targetRefs.length
    ? "target_param_ref"
    : valueToObjectRefs.length
      ? "value_to_object_ref"
      : nonTargetValueRefs.length
        ? "shared_value_ref"
        : objectRefs.length
          ? "shared_object_ref"
          : inferredLinks.length
          ? "inferred_data_link"
            : signatureAttachment
            ? "signature_material_attachment_window"
            : signatureEncoding
              ? "signature_encoding_boundary"
              : temporalOrder
                ? "temporal_runtime_order"
                : nearbyRuntime
                  ? "vmp_nearby_runtime_window"
                  : materialDispatch
                    ? "vmp_material_dispatch_window"
                    : requestBoundary
                      ? "request_boundary_runtime_window"
                      : sideProbe
                        ? "side_probe_runtime_window"
                        : "shared_source_ref";
  const refs = uniqueLimited([
    ...targetRefs,
    ...valueToObjectRefs,
    ...nonTargetValueRefs,
    ...objectRefs,
    ...inferredRefs,
    ...signatureAttachmentRefs,
    ...signatureEncodingRefs,
    ...temporalRefs,
    ...nearbyRefs,
    ...materialDispatchRefs,
    ...boundaryRefs,
    ...sideProbeRefs
  ], 8);
  const hasRuntimeRef = evidence.some((item) => ![
    "shared_source_ref",
    "inferred_data_link",
    "signature_material_attachment_window",
    "signature_encoding_boundary",
    "temporal_runtime_order",
    "vmp_nearby_runtime_window",
    "vmp_material_dispatch_window",
    "request_boundary_runtime_window",
    "side_probe_runtime_window"
  ].includes(item));
  return {
    from_order: left.order ?? null,
    to_order: right.order ?? null,
    from_stage: left.stage || "unknown",
    to_stage: right.stage || "unknown",
    relation,
    confidence: hasRuntimeRef ? "high" : inferredLinks.length ? inferredEdgeConfidence(inferredLinks) : signatureAttachment || signatureEncoding || temporalOrder || nearbyRuntime || materialDispatch || requestBoundary || sideProbe ? "low" : "medium",
    refs,
    source_refs: sourceRefs,
    evidence,
    ...(inferredBasis.length ? {inferred_basis: inferredBasis} : {}),
    ...(signatureAttachment ? {signature_attachment_basis: signatureAttachment.basis} : {}),
    ...(signatureEncoding ? {signature_encoding_basis: signatureEncoding.basis} : {}),
    ...(temporalOrder ? {temporal_basis: temporalOrder.basis} : {}),
    ...(nearbyRuntime ? {nearby_basis: nearbyRuntime.basis} : {}),
    ...(materialDispatch ? {material_dispatch_basis: materialDispatch.basis} : {}),
    ...(requestBoundary ? {boundary_basis: requestBoundary.basis} : {}),
    ...(sideProbe ? {side_probe_basis: sideProbe.basis} : {})
  };
}

function generationEdgesForPath(pathSteps, parameter = {}) {
  const edges = [];
  const steps = pathSteps || [];
  for (let index = 0; index < steps.length - 1; index += 1) {
    const edge = generationEdgeForAdjacentSteps(steps[index], steps[index + 1], parameter);
    if (edge) edges.push(edge);
  }
  return edges.slice(0, 12);
}

function runtimeRefLineageKind(ref, field = "") {
  const value = String(ref || "");
  if (field === "object_refs") return "object_ref";
  if (field === "value_refs") return "value_ref";
  if (/^(?:url_object|search_params|network_request|array_buffer|typed_array|data_view|state_object|target|arguments_list|subject|this|object_ref):/.test(value)) {
    return "object_ref";
  }
  return "value_ref";
}

function shouldIncludeRuntimeRefLineage(ref) {
  const value = String(ref || "");
  if (!value) return false;
  if (value.startsWith("target_params:")) return false;
  if (value.startsWith("url_shape:")) return false;
  if (/^(?:trace_distance|seq_distance|source):/.test(value)) return false;
  if (/^string:length:\d+$/.test(value)) return false;
  if (/^url_encoded:length:\d+$/.test(value)) return false;
  return /^(?:string_ref|string|url_encoded|base64|register|handler_return|handler_arg|number|url_object|search_params|network_request|array_buffer|typed_array|data_view|state_object|target|arguments_list|subject|this|object_ref):/.test(value) ||
    /(?:^|:)buffer/.test(value);
}

function runtimeRefLineageRank(entry) {
  const ref = String(entry?.ref || "");
  if (/^(?:string_ref|url_encoded|base64):/.test(ref)) return 0;
  if (/^(?:register|handler_return|handler_arg):/.test(ref)) return 1;
  if (/^(?:array_buffer|typed_array|data_view):/.test(ref) || /(?:^|:)buffer/.test(ref)) return 2;
  if ((entry?.kind || "") === "object_ref") return 3;
  if (ref.startsWith("number:")) return 4;
  if (ref.startsWith("string:")) return 5;
  return 6;
}

function runtimeRefLineageEntryForRef(byRef, ref, kind = "value_ref") {
  const key = String(ref || "");
  const existing = byRef.get(key);
  if (existing) {
    if (existing.kind !== "object_ref" && kind === "object_ref") existing.kind = kind;
    return existing;
  }
  const entry = {
    ref: key,
    kind,
    occurrences: [],
    edges: [],
    occurrenceKeys: new Set(),
    edgeEndpointKeys: new Set(),
    edgeKeys: new Set()
  };
  byRef.set(key, entry);
  return entry;
}

function addRuntimeRefLineageOccurrence(byRef, ref, kind, step, field) {
  if (!shouldIncludeRuntimeRefLineage(ref)) return;
  const entry = runtimeRefLineageEntryForRef(byRef, ref, kind);
  const order = step?.order ?? null;
  const stage = step?.stage || "unknown";
  const key = `${order}:${stage}:${field}`;
  if (entry.occurrenceKeys.has(key)) return;
  entry.occurrenceKeys.add(key);
  entry.occurrences.push({
    order,
    stage,
    apis: uniqueLimited(step?.apis || [], 6),
    field
  });
}

function addRuntimeRefLineageEdge(byRef, ref, kind, edge) {
  if (!shouldIncludeRuntimeRefLineage(ref)) return;
  const entry = runtimeRefLineageEntryForRef(byRef, ref, kind);
  const item = {
    from_stage: edge?.from_stage || "unknown",
    to_stage: edge?.to_stage || "unknown",
    relation: edge?.relation || "related",
    confidence: edge?.confidence || "unknown"
  };
  const key = `${edge?.from_order ?? ""}:${edge?.to_order ?? ""}:${item.from_stage}:${item.to_stage}:${item.relation}:${item.confidence}`;
  if (entry.edgeKeys.has(key)) return;
  entry.edgeKeys.add(key);
  entry.edgeEndpointKeys.add(`${edge?.from_order ?? ""}:${item.from_stage}`);
  entry.edgeEndpointKeys.add(`${edge?.to_order ?? ""}:${item.to_stage}`);
  entry.edges.push(item);
}

function buildRuntimeRefLineage(pathSteps, edges) {
  const byRef = new Map();
  for (const step of pathSteps || []) {
    for (const field of ["value_refs", "object_refs"]) {
      for (const ref of step?.[field] || []) {
        addRuntimeRefLineageOccurrence(byRef, ref, runtimeRefLineageKind(ref, field), step, field);
      }
    }
  }
  for (const edge of edges || []) {
    for (const ref of edge?.refs || []) {
      const existingKind = byRef.get(String(ref || ""))?.kind;
      addRuntimeRefLineageEdge(byRef, ref, existingKind || runtimeRefLineageKind(ref), edge);
    }
  }
  return [...byRef.values()]
    .filter((entry) => entry.edges.length)
    .map((entry) => {
      const occurrences = entry.occurrences
        .filter((item) => entry.edgeEndpointKeys.has(`${item.order ?? ""}:${item.stage}`))
        .sort((left, right) => (left.order ?? 9999) - (right.order ?? 9999) ||
          String(left.stage).localeCompare(String(right.stage)) ||
          String(left.field).localeCompare(String(right.field)));
      const edgesForRef = entry.edges.slice(0, 8);
      const first = occurrences[0] || {};
      const last = occurrences[occurrences.length - 1] || {};
      return {
        ref: entry.ref,
        kind: entry.kind,
        first_stage: first.stage || "",
        last_stage: last.stage || "",
        stages: uniqueLimited(occurrences.map((item) => item.stage), 8),
        apis: uniqueLimited(occurrences.flatMap((item) => item.apis || []), 12),
        occurrence_count: occurrences.length,
        edge_count: entry.edges.length,
        occurrences: occurrences.slice(0, 8),
        edges: edgesForRef
      };
    })
    .sort((left, right) => runtimeRefLineageRank(left) - runtimeRefLineageRank(right) ||
      (left.occurrences[0]?.order ?? 9999) - (right.occurrences[0]?.order ?? 9999) ||
      right.edge_count - left.edge_count ||
      String(left.ref).localeCompare(String(right.ref)))
    .slice(0, 16);
}

function buildRuntimeEventEvidence(pathSteps) {
  return (pathSteps || [])
    .filter((step) => (step.runtime_event_refs || []).length)
    .map((step) => ({
      order: step.order ?? null,
      stage: step.stage || "unknown",
      seq_start: step.seq_start ?? null,
      seq_end: step.seq_end ?? null,
      apis: uniqueLimited(step.apis || [], 8),
      event_count: (step.runtime_event_refs || []).length,
      events: compactRuntimeEventRefs(step.runtime_event_refs || [], 8),
      object_refs: uniquePrioritizedLimited(
        step.object_refs || [],
        step.stage === "dynamic_dispatch" ? 16 : 8,
        generationPathObjectRefRank
      ),
      value_refs: compactGenerationValueRefs(
        step.value_refs || [],
        step.stage === "dynamic_dispatch" ? 24 : 8,
        {preserveVmpStateRefs: step.stage === "dynamic_dispatch"}
      ),
      source_refs: uniqueLimited(generationStepSourceRefs(step), 8)
    }))
    .slice(0, 12);
}

function runtimeEventEvidenceKey(order, stage) {
  return `${order ?? ""}:${stage || "unknown"}`;
}

function runtimeEventsForRefOccurrence(occurrence, eventEvidenceByKey, eventEvidenceByStage) {
  const evidence = eventEvidenceByKey.get(runtimeEventEvidenceKey(occurrence.order, occurrence.stage)) ||
    eventEvidenceByStage.get(occurrence.stage || "unknown");
  if (!evidence) return [];
  const events = evidence.events || [];
  const apiSet = new Set(occurrence.apis || []);
  const matched = apiSet.size
    ? events.filter((event) => apiSet.has(event.api || ""))
    : events;
  return (matched.length ? matched : events).map((event) => ({
    order: occurrence.order ?? null,
    stage: occurrence.stage || "unknown",
    event_ref: event.event_ref || "",
    seq: event.seq ?? null,
    trace_index: event.trace_index ?? null,
    api: event.api || "unknown",
    category: event.category || "",
    phase: event.phase || "",
    stack_url: event.stack_url || "",
    asset_id: event.asset_id || ""
  }));
}

function buildRuntimeRefEventEvidence(lineage, runtimeEventEvidence) {
  const eventEvidenceByKey = new Map();
  const eventEvidenceByStage = new Map();
  for (const entry of runtimeEventEvidence || []) {
    eventEvidenceByKey.set(runtimeEventEvidenceKey(entry.order, entry.stage), entry);
    if (!eventEvidenceByStage.has(entry.stage || "unknown")) {
      eventEvidenceByStage.set(entry.stage || "unknown", entry);
    }
  }
  return (lineage || [])
    .map((entry) => {
      const events = [];
      const seen = new Set();
      for (const occurrence of entry.occurrences || []) {
        for (const event of runtimeEventsForRefOccurrence(occurrence, eventEvidenceByKey, eventEvidenceByStage)) {
          const key = `${event.order ?? ""}:${event.stage}:${event.event_ref}`;
          if (!event.event_ref || seen.has(key)) continue;
          seen.add(key);
          events.push(event);
        }
      }
      if (!events.length) return null;
      return {
        ref: entry.ref,
        kind: entry.kind,
        first_stage: entry.first_stage || "",
        last_stage: entry.last_stage || "",
        stages: uniqueLimited(entry.stages || [], 8),
        apis: uniqueLimited(entry.apis || [], 12),
        event_count: events.length,
        events: events.slice(0, 12)
      };
    })
    .filter(Boolean)
    .slice(0, 16);
}

function generationEdgeMap(edges) {
  const byPair = new Map();
  for (const edge of edges || []) {
    byPair.set(`${edge.from_order ?? ""}->${edge.to_order ?? ""}`, edge);
  }
  return byPair;
}

function generationEdgeGapForPair(left, right, edge) {
  const sourceRefs = uniqueLimited([
    ...generationStepSourceRefs(left),
    ...generationStepSourceRefs(right)
  ], 8);
  const objectRefs = uniqueLimited([
    ...(left.object_refs || []),
    ...(right.object_refs || [])
  ], 8);
  const valueRefs = uniqueLimited([
    ...(left.value_refs || []),
    ...(right.value_refs || [])
  ], 8);
  if (!edge) {
    return {
      from_order: left.order ?? null,
      to_order: right.order ?? null,
      from_stage: left.stage || "unknown",
      to_stage: right.stage || "unknown",
      gap: "missing_generation_edge",
      reason: "no_shared_runtime_or_source_ref",
      priority: "high",
      next_actions: [
        "capture_object_ids_for_data_links",
        "capture_or_retrieve_script_asset"
      ],
      source_refs: sourceRefs,
      object_refs: objectRefs,
      value_refs: valueRefs
    };
  }
  const sourceOnly = (edge.evidence || []).length === 1 && (edge.evidence || [])[0] === "shared_source_ref";
  const signatureAttachmentOnly = (edge.evidence || []).every((item) =>
    item === "signature_material_attachment_window" || item === "shared_source_ref");
  const temporalOnly = (edge.evidence || []).every((item) =>
    item === "temporal_runtime_order" || item === "shared_source_ref");
  const signatureEncodingOnly = (edge.evidence || []).every((item) =>
    item === "signature_encoding_boundary" || item === "shared_source_ref");
  const nearbyOnly = (edge.evidence || []).every((item) =>
    item === "vmp_nearby_runtime_window" || item === "shared_source_ref");
  const materialDispatchOnly = (edge.evidence || []).every((item) =>
    item === "vmp_material_dispatch_window" || item === "shared_source_ref");
  const requestBoundaryOnly = (edge.evidence || []).every((item) =>
    item === "request_boundary_runtime_window" || item === "shared_source_ref");
  const sideProbeOnly = (edge.evidence || []).every((item) =>
    item === "side_probe_runtime_window" || item === "shared_source_ref");
  if (sideProbeOnly && (edge.evidence || []).includes("side_probe_runtime_window")) {
    return null;
  }
  if (signatureAttachmentOnly && (edge.evidence || []).includes("signature_material_attachment_window")) {
    return {
      from_order: left.order ?? null,
      to_order: right.order ?? null,
      from_stage: left.stage || "unknown",
      to_stage: right.stage || "unknown",
      gap: "source_only_edge",
      reason: "signature_attachment_window_no_shared_value_ref",
      priority: "medium",
      next_actions: ["capture_object_ids_for_data_links"],
      source_refs: edge.source_refs || [],
      object_refs: objectRefs,
      value_refs: valueRefs
    };
  }
  if (signatureEncodingOnly && (edge.evidence || []).includes("signature_encoding_boundary")) {
    return {
      from_order: left.order ?? null,
      to_order: right.order ?? null,
      from_stage: left.stage || "unknown",
      to_stage: right.stage || "unknown",
      gap: "temporal_only_edge",
      reason: "signature_encoding_boundary_no_shared_value_ref",
      priority: "medium",
      next_actions: ["capture_object_ids_for_data_links"],
      source_refs: edge.source_refs || [],
      object_refs: objectRefs,
      value_refs: valueRefs
    };
  }
  if (materialDispatchOnly && (edge.evidence || []).includes("vmp_material_dispatch_window")) {
    return {
      from_order: left.order ?? null,
      to_order: right.order ?? null,
      from_stage: left.stage || "unknown",
      to_stage: right.stage || "unknown",
      gap: "nearby_runtime_only_edge",
      reason: "vmp_material_dispatch_window_no_shared_data_ref",
      priority: "medium",
      next_actions: [
        "capture_vmp_register_state_refs",
        "capture_object_ids_for_data_links"
      ],
      source_refs: edge.source_refs || [],
      object_refs: objectRefs,
      value_refs: valueRefs
    };
  }
  if (nearbyOnly && (edge.evidence || []).includes("vmp_nearby_runtime_window")) {
    return {
      from_order: left.order ?? null,
      to_order: right.order ?? null,
      from_stage: left.stage || "unknown",
      to_stage: right.stage || "unknown",
      gap: "nearby_runtime_only_edge",
      reason: "nearby_vmp_runtime_window_no_shared_data_ref",
      priority: "medium",
      next_actions: [
        "capture_vmp_register_state_refs",
        "capture_object_ids_for_data_links"
      ],
      source_refs: edge.source_refs || [],
      object_refs: objectRefs,
      value_refs: valueRefs
    };
  }
  if (requestBoundaryOnly && (edge.evidence || []).includes("request_boundary_runtime_window")) {
    return {
      from_order: left.order ?? null,
      to_order: right.order ?? null,
      from_stage: left.stage || "unknown",
      to_stage: right.stage || "unknown",
      gap: "temporal_only_edge",
      reason: "request_boundary_window_no_shared_data_ref",
      priority: "medium",
      next_actions: ["capture_object_ids_for_data_links"],
      source_refs: edge.source_refs || [],
      object_refs: objectRefs,
      value_refs: valueRefs
    };
  }
  if (temporalOnly && (edge.evidence || []).includes("temporal_runtime_order")) {
    return {
      from_order: left.order ?? null,
      to_order: right.order ?? null,
      from_stage: left.stage || "unknown",
      to_stage: right.stage || "unknown",
      gap: "temporal_only_edge",
      reason: "ordered_runtime_window_no_shared_data_ref",
      priority: "medium",
      next_actions: ["capture_object_ids_for_data_links"],
      source_refs: edge.source_refs || [],
      object_refs: objectRefs,
      value_refs: valueRefs
    };
  }
  if (!sourceOnly) return null;
  return {
    from_order: left.order ?? null,
    to_order: right.order ?? null,
    from_stage: left.stage || "unknown",
    to_stage: right.stage || "unknown",
    gap: "source_only_edge",
    reason: "only_shared_source_context_no_runtime_data_ref",
    priority: "medium",
    next_actions: ["capture_object_ids_for_data_links"],
    source_refs: edge.source_refs || [],
    object_refs: objectRefs,
    value_refs: valueRefs
  };
}

function generationEdgeGapsForPath(pathSteps, edges) {
  const gaps = [];
  const byPair = generationEdgeMap(edges);
  const steps = pathSteps || [];
  for (let index = 0; index < steps.length - 1; index += 1) {
    const left = steps[index];
    const right = steps[index + 1];
    const edge = byPair.get(`${left.order ?? ""}->${right.order ?? ""}`);
    const gap = generationEdgeGapForPair(left, right, edge);
    if (gap) gaps.push(gap);
  }
  return gaps.slice(0, 12);
}

function chainQualityForPath(pathSteps, edges, edgeGaps) {
  const stepCount = (pathSteps || []).length;
  const expectedEdgeCount = Math.max(0, stepCount - 1);
  const highConfidenceEdgeCount = (edges || []).filter((edge) => edge.confidence === "high").length;
  const mediumConfidenceEdgeCount = (edges || []).filter((edge) => edge.confidence === "medium").length;
  const sourceOnlyEdgeCount = (edgeGaps || []).filter((gap) => gap.gap === "source_only_edge").length;
  const temporalOnlyEdgeCount = (edgeGaps || []).filter((gap) => gap.gap === "temporal_only_edge").length;
  const nearbyRuntimeOnlyEdgeCount = (edgeGaps || []).filter((gap) => gap.gap === "nearby_runtime_only_edge").length;
  const missingEdgeCount = (edgeGaps || []).filter((gap) => gap.gap === "missing_generation_edge").length;
  let status = "strong";
  if (missingEdgeCount > 0) {
    status = "weak";
  } else if (sourceOnlyEdgeCount > 0 || temporalOnlyEdgeCount > 0 || nearbyRuntimeOnlyEdgeCount > 0 || (edges || []).length < expectedEdgeCount) {
    status = "partial";
  }
  return {
    status,
    step_count: stepCount,
    expected_edge_count: expectedEdgeCount,
    edge_count: (edges || []).length,
    high_confidence_edge_count: highConfidenceEdgeCount,
    medium_confidence_edge_count: mediumConfidenceEdgeCount,
    source_only_edge_count: sourceOnlyEdgeCount,
    temporal_only_edge_count: temporalOnlyEdgeCount,
    nearby_runtime_only_edge_count: nearbyRuntimeOnlyEdgeCount,
    missing_edge_count: missingEdgeCount
  };
}

function generationEdgesMarkdownSummary(edges) {
  return (edges || [])
    .slice(0, 8)
    .map((edge) => `${edge.from_order ?? "?"}:${edge.from_stage || "unknown"}->${edge.to_order ?? "?"}:${edge.to_stage || "unknown"}:${edge.relation || "related"}[${edge.confidence || "unknown"}] refs=${(edge.refs || []).slice(0, 4).join("|") || "none"} sources=${(edge.source_refs || []).slice(0, 4).join("|") || "none"}`)
    .join(";") || "none";
}

function runtimeRefLineageMarkdownSummary(lineage) {
  return (lineage || [])
    .slice(0, 6)
    .map((entry) => `${entry.ref}:${entry.kind}:${(entry.stages || []).join("->") || "unknown"} edges=${entry.edge_count ?? 0}`)
    .join(";") || "none";
}

function runtimeEventEvidenceMarkdownSummary(evidence) {
  return (evidence || [])
    .slice(0, 8)
    .map((entry) => {
      const events = (entry.events || [])
        .slice(0, 4)
        .map((event) => `${event.api || "unknown"}@${event.seq ?? event.trace_index ?? "?"}`)
        .join("|") || "none";
      return `${entry.stage || "unknown"}[${events}]`;
    })
    .join(";") || "none";
}

function runtimeRefEventEvidenceMarkdownSummary(evidence) {
  return (evidence || [])
    .slice(0, 6)
    .map((entry) => {
      const events = (entry.events || [])
        .slice(0, 6)
        .map((event) => `${event.api || "unknown"}@${event.seq ?? event.trace_index ?? "?"}`)
        .join("->") || "none";
      return `${entry.ref || "unknown"}[${events}]`;
    })
    .join(";") || "none";
}

function relatedParamEvidenceMarkdownSummary(evidence) {
  return (evidence || [])
    .slice(0, 6)
    .map((entry) => `${entry.param || "unknown"}[${entry.relation || "unknown"} refs=${(entry.shared_refs || []).slice(0, 3).join("|") || "none"} stages=${(entry.stages || []).slice(0, 8).join("->") || "unknown"} apis=${(entry.apis || []).slice(0, 8).join("|") || "none"}]`)
    .join(";") || "none";
}

function nativeCaptureRequirementMarkdownSummary(requirement) {
  return `native_requirement=${requirement.action || "unknown"} layer=${requirement.native_layer || "unknown"} priority=${requirement.priority || "medium"} params=${(requirement.params || []).join(",") || "none"} stages=${(requirement.stages || []).join(",") || "none"} gaps=${(requirement.gaps || []).join(",") || "none"} hooks=${(requirement.missing_hook_targets || []).slice(0, 8).join(",") || "none"} refs=${(requirement.missing_ref_types || []).slice(0, 8).join(",") || "none"} targets=${(requirement.implementation_targets || []).slice(0, 8).join(",") || "none"} source_hints=${(requirement.source_hints || []).slice(0, 6).map((hint) => hint.path || "").filter(Boolean).join("|") || "none"} validator=${(requirement.validator_hints?.flags || []).join("|") || "none"} endpoints=${(requirement.endpoints || []).slice(0, 4).join(",") || "none"}`;
}

function chainQualityMarkdownSummary(quality) {
  if (!quality) return "unknown";
  return `${quality.status || "unknown"} edges=${quality.edge_count ?? 0}/${quality.expected_edge_count ?? 0} high=${quality.high_confidence_edge_count ?? 0} medium=${quality.medium_confidence_edge_count ?? 0} source_only=${quality.source_only_edge_count ?? 0} temporal=${quality.temporal_only_edge_count ?? 0} nearby=${quality.nearby_runtime_only_edge_count ?? 0} missing=${quality.missing_edge_count ?? 0}`;
}

function generationEdgeGapsMarkdownSummary(gaps) {
  return (gaps || [])
    .slice(0, 8)
    .map((gap) => `${gap.from_order ?? "?"}:${gap.from_stage || "unknown"}->${gap.to_order ?? "?"}:${gap.to_stage || "unknown"}:${gap.gap || "unknown"}[${gap.priority || "medium"}] next=${(gap.next_actions || []).slice(0, 3).join("|") || "none"}`)
    .join(";") || "none";
}

function vmpOperationPatternsMarkdownSummary(patterns) {
  return (patterns || [])
    .slice(0, 6)
    .map((pattern) => `${pattern.pattern || "unknown"}[${pattern.confidence || "unknown"}]:${pattern.operation_signature || "unknown"} seq=${pattern.seq_start ?? "?"}..${pattern.seq_end ?? "?"} trace=${pattern.trace_start ?? "?"}..${pattern.trace_end ?? "?"} relation=${pattern.relation_to_signature_mutation || "unknown"} d_sig=${pattern.distance_to_signature_mutation ?? "?"} refs=${(pattern.shared_refs || []).slice(0, 4).join("|") || "none"}`)
    .join(";") || "none";
}

function generationHypothesisMarkdownSummary(hypothesis) {
  if (!hypothesis) return "none";
  const vmpState = hypothesis.vmp_state_trace?.status
    ? ` vmp_state=${hypothesis.vmp_state_trace.status}`
    : "";
  return `${hypothesis.status || "unknown"} pattern=${hypothesis.primary_pattern || "none"} quality=${hypothesis.chain_quality || "unknown"} direct_attachment=${hypothesis.direct_attachment_observed ? "true" : "false"} pre_signature_pattern=${hypothesis.pre_signature_pattern_observed ? "true" : "false"}${vmpState} gaps=${(hypothesis.remaining_gaps || []).slice(0, 6).join("|") || "none"} next=${(hypothesis.next_actions || []).slice(0, 6).join("|") || "none"}`;
}

function logicTraceRefsMarkdownSummary(step) {
  return [
    ...(step.object_refs || []),
    ...(step.value_refs || []),
    ...(step.source_refs || [])
  ].slice(0, 8).join("|") || "none";
}

function logicTraceRequestInputsMarkdownSummary(step) {
  const entries = (step.request_inputs || [])
    .slice(0, 8)
    .map((input) => {
      const parts = [];
      const params = (input.target_params || []).slice(0, 6).join("|");
      const query = (input.query_keys || []).slice(0, 8).join("|");
      const headers = (input.header_names || []).slice(0, 8).join("|");
      const names = (input.names || []).slice(0, 8).join("|");
      const keys = (input.keys || []).slice(0, 8).join("|");
      const scopes = (input.scopes || []).slice(0, 4).join("|");
      const refs = (input.value_refs || []).slice(0, 6).join("|");
      if (params) parts.push(`params=${params}`);
      if (query) parts.push(`query=${query}`);
      if (headers) parts.push(`headers=${headers}`);
      if (names) parts.push(`names=${names}`);
      if (keys) parts.push(`keys=${keys}`);
      if (scopes) parts.push(`scopes=${scopes}`);
      if (Number.isFinite(input.body_size)) parts.push(`body_size=${input.body_size}`);
      if (refs) parts.push(`refs=${refs}`);
      return `${input.category || "unknown"}(${parts.join(" ") || "observed"})`;
    })
    .join(";");
  return entries ? ` request_inputs=${entries}` : "";
}

function logicTraceRuntimeEventsMarkdownSummary(step) {
  const events = (step.runtime_events || [])
    .slice(0, 8)
    .map((event) => `${event.api || "unknown"}@${event.seq ?? event.trace_index ?? "?"}`)
    .join("|");
  return events ? ` events=${events}` : "";
}

function webCryptoOperationTraceMarkdownSummary(operations) {
  const entries = (operations || [])
    .slice(0, 8)
    .map((operation) => {
      const details = [
        operation.role ? `role=${operation.role}` : "",
        operation.operation_ref ? `op=${operation.operation_ref}` : "",
        operation.algorithm ? `alg=${operation.algorithm}` : "",
        operation.key_material_ref ? `key_material=${operation.key_material_ref}` : "",
        operation.key_ref ? `key=${operation.key_ref}` : "",
        operation.input_ref ? `input=${operation.input_ref}` : "",
        operation.result_ref ? `result=${operation.result_ref}` : "",
        operation.input_array_buffer_ref ? `input_buffer=${operation.input_array_buffer_ref}` : "",
        operation.result_array_buffer_ref ? `result_buffer=${operation.result_array_buffer_ref}` : ""
      ].filter(Boolean).join(" ");
      return `${operation.api || "unknown"}@${operation.seq ?? "?"}:${operation.phase || "unknown"}[${details || "observed"}]`;
    })
    .join("->");
  return entries ? ` webcrypto_ops=${entries}` : "";
}

function logicTraceStepMarkdownSummary(step) {
  const apis = (step.runtime_apis || []).slice(0, 6).join("|") || "none";
  const calls = (step.source_calls || []).slice(0, 6).join("|") || "none";
  const operators = (step.source_operators || []).slice(0, 6).join("|") || "none";
  const constants = (step.source_constants || []).slice(0, 6).join("|") || "none";
  const params = (step.target_params || []).slice(0, 6).join("|") || "none";
  const evidence = (step.evidence || []).slice(0, 8).join("|") || "none";
  return `logic_step=${step.order ?? "?"}:${step.phase || "unknown"}[${step.status || "unknown"}/${step.confidence || "unknown"}] claim=${step.claim || "unknown"} apis=${apis} calls=${calls} ops=${operators} constants=${constants} params=${params} refs=${logicTraceRefsMarkdownSummary(step)} evidence=${evidence}${logicTraceRuntimeEventsMarkdownSummary(step)}${webCryptoOperationTraceMarkdownSummary(step.webcrypto_operations)}${logicTraceRequestInputsMarkdownSummary(step)}`;
}

function logicTraceEdgeMarkdownSummary(edge, index) {
  const sources = (edge.source_refs || []).slice(0, 4).join("|") || "none";
  const refs = (edge.refs || []).slice(0, 6).join("|") || "none";
  const evidence = (edge.evidence || []).slice(0, 4).join("|") || "none";
  const gap = edge.gap ? ` gap=${edge.gap}` : "";
  return `logic_edge=${index + 1}:${edge.from_phase || "unknown"}->${edge.to_phase || "unknown"}[${edge.confidence || "unknown"}/${edge.relation || "unknown"}] stages=${edge.from_stage || "unknown"}->${edge.to_stage || "unknown"} sources=${sources} refs=${refs} evidence=${evidence}${gap}`;
}

function logicTraceEdgesMarkdownSummary(trace) {
  const edges = (trace?.edges || [])
    .slice(0, 8)
    .map(logicTraceEdgeMarkdownSummary)
    .join(" ");
  return edges || "";
}

function logicTraceFinalAttachmentMarkdownSummary(attachment) {
  if (!attachment) return "";
  const status = attachment.observed ? "observed" : "missing";
  const params = (attachment.target_params || []).slice(0, 6).join("|") || "none";
  const apis = (attachment.apis || []).slice(0, 6).join("|") || "none";
  return `final_attachment=${status} params=${params} apis=${apis} mode=${attachment.evidence_mode || "unknown"}`;
}

function candidateLogicTraceMarkdownSummary(trace) {
  if (!trace) return "none";
  const steps = (trace.steps || [])
    .slice(0, 4)
    .map(logicTraceStepMarkdownSummary)
    .join(" ") || "steps=none";
  const edges = logicTraceEdgesMarkdownSummary(trace);
  const finalAttachment = logicTraceFinalAttachmentMarkdownSummary(trace.final_attachment);
  return `${trace.summary || "unknown"} ${steps}${edges ? ` ${edges}` : ""}${finalAttachment ? ` ${finalAttachment}` : ""}`;
}

function candidateGenerationSummaryMarkdownSummary(summary) {
  if (!summary) return "none";
  const chain = (summary.stage_chain || []).slice(0, 12).join("->") || "none";
  const runtime = (summary.runtime_apis || []).slice(0, 6).join("|") || "none";
  const sourceHooks = (summary.source_observed_hooks || []).slice(0, 6).join("|") || "none";
  const runtimeHooks = (summary.runtime_observed_hooks || []).slice(0, 6).join("|") || "none";
  const params = (summary.target_params || []).slice(0, 6).join("|") || "none";
  const gaps = (summary.unresolved_gaps || []).slice(0, 6).join("|") || "none";
  const next = (summary.next_actions || []).slice(0, 6).join("|") || "none";
  const logic = summary.logic_hypothesis?.status || "unknown";
  const criticalPath = summary.logic_hypothesis?.critical_path?.status || "unknown";
  const capture = summary.capture_completeness?.status || "unknown";
  const phaseEdgeCount = (summary.logic_hypothesis?.phase_edges || []).length;
  const logicTrace = candidateLogicTraceMarkdownSummary(summary.logic_hypothesis?.agent_logic_trace);
  const materializations = signatureParamMaterializationsMarkdownSummary(
    summary.signature_param_materializations || []
  );
  const refs = [
    ...(summary.key_refs?.url_objects || []).slice(0, 2),
    ...(summary.key_refs?.search_params || []).slice(0, 2),
    ...(summary.key_refs?.buffers || []).slice(0, 3)
  ].join("|") || "none";
  const source = (summary.source_windows || []).slice(0, 3).map((window) => window.ref || "").filter(Boolean).join("|") || "none";
  return `chain=${chain} evidence=${summary.evidence_profile || "unknown"} readiness=${summary.readiness || "unknown"} capture=${capture} logic=${logic} critical_path=${criticalPath} phase_edges=${phaseEdgeCount} logic_trace=${logicTrace} dataflow=${summary.dataflow_status || "unknown"} params=${params} runtime=${runtime} source_hooks=${sourceHooks} runtime_hooks=${runtimeHooks} materializations=${materializations} refs=${refs} sources=${source} attachment=${summary.attachment?.observed ? "observed" : "missing"} gaps=${gaps} next=${next}`;
}

function hypothesisSummaryMarkdown(summary) {
  const patterns = Object.entries(summary?.primary_pattern_counts || {})
    .map(([pattern, count]) => `${pattern}:${count}`)
    .join(",") || "none";
  return `strong=${summary?.strong_chain_count ?? 0} partial=${summary?.partial_chain_count ?? 0} needs_more=${summary?.needs_more_evidence_count ?? 0} gaps=${summary?.unresolved_hypothesis_gap_count ?? 0} patterns=${patterns}`;
}

function blockingGapSummaryMarkdown(summary) {
  const top = (summary?.top_blockers || [])
    .slice(0, 6)
    .map((blocker) => `${blocker.gap || "unknown"}:${blocker.count ?? 0}[${blocker.priority || "medium"}]`)
    .join(",") || "none";
  const actions = Object.entries(summary?.action_counts || {})
    .map(([action, count]) => `${action}:${count}`)
    .join(",") || "none";
  return `total=${summary?.total_observation_count ?? 0} top=${top} actions=${actions}`;
}

function readinessSummaryMarkdown(summary) {
  return `ready=${summary?.ready_count ?? 0} partial=${summary?.partial_count ?? 0} insufficient=${summary?.insufficient_count ?? 0} avg=${summary?.average_score ?? 0}`;
}

function analysisReadinessMarkdownSummary(readiness) {
  if (!readiness) return "none";
  const summary = readiness.summary || {};
  const checklist = (readiness.checklist || [])
    .slice(0, 8)
    .map((item) => `${item.item || "unknown"}:${item.status || "unknown"}`)
    .join(",") || "none";
  return `${summary.status || "unknown"} score=${summary.score ?? 0} passed=${summary.passed_count ?? 0} partial=${summary.partial_count ?? 0} failed=${summary.failed_count ?? 0} primary=${summary.primary_next_action || "unknown"} checklist=${checklist}`;
}

function operationSubgraphNodeMarkdownSummary(node) {
  const parts = [node?.api || "unknown"];
  const operators = (node?.source_operators || []).slice(0, 4).join("|");
  const constants = (node?.source_constants || []).slice(0, 4).join("|");
  const inputs = (node?.input_refs || []).slice(0, 4).join("|");
  const result = node?.result_ref || "";
  const outputs = (node?.output_refs || []).slice(0, 4).join("|");
  const sources = (node?.source_refs || []).slice(0, 3).join("|");
  if (operators) parts.push(`ops=${operators}`);
  if (constants) parts.push(`constants=${constants}`);
  if (sources) parts.push(`src=${sources}`);
  if (inputs) parts.push(`inputs=${inputs}`);
  if (result) parts.push(`result=${result}`);
  if (outputs) parts.push(`outputs=${outputs}`);
  return parts.join(" ");
}

function operationSubgraphEdgesMarkdownSummary(edges) {
  return (edges || [])
    .slice(0, 6)
    .map((edge) => `${edge.from || "unknown"}->${edge.to || "unknown"}:${edge.via_ref || edge.relation || "related"}`)
    .join("|") || "none";
}

function operationSubgraphDetailsMarkdownSummary(graph) {
  const details = (graph?.operation_subgraphs || [])
    .slice(0, 4)
    .map((subgraph) => {
      const nodes = (subgraph.nodes || [])
        .slice(0, 4)
        .map(operationSubgraphNodeMarkdownSummary)
        .join("->") || "nodes=none";
      const outputs = (subgraph.output_refs || []).slice(0, 6).join("|") || "none";
      const edges = operationSubgraphEdgesMarkdownSummary(subgraph.edges || []);
      return `${subgraph.chain_id || "unknown"}:${subgraph.stage || "unknown"} attached=${subgraph.attached_node_id || "none"} outputs=${outputs} edges=${edges} nodes=${nodes} pattern=${subgraph.pattern || "unknown"}`;
    })
    .join(";") || "none";
  return details;
}

function generationGraphMarkdownSummary(graph) {
  if (!graph) return "none";
  const ops = (graph.operation_subgraphs || [])
    .slice(0, 6)
    .map((subgraph) => `${subgraph.pattern || "unknown"}:${subgraph.operation_count ?? 0}`)
    .join(",") || "none";
  const flow = graph.dataflow_summary || {};
  const bridges = (flow.bridge_links || []).length
    ? ` bridges=${(flow.bridge_links || []).length}`
    : "";
  const boundary = (flow.encoding_boundary_links || []).length
    ? ` boundary=${(flow.encoding_boundary_links || []).length}`
    : "";
  const unresolved = unresolvedOutputBridgesMarkdownSummary(flow.unresolved_output_bridges || []);
  const opDetails = operationSubgraphDetailsMarkdownSummary(graph);
  return `nodes=${graph.node_count ?? 0} edges=${graph.edge_count ?? 0} unresolved=${graph.unresolved_edge_count ?? 0} opgraphs=${(graph.operation_subgraphs || []).length} ops=${ops} flow=${flow.status || "unknown"} links=${flow.vmp_output_link_count ?? 0} request=${flow.attachment_to_request_link_observed ? "true" : "false"}${bridges}${boundary} entry=${graph.entry_node_id || "none"} exit=${graph.exit_node_id || "none"} readiness=${graph.readiness_status || "unknown"} next=${graph.primary_next_probe || "none"}${unresolved} op_details=${opDetails}`;
}

function reconstructionRecipeOpsMarkdownSummary(programs) {
  return (programs || [])
    .slice(0, 4)
    .map((program) => `${program.chain_id || program.opgraph_id || "unknown"}:${(program.lines || []).slice(0, 2).join("|") || "none"}`)
    .join(";") || "none";
}

function reconstructionRecipeInputsMarkdownSummary(programs) {
  return (programs || [])
    .flatMap((program) => program.input_bindings || [])
    .slice(0, 6)
    .map((binding) => {
      const requestInputs = (binding.request_input_categories || []).slice(0, 3).join("|") || "none";
      return `${binding.input_ref || "unknown"}->${binding.operation_id || "unknown"}[${binding.role || "unknown"} from=${binding.source_stage || "unknown"} request=${requestInputs}]`;
    })
    .join("|") || "none";
}

function reconstructionRecipeOutputsMarkdownSummary(programs) {
  return (programs || [])
    .flatMap((program) => program.output_bindings || [])
    .slice(0, 6)
    .map((binding) => {
      const requestNodes = (binding.request_node_ids || []).slice(0, 3).join("|") || "none";
      return `${binding.output_ref || "unknown"}<-${binding.operation_id || "unknown"}[${binding.relation || "unknown"} to=${binding.target_stage || "unknown"} request=${requestNodes}]`;
    })
    .join("|") || "none";
}

function reconstructionRecipeMaterializationsMarkdownSummary(programs) {
  return (programs || [])
    .flatMap((program) => program.lines || [])
    .slice(0, 8)
    .join("|") || "none";
}

function reconstructionRecipeAlgorithmMarkdownSummary(outline) {
  return (outline?.lines || [])
    .slice(0, 6)
    .join("|") || "none";
}

function reconstructionRecipeMarkdownSummary(recipe) {
  if (!recipe) return "none";
  const stages = (recipe.stage_chain || []).slice(0, 12).join("->") || "none";
  const ops = reconstructionRecipeOpsMarkdownSummary(recipe.operation_programs || []);
  const inputs = reconstructionRecipeInputsMarkdownSummary(recipe.operation_programs || []);
  const outputs = reconstructionRecipeOutputsMarkdownSummary(recipe.operation_programs || []);
  const algorithm = reconstructionRecipeAlgorithmMarkdownSummary(recipe.algorithm_outline);
  const materializations = reconstructionRecipeMaterializationsMarkdownSummary(recipe.materialization_programs || []);
  const algorithmText = algorithm !== "none" ? ` alg=${algorithm}` : "";
  const inputText = inputs !== "none" ? ` inputs=${inputs}` : "";
  const outputText = outputs !== "none" ? ` outputs=${outputs}` : "";
  const materializationText = materializations !== "none" ? ` materials=${materializations}` : "";
  const outputLinks = (recipe.attachment?.output_links || [])
    .slice(0, 6)
    .map((link) => link.output_ref || link.to_node_id || "")
    .filter(Boolean)
    .join("|") || "none";
  const requestLinks = (recipe.attachment?.request_links || [])
    .slice(0, 6)
    .map((link) => `${link.from_node_id || "unknown"}->${link.to_node_id || "unknown"}`)
    .join("|") || "none";
  return `${recipe.status || "unknown"} stages=${stages} ops=${ops}${algorithmText}${materializationText}${inputText}${outputText} attach=${recipe.attachment?.status || "unknown"} flow=${recipe.dataflow_status || "unknown"} output_links=${outputLinks} request_links=${requestLinks} gaps=${(recipe.evidence_gaps || []).join("|") || "none"} next=${(recipe.next_actions || []).slice(0, 6).join("|") || "none"}`;
}

function refGapPlanMarkdownSummary(refGapPlan) {
  return (refGapPlan || [])
    .slice(0, 4)
    .map((entry) => `${entry.from_stage || "unknown"}->${entry.to_stage || "unknown"}:${entry.gap || "unknown"}:${(entry.expected_ref_types || []).slice(0, 6).join("|") || "unknown"}`)
    .join(";") || "none";
}

function vmpStateModelMarkdownSummary(model) {
  if (!model) return "none";
  return `${model.status || "unknown"} handler_table=${model.handler_table || "unknown"} bytecode_pc=${model.bytecode_pc || "unknown"} dispatch=${model.dispatch_boundary || "unknown"} state_refs=${(model.state_refs || []).slice(0, 4).join("|") || "none"} register_refs=${(model.register_refs || []).slice(0, 4).join("|") || "none"} handler_returns=${(model.handler_return_refs || []).slice(0, 4).join("|") || "none"} linkage=${model.linkage?.register_to_integer_mixing || "unknown"}/${model.linkage?.handler_return_to_integer_mixing || "unknown"} gaps=${(model.unresolved_gaps || []).slice(0, 6).join("|") || "none"} next=${(model.next_actions || []).slice(0, 6).join("|") || "none"}`;
}

function unresolvedOutputBridgesMarkdownSummary(bridges) {
  if (!(bridges || []).length) return "";
  const summary = (bridges || [])
    .slice(0, 4)
    .map((bridge) => {
      const refs = (bridge.candidate_output_refs || []).slice(0, 4).join("|") || "none";
      const ops = (bridge.last_operations || [])
        .slice(0, 4)
        .map((op) => `${op.api || "unknown"}@${op.seq ?? "none"}`)
        .join("->") || "none";
      const missing = (bridge.missing_refs || []).slice(0, 4).join("|") || "none";
      return `${bridge.opgraph_id || "unknown"}:${bridge.from_node_id || "unknown"}->${bridge.to_node_id || "unknown"} refs=${refs} ops=${ops} missing=${missing}`;
    })
    .join(";");
  return ` unresolved_bridges=${summary}`;
}

function generationPathMarkdownSummary(pathSteps) {
  return (pathSteps || [])
    .slice(0, 8)
    .map((step) => {
      const apis = (step.apis || []).slice(0, 3).join("|") || "none";
      const distance = step.distance_to_signed_request ?? "unknown";
      const relation = step.param_relation || "unknown";
      const source = (step.source_evidence || [])[0];
      const sourceText = source
        ? `${source.ref}@${source.content_path || "none"}:${source.line_start ?? "none"}-${source.line_end ?? "none"}`
        : "none";
      return `${step.order ?? "?"}:${step.stage || "unknown"}[${apis} d=${distance} relation=${relation} src=${sourceText}]`;
    })
    .join("->") || "none";
}

function captureFocusReason(action, stages, gaps, attachmentEvidence = null) {
  if (action === "capture_url_search_params_mutation_or_header_set") {
    if (
      attachmentEvidence?.mode === "request_anchor_fallback" &&
      attachmentEvidence?.request_anchor_observed &&
      !attachmentEvidence?.direct_runtime_api_observed
    ) {
      return "direct_signature_mutation_runtime_api_missing";
    }
    return "signature_mutation_missing_runtime_or_source_context";
  }
  if (action === "expand_vmp_runtime_hooks") {
    return (stages || []).some((stage) => ["dynamic_dispatch", "integer_mixing", "text_or_string_decode", "byte_buffer"].includes(stage))
      ? "vmp_stage_runtime_api_missing"
      : "runtime_api_missing";
  }
  if (action === "capture_or_retrieve_script_asset") return "source_context_missing";
  if (action === "capture_object_ids_for_data_links") return "data_link_refs_missing";
  if (action === "capture_string_encoding_boundary_refs") return "string_encoding_boundary_refs_missing";
  if (action === "capture_vmp_register_state_refs") return "vmp_register_state_refs_missing";
  if (action === "prefer_pre_request_capture_window") return "post_request_activity";
  return (gaps || [])[0] || "review_capture_gap";
}

function captureFocusPriority(action, stages) {
  if (action === "capture_url_search_params_mutation_or_header_set") return "high";
  if (action === "expand_vmp_runtime_hooks" &&
    (stages || []).some((stage) => ["dynamic_dispatch", "integer_mixing", "signature_mutation"].includes(stage))) {
    return "high";
  }
  if (action === "capture_or_retrieve_script_asset") return "medium";
  if (action === "capture_string_encoding_boundary_refs") return "high";
  if (action === "capture_vmp_register_state_refs") return "high";
  return "medium";
}

function captureFocusGapsForAction(action, gaps) {
  if (action === "capture_url_search_params_mutation_or_header_set") {
    return (gaps || []).filter((gap) => [
      "runtime_api_not_observed",
      "source_context_not_available"
    ].includes(gap));
  }
  if (action === "expand_vmp_runtime_hooks") {
    return (gaps || []).filter((gap) => gap === "runtime_api_not_observed");
  }
  if (action === "capture_or_retrieve_script_asset") {
    return (gaps || []).filter((gap) => gap === "source_context_not_available");
  }
  if (action === "capture_object_ids_for_data_links") {
    return (gaps || []).filter((gap) => [
      "data_refs_not_observed",
      "source_only_edge",
      "temporal_only_edge",
      "nearby_runtime_only_edge",
      "missing_generation_edge"
    ].includes(gap));
  }
  if (action === "capture_vmp_register_state_refs") {
    const vmpOutputGap = (gaps || []).some((gap) => [
      "vmp_output_ref_to_signature_not_observed",
      "vmp_output_not_linked_to_signature"
    ].includes(gap));
    return (gaps || []).filter((gap) => [
      "nearby_runtime_only_edge",
      "vmp_output_ref_to_signature_not_observed",
      "vmp_output_not_linked_to_signature",
      "missing_generation_edge"
    ].includes(gap) || (vmpOutputGap && gap === "temporal_only_edge"));
  }
  if (action === "capture_string_encoding_boundary_refs") {
    const boundaryGap = (gaps || []).some((gap) => [
      "vmp_output_ref_to_signature_not_observed",
      "vmp_output_not_linked_to_signature",
      "signature_to_request_link_not_observed"
    ].includes(gap));
    return (gaps || []).filter((gap) => [
      "vmp_output_ref_to_signature_not_observed",
      "vmp_output_not_linked_to_signature",
      "signature_to_request_link_not_observed",
      "nearby_runtime_only_edge"
    ].includes(gap) || (boundaryGap && gap === "temporal_only_edge"));
  }
  if (action === "prefer_pre_request_capture_window") {
    return (gaps || []).filter((gap) => gap === "post_request_activity");
  }
  return gaps || [];
}

function captureFocusHookTargets(action, stages) {
  const targets = [];
  const stageSet = new Set(stages || []);
  function add(values) {
    for (const value of values) {
      if (!targets.includes(value)) targets.push(value);
    }
  }

  if (action === "capture_url_search_params_mutation_or_header_set") {
    add([
      "URLSearchParams.set",
      "URLSearchParams.append",
      "URL.search.set",
      "URL.href.set",
      "Headers.set",
      "XMLHttpRequest.setRequestHeader"
    ]);
  } else if (action === "expand_vmp_runtime_hooks") {
    if (stageSet.has("dynamic_dispatch")) {
      add([
        "Reflect.apply",
        "Function.prototype.call",
        "Function.prototype.apply",
        "Proxy.get"
      ]);
    }
    if (stageSet.has("integer_mixing")) {
      add([
        "Bitwise.xor",
        "Bitwise.and",
        "Bitwise.or",
        "Shift.left"
      ]);
    }
    if (stageSet.has("signature_mutation")) {
      add([
        "URLSearchParams.set",
        "URLSearchParams.append",
        "URL.search.set",
        "URL.href.set"
      ]);
    }
    if (!targets.length) {
      add([
        "Reflect.apply",
        "Function.prototype.call",
        "Bitwise.xor"
      ]);
    }
  } else if (action === "capture_or_retrieve_script_asset") {
    add([
      "script.source.asset",
      "stack.asset_id",
      "source_context.window"
    ]);
  } else if (action === "capture_object_ids_for_data_links") {
    add([
      "object_ref.url_object",
      "object_ref.search_params",
      "value_ref.url_shape",
      "value_ref.buffer"
    ]);
  } else if (action === "capture_string_encoding_boundary_refs") {
    add([
      "TextEncoder.encode",
      "TextDecoder.decode",
      "String.fromCharCode",
      "String.prototype.charCodeAt",
      "btoa",
      "atob",
      "encodeURIComponent",
      "URLSearchParams.toString"
    ]);
  } else if (action === "capture_vmp_register_state_refs") {
    add([
      "vmp.state_object_id",
      "vmp.register_ref",
      "vmp.handler.return_ref",
      "Bitwise.input_ref"
    ]);
  }

  return targets.slice(0, 12);
}

function captureFocusObjectRefRank(action, ref) {
  const value = String(ref || "");
  if (action === "capture_vmp_register_state_refs") {
    if (value.startsWith("state_object:")) return 0;
    if (value.startsWith("target:")) return 1;
    if (value.startsWith("arguments_list:")) return 2;
    if (value.startsWith("subject:")) return 3;
    if (value.startsWith("this:")) return 4;
    return 10;
  }
  if (action !== "capture_object_ids_for_data_links") return 10;
  if (value.startsWith("url_object:")) return 0;
  if (value.startsWith("search_params:")) return 1;
  if (/^(?:typed_array|array_buffer|data_view):/.test(value)) return 2;
  if (value.startsWith("network_request:")) return 3;
  return 10;
}

function captureFocusValueRefRank(action, ref) {
  const value = String(ref || "");
  if (action === "capture_vmp_register_state_refs") {
    if (value.startsWith("register:")) return 0;
    if (value.startsWith("handler_return:")) return 1;
    if (value.startsWith("number:")) return 2;
    return 10;
  }
  if (action !== "capture_object_ids_for_data_links") return 10;
  if (value.startsWith("target_params:")) return 0;
  if (value.startsWith("url_shape:")) return 1;
  if (/(?:^|:)buffer/.test(value)) return 2;
  return 10;
}

function uniquePrioritizedLimited(values, limit, rankFn) {
  const items = [];
  const seen = new Set();
  let index = 0;
  for (const value of values || []) {
    if (!value || seen.has(value)) {
      index += 1;
      continue;
    }
    seen.add(value);
    items.push({value, index, rank: rankFn(value)});
    index += 1;
  }
  return items
    .sort((left, right) => left.rank - right.rank || left.index - right.index)
    .slice(0, limit)
    .map((item) => item.value);
}

function captureFocusObjectRefs(action, refs) {
  const limit = action === "capture_vmp_register_state_refs" ? 16 : 8;
  return uniquePrioritizedLimited(refs, limit, (ref) => captureFocusObjectRefRank(action, ref));
}

function captureFocusValueRefs(action, refs) {
  const limit = action === "capture_vmp_register_state_refs" ? 24 : 8;
  return uniquePrioritizedLimited(refs, limit, (ref) => captureFocusValueRefRank(action, ref));
}

function expectedRefTypesForStage(stage) {
  if (["input_url", "request_construction"].includes(stage)) {
    return ["object_ref.url_object", "value_ref.url_shape"];
  }
  if (["signature_mutation", "url_encoding"].includes(stage)) {
    return [
      "object_ref.url_object",
      "object_ref.search_params",
      "value_ref.url_shape",
      "URLSearchParams.toString.result_ref"
    ];
  }
  if (["request_headers", "request_body", "signed_request"].includes(stage)) {
    return ["network_request_ref", "url_ref", "headers_ref", "body_ref"];
  }
  if (stage === "dynamic_dispatch") {
    return ["vmp.state_object_id", "vmp.register_ref", "vmp.handler.return_ref"];
  }
  if (["integer_mixing", "hash_or_digest"].includes(stage)) {
    return ["Bitwise.input_ref", "Bitwise.result_ref"];
  }
  if (["byte_buffer", "text_or_string_decode"].includes(stage)) {
    return ["object_ref.array_buffer", "object_ref.typed_array", "value_ref.buffer"];
  }
  if (stage === "string_transform") {
    return ["string_ref", "StringAdd.result_ref"];
  }
  return [];
}

function expectedRefTypesForGap(gap) {
  const refs = [
    ...expectedRefTypesForStage(gap?.from_stage || ""),
    ...expectedRefTypesForStage(gap?.to_stage || "")
  ];
  return uniqueLimited(refs.length ? refs : ["shared_object_ref", "shared_value_ref"], 12);
}

function stageStepByOrder(parameter, order) {
  return (parameter?.generation_path || []).find((step) => step.order === order) || null;
}

function sourceRefsForGapPlan(gap, leftStep, rightStep) {
  return uniqueLimited([
    ...(gap?.source_refs || []),
    ...generationStepSourceRefs(leftStep || {}),
    ...generationStepSourceRefs(rightStep || {})
  ], 8);
}

function refGapPlanForGenerationGap(parameter, action, gap) {
  const leftStep = stageStepByOrder(parameter, gap?.from_order);
  const rightStep = stageStepByOrder(parameter, gap?.to_order);
  const stages = [gap?.from_stage, gap?.to_stage].filter(Boolean);
  return {
    param: parameter?.param || "",
    endpoint: parameter?.endpoint || "",
    action,
    from_order: gap?.from_order ?? null,
    to_order: gap?.to_order ?? null,
    from_stage: gap?.from_stage || "",
    to_stage: gap?.to_stage || "",
    gap: gap?.gap || "missing_generation_edge",
    reason: gap?.reason || "",
    priority: gap?.priority || "medium",
    required_link: "shared_runtime_ref",
    expected_ref_types: expectedRefTypesForGap(gap),
    hook_targets: captureFocusHookTargets(action, stages),
    observed_refs: {
      source_refs: sourceRefsForGapPlan(gap, leftStep, rightStep),
      object_refs: uniqueLimited([
        ...(gap?.object_refs || []),
        ...(leftStep?.object_refs || []),
        ...(rightStep?.object_refs || [])
      ], 8),
      value_refs: uniqueLimited([
        ...(gap?.value_refs || []),
        ...(leftStep?.value_refs || []),
        ...(rightStep?.value_refs || [])
      ], 8)
    }
  };
}

function refGapPlanKey(plan) {
  return [
    plan?.param || "",
    plan?.action || "",
    plan?.from_order ?? "",
    plan?.to_order ?? "",
    plan?.from_stage || "",
    plan?.to_stage || "",
    plan?.gap || ""
  ].join("\u0000");
}

function addRefGapPlanToFocusItem(item, parameter, action, gap) {
  if (!item || !gap || !action) return;
  if (!item.ref_gap_plan) item.ref_gap_plan = [];
  if (!item.ref_gap_plan_keys) item.ref_gap_plan_keys = new Set();
  const plan = refGapPlanForGenerationGap(parameter, action, gap);
  const key = refGapPlanKey(plan);
  if (item.ref_gap_plan_keys.has(key)) return;
  item.ref_gap_plan_keys.add(key);
  item.ref_gap_plan.push(plan);
}

function observedStageCandidatesForRuntimeApi(api, stageChain = []) {
  const family = vmpFamilyForApi(api);
  const stagesByFamily = {
    base64: ["text_or_string_decode"],
    text_codec: ["text_or_string_decode", "byte_buffer"],
    json_serialization: ["json_serialization"],
    hash_crypto: ["hash_or_digest"],
    byte_buffer: ["byte_buffer"],
    typed_array: ["byte_buffer", "text_or_string_decode"],
    array_table: ["dynamic_dispatch"],
    dynamic_dispatch: ["dynamic_dispatch"],
    collection_table: ["dynamic_dispatch"],
    proxy_trap: ["dynamic_dispatch"],
    int_bitwise: ["integer_mixing"],
    int_arithmetic: ["integer_mixing"],
    string_decode: ["text_or_string_decode"],
    string_transform: ["string_transform"],
    regexp_probe: ["dynamic_dispatch"],
    url_encoding: ["signature_mutation", "request_construction"],
    anti_debug_timing: ["dynamic_dispatch"],
    source_probe: ["dynamic_dispatch"],
    stack_probe: ["dynamic_dispatch"],
    exception_probe: ["dynamic_dispatch"]
  };
  const mapped = stagesByFamily[family] || [];
  const chain = stageChain || [];
  const observed = mapped.filter((stage) => chain.includes(stage));
  return observed.length ? observed : mapped.length ? mapped : chain;
}

function addObservedHookStages(index, api, stages) {
  if (!api) return;
  const existing = index.get(api) || new Set();
  for (const stage of stages || []) {
    if (stage) existing.add(stage);
  }
  index.set(api, existing);
}

function buildObservedHookStageIndex(parameters) {
  const index = new Map();
  for (const parameter of parameters || []) {
    for (const step of parameter.generation_path || []) {
      for (const api of step.apis || []) {
        addObservedHookStages(index, api, [step.stage]);
      }
    }
    const summary = parameter.candidate_generation_summary || {};
    for (const api of summary.runtime_apis || []) {
      addObservedHookStages(
        index,
        api,
        observedStageCandidatesForRuntimeApi(api, summary.stage_chain || parameter.confirmed_stages || [])
      );
    }
  }
  return index;
}

function refsObservedForPseudoHookTarget(target, refs = {}) {
  const objectRefs = refs.object_refs || [];
  const valueRefs = refs.value_refs || [];
  if (target === "object_ref.url_object") {
    return objectRefs.filter((ref) => String(ref).startsWith("url_object:"));
  }
  if (target === "object_ref.search_params") {
    return objectRefs.filter((ref) => String(ref).startsWith("search_params:"));
  }
  if (target === "value_ref.url_shape") {
    return valueRefs.filter((ref) => String(ref).startsWith("url_shape:"));
  }
  if (target === "value_ref.buffer") {
    return [
      ...objectRefs.filter((ref) => /^(?:array_buffer|typed_array|data_view):/.test(String(ref))),
      ...valueRefs.filter((ref) => /(?:^|:)buffer/.test(String(ref)))
    ];
  }
  if (target === "vmp.state_object_id") {
    return objectRefs.filter((ref) => String(ref).startsWith("state_object:"));
  }
  if (target === "vmp.register_ref") {
    return valueRefs.filter((ref) => String(ref).startsWith("register:"));
  }
  if (target === "vmp.handler.return_ref") {
    return valueRefs.filter((ref) => String(ref).startsWith("handler_return:"));
  }
  if (target === "Bitwise.input_ref") {
    return valueRefs.filter((ref) => /^(?:register:|number:)/.test(String(ref)));
  }
  return [];
}

function captureFocusHookTargetStatuses(hookTargets, stages, observedHookStages, refs = {}) {
  const focusStages = new Set(stages || []);
  return (hookTargets || []).map((target) => {
    const observedStages = uniqueLimited([...(observedHookStages.get(target) || [])], 8);
    const observedInFocusStage = observedStages.some((stage) => focusStages.has(stage));
    const observedRefs = uniqueLimited(refsObservedForPseudoHookTarget(target, refs), 8);
    const status = observedInFocusStage
      ? "observed_in_focus_stage"
      : observedStages.length
        ? "observed_elsewhere"
        : observedRefs.length
          ? "observed_in_focus_refs"
          : "missing";
    return {
      target,
      status,
      observed_stages: observedStages,
      ...(observedRefs.length ? {observed_refs: observedRefs} : {})
    };
  });
}

function captureFocusRank(item) {
  const priorityRank = {high: 0, medium: 1, low: 2};
  const actionRank = {
    capture_url_search_params_mutation_or_header_set: 0,
    expand_vmp_runtime_hooks: 1,
    capture_string_encoding_boundary_refs: 2,
    capture_vmp_register_state_refs: 3,
    capture_or_retrieve_script_asset: 4,
    capture_object_ids_for_data_links: 5,
    prefer_pre_request_capture_window: 6
  };
  return [
    priorityRank[item.priority] ?? 9,
    item.primary_readiness_action ? 0 : 1,
    actionRank[item.action] ?? 9,
    String(item.action || "")
  ];
}

function compareCaptureFocus(left, right) {
  const leftRank = captureFocusRank(left);
  const rightRank = captureFocusRank(right);
  for (let index = 0; index < leftRank.length; index += 1) {
    if (leftRank[index] < rightRank[index]) return -1;
    if (leftRank[index] > rightRank[index]) return 1;
  }
  return 0;
}

function shouldIncludeParameterPathRefsInFocus(action) {
  return action === "capture_object_ids_for_data_links" ||
    action === "capture_string_encoding_boundary_refs" ||
    action === "capture_vmp_register_state_refs";
}

function addParameterPathRefsToFocusItem(item, parameter, action) {
  if (!shouldIncludeParameterPathRefsInFocus(action)) return;
  for (const step of parameter?.generation_path || []) {
    for (const source of step.source_evidence || []) {
      if (source.ref) item.source_refs.add(source.ref);
    }
    for (const ref of step.object_refs || []) item.object_refs.add(ref);
    for (const ref of step.value_refs || []) item.value_refs.add(ref);
  }
}

function shouldSkipCandidateFocusAction(action) {
  return !action ||
    action === "review_source_refs" ||
    action === "review_agent_pack" ||
    action === "review_step_source_context";
}

function candidateFocusActions(parameter) {
  const attachment = parameter?.candidate_generation_summary?.attachment;
  const attachmentCaptureAction = attachment?.evidence_mode === "request_anchor_fallback" &&
      attachment.request_anchor_observed &&
      !attachment.direct_runtime_api_observed &&
      (attachment.missing_runtime_hooks || []).length
    ? "capture_url_search_params_mutation_or_header_set"
    : "";
  return uniqueLimited([
    ...(parameter.candidate_generation_summary?.next_actions || []),
    ...(parameter.generation_graph?.dataflow_summary?.next_actions || []),
    parameter.analysis_readiness?.summary?.primary_next_action,
    parameter.analysis_readiness?.next_probe_plan?.action,
    attachmentCaptureAction
  ].filter((action) => !shouldSkipCandidateFocusAction(action)), 16);
}

function candidateFocusGaps(parameter) {
  return uniqueLimited([
    ...(parameter.candidate_generation_summary?.unresolved_gaps || []),
    ...(parameter.candidate_generation_summary?.dataflow_gaps || []),
    ...(parameter.generation_graph?.dataflow_summary?.gaps || []),
    ...(parameter.generation_edge_gaps || []).map((gap) => gap.gap).filter(Boolean)
  ], 16);
}

function createCaptureFocusItem(action) {
  return {
    action,
    params: new Set(),
    stages: new Set(),
    gaps: new Set(),
    endpoints: new Set(),
    source_refs: new Set(),
    object_refs: new Set(),
    value_refs: new Set(),
    ref_gap_plan: [],
    ref_gap_plan_keys: new Set(),
    primary_readiness_params: new Set(),
    primary_readiness_action: false,
    attachment_evidence: null
  };
}

function markPrimaryReadinessFocus(item, parameter, action) {
  const primaryAction = parameter?.analysis_readiness?.summary?.primary_next_action;
  if (!primaryAction || action !== primaryAction) return;
  item.primary_readiness_action = true;
  if (parameter?.param) item.primary_readiness_params.add(parameter.param);
}

function candidateFocusStages(parameter) {
  return uniqueLimited([
    ...(parameter.candidate_generation_summary?.stage_chain || []),
    ...(parameter.confirmed_stages || []),
    ...(parameter.generation_path || []).map((step) => step.stage || "").filter(Boolean)
  ], 16);
}

function addCandidateGenerationRefsToFocusItem(item, parameter) {
  const summary = parameter.candidate_generation_summary || {};
  const keyRefs = summary.key_refs || {};
  for (const source of summary.source_windows || []) {
    if (source.ref) item.source_refs.add(source.ref);
  }
  for (const ref of [
    ...(keyRefs.url_objects || []),
    ...(keyRefs.search_params || []),
    ...(keyRefs.buffers || []),
    ...(keyRefs.network_requests || []),
    ...(summary.attachment?.object_refs || [])
  ]) {
    if (ref) item.object_refs.add(ref);
  }
  for (const ref of [
    ...(keyRefs.url_shapes || []),
    ...(keyRefs.target_params || []).map((param) => `target_params:${param}`),
    ...(summary.attachment?.value_refs || [])
  ]) {
    if (ref) item.value_refs.add(ref);
  }
}

function addAttachmentEvidenceToFocusItem(item, parameter, action) {
  if (action !== "capture_url_search_params_mutation_or_header_set") return;
  const evidence = attachmentEvidenceForProbePlan(parameter);
  if (!evidence ||
      evidence.mode !== "request_anchor_fallback" ||
      evidence.direct_runtime_api_observed ||
      !evidence.request_anchor_observed) {
    return;
  }
  item.attachment_evidence = item.attachment_evidence || evidence;
  item.stages.add("signature_mutation");
  item.stages.add(evidence.fallback_stage || "signed_request");
  item.gaps.add("runtime_api_not_observed");
  for (const ref of evidence.request_anchor_refs || []) {
    if (String(ref).startsWith("network_request:")) {
      item.object_refs.add(ref);
    } else {
      item.value_refs.add(ref);
    }
  }
}

function buildNextCaptureFocus(parameters) {
  const byAction = new Map();
  const observedHookStages = buildObservedHookStageIndex(parameters);
  for (const parameter of parameters || []) {
    const directWebCrypto = isDirectWebCryptoParameter(parameter);
    for (const step of parameter.generation_path || []) {
      const actions = filterDirectWebCryptoActions(step.recommended_next_actions || [], directWebCrypto)
        .filter((action) => action && action !== "review_step_source_context");
      if (!actions.length) continue;
      for (const action of actions) {
        const item = byAction.get(action) || createCaptureFocusItem(action);
        markPrimaryReadinessFocus(item, parameter, action);
        if (parameter.param) item.params.add(parameter.param);
        if (step.stage) item.stages.add(step.stage);
        if (parameter.endpoint) item.endpoints.add(parameter.endpoint);
        for (const gap of captureFocusGapsForAction(action, step.evidence_gaps || [])) item.gaps.add(gap);
        for (const source of step.source_evidence || []) {
          if (source.ref) item.source_refs.add(source.ref);
        }
        for (const ref of step.object_refs || []) item.object_refs.add(ref);
        for (const ref of step.value_refs || []) item.value_refs.add(ref);
        addParameterPathRefsToFocusItem(item, parameter, action);
        addAttachmentEvidenceToFocusItem(item, parameter, action);
        byAction.set(action, item);
      }
    }
    for (const gap of parameter.generation_edge_gaps || []) {
      const actions = filterDirectWebCryptoActions(gap.next_actions || [], directWebCrypto).filter(Boolean);
      for (const action of actions) {
        const item = byAction.get(action) || createCaptureFocusItem(action);
        markPrimaryReadinessFocus(item, parameter, action);
        if (parameter.param) item.params.add(parameter.param);
        if (gap.from_stage) item.stages.add(gap.from_stage);
        if (gap.to_stage) item.stages.add(gap.to_stage);
        if (gap.gap) item.gaps.add(gap.gap);
        if (parameter.endpoint) item.endpoints.add(parameter.endpoint);
        for (const ref of gap.source_refs || []) item.source_refs.add(ref);
        for (const ref of gap.object_refs || []) item.object_refs.add(ref);
        for (const ref of gap.value_refs || []) item.value_refs.add(ref);
        addRefGapPlanToFocusItem(item, parameter, action, gap);
        addParameterPathRefsToFocusItem(item, parameter, action);
        addAttachmentEvidenceToFocusItem(item, parameter, action);
        byAction.set(action, item);
      }
    }
    const dataflowActions = filterDirectWebCryptoActions(candidateFocusActions(parameter), directWebCrypto);
    const dataflowGaps = filterDirectWebCryptoGaps(candidateFocusGaps(parameter), directWebCrypto);
    const dataflowStages = candidateFocusStages(parameter);
    for (const action of dataflowActions) {
      const item = byAction.get(action) || createCaptureFocusItem(action);
      markPrimaryReadinessFocus(item, parameter, action);
      if (parameter.param) item.params.add(parameter.param);
      if (parameter.endpoint) item.endpoints.add(parameter.endpoint);
      for (const stage of dataflowStages) item.stages.add(stage);
      for (const gap of captureFocusGapsForAction(action, dataflowGaps)) item.gaps.add(gap);
      addParameterPathRefsToFocusItem(item, parameter, action);
      addCandidateGenerationRefsToFocusItem(item, parameter);
      addAttachmentEvidenceToFocusItem(item, parameter, action);
      byAction.set(action, item);
    }
  }

  return [...byAction.values()]
    .map((item) => {
      const stages = uniqueLimited([...item.stages], 12);
      const gaps = uniqueLimited([...item.gaps], 12);
      const action = item.action;
      const hookTargets = captureFocusHookTargets(action, stages);
      const objectRefs = captureFocusObjectRefs(action, [...item.object_refs]);
      const valueRefs = captureFocusValueRefs(action, [...item.value_refs]);
      return {
        action,
        priority: captureFocusPriority(action, stages),
        reason: captureFocusReason(action, stages, gaps, item.attachment_evidence),
        params: sortParamNames([...item.params]),
        primary_readiness_action: Boolean(item.primary_readiness_action),
        readiness_primary_params: sortParamNames([...item.primary_readiness_params]),
        stages,
        gaps,
        endpoints: uniqueLimited([...item.endpoints], 8),
        hook_targets: hookTargets,
        hook_target_statuses: captureFocusHookTargetStatuses(hookTargets, stages, observedHookStages, {
          object_refs: objectRefs,
          value_refs: valueRefs
        }),
        ...(item.ref_gap_plan.length ? {ref_gap_plan: item.ref_gap_plan.slice(0, 12)} : {}),
        source_refs: uniqueLimited([...item.source_refs], 8),
        object_refs: objectRefs,
        value_refs: valueRefs
      };
    })
    .sort(compareCaptureFocus)
    .slice(0, 12);
}

function isVmpRuntimeHookTarget(target) {
  return /^(?:Reflect\.|Function\.prototype\.|Proxy\.|Bitwise\.|Shift\.|Math\.|String\.|TextEncoder\.|TextDecoder\.|DataView\.|TypedArray\.|ArrayBuffer\.|Array\.prototype\.|Object\.|Map\.|Set\.|RegExp\.|JSON\.|Error\.|Exception\.|vmp\.)/.test(String(target || "")) ||
    ["btoa", "atob", "encodeURI", "encodeURIComponent", "decodeURI", "decodeURIComponent"].includes(String(target || ""));
}

function nativeRequirementLayer(action, targets) {
  if (action === "capture_or_retrieve_script_asset") return "asset";
  if (action === "capture_url_search_params_mutation_or_header_set") return "blink";
  if (action === "capture_unsigned_request_construction") return "blink";
  if (action === "capture_browser_network_request_anchor") return "browser";
  if ((targets || []).some(isVmpRuntimeHookTarget)) return "v8";
  if ((targets || []).some((target) => /^(?:URL|Headers|XMLHttpRequest|Request|object_ref\.url|object_ref\.search|network_request_ref|url_ref|headers_ref|body_ref)/.test(String(target || "")))) {
    return "blink";
  }
  return "mixed";
}

function implementationTargetForNativeHook(target, fallbackLayer) {
  const value = String(target || "");
  if (!value) return "";
  if (/^(?:script\.|stack\.|source_context\.)/.test(value)) return `asset:${value}`;
  if (isVmpRuntimeHookTarget(value)) return `v8:${value}`;
  if (/^(?:URL|Headers|XMLHttpRequest|Request|object_ref\.url|object_ref\.search|value_ref\.url|network_request_ref|url_ref|headers_ref|body_ref)/.test(value)) {
    return `blink:${value}`;
  }
  return `${fallbackLayer || "native"}:${value}`;
}

function isRefRequirementTarget(target) {
  return /(?:_ref|\.ref|object_ref\.|value_ref\.|network_request_ref|url_ref|headers_ref|body_ref|vmp\.)/.test(String(target || ""));
}

const IMPLEMENTED_SIGNATURE_ATTACHMENT_HOOKS = new Set([
  "URLSearchParams.set",
  "URLSearchParams.append",
  "URL.search.set",
  "URL.href.set",
  "Headers.set",
  "XMLHttpRequest.setRequestHeader"
]);

function isRequestAnchorRuntimeAbsenceFocus(focus, missingRefTypes) {
  if (focus?.action !== "capture_url_search_params_mutation_or_header_set") return false;
  if (focus?.reason !== "direct_signature_mutation_runtime_api_missing") return false;
  if ((missingRefTypes || []).length) return false;
  const gaps = focus?.gaps || [];
  return !gaps.length || gaps.every((gap) => gap === "runtime_api_not_observed");
}

function nativeRequirementHookStatuses(focus) {
  let statuses = focus?.hook_target_statuses || [];
  if (focus?.action === "expand_vmp_runtime_hooks") {
    statuses = statuses.filter((status) => isVmpRuntimeHookTarget(status.target));
  }
  return statuses;
}

function missingNativeHookTargets(focus, options = {}) {
  const targets = uniqueLimited(nativeRequirementHookStatuses(focus)
    .filter((status) => status.status !== "observed_in_focus_stage" && status.status !== "observed_in_focus_refs")
    .map((status) => status.target || "")
    .filter((target) => target && !isRefRequirementTarget(target)), 16);
  if (!isRequestAnchorRuntimeAbsenceFocus(focus, options.missingRefTypes)) {
    return targets;
  }
  return targets.filter((target) => !IMPLEMENTED_SIGNATURE_ATTACHMENT_HOOKS.has(target));
}

function observedNativeRequirementRefs(focus) {
  return {
    source_refs: uniqueLimited([
      ...(focus?.source_refs || []),
      ...(focus?.ref_gap_plan || []).flatMap((plan) => plan.observed_refs?.source_refs || [])
    ], 8),
    object_refs: uniqueLimited([
      ...(focus?.object_refs || []),
      ...(focus?.ref_gap_plan || []).flatMap((plan) => plan.observed_refs?.object_refs || [])
    ], 8),
    value_refs: uniqueLimited([
      ...(focus?.value_refs || []),
      ...(focus?.ref_gap_plan || []).flatMap((plan) => plan.observed_refs?.value_refs || [])
    ], 8)
  };
}

function missingRefTypesForNativeRequirement(focus) {
  const missingStatusRefs = nativeRequirementHookStatuses(focus)
    .filter((status) => status.status === "missing")
    .map((status) => status.target || "")
    .filter(isRefRequirementTarget);
  const expectedGapRefs = (focus?.ref_gap_plan || [])
    .flatMap((plan) => plan.expected_ref_types || []);
  return uniqueLimited([...missingStatusRefs, ...expectedGapRefs], 16);
}

function nativeSourceHint(path, reason) {
  return {path, reason};
}

function sourceHintsForNativeRequirement(action, nativeLayer, implementationInputs) {
  const inputs = implementationInputs || [];
  const hints = [];
  function add(path, reason) {
    if (!path || hints.some((hint) => hint.path === path)) return;
    hints.push(nativeSourceHint(path, reason));
  }

  if (nativeLayer === "v8") {
    if (action === "capture_vmp_register_state_refs" ||
        inputs.some((target) => String(target).startsWith("vmp.") || String(target) === "Bitwise.input_ref")) {
      add("chromium/src/v8/src/runtime/runtime-typedarray.cc", "vmp runtime ref serialization and dispatch result args");
      add("chromium/src/v8/src/builtins/arm64/builtins-arm64.cc", "arm64 dynamic dispatch boundary register capture");
      add("chromium/src/v8/src/runtime/runtime.h", "v8 runtime entry wiring");
      return hints;
    }
    if (inputs.some((target) => /^(?:Reflect\.|Function\.prototype\.)/.test(String(target)))) {
      add("chromium/src/v8/src/builtins/arm64/builtins-arm64.cc", "arm64 dynamic dispatch boundary register capture");
      add("chromium/src/v8/src/runtime/runtime-typedarray.cc", "vmp dispatch event serialization");
      add("chromium/src/v8/src/runtime/runtime.h", "v8 runtime entry wiring");
    }
    if (inputs.some((target) => /^(?:Bitwise\.|Shift\.|Math\.imul)/.test(String(target)))) {
      add("chromium/src/v8/src/builtins/number.tq", "numeric and bitwise builtin hook callsites");
      add("chromium/src/v8/src/builtins/builtins-number-gen.cc", "numeric result ref logging helpers");
      add("chromium/src/v8/src/interpreter/interpreter-generator.cc", "interpreter bitwise result ref logging");
    }
    if (inputs.some((target) => /^(?:String\.|TextEncoder\.|TextDecoder\.|encode|decode|btoa|atob|URLSearchParams\.toString)/.test(String(target)))) {
      add("chromium/src/v8/src/builtins/builtins-string.cc", "string boundary result ref logging");
      add("chromium/src/v8/src/builtins/builtins-string-gen.cc", "string construction runtime hook callsites");
      add("chromium/src/third_party/blink/renderer/modules/encoding/text_encoder.cc", "TextEncoder input and output ref logging");
    }
  } else if (nativeLayer === "blink") {
    add("chromium/src/third_party/blink/renderer/core/fetch/request.cc", "request construction and URL material refs");
    add("chromium/src/third_party/blink/renderer/core/fetch/headers.cc", "header mutation refs");
    add("chromium/src/third_party/blink/renderer/core/xmlhttprequest/xml_http_request.cc", "XHR request and header refs");
  } else if (nativeLayer === "browser") {
    add("chromium/src/content/browser/xtrace/xtrace_host_impl.cc", "browser-process trace persistence and network anchors");
  } else if (nativeLayer === "asset") {
    add("xtrace-gui/src/main/xtraceReport.js", "asset retrieval and source-window report analysis");
  }

  return hints.slice(0, 8);
}

function vmpFamilyFlagsForRequirement(stages, implementationInputs) {
  const values = [
    ...(stages || []),
    ...(implementationInputs || [])
  ].map(String);
  const flags = [];
  function add(flag) {
    if (!flags.includes(flag)) flags.push(flag);
  }
  if (values.some((value) => /dynamic_dispatch|Reflect\.|Function\.prototype\.|Proxy\.|vmp\./.test(value))) {
    add("--require-vmp-family dynamic_dispatch");
  }
  if (values.some((value) => /integer_mixing|Bitwise\.|Shift\.|Math\.imul/.test(value))) {
    add("--require-vmp-family int_bitwise");
  }
  if (values.some((value) => /text_or_string_decode|String\.|TextEncoder\.|TextDecoder\.|btoa|atob/.test(value))) {
    add("--require-vmp-family text_codec");
  }
  if (values.some((value) => /url_encoding|URLSearchParams\.toString|encodeURI|encodeURIComponent|decodeURI|decodeURIComponent/.test(value))) {
    add("--require-vmp-family url_encoding");
  }
  return flags;
}

function validatorHintsForNativeRequirement(stages, implementationInputs) {
  const flags = ["--schema-version 1"];
  if ((implementationInputs || []).some(isRefRequirementTarget)) {
    flags.push("--require-vmp-next-hook-fields");
  }
  flags.push(...vmpFamilyFlagsForRequirement(stages, implementationInputs));
  return {
    profile: "reverse",
    flags: uniqueLimited(flags, 12)
  };
}

function buildNativeCaptureRequirements(nextCaptureFocus) {
  return (nextCaptureFocus || [])
    .map((focus) => {
      const missingRefTypes = missingRefTypesForNativeRequirement(focus);
      const missingHookTargets = missingNativeHookTargets(focus, {missingRefTypes});
      const implementationInputs = uniqueLimited([...missingHookTargets, ...missingRefTypes], 24);
      if (!implementationInputs.length) return null;
      const nativeLayer = nativeRequirementLayer(focus.action, implementationInputs);
      const stages = uniqueLimited(focus.stages || [], 12);
      return {
        action: focus.action || "",
        priority: focus.priority || "medium",
        native_layer: nativeLayer,
        reason: focus.reason || "review_capture_gap",
        params: sortParamNames(focus.params || []),
        stages,
        gaps: uniqueLimited(focus.gaps || [], 12),
        endpoints: uniqueLimited(focus.endpoints || [], 8),
        missing_hook_targets: missingHookTargets,
        missing_ref_types: missingRefTypes,
        observed_refs: observedNativeRequirementRefs(focus),
        implementation_targets: implementationInputs
          .map((target) => implementationTargetForNativeHook(target, nativeLayer))
          .filter(Boolean),
        source_hints: sourceHintsForNativeRequirement(focus.action || "", nativeLayer, implementationInputs),
        validator_hints: validatorHintsForNativeRequirement(stages, implementationInputs)
      };
    })
    .filter(Boolean)
    .slice(0, 12);
}

function generationHypothesisStatus({
  evidenceLevel,
  chainQuality,
  directAttachmentObserved,
  preSignaturePatternObserved,
  primaryPattern,
  vmpStateObserved
}) {
  const strongPattern = primaryPattern?.confidence === "high";
  if (evidenceLevel === "high" &&
      chainQuality?.status === "strong" &&
      directAttachmentObserved &&
      preSignaturePatternObserved &&
      strongPattern) {
    return "strong_pre_signature_runtime_chain";
  }
  if (directAttachmentObserved && vmpStateObserved) {
    return "observed_vmp_state_runtime_chain";
  }
  if (directAttachmentObserved && preSignaturePatternObserved && primaryPattern) {
    return "partial_pre_signature_runtime_chain";
  }
  if (directAttachmentObserved) {
    return "attachment_observed_without_pre_signature_pattern";
  }
  if (primaryPattern) {
    return "vmp_pattern_without_attachment";
  }
  return "needs_more_evidence";
}

function buildGenerationHypothesis({
  parameter,
  evidenceLevel,
  generationPath,
  generationEdgeGaps,
  vmpOperationPatterns,
  chainQuality,
  recommendedActions
}) {
  const primaryPattern = (vmpOperationPatterns || [])[0] || null;
  const rawVmpStateTrace = parameter.vmp_state_trace || null;
  const vmpStateTrace = rawVmpStateTrace?.status && rawVmpStateTrace.status !== "missing"
    ? rawVmpStateTrace
    : null;
  const vmpStateObserved = vmpStateTrace?.status === "observed";
  const directAttachmentObserved = (generationPath || []).some((step) =>
    step.stage === "signature_mutation" && step.param_relation === "direct_observed"
  );
  const preSignaturePatternObserved = vmpStateObserved ||
    (vmpOperationPatterns || []).some((pattern) =>
      pattern.relation_to_signature_mutation === "before_signature_mutation"
    );
  const status = generationHypothesisStatus({
    evidenceLevel,
    chainQuality,
    directAttachmentObserved,
    preSignaturePatternObserved,
    primaryPattern,
    vmpStateObserved
  });
  return {
    status,
    evidence_level: evidenceLevel,
    chain_quality: chainQuality?.status || "unknown",
    direct_attachment_observed: directAttachmentObserved,
    pre_signature_pattern_observed: preSignaturePatternObserved,
    primary_pattern: primaryPattern?.pattern || "none",
    primary_pattern_confidence: primaryPattern?.confidence || "none",
    primary_operation_signature: primaryPattern?.operation_signature || "none",
    ...(vmpStateTrace ? {vmp_state_trace: vmpStateTrace} : {}),
    stage_chain: uniqueLimited((generationPath || []).map((step) => step.stage || "unknown"), 12),
    evidence_refs: uniqueLimited([
      primaryPattern?.chain_id,
      ...(primaryPattern?.source_context_refs || []),
      ...(primaryPattern?.shared_refs || []).slice(0, 4),
      ...(vmpStateTrace?.evidence_refs || []).slice(0, 8)
    ].filter(Boolean), 12),
    remaining_gaps: uniqueLimited([
      ...(parameter.evidence_gaps || []),
      ...(generationEdgeGaps || []).map((gap) => gap.gap || "").filter(Boolean)
    ], 12),
    next_actions: uniqueLimited(recommendedActions || [], 8)
  };
}

function incrementCount(map, key) {
  if (!key) return;
  map[key] = (map[key] || 0) + 1;
}

function buildHypothesisSummary(parameters) {
  const statusCounts = {};
  const primaryPatternCounts = {};
  let strongChainCount = 0;
  let partialChainCount = 0;
  let needsMoreEvidenceCount = 0;
  let unresolvedHypothesisGapCount = 0;
  for (const parameter of parameters || []) {
    const hypothesis = parameter.generation_hypothesis || {};
    const status = hypothesis.status || "unknown";
    incrementCount(statusCounts, status);
    if (hypothesis.primary_pattern && hypothesis.primary_pattern !== "none") {
      incrementCount(primaryPatternCounts, hypothesis.primary_pattern);
    }
    if (status === "strong_pre_signature_runtime_chain") strongChainCount += 1;
    if (status === "partial_pre_signature_runtime_chain") partialChainCount += 1;
    if (status === "needs_more_evidence") needsMoreEvidenceCount += 1;
    unresolvedHypothesisGapCount += (hypothesis.remaining_gaps || []).length;
  }
  return {
    status_counts: statusCounts,
    primary_pattern_counts: primaryPatternCounts,
    strong_chain_count: strongChainCount,
    partial_chain_count: partialChainCount,
    needs_more_evidence_count: needsMoreEvidenceCount,
    unresolved_hypothesis_gap_count: unresolvedHypothesisGapCount
  };
}

function stageForParameterGap(gap) {
  if (gap === "signature_mutation_not_observed") return "signature_mutation";
  if (gap === "unsigned_input_not_observed") return "input_url";
  if (gap === "material_source_not_observed") return "material_flow";
  if (gap === "data_links_not_observed") return "data_link";
  if (gap === "source_context_not_available") return "source_context";
  return "parameter";
}

function actionsForGapObservation(gap, stage) {
  const actions = [];
  if (stage === "signature_mutation" && [
    "runtime_api_not_observed",
    "source_context_not_available",
    "data_refs_not_observed"
  ].includes(gap)) {
    actions.push("capture_url_search_params_mutation_or_header_set");
  }
  if (gap === "runtime_api_not_observed") actions.push("expand_vmp_runtime_hooks");
  else if (gap === "source_context_not_available") actions.push("capture_or_retrieve_script_asset");
  else if (gap === "data_refs_not_observed" || gap === "data_links_not_observed") actions.push("capture_object_ids_for_data_links");
  else if (gap === "post_request_activity") actions.push("prefer_pre_request_capture_window");
  else if (gap === "signature_mutation_not_observed") actions.push("capture_url_search_params_mutation_or_header_set");
  else if (gap === "unsigned_input_not_observed") actions.push("capture_unsigned_request_construction");
  else if (gap === "material_source_not_observed") actions.push("capture_text_buffer_or_storage_material");
  else if (gap === "source_only_edge" || gap === "temporal_only_edge") actions.push("capture_object_ids_for_data_links");
  else if (gap === "nearby_runtime_only_edge") actions.push("capture_vmp_register_state_refs", "capture_object_ids_for_data_links");
  else if (gap === "missing_generation_edge") actions.push("capture_object_ids_for_data_links", "capture_or_retrieve_script_asset");
  return uniqueLimited(actions, 8);
}

function stageParts(stages) {
  return uniqueLimited((stages || [])
    .flatMap((stage) => String(stage || "").split("->"))
    .filter(Boolean), 12);
}

function priorityRank(priority) {
  return {high: 0, medium: 1, low: 2}[priority] ?? 1;
}

function strongestPriority(left, right) {
  return priorityRank(left) <= priorityRank(right) ? left : right;
}

function priorityForGapObservation(gap, stage, actions, explicitPriority) {
  if (explicitPriority) return explicitPriority;
  if (gap === "signature_mutation_not_observed" || gap === "missing_generation_edge") return "high";
  let priority = "medium";
  const stages = stageParts([stage]);
  for (const action of actions || []) {
    priority = strongestPriority(priority, captureFocusPriority(action, stages));
  }
  return priority;
}

function hookTargetsForActions(actions, stages) {
  const targets = [];
  const parts = stageParts(stages);
  for (const action of actions || []) {
    for (const target of captureFocusHookTargets(action, parts)) {
      if (!targets.includes(target)) targets.push(target);
    }
  }
  return targets.slice(0, 8);
}

function addBlockingGapObservation(byGap, observation) {
  if (!observation.gap) return;
  const gap = observation.gap;
  const item = byGap.get(gap) || {
    gap,
    count: 0,
    priority: "medium",
    params: new Set(),
    stages: new Set(),
    actions: new Set(),
    endpoints: new Set(),
    source_refs: new Set(),
    object_refs: new Set(),
    value_refs: new Set()
  };
  item.count += 1;
  item.priority = strongestPriority(item.priority, observation.priority || "medium");
  if (observation.param) item.params.add(observation.param);
  if (observation.stage) item.stages.add(observation.stage);
  if (observation.endpoint) item.endpoints.add(observation.endpoint);
  for (const action of observation.actions || []) item.actions.add(action);
  for (const ref of observation.source_refs || []) item.source_refs.add(ref);
  for (const ref of observation.object_refs || []) item.object_refs.add(ref);
  for (const ref of observation.value_refs || []) item.value_refs.add(ref);
  byGap.set(gap, item);
}

function blockingGapRank(left, right) {
  if ((right.count ?? 0) !== (left.count ?? 0)) return (right.count ?? 0) - (left.count ?? 0);
  const priority = priorityRank(left.priority) - priorityRank(right.priority);
  if (priority) return priority;
  return String(left.gap || "").localeCompare(String(right.gap || ""));
}

function buildBlockingGapSummary(parameters) {
  const byGap = new Map();
  const gapCounts = {};
  const stageCounts = {};
  const actionCounts = {};

  function observe(observation) {
    const actions = observation.actions?.length
      ? uniqueLimited(observation.actions, 8)
      : actionsForGapObservation(observation.gap, observation.stage);
    const priority = priorityForGapObservation(observation.gap, observation.stage, actions, observation.priority);
    const normalized = {...observation, actions, priority};
    addBlockingGapObservation(byGap, normalized);
    incrementCount(gapCounts, normalized.gap);
    incrementCount(stageCounts, normalized.stage || "unknown");
    for (const action of actions) incrementCount(actionCounts, action);
  }

  for (const parameter of parameters || []) {
    for (const gap of parameter.unresolved_gaps || []) {
      observe({
        gap,
        stage: stageForParameterGap(gap),
        param: parameter.param,
        endpoint: parameter.endpoint,
        source_refs: parameter.source_refs || []
      });
    }
    for (const step of parameter.generation_path || []) {
      for (const gap of step.evidence_gaps || []) {
        observe({
          gap,
          stage: step.stage || "unknown",
          param: parameter.param,
          endpoint: parameter.endpoint,
          source_refs: generationStepSourceRefs(step),
          object_refs: step.object_refs || [],
          value_refs: step.value_refs || []
        });
      }
    }
    for (const gap of parameter.generation_edge_gaps || []) {
      observe({
        gap: gap.gap,
        stage: `${gap.from_stage || "unknown"}->${gap.to_stage || "unknown"}`,
        param: parameter.param,
        endpoint: parameter.endpoint,
        actions: gap.next_actions || [],
        priority: gap.priority || "medium",
        source_refs: gap.source_refs || [],
        object_refs: gap.object_refs || [],
        value_refs: gap.value_refs || []
      });
    }
  }

  const topBlockers = [...byGap.values()]
    .sort(blockingGapRank)
    .slice(0, 8)
    .map((item) => {
      const stages = uniqueLimited([...item.stages], 12);
      const actions = uniqueLimited([...item.actions], 12);
      return {
        gap: item.gap,
        count: item.count,
        priority: item.priority,
        params: sortParamNames([...item.params]),
        stages,
        actions,
        endpoints: uniqueLimited([...item.endpoints], 8),
        hook_targets: hookTargetsForActions(actions, stages),
        source_refs: uniqueLimited([...item.source_refs], 8),
        object_refs: uniqueLimited([...item.object_refs], 8),
        value_refs: uniqueLimited([...item.value_refs], 8)
      };
    });

  return {
    total_observation_count: Object.values(gapCounts).reduce((sum, count) => sum + count, 0),
    gap_counts: gapCounts,
    stage_counts: stageCounts,
    action_counts: actionCounts,
    top_blockers: topBlockers
  };
}

function readinessEntry(item, status, evidenceRefs = [], gaps = [], nextActions = []) {
  return {
    item,
    status,
    evidence_refs: uniqueLimited(evidenceRefs.filter(Boolean), 8),
    gaps: uniqueLimited(gaps.filter(Boolean), 8),
    next_actions: uniqueLimited(nextActions.filter(Boolean), 8)
  };
}

function firstStageStep(generationPath, stage) {
  return (generationPath || []).find((step) => step.stage === stage) || null;
}

function stepEvidenceRefs(step) {
  if (!step) return [];
  return uniqueLimited([
    step.stage ? `stage:${step.stage}` : "",
    ...(step.apis || []).slice(0, 2).map((api) => `api:${api}`),
    ...generationStepSourceRefs(step).slice(0, 2).map((ref) => `source:${ref}`),
    ...(step.object_refs || []).slice(0, 2),
    ...(step.value_refs || []).slice(0, 2)
  ].filter(Boolean), 8);
}

function transformRuntimeSteps(generationPath) {
  const transformStages = new Set([
    "dynamic_dispatch",
    "integer_mixing",
    "text_or_string_decode",
    "byte_buffer",
    "material_serialization"
  ]);
  return (generationPath || []).filter((step) => transformStages.has(step.stage));
}

function sourceContextResolved(parameter) {
  return Boolean(
    (parameter.source_evidence || []).some((source) => source.ref) ||
    (parameter.source_refs || []).length ||
    (parameter.generation_path || []).some((step) => (step.source_evidence || []).some((source) => source.ref))
  );
}

function sourceContextRefs(parameter) {
  return uniqueLimited([
    ...(parameter.source_refs || []),
    ...(parameter.source_evidence || []).map((source) => source.ref || ""),
    ...(parameter.generation_path || []).flatMap((step) => generationStepSourceRefs(step))
  ].filter(Boolean), 8);
}

function inputMaterialReadinessEvidence(parameter) {
  const path = parameter.generation_path || [];
  const inputStep = firstStageStep(path, "input_url") || firstStageStep(path, "request_construction");
  if (inputStep) return stepEvidenceRefs(inputStep);
  const requestInputSummary = parameter.candidate_generation_summary?.request_input_summary || {};
  const evidence = [
    ...(requestInputSummary.observed_categories || []).map((category) => `request_input_category:${category}`),
    ...(requestInputSummary.evidence_refs || []).map((ref) => `request_input:${ref}`)
  ];
  return uniqueLimited(evidence, 8);
}

function buildReadinessChecklist(parameter) {
  const path = parameter.generation_path || [];
  const checklist = [];
  const directWebCrypto = isDirectWebCryptoParameter(parameter);
  const webcryptoSignatureSummary = compactWebCryptoSignatureSummary(parameter.webcrypto_signature_summary);
  const inputMaterialEvidence = inputMaterialReadinessEvidence(parameter);
  checklist.push(inputMaterialEvidence.length
    ? readinessEntry("unsigned_input_observed", "pass", inputMaterialEvidence)
    : readinessEntry("unsigned_input_observed", "fail", [], ["unsigned_input_not_observed"], ["capture_unsigned_request_construction"])
  );

  const transformSteps = transformRuntimeSteps(path);
  const runtimeTransform = transformSteps.find((step) => (step.apis || []).length);
  const sourceOnlyTransform = transformSteps.find((step) =>
    generationStepSourceRefs(step).length ||
    (step.source_calls || []).length ||
    (step.source_signals || []).length ||
    (step.source_operators || []).length ||
    (step.source_constants || []).length
  );
  if (runtimeTransform) {
    checklist.push(readinessEntry("transform_runtime_observed", "pass", stepEvidenceRefs(runtimeTransform)));
  } else if (sourceOnlyTransform || (parameter.vmp_operation_patterns || []).length) {
    checklist.push(readinessEntry(
      "transform_runtime_observed",
      "partial",
      sourceOnlyTransform ? stepEvidenceRefs(sourceOnlyTransform) : (parameter.vmp_operation_patterns || []).slice(0, 2).map((pattern) => `pattern:${pattern.pattern}`),
      ["runtime_api_not_observed"],
      ["expand_vmp_runtime_hooks"]
    ));
  } else {
    checklist.push(readinessEntry("transform_runtime_observed", "fail", [], ["runtime_api_not_observed"], ["expand_vmp_runtime_hooks"]));
  }

  const primaryPattern = (parameter.vmp_operation_patterns || [])[0];
  const vmpStateTrace = parameter.vmp_state_trace || null;
  if (directWebCrypto) {
    checklist.push(readinessEntry(
      "vmp_operation_pattern_observed",
      "pass",
      directWebCryptoEvidenceRefs(webcryptoSignatureSummary)
    ));
  } else if (primaryPattern) {
    checklist.push(readinessEntry("vmp_operation_pattern_observed", "pass", [
      `pattern:${primaryPattern.pattern || "unknown"}`,
      primaryPattern.chain_id || ""
    ]));
  } else if (vmpStateTrace?.status === "observed") {
    checklist.push(readinessEntry("vmp_operation_pattern_observed", "pass", [
      "vmp_state_model:observed",
      ...(vmpStateTrace.evidence_refs || []).slice(0, 7)
    ]));
  } else if (transformSteps.length) {
    checklist.push(readinessEntry("vmp_operation_pattern_observed", "partial", transformSteps.flatMap(stepEvidenceRefs), ["vmp_pattern_not_ranked"], ["capture_vmp_register_state_refs"]));
  } else {
    checklist.push(readinessEntry("vmp_operation_pattern_observed", "fail", [], ["vmp_pattern_not_observed"], ["expand_vmp_runtime_hooks"]));
  }

  const attachmentStep = path.find((step) =>
    step.stage === "signature_mutation" && step.param_relation === "direct_observed"
  );
  if (attachmentStep && (attachmentStep.apis || []).length) {
    checklist.push(readinessEntry("signature_attachment_observed", "pass", stepEvidenceRefs(attachmentStep)));
  } else if (attachmentStep) {
    checklist.push(readinessEntry(
      "signature_attachment_observed",
      "partial",
      stepEvidenceRefs(attachmentStep),
      uniqueLimited(["runtime_api_not_observed", ...(attachmentStep.evidence_gaps || [])], 8),
      ["capture_url_search_params_mutation_or_header_set"]
    ));
  } else {
    checklist.push(readinessEntry("signature_attachment_observed", "fail", [], ["signature_mutation_not_observed"], ["capture_url_search_params_mutation_or_header_set"]));
  }

  const signedRequestStep = firstStageStep(path, "signed_request");
  checklist.push(signedRequestStep
    ? readinessEntry("signed_request_observed", "pass", stepEvidenceRefs(signedRequestStep))
    : readinessEntry("signed_request_observed", "fail", [], ["signed_request_not_observed"], ["capture_browser_network_request_anchor"])
  );

  if (sourceContextResolved(parameter)) {
    checklist.push(readinessEntry("source_context_resolved", "pass", sourceContextRefs(parameter)));
  } else {
    checklist.push(readinessEntry("source_context_resolved", "fail", [], ["source_context_not_available"], ["capture_or_retrieve_script_asset"]));
  }

  const quality = parameter.chain_quality || {};
  if (quality.status === "strong") {
    checklist.push(readinessEntry("generation_edges_resolved", "pass", [
      `edges:${quality.edge_count ?? 0}/${quality.expected_edge_count ?? 0}`,
      `quality:${quality.status}`
    ]));
  } else if (quality.status === "partial") {
    checklist.push(readinessEntry("generation_edges_resolved", "partial", [
      `edges:${quality.edge_count ?? 0}/${quality.expected_edge_count ?? 0}`,
      `quality:${quality.status}`
    ], (parameter.generation_edge_gaps || []).map((gap) => gap.gap || ""), ["capture_object_ids_for_data_links"]));
  } else {
    checklist.push(readinessEntry("generation_edges_resolved", "fail", [
      `edges:${quality.edge_count ?? 0}/${quality.expected_edge_count ?? 0}`,
      `quality:${quality.status || "unknown"}`
    ], (parameter.generation_edge_gaps || []).map((gap) => gap.gap || "missing_generation_edge"), ["capture_object_ids_for_data_links"]));
  }

  return checklist;
}

function readinessScore(checklist) {
  const score = (checklist || []).reduce((sum, item) => {
    if (item.status === "pass") return sum + 1;
    if (item.status === "partial") return sum + 0.5;
    return sum;
  }, 0);
  return Math.ceil((score / Math.max(1, (checklist || []).length)) * 100);
}

function readinessStatus(score, failedCount) {
  if (score >= 90 && failedCount === 0) return "ready_for_detailed_generation_analysis";
  if (score >= 40) return "partial_needs_targeted_capture";
  return "insufficient_evidence_for_generation_analysis";
}

function primaryReadinessAction(status, checklist, recommendedActions) {
  if (status === "ready_for_detailed_generation_analysis") {
    return (recommendedActions || []).includes("review_source_refs")
      ? "review_source_refs"
      : "review_agent_pack";
  }
  const candidates = uniqueLimited([
    ...(checklist || []).flatMap((item) => item.next_actions || []),
    ...(recommendedActions || [])
  ], 16);
  const rank = [
    "capture_url_search_params_mutation_or_header_set",
    "expand_vmp_runtime_hooks",
    "capture_vmp_register_state_refs",
    "capture_object_ids_for_data_links",
    "capture_or_retrieve_script_asset",
    "capture_unsigned_request_construction"
  ];
  return rank.find((action) => candidates.includes(action)) || candidates[0] || "review_agent_pack";
}

function attachmentEvidenceForProbePlan(parameter) {
  const attachment = candidateSummaryAttachment(parameter);
  if (!attachment?.observed) return null;
  return {
    mode: attachment.evidence_mode || "unknown",
    direct_runtime_api_observed: Boolean(attachment.direct_runtime_api_observed),
    request_anchor_observed: Boolean(attachment.request_anchor_observed),
    fallback_stage: attachment.fallback_stage || "",
    request_anchor_apis: uniqueLimited(attachment.request_anchor_apis || [], 8),
    request_anchor_refs: uniqueLimited(attachment.request_anchor_refs || [], 8),
    missing_runtime_hooks: uniqueLimited(attachment.missing_runtime_hooks || [], 8)
  };
}

function buildReadinessNextProbePlan(parameter, checklist, summary) {
  const action = summary.primary_next_action;
  const unresolved = (checklist || []).filter((item) => item.status !== "pass");
  const stages = summary.status === "ready_for_detailed_generation_analysis"
    ? uniqueLimited((parameter.generation_path || []).map((step) => step.stage || "").filter(Boolean), 12)
    : uniqueLimited((parameter.generation_path || [])
      .filter((step) => (step.evidence_gaps || []).length || (step.recommended_next_actions || []).includes(action))
      .map((step) => step.stage || "")
      .filter(Boolean), 12);
  const gaps = uniqueLimited(unresolved.flatMap((item) => item.gaps || []), 12);
  const attachmentEvidence = attachmentEvidenceForProbePlan(parameter);
  return {
    action,
    reason: summary.status === "ready_for_detailed_generation_analysis"
      ? "ready_for_agent_review"
      : captureFocusReason(action, stages, gaps, attachmentEvidence),
    stages,
    gaps,
    hook_targets: summary.status === "ready_for_detailed_generation_analysis"
      ? []
      : captureFocusHookTargets(action, stages),
    source_refs: sourceContextRefs(parameter),
    object_refs: uniqueLimited((parameter.generation_path || []).flatMap((step) => step.object_refs || []), 8),
    value_refs: uniqueLimited((parameter.generation_path || []).flatMap((step) => step.value_refs || []), 8),
    ...(summary.status !== "ready_for_detailed_generation_analysis" && attachmentEvidence
      ? {attachment_evidence: attachmentEvidence}
      : {})
  };
}

function buildAnalysisReadiness(parameter, recommendedActions) {
  const checklist = buildReadinessChecklist(parameter);
  const passedCount = checklist.filter((item) => item.status === "pass").length;
  const partialCount = checklist.filter((item) => item.status === "partial").length;
  const failedCount = checklist.filter((item) => item.status === "fail").length;
  const score = readinessScore(checklist);
  const status = readinessStatus(score, failedCount);
  const summary = {
    status,
    score,
    passed_count: passedCount,
    partial_count: partialCount,
    failed_count: failedCount,
    primary_next_action: primaryReadinessAction(status, checklist, recommendedActions)
  };
  return {
    summary,
    checklist,
    next_probe_plan: buildReadinessNextProbePlan(parameter, checklist, summary)
  };
}

function buildReadinessSummary(parameters) {
  let readyCount = 0;
  let partialCount = 0;
  let insufficientCount = 0;
  let scoreSum = 0;
  for (const parameter of parameters || []) {
    const summary = parameter.analysis_readiness?.summary || {};
    if (summary.status === "ready_for_detailed_generation_analysis") readyCount += 1;
    else if (summary.status === "partial_needs_targeted_capture") partialCount += 1;
    else insufficientCount += 1;
    scoreSum += summary.score ?? 0;
  }
  return {
    ready_count: readyCount,
    partial_count: partialCount,
    insufficient_count: insufficientCount,
    average_score: Math.round(scoreSum / Math.max(1, (parameters || []).length))
  };
}

function generationGraphNodeId(step) {
  return `step_${step.order ?? "?"}_${String(step.stage || "unknown").replace(/[^A-Za-z0-9_]+/g, "_")}`;
}

function generationGraphNodeStatus(step) {
  if ((step.evidence_gaps || []).length) return "partial";
  return "observed";
}

function operationGraphNodeId(chainId, step) {
  return `op_${chainId || "chain"}_${step.seq ?? step.trace_index ?? "unknown"}`;
}

function operationGraphEdges(chainId, nodes) {
  const edges = [];
  for (let index = 0; index < nodes.length - 1; index += 1) {
    const left = nodes[index];
    const right = nodes[index + 1];
    if (!left.result_ref || !(right.input_refs || []).includes(left.result_ref)) continue;
    edges.push({
      id: `op_edge_${chainId || "chain"}_${left.seq ?? index}_${right.seq ?? index + 1}`,
      from: left.id,
      to: right.id,
      relation: "result_to_input",
      via_ref: left.result_ref
    });
  }
  return edges;
}

function sourceOperationPatternName(step) {
  const operators = new Set(step?.source_operators || []);
  const calls = new Set([...(step?.apis || []), ...(step?.source_calls || [])]);
  const hasMultiply = calls.has("Math.imul") || calls.has("imul");
  if (operators.has("^") && hasMultiply && (operators.has(">>>") || operators.has(">>"))) {
    return "source_xor_imul_shift_mixing";
  }
  if (operators.has("^") && hasMultiply) return "source_xor_imul_mixing";
  if (operators.has("^")) return "source_xor_mixing";
  if (hasMultiply) return "source_imul_mixing";
  return "source_operation_mixing";
}

function sourceOperationSignature(step) {
  const calls = uniqueLimited([...(step?.apis || []), ...(step?.source_calls || [])], 6);
  const operators = uniqueLimited(step?.source_operators || [], 6);
  const constants = uniqueLimited(step?.source_constants || [], 6);
  return [
    calls.join(" -> "),
    operators.length ? `ops:${operators.join("|")}` : "",
    constants.length ? `constants:${constants.join("|")}` : ""
  ].filter(Boolean).join(" ") || "source_operation";
}

function sourceOperationApi(step) {
  const calls = uniqueLimited([...(step?.apis || []), ...(step?.source_calls || [])], 6);
  return calls.find((call) => /(?:Math\.imul|Bitwise\.|Shift\.)/.test(call)) ||
    calls[0] ||
    `source:${step?.stage || "operation"}`;
}

function sourceOperationOutputRefs(step) {
  return uniqueLimited((step?.value_refs || [])
    .filter((ref) => ref && !String(ref).startsWith("target_params:")), 8);
}

function shouldBuildSourceOperationSubgraph(step, coveredStages) {
  if (!step?.stage || coveredStages.has(step.stage)) return false;
  if (!["integer_mixing", "hash_or_digest", "dynamic_dispatch", "string_transform"].includes(step.stage)) return false;
  return Boolean((step.source_operators || []).length || (step.source_constants || []).length);
}

function buildSourceOperationSubgraphs(parameter, nodeIdByStage, coveredStages) {
  return (parameter.generation_path || [])
    .filter((step) => shouldBuildSourceOperationSubgraph(step, coveredStages))
    .slice(0, 8)
    .map((step, index) => {
      const chainId = `source_${step.order ?? index + 1}_${step.stage || "operation"}`;
      const sourceRefs = generationStepSourceRefs(step);
      const sourceOperators = uniqueLimited(step.source_operators || [], 8);
      const sourceConstants = uniqueLimited(step.source_constants || [], 8);
      const outputRefs = sourceOperationOutputRefs(step);
      const node = {
        id: `op_${chainId}`,
        order: 1,
        api: sourceOperationApi(step),
        seq: step.seq_start ?? null,
        trace_index: null,
        input_refs: [],
        result_ref: "",
        ...(outputRefs.length ? {output_refs: outputRefs} : {}),
        source_refs: sourceRefs,
        source_operators: sourceOperators,
        source_constants: sourceConstants
      };
      return {
        id: `opgraph_${chainId}`,
        chain_id: chainId,
        stage: step.stage || "unknown",
        attached_node_id: nodeIdByStage.get(step.stage || "") || "",
        pattern: sourceOperationPatternName(step),
        operation_signature: sourceOperationSignature(step),
        confidence: (step.apis || []).length || outputRefs.length ? "medium" : "low",
        operation_count: 1,
        source_only: true,
        source_operators: sourceOperators,
        source_constants: sourceConstants,
        shared_refs: [],
        output_refs: outputRefs,
        nodes: [node],
        edges: []
      };
    });
}

function buildOperationSubgraphs(parameter, nodeIdByStage) {
  const patternByChain = new Map((parameter.vmp_operation_patterns || [])
    .map((pattern) => [pattern.chain_id, pattern]));
  const runtimeSubgraphs = (parameter.vmp_scalar_chain_links || [])
    .filter((link) => (link.operation_trace || []).length)
    .slice(0, 8)
    .map((link) => {
      const chainId = link.chain_id || "chain";
      const pattern = patternByChain.get(link.chain_id) || {};
      const nodes = (link.operation_trace || []).slice(0, 12).map((step, index) => {
        const resultRef = step.result_ref || "";
        const nodeOutputRefs = uniqueLimited([
          resultRef,
          ...(step.output_refs || [])
        ].filter(Boolean), 8);
        return {
          id: operationGraphNodeId(chainId, step),
          order: index + 1,
          api: step.api || "unknown",
          seq: step.seq ?? null,
          trace_index: step.trace_index ?? null,
          input_refs: uniqueLimited(step.input_refs || [], 8),
          result_ref: resultRef,
          ...(nodeOutputRefs.some((ref) => ref !== resultRef) ? {output_refs: nodeOutputRefs} : {}),
          source_refs: uniqueLimited(step.source_context_refs || [], 8)
        };
      });
      const outputRefs = uniqueLimited(nodes
        .flatMap((node) => (node.output_refs?.length ? node.output_refs : [node.result_ref]))
        .filter(Boolean), 8);
      return {
        id: `opgraph_${chainId}`,
        chain_id: chainId,
        stage: link.stage || pattern.stage || "unknown",
        attached_node_id: nodeIdByStage.get(link.stage || pattern.stage) || "",
        pattern: pattern.pattern || vmpOperationPatternName(link.apis || []),
        operation_signature: pattern.operation_signature || (link.apis || []).join(" -> ") || "unknown",
        confidence: pattern.confidence || link.confidence || "medium",
        operation_count: nodes.length,
        shared_refs: uniqueLimited(link.shared_refs || pattern.shared_refs || [], 8),
        output_refs: outputRefs,
        nodes,
        edges: operationGraphEdges(chainId, nodes)
      };
    });
  const coveredStages = new Set(runtimeSubgraphs.map((subgraph) => subgraph.stage).filter(Boolean));
  return [
    ...runtimeSubgraphs,
    ...buildSourceOperationSubgraphs(parameter, nodeIdByStage, coveredStages)
  ].slice(0, 8);
}

function generationGraphNodeRefs(node) {
  return new Set([
    ...(node.object_refs || []),
    ...(node.value_refs || [])
  ].filter(Boolean));
}

function dataflowEdgeSummary(edge) {
  return {
    from_node_id: edge.from || "",
    to_node_id: edge.to || "",
    relation: edge.relation || edge.gap || "related",
    refs: uniqueLimited(edge.refs || [], 8)
  };
}

function findGraphPathEdges(edges, startNodeIds, targetNodeIds) {
  const starts = [...(startNodeIds || [])].filter(Boolean);
  const targets = new Set([...(targetNodeIds || [])].filter(Boolean));
  if (!starts.length || !targets.size) return [];
  const byFrom = new Map();
  for (const edge of edges || []) {
    if (!edge?.from || !edge?.to) continue;
    const list = byFrom.get(edge.from) || [];
    list.push(edge);
    byFrom.set(edge.from, list);
  }
  const queue = starts.map((nodeId) => ({nodeId, path: []}));
  const visited = new Set(starts);
  while (queue.length) {
    const current = queue.shift();
    if (targets.has(current.nodeId) && current.path.length) return current.path;
    for (const edge of byFrom.get(current.nodeId) || []) {
      if (visited.has(edge.to)) continue;
      const nextPath = [...current.path, edge];
      if (targets.has(edge.to)) return nextPath;
      visited.add(edge.to);
      queue.push({nodeId: edge.to, path: nextPath});
    }
  }
  return [];
}

function buildVmpSignatureBridgeLinks(graph, signatureNodeIds) {
  const signatureIds = new Set(signatureNodeIds || []);
  const links = [];
  for (const subgraph of graph.operation_subgraphs || []) {
    if (!subgraph.attached_node_id) continue;
    for (const edge of graph.edges || []) {
      if (edge.from !== subgraph.attached_node_id || !signatureIds.has(edge.to)) continue;
      links.push({
        opgraph_id: subgraph.id || "",
        from_node_id: edge.from,
        to_node_id: edge.to,
        relation: edge.relation || "related",
        confidence: edge.confidence || subgraph.confidence || "medium",
        refs: uniqueLimited(edge.refs || [], 8)
      });
    }
  }
  return links.slice(0, 8);
}

const STRING_ENCODING_BOUNDARY_STAGES = new Set([
  "text_or_string_decode",
  "string_transform",
  "url_encoding"
]);

function stringLengthRefsForRef(ref) {
  const value = String(ref || "");
  if (!value) return [];
  const refs = [];
  const pattern = /(?:^|[^A-Za-z0-9_])string:length:(\d+)(?=$|[^0-9])/g;
  let match = pattern.exec(value);
  while (match) {
    refs.push(`string:length:${match[1]}`);
    match = pattern.exec(value);
  }
  return uniqueLimited(refs, 4);
}

function isStringLengthBoundaryMatch(outputRef, boundaryRef) {
  if (!outputRef || !boundaryRef) return false;
  if (outputRef === boundaryRef && /^string:length:\d+$/.test(outputRef)) return true;
  return stringLengthRefsForRef(outputRef).includes(boundaryRef);
}

function outputBoundaryMatch(outputRef, boundaryRefs) {
  if (!outputRef || !boundaryRefs?.size) return null;
  if (boundaryRefs.has(outputRef)) {
    return {
      output_ref: outputRef,
      boundary_ref: outputRef,
      match_type: isStringLengthBoundaryMatch(outputRef, outputRef) ? "string_length" : "exact"
    };
  }
  const boundaryLengthRefs = new Set(
    [...boundaryRefs].flatMap((ref) => stringLengthRefsForRef(ref))
  );
  for (const lengthRef of stringLengthRefsForRef(outputRef)) {
    if (boundaryRefs.has(lengthRef) || boundaryLengthRefs.has(lengthRef)) {
      return {
        output_ref: outputRef,
        boundary_ref: lengthRef,
        match_type: "string_length"
      };
    }
  }
  return null;
}

function isRegisterStringSourceOutputRef(ref) {
  return /(?:^|[^A-Za-z0-9_])register:string:length:\d+\/number:-?\d+(?:\.\d+)?/.test(String(ref || ""));
}

function stringLengthValue(ref) {
  const match = /^string:length:(\d+)$/.exec(String(ref || ""));
  return match ? Number(match[1]) : 0;
}

function rankedTransformedStringBoundaryRefs(boundaryLengthRefs, outputLengthRefs) {
  return uniqueLimited(boundaryLengthRefs || [], 8)
    .filter((ref) => !outputLengthRefs.has(ref))
    .sort((left, right) => {
      const leftLength = stringLengthValue(left);
      const rightLength = stringLengthValue(right);
      if ((leftLength > 0) !== (rightLength > 0)) return rightLength > 0 ? 1 : -1;
      return rightLength - leftLength;
    });
}

function outputStringSourceBoundaryMatch(outputRef, boundaryRefs) {
  if (!isRegisterStringSourceOutputRef(outputRef) || !boundaryRefs?.size) return null;
  const outputLengthRefs = new Set(stringLengthRefsForRef(outputRef));
  const boundaryLengthRefs = uniqueLimited(
    [...boundaryRefs].flatMap((ref) => stringLengthRefsForRef(ref)),
    8
  );
  const transformedBoundaryRef = rankedTransformedStringBoundaryRefs(
    boundaryLengthRefs,
    outputLengthRefs
  )[0];
  if (!transformedBoundaryRef) return null;
  return {
    output_ref: outputRef,
    boundary_ref: transformedBoundaryRef,
    match_type: "string_source"
  };
}

function signatureBridgeEdgeForSubgraph(graph, subgraph, signatureIds) {
  if (!subgraph?.attached_node_id) return null;
  return (graph.edges || []).find((edge) =>
    edge.from === subgraph.attached_node_id && signatureIds.has(edge.to)
  ) || null;
}

function buildEncodingBoundaryLinks(graph, signatureNodeIds) {
  const signatureIds = new Set(signatureNodeIds || []);
  const links = [];
  for (const subgraph of graph.operation_subgraphs || []) {
    if (!subgraph.attached_node_id) continue;
    const outputRefs = subgraph.output_refs || [];
    if (!outputRefs.length) continue;
    const linkedOutputRefs = new Set();
    const signatureBridgeEdge = signatureBridgeEdgeForSubgraph(graph, subgraph, signatureIds);
    for (const boundaryNode of graph.nodes || []) {
      if (!STRING_ENCODING_BOUNDARY_STAGES.has(boundaryNode.stage)) continue;
      const boundaryRefs = generationGraphNodeRefs(boundaryNode);
      const directMatch = outputRefs
        .filter((ref) => !linkedOutputRefs.has(ref))
        .map((ref) => outputBoundaryMatch(ref, boundaryRefs))
        .find(Boolean);
      const sourceMatch = directMatch ? null : outputRefs
        .filter((ref) => !linkedOutputRefs.has(ref))
        .map((ref) => outputStringSourceBoundaryMatch(ref, boundaryRefs))
        .find(Boolean);
      const match = directMatch || sourceMatch;
      if (!match) continue;
      const {output_ref: outputRef, boundary_ref: boundaryRef, match_type: matchType} = match;
      const fromEdge = (graph.edges || []).find((edge) =>
        edge.from === subgraph.attached_node_id &&
        edge.to === boundaryNode.id &&
        ((edge.refs || []).includes(outputRef) || (edge.refs || []).includes(boundaryRef))
      );
      const boundaryToSignaturePath = findGraphPathEdges(graph.edges || [], new Set([boundaryNode.id]), signatureIds);
      if (matchType !== "string_source" && !fromEdge && matchType !== "string_length") continue;
      if (!boundaryToSignaturePath.length && !(matchType === "string_source" && signatureBridgeEdge)) continue;
      const signatureEdge = boundaryToSignaturePath[boundaryToSignaturePath.length - 1] || signatureBridgeEdge;
      const sourceBoundaryRefs = matchType === "string_source"
        ? uniqueLimited([
          ...(fromEdge?.source_refs || []),
          ...(signatureBridgeEdge?.source_refs || []),
          ...boundaryToSignaturePath.flatMap((edge) => edge.source_refs || [])
        ], 4)
        : [];
      links.push({
        opgraph_id: subgraph.id || "",
        output_ref: outputRef,
        from_node_id: subgraph.attached_node_id,
        via_node_id: boundaryNode.id,
        via_stage: boundaryNode.stage,
        to_node_id: signatureEdge.to,
        relation: matchType === "string_source"
          ? "vmp_output_to_signature_via_string_source_boundary"
          : "vmp_output_to_signature_via_string_boundary",
        confidence: matchType === "string_source"
          ? "medium"
          : fromEdge?.confidence === "high" ? "high" : subgraph.confidence || "medium",
        refs: matchType === "string_source" ? uniqueLimited([
          outputRef,
          boundaryRef,
          ...sourceBoundaryRefs
        ].filter(Boolean), 8) : uniqueLimited([
          outputRef,
          boundaryRef !== outputRef ? boundaryRef : "",
          ...boundaryToSignaturePath.flatMap((edge) => edge.refs || [])
            .filter((ref) => ref && !String(ref).startsWith("target_params:"))
        ].filter(Boolean), 8)
      });
      linkedOutputRefs.add(outputRef);
    }
  }
  return links.slice(0, 8);
}

function unresolvedBridgeOperationSummary(subgraph) {
  return (subgraph?.nodes || [])
    .filter((node) => node.result_ref)
    .slice(-4)
    .map((node) => ({
      api: node.api || "",
      seq: node.seq ?? null,
      result_ref: node.result_ref
    }));
}

function buildUnresolvedOutputBridges(graph, bridgeLinks, downstreamRequestObserved) {
  if (!(bridgeLinks || []).length) return [];
  const subgraphsById = new Map((graph.operation_subgraphs || [])
    .map((subgraph) => [subgraph.id || "", subgraph]));
  return (bridgeLinks || []).slice(0, 8).map((bridge) => {
    const subgraph = subgraphsById.get(bridge.opgraph_id || "") || {};
    return {
      opgraph_id: bridge.opgraph_id || "",
      from_node_id: bridge.from_node_id || "",
      to_node_id: bridge.to_node_id || "",
      relation: bridge.relation || "related",
      confidence: bridge.confidence || subgraph.confidence || "medium",
      candidate_output_refs: uniqueLimited(subgraph.output_refs || [], 8),
      last_operations: unresolvedBridgeOperationSummary(subgraph),
      missing_refs: [
        "vmp_output_ref_on_signature_stage",
        "vmp_output_ref_on_string_encoding_boundary"
      ],
      downstream_request_observed: Boolean(downstreamRequestObserved),
      next_actions: [
        "capture_string_encoding_boundary_refs",
        "capture_vmp_register_state_refs",
        "capture_object_ids_for_data_links"
      ]
    };
  });
}

function buildDirectWebCryptoDataflowSummary(graph, parameter) {
  const summary = compactWebCryptoSignatureSummary(parameter?.webcrypto_signature_summary);
  const requestNodeIds = new Set((graph.nodes || [])
    .filter((node) => node.stage === "signed_request")
    .map((node) => node.id));
  const webcryptoNodeIds = new Set((graph.nodes || [])
    .filter((node) => node.stage === "hash_or_digest")
    .map((node) => node.id));
  const requestLinks = findGraphPathEdges(graph.edges || [], webcryptoNodeIds, requestNodeIds)
    .map(dataflowEdgeSummary);
  return {
    status: "direct_webcrypto_operation_path",
    vmp_output_link_count: 0,
    attachment_to_request_link_observed: requestLinks.length > 0,
    linked_output_refs: uniqueLimited([
      ...(summary?.result_refs || []),
      ...(summary?.result_array_buffer_refs || [])
    ], 8),
    links: [],
    request_links: requestLinks.slice(0, 8),
    webcrypto_operation_refs: uniqueLimited(summary?.operation_refs || [], 12),
    webcrypto_input_refs: uniqueLimited([
      ...(summary?.input_refs || []),
      ...(summary?.input_array_buffer_refs || [])
    ], 12),
    webcrypto_result_refs: uniqueLimited([
      ...(summary?.result_refs || []),
      ...(summary?.result_array_buffer_refs || [])
    ], 12),
    gaps: [],
    next_actions: directWebCryptoNextActions(parameter)
  };
}

function buildGenerationGraphDataflowSummary(graph, parameter = {}) {
  const operationSubgraphs = graph.operation_subgraphs || [];
  if (!operationSubgraphs.length) {
    if (isDirectWebCryptoParameter(parameter)) {
      return buildDirectWebCryptoDataflowSummary(graph, parameter);
    }
    return {
      status: "no_vmp_operation_subgraph",
      vmp_output_link_count: 0,
      attachment_to_request_link_observed: false,
      linked_output_refs: [],
      links: [],
      request_links: [],
      gaps: ["vmp_operation_subgraph_not_observed"],
      next_actions: ["expand_vmp_runtime_hooks"]
    };
  }

  const signatureNodes = (graph.nodes || []).filter((node) => node.stage === "signature_mutation");
  const requestNodes = (graph.nodes || []).filter((node) => node.stage === "signed_request");
  const signatureNodeIds = new Set(signatureNodes.map((node) => node.id));
  const requestNodeIds = new Set(requestNodes.map((node) => node.id));
  const signatureRefsByNode = new Map(signatureNodes.map((node) => [node.id, generationGraphNodeRefs(node)]));
  const links = [];

  for (const subgraph of operationSubgraphs) {
    for (const outputRef of subgraph.output_refs || []) {
      for (const signatureNode of signatureNodes) {
        const signatureRefs = signatureRefsByNode.get(signatureNode.id) || new Set();
        if (!signatureRefs.has(outputRef)) continue;
        links.push({
          opgraph_id: subgraph.id || "",
          output_ref: outputRef,
          to_node_id: signatureNode.id,
          to_stage: signatureNode.stage,
          relation: "vmp_output_ref_on_signature_stage",
          confidence: subgraph.confidence || "medium"
        });
      }
    }
  }

  const requestLinks = findGraphPathEdges(graph.edges || [], signatureNodeIds, requestNodeIds)
    .map(dataflowEdgeSummary);

  const linkedOutputRefs = uniqueLimited(links.map((link) => link.output_ref), 8);
  const encodingBoundaryLinks = links.length ? [] : buildEncodingBoundaryLinks(graph, signatureNodeIds);
  const bridgeLinks = links.length ? [] : buildVmpSignatureBridgeLinks(graph, signatureNodeIds);
  const attachmentToRequestLinkObserved = requestLinks.length > 0;
  const unresolvedOutputBridges = !links.length && !encodingBoundaryLinks.length
    ? buildUnresolvedOutputBridges(graph, bridgeLinks, attachmentToRequestLinkObserved)
    : [];
  let status = "vmp_output_reaches_signed_request";
  let gaps = [];
  let nextActions = ["review_source_refs"];

  if (!links.length) {
    if (encodingBoundaryLinks.length && attachmentToRequestLinkObserved) {
      status = "vmp_output_reaches_signed_request_via_string_boundary";
      gaps = [];
      nextActions = ["review_source_refs"];
    } else if (encodingBoundaryLinks.length) {
      status = "vmp_output_reaches_signature_via_string_boundary";
      gaps = ["signature_to_request_link_not_observed"];
      nextActions = ["capture_url_search_params_mutation_or_header_set"];
    } else if (bridgeLinks.length && attachmentToRequestLinkObserved) {
      status = "vmp_stage_bridge_reaches_signed_request";
      gaps = ["vmp_output_ref_to_signature_not_observed"];
      nextActions = [
        "capture_string_encoding_boundary_refs",
        "capture_object_ids_for_data_links",
        "capture_vmp_register_state_refs"
      ];
    } else if (bridgeLinks.length) {
      status = "vmp_stage_bridge_reaches_signature_attachment";
      gaps = ["vmp_output_ref_to_signature_not_observed", "signature_to_request_link_not_observed"];
      nextActions = [
        "capture_string_encoding_boundary_refs",
        "capture_url_search_params_mutation_or_header_set"
      ];
    } else {
      status = "vmp_output_not_linked_to_signature";
      gaps = ["vmp_output_not_linked_to_signature"];
      nextActions = ["capture_object_ids_for_data_links", "capture_vmp_register_state_refs"];
    }
  } else if (!attachmentToRequestLinkObserved) {
    status = "vmp_output_reaches_signature_attachment";
    gaps = ["signature_to_request_link_not_observed"];
    nextActions = ["capture_url_search_params_mutation_or_header_set"];
  }

  return {
    status,
    vmp_output_link_count: links.length,
    attachment_to_request_link_observed: attachmentToRequestLinkObserved,
    linked_output_refs: linkedOutputRefs,
    links: links.slice(0, 12),
    request_links: requestLinks.slice(0, 8),
    ...(encodingBoundaryLinks.length ? {
      encoding_boundary_link_count: encodingBoundaryLinks.length,
      encoding_boundary_links: encodingBoundaryLinks
    } : {}),
    ...(bridgeLinks.length ? {bridge_links: bridgeLinks} : {}),
    ...(unresolvedOutputBridges.length ? {
      unresolved_output_bridges: unresolvedOutputBridges
    } : {}),
    gaps,
    next_actions: nextActions
  };
}

function buildGenerationGraph(parameter) {
  const path = parameter.generation_path || [];
  const nodes = path.map((step) => ({
    id: generationGraphNodeId(step),
    order: step.order ?? null,
    stage: step.stage || "unknown",
    role: step.role || "context",
    status: generationGraphNodeStatus(step),
    apis: uniqueLimited(step.apis || [], 8),
    relation_to_signed_request: step.relation_to_signed_request || "unknown",
    distance_to_signed_request: step.distance_to_signed_request ?? null,
    evidence_flags: uniqueLimited(step.evidence_flags || [], 8),
    evidence_gaps: uniqueLimited(step.evidence_gaps || [], 8),
    source_refs: generationStepSourceRefs(step),
    object_refs: uniqueLimited(step.object_refs || [], 8),
    value_refs: uniqueLimited(step.value_refs || [], 8)
  }));
  const nodeIdByOrder = new Map(nodes.map((node) => [node.order, node.id]));
  const nodeIdByStage = new Map(nodes.map((node) => [node.stage, node.id]));
  const edges = (parameter.generation_edges || []).slice(0, 16).map((edge) => ({
    id: `edge_${edge.from_order ?? "?"}_${edge.to_order ?? "?"}`,
    from: nodeIdByOrder.get(edge.from_order) || `step_${edge.from_order ?? "?"}_${edge.from_stage || "unknown"}`,
    to: nodeIdByOrder.get(edge.to_order) || `step_${edge.to_order ?? "?"}_${edge.to_stage || "unknown"}`,
    status: "confirmed",
    relation: edge.relation || "related",
    confidence: edge.confidence || "unknown",
    refs: uniqueLimited(edge.refs || [], 8),
    source_refs: uniqueLimited(edge.source_refs || [], 8),
    evidence: uniqueLimited(edge.evidence || [], 8)
  }));
  const unresolvedEdges = (parameter.generation_edge_gaps || []).slice(0, 16).map((gap) => ({
    id: `gap_${gap.from_order ?? "?"}_${gap.to_order ?? "?"}`,
    from: nodeIdByOrder.get(gap.from_order) || `step_${gap.from_order ?? "?"}_${gap.from_stage || "unknown"}`,
    to: nodeIdByOrder.get(gap.to_order) || `step_${gap.to_order ?? "?"}_${gap.to_stage || "unknown"}`,
    status: "unresolved",
    gap: gap.gap || "unknown",
    reason: gap.reason || "unknown",
    priority: gap.priority || "medium",
    next_actions: uniqueLimited(gap.next_actions || [], 8),
    source_refs: uniqueLimited(gap.source_refs || [], 8),
    object_refs: uniqueLimited(gap.object_refs || [], 8),
    value_refs: uniqueLimited(gap.value_refs || [], 8)
  }));
  const graph = {
    node_count: nodes.length,
    edge_count: edges.length,
    unresolved_edge_count: unresolvedEdges.length,
    entry_node_id: nodes[0]?.id || "",
    exit_node_id: nodes[nodes.length - 1]?.id || "",
    readiness_status: parameter.analysis_readiness?.summary?.status || "unknown",
    primary_next_probe: parameter.analysis_readiness?.summary?.primary_next_action || "unknown",
    nodes,
    edges,
    unresolved_edges: unresolvedEdges,
    operation_subgraphs: buildOperationSubgraphs(parameter, nodeIdByStage)
  };
  graph.dataflow_summary = buildGenerationGraphDataflowSummary(graph, parameter);
  return graph;
}

function reconstructionRecipeStatus(graph, parameter = {}) {
  if (isDirectWebCryptoParameter(parameter)) return "direct_webcrypto_reconstruction_candidate";
  const flow = graph?.dataflow_summary || {};
  const opgraphCount = (graph?.operation_subgraphs || []).length;
  if (!opgraphCount) return "needs_vmp_operation_capture";
  if ((flow.gaps || []).length) return "partial_reconstruction_needs_refs";
  if (flow.attachment_to_request_link_observed &&
      ((flow.links || []).length || (flow.encoding_boundary_links || []).length)) {
    return "ready_for_agent_reconstruction";
  }
  return "candidate_reconstruction";
}

function operationProgramLine(node) {
  const order = node?.order ?? "?";
  const api = node?.api || "unknown";
  const inputs = (node?.input_refs || []).slice(0, 4).join(",");
  const result = node?.result_ref || (node?.output_refs || [])[0] || "unknown";
  return `op${order}=${api}(${inputs})->${result}`;
}

function operationProgramNodeOutputRefs(node) {
  return uniqueLimited([
    node?.result_ref,
    ...(node?.output_refs || [])
  ].filter(Boolean), 8);
}

function operationProgramSourceStep(parameter, subgraph) {
  const attachedNodeId = subgraph?.attached_node_id || "";
  const stage = subgraph?.stage || "";
  return (parameter?.generation_path || []).find((step) => generationGraphNodeId(step) === attachedNodeId) ||
    (parameter?.generation_path || []).find((step) => step.stage === stage) ||
    null;
}

function operationProgramTargetParams(parameter) {
  return sortParamNames(uniqueLimited([
    parameter?.param,
    ...(parameter?.target_params || []),
    ...(parameter?.candidate_generation_summary?.request_input_summary?.target_params || []),
    ...(parameter?.candidate_generation_summary?.target_params || [])
  ].filter(Boolean), 16));
}

function operationProgramInputSourceRefs(subgraph, node, sourceStep) {
  return uniqueLimited([
    ...(node?.source_refs || []),
    ...(subgraph?.source_refs || []),
    ...(subgraph?.source_context_refs || []),
    ...generationStepSourceRefs(sourceStep || {}),
    ...(sourceStep?.source_refs || [])
  ], 8);
}

function vmpExternalInputRefsByOperation(nodes) {
  const producedRefs = new Set();
  const seenInputs = new Set();
  const entries = [];
  for (const node of nodes || []) {
    for (const inputRef of node?.input_refs || []) {
      if (!inputRef || producedRefs.has(inputRef)) continue;
      const key = `${node?.id || ""}\u0000${inputRef}`;
      if (seenInputs.has(key)) continue;
      seenInputs.add(key);
      entries.push({node, inputRef});
    }
    for (const outputRef of operationProgramNodeOutputRefs(node)) producedRefs.add(outputRef);
  }
  return entries;
}

function buildVmpOperationProgramInputBindings(parameter, subgraph) {
  const sourceStep = operationProgramSourceStep(parameter, subgraph);
  const targetParams = operationProgramTargetParams(parameter);
  return vmpExternalInputRefsByOperation(subgraph?.nodes || [])
    .slice(0, 16)
    .map(({node, inputRef}) => {
      const matchedRuntimeRef = Boolean(sourceStep && stepRefsForInputBinding(sourceStep).has(inputRef));
      return {
        input_ref: inputRef,
        operation_id: node?.id || "",
        role: "vmp_operation_input",
        source_stage: sourceStep?.stage || subgraph?.stage || "unknown",
        source_order: sourceStep?.order ?? null,
        source_refs: operationProgramInputSourceRefs(subgraph, node, sourceStep),
        target_params: targetParams,
        evidence: uniqueLimited([
          ...(matchedRuntimeRef ? ["shared_runtime_ref"] : []),
          "vmp_operation_input_ref"
        ], 8)
      };
    });
}

function outputLinkTargetStage(graph, link) {
  return link?.to_stage ||
    (graph?.nodes || []).find((node) => node.id === link?.to_node_id)?.stage ||
    "unknown";
}

function requestLinkTargetParams(requestLinks) {
  return sortParamNames(uniqueLimited((requestLinks || [])
    .flatMap((link) => link.refs || [])
    .filter((ref) => String(ref || "").startsWith("target_params:"))
    .map((ref) => String(ref).slice("target_params:".length)), 16));
}

function operationProgramProducerIdForOutput(subgraph, outputRef) {
  const producer = (subgraph?.nodes || []).find((node) =>
    operationProgramNodeOutputRefs(node).includes(outputRef)
  );
  return producer?.id || "";
}

function buildVmpOperationProgramOutputBindings(parameter, graph, subgraph) {
  const flow = graph?.dataflow_summary || {};
  const requestLinks = flow.request_links || [];
  const requestNodeIds = uniqueLimited(requestLinks.map((link) => link.to_node_id).filter(Boolean), 8);
  const targetParams = sortParamNames(uniqueLimited([
    ...requestLinkTargetParams(requestLinks),
    ...operationProgramTargetParams(parameter)
  ], 16));
  return [
    ...(flow.links || []),
    ...(flow.encoding_boundary_links || [])
  ]
    .filter((link) => (link?.opgraph_id || "") === (subgraph?.id || ""))
    .slice(0, 16)
    .map((link) => ({
      output_ref: link.output_ref || "",
      operation_id: operationProgramProducerIdForOutput(subgraph, link.output_ref || ""),
      target_stage: outputLinkTargetStage(graph, link),
      target_node_id: link.to_node_id || "",
      request_node_ids: requestNodeIds,
      relation: link.relation || "related",
      confidence: link.confidence || subgraph?.confidence || "unknown",
      target_params: targetParams,
      evidence: uniqueLimited([
        "vmp_output_link",
        ...(requestNodeIds.length ? ["request_attachment_link"] : [])
      ], 8)
    }));
}

function buildVmpOperationProgramOperation(node) {
  const resultRef = node?.result_ref || "";
  const outputRefs = operationProgramNodeOutputRefs(node);
  return {
    id: node?.id || "",
    order: node?.order ?? null,
    api: node?.api || "unknown",
    seq: node?.seq ?? null,
    trace_index: node?.trace_index ?? null,
    input_refs: uniqueLimited(node?.input_refs || [], 8),
    result_ref: resultRef,
    ...(outputRefs.some((ref) => ref !== resultRef) ? {output_refs: outputRefs} : {}),
    source_refs: uniqueLimited(node?.source_refs || [], 8)
  };
}

function buildOperationProgram(subgraph, parameter = {}, graph = {}) {
  const inputBindings = buildVmpOperationProgramInputBindings(parameter, subgraph);
  const outputBindings = buildVmpOperationProgramOutputBindings(parameter, graph, subgraph);
  return {
    opgraph_id: subgraph.id || "",
    chain_id: subgraph.chain_id || "",
    stage: subgraph.stage || "unknown",
    attached_node_id: subgraph.attached_node_id || "",
    pattern: subgraph.pattern || "unknown",
    confidence: subgraph.confidence || "unknown",
    output_refs: uniqueLimited(subgraph.output_refs || [], 8),
    ...(outputBindings.length ? {output_bindings: outputBindings} : {}),
    ...(inputBindings.length ? {input_bindings: inputBindings} : {}),
    lines: (subgraph.nodes || []).slice(0, 12).map(operationProgramLine),
    edges: (subgraph.edges || []).slice(0, 12).map((edge) => ({
      from: edge.from || "",
      to: edge.to || "",
      via_ref: edge.via_ref || edge.relation || "related"
    })),
    operations: (subgraph.nodes || []).slice(0, 12).map(buildVmpOperationProgramOperation)
  };
}

function operationProgramSafeId(value) {
  return String(value || "unknown").replace(/[^A-Za-z0-9_-]+/g, "_");
}

function webCryptoProgramNodeId(operation) {
  const operationRef = operation?.operation_ref || `seq_${operation?.seq ?? "unknown"}`;
  return `webcrypto_${operationProgramSafeId(operationRef)}_${operation?.phase || "event"}`;
}

function webCryptoProgramInputRefs(operation) {
  if (operation?.phase === "return") {
    return uniqueLimited([operation.operation_ref].filter(Boolean), 4);
  }
  return uniqueLimited([
    operation?.key_ref,
    operation?.key_material_ref,
    operation?.input_ref,
    operation?.input_array_buffer_ref
  ].filter(Boolean), 8);
}

function webCryptoProgramResultRef(operation) {
  if (operation?.phase !== "return") return operation?.operation_ref || "unknown";
  return operation?.key_ref || operation?.result_ref || operation?.result_array_buffer_ref || operation?.operation_ref || "unknown";
}

function webCryptoProgramOutputRefs(operation) {
  if (operation?.phase !== "return") return uniqueLimited([operation?.operation_ref].filter(Boolean), 4);
  return uniqueLimited([
    operation?.key_ref,
    operation?.result_ref,
    operation?.result_array_buffer_ref
  ].filter(Boolean), 8);
}

function webCryptoOperationProgramLine(operation, index) {
  const role = candidateLogicWebCryptoOperationRole(operation);
  const metadata = [
    operation?.phase || "event",
    `role=${role}`,
    operation?.operation_ref ? `op=${operation.operation_ref}` : "",
    operation?.algorithm ? `alg=${operation.algorithm}` : ""
  ].filter(Boolean).join(" ");
  const inputs = webCryptoProgramInputRefs(operation).join(",");
  return `op${index + 1}=${operation?.api || "unknown"}[${metadata}](${inputs})->${webCryptoProgramResultRef(operation)}`;
}

function directWebCryptoProgramPattern(operations) {
  const apis = new Set((operations || []).map((operation) => operation.api).filter(Boolean));
  if (apis.has("SubtleCrypto.importKey") && apis.has("SubtleCrypto.sign")) return "webcrypto_importKey_sign";
  if (apis.has("SubtleCrypto.sign")) return "webcrypto_sign";
  if (apis.has("SubtleCrypto.digest")) return "webcrypto_digest";
  return "webcrypto_operation_path";
}

function directWebCryptoProgramOutputRefs(summary) {
  return uniqueLimited([
    ...(summary?.result_refs || []),
    ...(summary?.result_array_buffer_refs || []),
    ...(summary?.key_refs || [])
  ], 8);
}

function buildWebCryptoOperationProgramEdges(operations) {
  const edges = [];
  const seen = new Set();
  function add(left, right, ref) {
    if (!ref) return;
    const from = webCryptoProgramNodeId(left);
    const to = webCryptoProgramNodeId(right);
    const key = `${from}\u0000${to}\u0000${ref}`;
    if (seen.has(key)) return;
    seen.add(key);
    edges.push({from, to, via_ref: ref});
  }
  for (let leftIndex = 0; leftIndex < (operations || []).length; leftIndex += 1) {
    const left = operations[leftIndex];
    const outputs = new Set(webCryptoProgramOutputRefs(left));
    for (let rightIndex = leftIndex + 1; rightIndex < (operations || []).length; rightIndex += 1) {
      const right = operations[rightIndex];
      for (const input of webCryptoProgramInputRefs(right)) {
        if (outputs.has(input)) add(left, right, input);
      }
    }
  }
  return edges.slice(0, 12);
}

function directWebCryptoRequestInputCategories(parameter) {
  return uniqueLimited(
    parameter?.candidate_generation_summary?.request_input_summary?.observed_categories || [],
    8
  );
}

function directWebCryptoTargetParams(parameter) {
  return operationProgramTargetParams(parameter);
}

function stepRefsForInputBinding(step) {
  return new Set([
    ...(step?.object_refs || []),
    ...(step?.value_refs || [])
  ].filter(Boolean));
}

function directWebCryptoSourceStepForInput(parameter, inputRef) {
  const matches = (parameter?.generation_path || []).filter((step) => stepRefsForInputBinding(step).has(inputRef));
  if (!matches.length) return (parameter?.generation_path || []).find((step) => step.stage === "hash_or_digest") || null;
  return matches.find((step) => step.stage !== "hash_or_digest") || matches[0];
}

function webCryptoExternalInputRefsByOperation(operations) {
  const producedRefs = new Set();
  const entries = [];
  for (const operation of operations || []) {
    const role = candidateLogicWebCryptoOperationRole(operation);
    for (const inputRef of webCryptoProgramInputRefs(operation)) {
      if (!inputRef || producedRefs.has(inputRef)) continue;
      if (operation.phase !== "call") continue;
      entries.push({operation, inputRef, role});
    }
    for (const outputRef of webCryptoProgramOutputRefs(operation)) producedRefs.add(outputRef);
  }
  return entries;
}

function buildDirectWebCryptoInputBindings(parameter, operations) {
  const requestInputCategories = directWebCryptoRequestInputCategories(parameter);
  const targetParams = directWebCryptoTargetParams(parameter);
  return webCryptoExternalInputRefsByOperation(operations)
    .slice(0, 16)
    .map(({operation, inputRef, role}) => {
      const sourceStep = directWebCryptoSourceStepForInput(parameter, inputRef);
      const sourceRefs = generationStepSourceRefs(sourceStep || {});
      const matchedRuntimeRef = Boolean(sourceStep && stepRefsForInputBinding(sourceStep).has(inputRef));
      return {
        input_ref: inputRef,
        operation_id: webCryptoProgramNodeId(operation),
        role,
        source_stage: sourceStep?.stage || "hash_or_digest",
        source_order: sourceStep?.order ?? null,
        source_refs: uniqueLimited(sourceRefs, 8),
        request_input_categories: requestInputCategories,
        target_params: targetParams,
        evidence: uniqueLimited([
          ...(matchedRuntimeRef && sourceStep?.stage !== "hash_or_digest" ? ["shared_runtime_ref"] : []),
          "webcrypto_input_ref"
        ], 8)
      };
    });
}

function directWebCryptoTargetNodeId(graph) {
  const flow = graph?.dataflow_summary || {};
  const signatureNodeIds = (graph?.nodes || [])
    .filter((node) => node.stage === "signature_mutation")
    .map((node) => node.id);
  const requestNodeIds = (graph?.nodes || [])
    .filter((node) => node.stage === "signed_request")
    .map((node) => node.id);
  return signatureNodeIds[0] || requestNodeIds[0] || flow.request_links?.[0]?.to_node_id || "";
}

function directWebCryptoOutputLinks(parameter, graph) {
  const flow = graph?.dataflow_summary || {};
  const targetNodeId = directWebCryptoTargetNodeId(graph);
  if (flow.status !== "direct_webcrypto_operation_path" || !targetNodeId) return [];
  const hasSignatureNode = (graph?.nodes || []).some((node) => node.stage === "signature_mutation");
  return (flow.webcrypto_result_refs || []).slice(0, 12).map((ref) => ({
    opgraph_id: `webcrypto_${operationProgramSafeId(parameter?.param || "parameter")}`,
    output_ref: ref,
    to_node_id: targetNodeId,
    relation: hasSignatureNode
      ? "webcrypto_result_ref_on_signature_stage"
      : "webcrypto_result_ref_on_request_path",
    confidence: hasSignatureNode ? "high" : "medium"
  }));
}

function webCryptoOperationProducerIdForOutput(operations, outputRef) {
  const producer = (operations || []).find((operation) =>
    webCryptoProgramOutputRefs(operation).includes(outputRef)
  );
  return producer ? webCryptoProgramNodeId(producer) : "";
}

function buildDirectWebCryptoOutputBindings(parameter, graph, operations) {
  const flow = graph?.dataflow_summary || {};
  const requestLinks = flow.request_links || [];
  const links = directWebCryptoOutputLinks(parameter, graph);
  const requestNodeIds = uniqueLimited([
    ...requestLinks.map((link) => link.to_node_id).filter(Boolean),
    ...links.map((link) => link.to_node_id).filter(Boolean)
  ], 8);
  const targetParams = sortParamNames(uniqueLimited([
    ...requestLinkTargetParams(requestLinks),
    ...directWebCryptoTargetParams(parameter)
  ], 16));
  return links.map((link) => ({
    output_ref: link.output_ref || "",
    operation_id: webCryptoOperationProducerIdForOutput(operations, link.output_ref || ""),
    target_stage: outputLinkTargetStage(graph, link),
    target_node_id: link.to_node_id || "",
    request_node_ids: requestNodeIds,
    relation: link.relation || "related",
    confidence: link.confidence || "unknown",
    target_params: targetParams,
    evidence: uniqueLimited([
      "webcrypto_output_link",
      ...(requestNodeIds.length ? ["request_attachment_link"] : [])
    ], 8)
  }));
}

function buildDirectWebCryptoOperationPrograms(parameter, graph) {
  if (!isDirectWebCryptoParameter(parameter)) return [];
  const summary = compactWebCryptoSignatureSummary(parameter?.webcrypto_signature_summary);
  const operations = candidateLogicWebCryptoOperations(summary);
  if (!operations.length) return [];
  const attachedNode = (graph?.nodes || []).find((node) => node.stage === "hash_or_digest") || null;
  const safeParam = operationProgramSafeId(parameter?.param || "parameter");
  return [{
    opgraph_id: `webcrypto_${safeParam}`,
    chain_id: `direct_webcrypto_${safeParam}`,
    stage: "hash_or_digest",
    attached_node_id: attachedNode?.id || "",
    pattern: directWebCryptoProgramPattern(operations),
    confidence: "high",
    output_refs: directWebCryptoProgramOutputRefs(summary),
    lines: operations.slice(0, 12).map(webCryptoOperationProgramLine),
    edges: buildWebCryptoOperationProgramEdges(operations),
    input_bindings: buildDirectWebCryptoInputBindings(parameter, operations),
    output_bindings: buildDirectWebCryptoOutputBindings(parameter, graph, operations),
    operations: operations.slice(0, 12).map((operation, index) => ({
      id: webCryptoProgramNodeId(operation),
      order: index + 1,
      api: operation.api || "",
      phase: operation.phase || "",
      role: candidateLogicWebCryptoOperationRole(operation),
      seq: operation.seq ?? null,
      operation_ref: operation.operation_ref || "",
      algorithm: operation.algorithm || "",
      input_refs: webCryptoProgramInputRefs(operation),
      result_ref: webCryptoProgramResultRef(operation)
    }))
  }];
}

function buildReconstructionAttachment(graph, parameter = {}) {
  const flow = graph?.dataflow_summary || {};
  const signatureNodeIds = (graph?.nodes || [])
    .filter((node) => node.stage === "signature_mutation")
    .map((node) => node.id);
  const requestNodeIds = (graph?.nodes || [])
    .filter((node) => node.stage === "signed_request")
    .map((node) => node.id);
  const outputLinks = [
    ...(flow.links || []),
    ...(flow.encoding_boundary_links || []),
    ...directWebCryptoOutputLinks(parameter, graph)
  ].slice(0, 12).map((link) => ({
    opgraph_id: link.opgraph_id || "",
    output_ref: link.output_ref || "",
    to_node_id: link.to_node_id || "",
    relation: link.relation || "related",
    confidence: link.confidence || "unknown"
  }));
  const requestLinks = (flow.request_links || []).slice(0, 8).map((link) => ({
    from_node_id: link.from_node_id || "",
    to_node_id: link.to_node_id || "",
    relation: link.relation || "related",
    refs: uniqueLimited(link.refs || [], 8)
  }));
  return {
    status: outputLinks.length && requestLinks.length ? "observed" : "partial",
    signature_node_ids: signatureNodeIds,
    request_node_ids: requestNodeIds,
    output_links: outputLinks,
    request_links: requestLinks
  };
}

function materializationProgramOutputRef(event) {
  if (event?.result_ref) return event.result_ref;
  const inputRefs = new Set(event?.input_refs || []);
  const candidates = (event?.value_refs || [])
    .filter((ref) =>
      ref &&
      !inputRefs.has(ref) &&
      !String(ref).startsWith("target_params:") &&
      !String(ref).startsWith("url_shape:"));
  return candidates[candidates.length - 1] || candidates[0] || "unknown";
}

function materializationProgramInputRefs(event) {
  const outputRef = materializationProgramOutputRef(event);
  return compactGenerationValueRefs(
    [
      ...(event?.input_refs || []),
      ...(event?.value_refs || []).filter((ref) =>
        ref &&
        ref !== outputRef &&
        !String(ref).startsWith("target_params:") &&
        !String(ref).startsWith("url_shape:"))
    ],
    8,
    {preserveStringRuntimeRefs: true}
  );
}

function materializationProgramLine(event, index) {
  const inputs = materializationProgramInputRefs(event).join(",") || "unknown";
  const output = materializationProgramOutputRef(event);
  const seq = event?.seq ?? event?.trace_index ?? "?";
  return `mat${index + 1}=${event?.param || "unknown"}:${event?.api || "unknown"}@${seq}(${inputs}->${output})`;
}

function materializationProgramOperation(event, index) {
  return {
    id: `mat_${operationProgramSafeId(event?.param || "param")}_${event?.seq ?? event?.trace_index ?? index + 1}`,
    order: index + 1,
    param: event?.param || "",
    api: event?.api || "",
    seq: event?.seq ?? null,
    ...(Number.isFinite(event?.trace_index) ? {trace_index: event.trace_index} : {}),
    action: event?.action || "string_materialize",
    input_refs: materializationProgramInputRefs(event),
    result_ref: materializationProgramOutputRef(event),
    value_refs: compactGenerationValueRefs(event?.value_refs || [], 12, {preserveStringRuntimeRefs: true})
  };
}

function materializationProgramEvents(parameter) {
  const targetParams = new Set(operationProgramTargetParams(parameter));
  return compactSignatureParamMaterializations([
    ...(parameter?.candidate_generation_summary?.signature_param_materializations || []),
    ...(parameter?.signature_param_materializations || [])
  ])
    .filter((event) => !targetParams.size || targetParams.has(event.param));
}

function buildMaterializationPrograms(parameter) {
  const events = materializationProgramEvents(parameter);
  if (!events.length) return [];
  const targetParams = sortParamNames(uniqueLimited(events.map((event) => event.param).filter(Boolean), 16));
  const safeParam = operationProgramSafeId(parameter?.param || targetParams[0] || "parameter");
  return [{
    opgraph_id: `materialization_${safeParam}`,
    chain_id: `signature_materialization_${safeParam}`,
    stage: "signature_materialization",
    pattern: "runtime_signature_param_materialization",
    confidence: "high",
    target_params: targetParams,
    output_refs: uniqueLimited(events.map(materializationProgramOutputRef).filter((ref) => ref && ref !== "unknown"), 12),
    lines: events.slice(0, 12).map(materializationProgramLine),
    operations: events.slice(0, 12).map(materializationProgramOperation)
  }];
}

function reconstructionAlgorithmInputBindings(operationPrograms) {
  const output = [];
  const seen = new Set();
  for (const program of operationPrograms || []) {
    for (const binding of program?.input_bindings || []) {
      const inputRef = binding?.input_ref || "";
      const operationId = binding?.operation_id || "";
      if (!inputRef || !operationId) continue;
      const key = `${inputRef}\u0000${operationId}\u0000${binding?.role || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      output.push(binding);
      if (output.length >= 16) return output;
    }
  }
  return output;
}

function reconstructionAlgorithmInputLine(binding, index) {
  return `input${index + 1}=${binding?.input_ref || "unknown"}=>${binding?.operation_id || "unknown"}[${binding?.role || "input"} stage=${binding?.source_stage || "unknown"}]`;
}

function reconstructionAlgorithmMaterializationInputRefs(materializationPrograms) {
  return uniqueLimited((materializationPrograms || [])
    .flatMap((program) => program?.operations || [])
    .flatMap((operation) => operation?.input_refs || [])
    .filter(Boolean), 16);
}

function reconstructionAlgorithmProgramLine(program, index) {
  return `program${index + 1}=${program?.chain_id || program?.opgraph_id || "unknown"}:${program?.stage || "unknown"} pattern=${program?.pattern || "unknown"}`;
}

function stageFromGenerationNodeId(nodeId) {
  const match = /^step_\d+_(.+)$/.exec(String(nodeId || ""));
  return match ? match[1] : "unknown";
}

function reconstructionAlgorithmAttachmentLines(attachment) {
  return (attachment?.output_links || []).slice(0, 8).map((link, index) =>
    `attach${index + 1}=${link?.output_ref || "unknown"}->${stageFromGenerationNodeId(link?.to_node_id)}[${link?.to_node_id || "unknown"} confidence=${link?.confidence || "unknown"}]`
  );
}

function reconstructionAlgorithmRequestLines(attachment, graph) {
  const requestLinks = (attachment?.request_links || []).slice(0, 8);
  if (requestLinks.length) {
    return requestLinks.map((link, index) =>
      `request${index + 1}=${link?.from_node_id || "unknown"}->${link?.to_node_id || "unknown"}[${link?.relation || "related"} refs=${(link?.refs || []).join(",") || "none"}]`
    );
  }
  return (graph?.edges || [])
    .filter((edge) => stageFromGenerationNodeId(edge?.to) === "signed_request")
    .slice(0, 8)
    .map((edge, index) =>
      `request${index + 1}=${edge?.from || "unknown"}->${edge?.to || "unknown"}[${edge?.relation || "related"} refs=${(edge?.refs || []).join(",") || "none"}]`
    );
}

function reconstructionAlgorithmOutputRefs(operationPrograms, materializationPrograms, attachment) {
  const attachedOutputs = (attachment?.output_links || [])
    .map((link) => link?.output_ref || "")
    .filter(Boolean);
  if (attachedOutputs.length) return uniqueLimited(attachedOutputs, 16);
  return uniqueLimited([
    ...(operationPrograms || []).flatMap((program) => program?.output_refs || []),
    ...(materializationPrograms || []).flatMap((program) => program?.output_refs || [])
  ].filter(Boolean), 16);
}

function reconstructionAlgorithmReproducibility(status, operationPrograms, materializationPrograms, attachment) {
  if ((attachment?.status || "") === "observed" && (operationPrograms || []).length) return "observed_runtime_replay";
  if ((attachment?.request_links || []).length && ((operationPrograms || []).length || (materializationPrograms || []).length)) return "observed_runtime_replay";
  if ((operationPrograms || []).length || (materializationPrograms || []).length) return "partial_runtime_replay";
  return status === "needs_vmp_operation_capture" ? "not_reproducible_yet" : "partial_runtime_replay";
}

function buildReconstructionAlgorithmOutline({
  status,
  targetParams,
  operationPrograms,
  materializationPrograms,
  attachment,
  graph,
  evidenceGaps
}) {
  const inputBindings = reconstructionAlgorithmInputBindings(operationPrograms);
  const materializationInputRefs = reconstructionAlgorithmMaterializationInputRefs(materializationPrograms);
  const lines = [
    ...inputBindings.slice(0, 12).map(reconstructionAlgorithmInputLine)
  ];
  let programIndex = 0;
  for (const program of operationPrograms || []) {
    lines.push(reconstructionAlgorithmProgramLine(program, programIndex));
    programIndex += 1;
    lines.push(...(program?.lines || []).slice(0, 12));
    if (lines.length >= 48) break;
  }
  for (const program of materializationPrograms || []) {
    lines.push(reconstructionAlgorithmProgramLine(program, programIndex));
    programIndex += 1;
    lines.push(...(program?.lines || []).slice(0, 12));
    if (lines.length >= 48) break;
  }
  lines.push(...reconstructionAlgorithmAttachmentLines(attachment));
  lines.push(...reconstructionAlgorithmRequestLines(attachment, graph));
  const compactLines = uniqueLimited(lines.filter(Boolean), 64);
  if (!compactLines.length) return null;
  return {
    status,
    target_params: targetParams,
    reproducibility: reconstructionAlgorithmReproducibility(status, operationPrograms, materializationPrograms, attachment),
    lines: compactLines,
    inputs: uniqueLimited([
      ...inputBindings.map((binding) => binding.input_ref).filter(Boolean),
      ...materializationInputRefs
    ], 16),
    outputs: reconstructionAlgorithmOutputRefs(operationPrograms, materializationPrograms, attachment),
    gaps: uniqueLimited(evidenceGaps || [], 16)
  };
}

function buildReconstructionRecipe(parameter) {
  const graph = parameter.generation_graph || {};
  const flow = graph.dataflow_summary || {};
  const operationPrograms = [
    ...(graph.operation_subgraphs || []).slice(0, 8).map((subgraph) => buildOperationProgram(subgraph, parameter, graph)),
    ...buildDirectWebCryptoOperationPrograms(parameter, graph)
  ].slice(0, 8);
  const materializationPrograms = buildMaterializationPrograms(parameter);
  const status = reconstructionRecipeStatus(graph, parameter);
  const targetParams = operationProgramTargetParams(parameter);
  const attachment = buildReconstructionAttachment(graph, parameter);
  const evidenceGaps = uniqueLimited(flow.gaps || [], 12);
  const algorithmOutline = buildReconstructionAlgorithmOutline({
    status,
    targetParams,
    operationPrograms,
    materializationPrograms,
    attachment,
    graph,
    evidenceGaps
  });
  return {
    status,
    param: parameter.param || "",
    endpoint: parameter.endpoint || "",
    stage_chain: uniqueLimited((parameter.generation_path || [])
      .map((step) => step.stage)
      .filter(Boolean), 16),
    dataflow_status: flow.status || "unknown",
    operation_programs: operationPrograms,
    ...(materializationPrograms.length ? {materialization_programs: materializationPrograms} : {}),
    ...(algorithmOutline ? {algorithm_outline: algorithmOutline} : {}),
    attachment,
    evidence_gaps: evidenceGaps,
    next_actions: uniqueLimited(flow.next_actions || parameter.recommended_next_actions || [], 12)
  };
}

function vmpStepHasFamily(step, families) {
  const familySet = new Set(families || []);
  return (step?.apis || []).some((api) => familySet.has(vmpFamilyForApi(api)));
}

function isVmpDynamicDispatchStep(step) {
  return step?.stage === "dynamic_dispatch" ||
    vmpStepHasFamily(step, ["dynamic_dispatch"]) ||
    (step?.source_signals || []).includes("vmp_dynamic_dispatch") ||
    (step?.source_calls || []).some((call) => /(?:Reflect\.apply|\.call|\.apply)/.test(String(call || "")));
}

function isVmpIntegerMixingStep(step) {
  return step?.stage === "integer_mixing" ||
    vmpStepHasFamily(step, ["int_bitwise", "int_arithmetic"]) ||
    (step?.apis || []).some((api) => /^(?:Bitwise\.|Shift\.)/.test(api || "") || api === "Math.imul");
}

function refsForStepsByPrefix(steps, fields, prefix, limit = 8) {
  return uniqueLimited((steps || [])
    .flatMap((step) => (fields || []).flatMap((field) => step?.[field] || []))
    .filter((ref) => String(ref || "").startsWith(prefix)), limit);
}

function sourceRefsForSteps(steps, limit = 16) {
  return uniqueLimited((steps || [])
    .flatMap((step) => generationStepSourceRefs(step)), limit);
}

function sourceEvidencePreviewsForParameter(parameter) {
  return uniqueLimited([
    ...(parameter.source_evidence || []).map((source) => source.preview || ""),
    ...(parameter.generation_path || [])
      .flatMap((step) => step.source_evidence || [])
      .map((source) => source.preview || "")
  ].filter(Boolean), 8);
}

function sourceSignalsForVmpStateModel(parameter) {
  const previews = sourceEvidencePreviewsForParameter(parameter);
  const previewSignals = previews.flatMap((preview) => analyzeJavaScriptSource(preview).signals || []);
  return uniqueLimited([
    ...(parameter.generation_path || []).flatMap((step) => step.source_signals || []),
    ...(parameter.source_evidence || []).flatMap((source) => source.signals || []),
    ...(parameter.generation_path || [])
      .flatMap((step) => step.source_evidence || [])
      .flatMap((source) => source.signals || []),
    ...previewSignals
  ], 16);
}

function sourceCallsForVmpStateModel(parameter) {
  return uniqueLimited((parameter.generation_path || [])
    .flatMap((step) => step.source_calls || []), 16);
}

function sourceRefsForVmpStateModel(parameter) {
  return uniqueLimited([
    ...(parameter.source_refs || []),
    ...(parameter.generation_path || []).flatMap((step) => generationStepSourceRefs(step))
  ], 12);
}

function vmpStateStatus({handlerTable, bytecodePc, dispatchBoundary, stateRefs, registerRefs}) {
  if (
    handlerTable === "observed_source_and_runtime" &&
    bytecodePc === "observed_source" &&
    dispatchBoundary === "observed_runtime" &&
    stateRefs.length &&
    registerRefs.length
  ) {
    return "observed";
  }
  if (
    handlerTable !== "missing" ||
    bytecodePc !== "missing" ||
    dispatchBoundary !== "missing" ||
    stateRefs.length ||
    registerRefs.length
  ) {
    return "partial";
  }
  return "missing";
}

function vmpStateNextActions(gaps) {
  const actions = [];
  if (!(gaps || []).length) return ["review_vmp_state_model"];
  if ((gaps || []).some((gap) => [
    "vmp_state_object_ref_not_observed",
    "vmp_register_ref_not_observed",
    "vmp_handler_return_ref_not_observed",
    "vmp_register_to_mixing_link_not_observed",
    "vmp_register_value_ref_to_mixing_not_observed"
  ].includes(gap))) {
    actions.push("capture_vmp_register_state_refs");
  }
  if ((gaps || []).some((gap) => [
    "vmp_handler_table_source_not_observed",
    "vmp_bytecode_pc_source_not_observed"
  ].includes(gap))) {
    actions.push("capture_or_retrieve_script_asset");
  }
  if ((gaps || []).includes("vmp_dynamic_dispatch_boundary_not_observed")) {
    actions.push("expand_vmp_runtime_hooks");
  }
  return uniqueLimited(actions, 8);
}

function inferredRegisterToMixingLink(dynamicSteps, mixingSteps, dynamicRegisterRefs, sourceSignals) {
  if (!(dynamicRegisterRefs || []).length || !(mixingSteps || []).length) return null;
  if (!(sourceSignals || []).includes("vmp_register_state")) return null;
  const dynamicSourceRefs = sourceRefsForSteps(dynamicSteps, 24);
  const mixingSourceRefs = sourceRefsForSteps(mixingSteps, 24);
  const sharedSourceRefs = intersectRefs(dynamicSourceRefs, mixingSourceRefs);
  if (!sharedSourceRefs.length) return null;
  const hasOrderedWindow = (dynamicSteps || []).some((dynamicStep) =>
    (mixingSteps || []).some((mixingStep) =>
      dynamicStep.relation_to_signed_request === "before_signed_request" &&
      mixingStep.relation_to_signed_request === "before_signed_request" &&
      dynamicStep.distance_basis === mixingStep.distance_basis &&
      Number.isFinite(dynamicStep.distance_to_signed_request) &&
      Number.isFinite(mixingStep.distance_to_signed_request) &&
      dynamicStep.distance_to_signed_request >= mixingStep.distance_to_signed_request
    )
  );
  return {
    refs: uniqueLimited(dynamicRegisterRefs, 8),
    source_refs: sharedSourceRefs,
    basis: uniqueLimited([
      "shared_vmp_register_state_source",
      ...(hasOrderedWindow ? ["pre_request_stage_order"] : [])
    ], 4)
  };
}

function buildVmpStateModel(parameter) {
  if (isDirectWebCryptoParameter(parameter)) {
    return {
      status: "not_applicable",
      handler_table: "not_applicable",
      bytecode_pc: "not_applicable",
      dispatch_boundary: "not_applicable",
      state_refs: [],
      register_refs: [],
      handler_return_refs: [],
      handler_arg_refs: [],
      runtime_apis: [],
      source_refs: [],
      source_calls: [],
      source_signals: [],
      linkage: {
        register_to_integer_mixing: "not_applicable",
        handler_return_to_integer_mixing: "not_applicable",
        handler_arg_to_integer_mixing: "not_applicable",
        register_to_integer_mixing_refs: [],
        handler_return_to_integer_mixing_refs: [],
        handler_arg_to_integer_mixing_refs: []
      },
      unresolved_gaps: [],
      next_actions: []
    };
  }
  const path = parameter.generation_path || [];
  const dynamicSteps = path.filter(isVmpDynamicDispatchStep);
  const mixingSteps = path.filter(isVmpIntegerMixingStep);
  const sourceSignals = sourceSignalsForVmpStateModel(parameter);
  const sourceCalls = sourceCallsForVmpStateModel(parameter);
  const sourceRefs = sourceRefsForVmpStateModel(parameter);
  const sourcePreviews = sourceEvidencePreviewsForParameter(parameter);
  const runtimeApis = uniqueLimited(dynamicSteps.flatMap((step) => step.apis || []), 16);
  const stateRefs = refsForStepsByPrefix(dynamicSteps.length ? dynamicSteps : path, ["object_refs"], "state_object:", 8);
  const dynamicRegisterRefs = refsForStepsByPrefix(dynamicSteps, ["value_refs"], "register:", 16);
  const dynamicHandlerReturnRefs = refsForStepsByPrefix(dynamicSteps, ["value_refs"], "handler_return:", 16);
  const dynamicHandlerArgRefs = refsForStepsByPrefix(dynamicSteps, ["value_refs"], "handler_arg:", 16);
  const mixingRegisterRefs = refsForStepsByPrefix(mixingSteps, ["value_refs"], "register:", 16);
  const mixingHandlerReturnRefs = refsForStepsByPrefix(mixingSteps, ["value_refs"], "handler_return:", 16);
  const mixingHandlerArgRefs = refsForStepsByPrefix(mixingSteps, ["value_refs"], "handler_arg:", 16);
  const fallbackRegisterRefs = refsForStepsByPrefix(path, ["value_refs"], "register:", 16);
  const fallbackHandlerReturnRefs = refsForStepsByPrefix(path, ["value_refs"], "handler_return:", 16);
  const fallbackHandlerArgRefs = refsForStepsByPrefix(path, ["value_refs"], "handler_arg:", 16);
  const registerRefs = uniqueLimited([
    ...(dynamicSteps.length ? dynamicRegisterRefs : fallbackRegisterRefs),
    ...mixingRegisterRefs
  ], 8);
  const handlerReturnRefs = uniqueLimited([
    ...(dynamicSteps.length ? dynamicHandlerReturnRefs : fallbackHandlerReturnRefs),
    ...mixingHandlerReturnRefs
  ], 8);
  const handlerArgRefs = uniqueLimited([
    ...(dynamicSteps.length ? dynamicHandlerArgRefs : fallbackHandlerArgRefs),
    ...mixingHandlerArgRefs
  ], 8);
  const mixingValueRefs = uniqueLimited(mixingSteps.flatMap((step) => step.value_refs || []), 32);
  const registerToMixingRefs = intersectRefs(dynamicRegisterRefs, mixingValueRefs);
  const handlerReturnToMixingRefs = intersectRefs(dynamicHandlerReturnRefs, mixingValueRefs);
  const handlerArgToMixingRefs = intersectRefs(handlerArgRefs, mixingValueRefs);
  const hasSourceHandler = sourceSignals.includes("vmp_handler_table");
  const hasSourceDispatch = sourceSignals.includes("vmp_dynamic_dispatch") ||
    sourceCalls.some((call) => /(?:Reflect\.apply|\.call|\.apply)/.test(String(call || "")));
  const hasRuntimeDispatch = dynamicSteps.some((step) =>
    (step.apis || []).length ||
    (step.object_refs || []).length ||
    (step.value_refs || []).length
  );
  const hasSourceBytecodePc = sourceSignals.includes("vmp_bytecode_array") ||
    sourceSignals.includes("vmp_bytecode_cursor") ||
    sourceSignals.includes("vmp_dispatch_loop") ||
    sourcePreviews.some((preview) => /\b(?:bytecode|opcode|pc|offset)\b/.test(preview));
  const handlerTable = hasSourceHandler && hasRuntimeDispatch
    ? "observed_source_and_runtime"
    : hasSourceHandler
      ? "observed_source"
      : hasRuntimeDispatch
        ? "inferred_runtime_dispatch"
        : "missing";
  const bytecodePc = hasSourceBytecodePc
    ? "observed_source"
    : stateRefs.length || registerRefs.length
      ? "inferred_runtime_state"
      : "missing";
  const dispatchBoundary = hasRuntimeDispatch
    ? "observed_runtime"
    : hasSourceDispatch
      ? "observed_source"
      : "missing";
  const inferredRegisterLink = registerToMixingRefs.length
    ? null
    : inferredRegisterToMixingLink(dynamicSteps, mixingSteps, dynamicRegisterRefs, sourceSignals);
  const registerLinkStatus = registerToMixingRefs.length
    ? "observed"
    : mixingRegisterRefs.length
      ? "observed_mixing_input"
    : inferredRegisterLink
      ? "inferred_source_window"
      : "missing";
  const handlerReturnLink = handlerReturnToMixingRefs.length
    ? "observed"
    : handlerReturnRefs.length && registerToMixingRefs.length
      ? "via_register_state"
      : handlerReturnRefs.length && inferredRegisterLink
        ? "via_inferred_register_state"
      : "missing";
  const handlerArgLink = handlerArgToMixingRefs.length
    ? "observed"
    : handlerArgRefs.length && registerToMixingRefs.length
      ? "via_register_state"
      : handlerArgRefs.length && inferredRegisterLink
        ? "via_inferred_register_state"
      : "missing";
  const gaps = [];
  if (handlerTable === "missing" || handlerTable === "inferred_runtime_dispatch") {
    gaps.push("vmp_handler_table_source_not_observed");
  }
  if (bytecodePc !== "observed_source") gaps.push("vmp_bytecode_pc_source_not_observed");
  if (dispatchBoundary === "missing") gaps.push("vmp_dynamic_dispatch_boundary_not_observed");
  if (!stateRefs.length) gaps.push("vmp_state_object_ref_not_observed");
  if (!registerRefs.length) gaps.push("vmp_register_ref_not_observed");
  if (!handlerReturnRefs.length) gaps.push("vmp_handler_return_ref_not_observed");
  if (dynamicSteps.length && mixingSteps.length && registerLinkStatus === "missing") {
    gaps.push("vmp_register_to_mixing_link_not_observed");
  } else if (registerLinkStatus === "inferred_source_window") {
    gaps.push("vmp_register_value_ref_to_mixing_not_observed");
  }
  const status = vmpStateStatus({
    handlerTable,
    bytecodePc,
    dispatchBoundary,
    stateRefs,
    registerRefs
  });
  return {
    status,
    handler_table: handlerTable,
    bytecode_pc: bytecodePc,
    dispatch_boundary: dispatchBoundary,
    state_refs: stateRefs,
    register_refs: registerRefs,
    handler_return_refs: handlerReturnRefs,
    handler_arg_refs: handlerArgRefs,
    runtime_apis: runtimeApis,
    source_refs: sourceRefs,
    source_calls: sourceCalls,
    source_signals: sourceSignals,
    linkage: {
      register_to_integer_mixing: registerLinkStatus,
      handler_return_to_integer_mixing: handlerReturnLink,
      handler_arg_to_integer_mixing: handlerArgLink,
      register_to_integer_mixing_refs: registerToMixingRefs.length
        ? registerToMixingRefs
        : mixingRegisterRefs.length
          ? uniqueLimited(mixingRegisterRefs, 8)
        : inferredRegisterLink?.refs || [],
      handler_return_to_integer_mixing_refs: handlerReturnToMixingRefs,
      handler_arg_to_integer_mixing_refs: handlerArgToMixingRefs,
      ...(inferredRegisterLink ? {
        register_to_integer_mixing_source_refs: inferredRegisterLink.source_refs,
        register_to_integer_mixing_basis: inferredRegisterLink.basis
      } : {})
    },
    unresolved_gaps: uniqueLimited(gaps, 12),
    next_actions: vmpStateNextActions(gaps)
  };
}

function buildVmpStateTrace(parameter) {
  const model = parameter.vmp_state_model || {};
  if (model.status === "not_applicable") {
    return {
      status: "not_applicable",
      stage_chain: [],
      evidence_refs: []
    };
  }
  if (!model.status || model.status === "missing") {
    return {
      status: model.status || "missing",
      stage_chain: [],
      evidence_refs: []
    };
  }
  const stageChain = uniqueLimited((parameter.generation_path || [])
    .map((step) => step.stage)
    .filter((stage) => [
      "dynamic_dispatch",
      "integer_mixing",
      "signature_mutation",
      "signed_request"
    ].includes(stage)), 8);
  const linkage = model.linkage || {};
  const evidenceRefs = uniqueLimited([
    ...(model.source_refs || []).slice(0, 4),
    ...(model.state_refs || []).slice(0, 4),
    ...(model.register_refs || []).slice(0, 4),
    ...(model.handler_return_refs || []).slice(0, 2),
    ...(model.handler_arg_refs || []).slice(0, 2),
    ...(linkage.register_to_integer_mixing_refs || []).slice(0, 4),
    ...(linkage.handler_return_to_integer_mixing_refs || []).slice(0, 2),
    ...(linkage.handler_arg_to_integer_mixing_refs || []).slice(0, 2)
  ], 16);
  return {
    status: model.status,
    stage_chain: stageChain,
    runtime_apis: uniqueLimited(model.runtime_apis || [], 8),
    source_signals: uniqueLimited(model.source_signals || [], 8),
    source_refs: uniqueLimited(model.source_refs || [], 8),
    evidence_refs: evidenceRefs,
    linkage: {
      register_to_integer_mixing: linkage.register_to_integer_mixing || "unknown",
      handler_return_to_integer_mixing: linkage.handler_return_to_integer_mixing || "unknown",
      handler_arg_to_integer_mixing: linkage.handler_arg_to_integer_mixing || "unknown",
      register_to_integer_mixing_refs: uniqueLimited(linkage.register_to_integer_mixing_refs || [], 8),
      handler_return_to_integer_mixing_refs: uniqueLimited(linkage.handler_return_to_integer_mixing_refs || [], 8),
      handler_arg_to_integer_mixing_refs: uniqueLimited(linkage.handler_arg_to_integer_mixing_refs || [], 8)
    },
    unresolved_gaps: uniqueLimited(model.unresolved_gaps || [], 8)
  };
}

function mergeVmpStateModelIntoParameter(parameter) {
  const model = parameter.vmp_state_model || {};
  const vmpGaps = parameter.vmp_state_model?.unresolved_gaps || [];
  const hasStateEvidence = Boolean(
    (model.state_refs || []).length ||
    (model.register_refs || []).length ||
    (model.handler_return_refs || []).length ||
    (model.handler_arg_refs || []).length ||
    (model.linkage?.register_to_integer_mixing_refs || []).length ||
    (model.linkage?.handler_return_to_integer_mixing_refs || []).length ||
    (model.linkage?.handler_arg_to_integer_mixing_refs || []).length
  );
  if (model.status === "missing" || !hasStateEvidence || !(vmpGaps || []).length) return parameter;
  parameter.unresolved_gaps = uniqueLimited([
    ...(parameter.unresolved_gaps || []),
    ...vmpGaps
  ], 12);
  parameter.recommended_next_actions = uniqueLimited([
    ...(parameter.recommended_next_actions || []),
    ...(parameter.vmp_state_model?.next_actions || []).filter((action) => action !== "review_vmp_state_model")
  ].filter(Boolean), 12);
  return parameter;
}

const PROMOTED_DATAFLOW_GAPS = new Set([
  "vmp_output_ref_to_signature_not_observed"
]);

function mergeGenerationGraphDataflowIntoParameter(parameter) {
  const summary = parameter.generation_graph?.dataflow_summary || {};
  const gaps = uniqueLimited((summary.gaps || [])
    .filter((gap) => PROMOTED_DATAFLOW_GAPS.has(gap)), 8);
  if (!gaps.length) return parameter;

  parameter.unresolved_gaps = uniqueLimited([
    ...(parameter.unresolved_gaps || []),
    ...gaps
  ], 12);
  parameter.recommended_next_actions = uniqueLimited([
    ...(parameter.recommended_next_actions || []),
    ...(summary.next_actions || [])
  ].filter(Boolean), 12);
  return parameter;
}

function buildAgentAnalysis(pack) {
  const tracePath = pack.trace?.path || "";
  const coreAssets = (pack.core_assets || []).slice(0, 8).map((entry) => compactAgentCoreAssetEntry(entry));
  const sourceRefIndex = [
    ...(pack.source_ref_index || []),
    ...sourceIndexEntriesForCoreAssets(coreAssets)
  ];
  const parameters = (pack.parameters || []).map((parameter) => {
    const combinedSourceRefs = uniqueLimited([
      ...(parameter.source_refs || []),
      ...coreAssetSourceRefsForParameter(coreAssets, parameter.param || "")
    ], 16);
    const parameterWithCoreSources = {
      ...parameter,
      source_refs: combinedSourceRefs
    };
    const confirmedStages = uniqueLimited((parameter.generation_trace || [])
      .map((step) => step.stage)
      .filter(Boolean), 12);
    const generationPath = generationPathForParameter(parameterWithCoreSources, sourceRefIndex, tracePath);
    const generationEdges = generationEdgesForPath(generationPath, parameterWithCoreSources);
    const generationEdgeGaps = generationEdgeGapsForPath(generationPath, generationEdges);
    const runtimeRefLineage = buildRuntimeRefLineage(generationPath, generationEdges);
    const runtimeEventEvidence = buildRuntimeEventEvidence(generationPath);
    const runtimeRefEventEvidence = buildRuntimeRefEventEvidence(runtimeRefLineage, runtimeEventEvidence);
    const vmpScalarChainLinks = (parameter.vmp_scalar_chain_links || []).slice(0, 8).map(compactAgentScalarChainLink);
    const vmpOperationPatterns = vmpOperationPatternsForLinks(vmpScalarChainLinks, generationPath);
    const evidenceLevel = parameterEvidenceLevel(parameterWithCoreSources);
    const chainQuality = chainQualityForPath(generationPath, generationEdges, generationEdgeGaps);
    const recommendedActions = recommendedActionsForParameter(parameterWithCoreSources);
    const generationHypothesis = buildGenerationHypothesis({
      parameter: parameterWithCoreSources,
      evidenceLevel,
      generationPath,
      generationEdgeGaps,
      vmpOperationPatterns,
      chainQuality,
      recommendedActions
    });
    const agentParameter = {
      param: parameter.param || "",
      conclusion: parameterConclusion(parameter),
      evidence_level: evidenceLevel,
      best_flow_id: parameter.best_flow_id || "",
      endpoint: parameter.endpoint || "",
      chain_summary: confirmedStages.join(" -> ") || "unknown",
      confirmed_stages: confirmedStages,
      source_refs: uniqueLimited(parameterWithCoreSources.source_refs || [], 12),
      source_evidence: sourceEvidenceForParameter(parameterWithCoreSources, sourceRefIndex, tracePath),
      generation_path: generationPath,
      generation_edges: generationEdges,
      generation_edge_gaps: generationEdgeGaps,
      runtime_ref_lineage: runtimeRefLineage,
      runtime_event_evidence: runtimeEventEvidence,
      runtime_ref_event_evidence: runtimeRefEventEvidence,
      vmp_scalar_chain_links: vmpScalarChainLinks,
      vmp_operation_patterns: vmpOperationPatterns,
      signature_param_materializations: compactSignatureParamMaterializations(
        parameter.signature_param_materializations || [],
        parameter.param || ""
      ),
      ...(parameter.request_input_bundle ? {request_input_bundle: compactAgentRequestInputBundle(parameter.request_input_bundle)} : {}),
      ...(parameter.webcrypto_signature_summary ? {webcrypto_signature_summary: compactWebCryptoSignatureSummary(parameter.webcrypto_signature_summary)} : {}),
      generation_hypothesis: generationHypothesis,
      chain_quality: chainQuality,
      source_candidate_ids: uniqueLimited(parameter.source_candidate_ids || [], 8),
      review_entry_ids: uniqueLimited(parameter.review_entry_ids || [], 8),
      unresolved_gaps: uniqueLimited(parameterWithCoreSources.evidence_gaps || [], 8),
      recommended_next_actions: recommendedActions,
      generation_trace: parameter.generation_trace || []
    };
    agentParameter.analysis_readiness = buildAnalysisReadiness(agentParameter, recommendedActions);
    agentParameter.generation_graph = buildGenerationGraph(agentParameter);
    mergeGenerationGraphDataflowIntoParameter(agentParameter);
    agentParameter.vmp_state_model = buildVmpStateModel(agentParameter);
    agentParameter.vmp_state_trace = buildVmpStateTrace(agentParameter);
    mergeVmpStateModelIntoParameter(agentParameter);
    agentParameter.generation_hypothesis = buildGenerationHypothesis({
      parameter: agentParameter,
      evidenceLevel,
      generationPath,
      generationEdgeGaps,
      vmpOperationPatterns,
      chainQuality,
      recommendedActions: agentParameter.recommended_next_actions
    });
    agentParameter.analysis_readiness = buildAnalysisReadiness(agentParameter, agentParameter.recommended_next_actions);
    agentParameter.generation_graph = buildGenerationGraph(agentParameter);
    agentParameter.candidate_generation_summary = buildCandidateGenerationSummary(agentParameter, parameter);
    agentParameter.related_param_evidence = buildRelatedParamEvidence(agentParameter);
    agentParameter.reconstruction_recipe = buildReconstructionRecipe(agentParameter);
    return agentParameter;
  });
  const nextCaptureFocus = buildNextCaptureFocus(parameters);
  return {
    version: 1,
    purpose: "codex_agent_signature_analysis",
    redaction: pack.redaction || {
      values_redacted: false,
      output: "raw_values_preserved"
    },
    trace: pack.trace || {},
    capture_recipe: pack.capture_recipe || null,
    summary: {
      parameter_count: (pack.parameters || []).length,
      high_evidence_count: (pack.parameters || []).filter((parameter) => parameterEvidenceLevel(parameter) === "high").length,
      unresolved_gap_count: (pack.parameters || [])
        .reduce((sum, parameter) => sum + (parameter.evidence_gaps || []).length, 0),
      hypothesis_summary: buildHypothesisSummary(parameters),
      blocking_gap_summary: buildBlockingGapSummary(parameters),
      readiness_summary: buildReadinessSummary(parameters)
    },
    next_capture_focus: nextCaptureFocus,
    native_capture_requirements: buildNativeCaptureRequirements(nextCaptureFocus),
    core_assets: coreAssets,
    parameters
  };
}

function renderAgentAnalysisMarkdown(analysis) {
  const lines = [
    "# XTrace Agent Analysis",
    "",
    `Trace: \`${analysis.trace?.path || ""}\``,
    `Parameters: ${analysis.summary?.parameter_count ?? 0}`,
    `High evidence: ${analysis.summary?.high_evidence_count ?? 0}`,
    `Unresolved gaps: ${analysis.summary?.unresolved_gap_count ?? 0}`,
    `Hypotheses: ${hypothesisSummaryMarkdown(analysis.summary?.hypothesis_summary)}`,
    `Readiness: ${readinessSummaryMarkdown(analysis.summary?.readiness_summary)}`,
    `Blocking gaps: ${blockingGapSummaryMarkdown(analysis.summary?.blocking_gap_summary)}`,
    "",
    "## Parameter Conclusions",
    ""
  ];
  for (const parameter of analysis.parameters || []) {
    const sourceEvidence = (parameter.source_evidence || [])
      .slice(0, 6)
      .map((source) => `${source.ref}@${source.content_path || "none"}:${source.line_start ?? "none"}-${source.line_end ?? "none"}`)
      .join(",") || "none";
    const sourcePreview = (parameter.source_evidence || [])
      .map((source) => source.preview || "")
      .find(Boolean) || "none";
    lines.push(
      `- ${parameter.param || "unknown"}: ${parameter.conclusion || "unknown"} evidence=${parameter.evidence_level || "low"} endpoint=${parameter.endpoint || "unknown"} chain=${parameter.chain_summary || "unknown"} candidate_generation=${candidateGenerationSummaryMarkdownSummary(parameter.candidate_generation_summary)} related_params=${relatedParamEvidenceMarkdownSummary(parameter.related_param_evidence)} hypothesis=${generationHypothesisMarkdownSummary(parameter.generation_hypothesis)} readiness=${analysisReadinessMarkdownSummary(parameter.analysis_readiness)} graph=${generationGraphMarkdownSummary(parameter.generation_graph)} recipe=${reconstructionRecipeMarkdownSummary(parameter.reconstruction_recipe)} vmp_state_model=${vmpStateModelMarkdownSummary(parameter.vmp_state_model)} quality=${chainQualityMarkdownSummary(parameter.chain_quality)} path=${generationPathMarkdownSummary(parameter.generation_path)} edges=${generationEdgesMarkdownSummary(parameter.generation_edges)} ref_lineage=${runtimeRefLineageMarkdownSummary(parameter.runtime_ref_lineage)} ref_events=${runtimeRefEventEvidenceMarkdownSummary(parameter.runtime_ref_event_evidence)} event_evidence=${runtimeEventEvidenceMarkdownSummary(parameter.runtime_event_evidence)} edge_gaps=${generationEdgeGapsMarkdownSummary(parameter.generation_edge_gaps)} vmp_patterns=${vmpOperationPatternsMarkdownSummary(parameter.vmp_operation_patterns)} gaps=${(parameter.unresolved_gaps || []).join(",") || "none"} next=${(parameter.recommended_next_actions || []).join(",") || "none"} sources=${(parameter.source_refs || []).slice(0, 6).join(",") || "none"} source_evidence=${sourceEvidence} source_preview=${sourcePreview}`
    );
  }
  if (!(analysis.parameters || []).length) {
    lines.push("- none");
  }
  lines.push("", "## Native Capture Requirements", "");
  for (const requirement of (analysis.native_capture_requirements || []).slice(0, 12)) {
    lines.push(`- ${nativeCaptureRequirementMarkdownSummary(requirement)}`);
  }
  if (!(analysis.native_capture_requirements || []).length) {
    lines.push("- none");
  }
  lines.push("", "## Core Signature Assets", "");
  for (const asset of (analysis.core_assets || []).slice(0, 8)) {
    lines.push(
      `- core_asset=${asset.asset_id || "none"} role=${asset.asset_role || "none"} status=${asset.source_status || "unknown"} path=${asset.content_path || "none"} params=${(asset.target_params || []).join(",") || "none"} focus=${(asset.review_focus || []).join(",") || "none"} related_params=${(asset.related_params || []).join(",") || "none"} signals=${(asset.signals || []).slice(0, 8).join(",") || "none"}`
    );
    for (const entry of (asset.runtime_entrypoints || []).slice(0, 4)) {
      lines.push(
        `  - runtime_entry=${entry.function || "(anonymous)"} candidate=${entry.source_candidate_id || "none"} review=${entry.review_entry_id || "none"} causality=${entry.causality || "unknown"} priority=${entry.review_priority || "unknown"} params=${(entry.target_params || []).join(",") || "none"} related_params=${(entry.related_params || []).join(",") || "none"} link_status=${entry.link_status || "unknown"} missing=${(entry.missing_links || []).join(",") || "none"} next_hooks=${(entry.next_hooks || []).join(",") || "none"} stages=${(entry.stages || []).join(",") || "none"} apis=${(entry.runtime_apis || []).slice(0, 8).join(",") || "none"} refs=${(entry.source_refs || []).join(",") || "none"} endpoints=${(entry.endpoints || []).slice(0, 4).join(",") || "none"}`
      );
    }
    for (const window of (asset.source_windows || []).slice(0, 4)) {
      lines.push(
        `  - source_window=${window.focus || "unknown"} lines=${window.line_start ?? "none"}-${window.line_end ?? "none"} params=${(window.target_params || []).join(",") || "none"} preview=${window.preview || "none"}`
      );
    }
  }
  if (!(analysis.core_assets || []).length) {
    lines.push("- none");
  }
  lines.push("", "## Next Capture Focus", "");
  for (const focus of (analysis.next_capture_focus || []).slice(0, 8)) {
    const hookStatuses = (focus.hook_target_statuses || [])
      .slice(0, 8)
      .map((item) => `${item.target}:${item.status}`)
      .join(",") || "none";
    lines.push(
      `- action=${focus.action || "unknown"} priority=${focus.priority || "medium"} reason=${focus.reason || "unknown"} params=${(focus.params || []).join(",") || "none"} stages=${(focus.stages || []).join(",") || "none"} gaps=${(focus.gaps || []).join(",") || "none"} hooks=${(focus.hook_targets || []).slice(0, 8).join(",") || "none"} hook_status=${hookStatuses} ref_gaps=${refGapPlanMarkdownSummary(focus.ref_gap_plan)} endpoints=${(focus.endpoints || []).slice(0, 4).join(",") || "none"} sources=${(focus.source_refs || []).slice(0, 4).join(",") || "none"}`
    );
  }
  if (!(analysis.next_capture_focus || []).length) {
    lines.push("- none");
  }
  if (analysis.capture_recipe) {
    lines.push(
      "",
      "## Capture Recipe",
      "",
      `- start_url=${analysis.capture_recipe.start_url || "about:blank"} stop_when=${analysis.capture_recipe.stop_when || "none"}`,
      `- target_endpoint_patterns=${(analysis.capture_recipe.target_endpoint_patterns || []).join(",") || "none"}`
    );
  }
  lines.push("");
  return lines.join("\n");
}

function candidateTraceChainStepsSummary(chain) {
  const groups = [];
  for (const step of chain?.steps || []) {
    const phase = step.phase || "unknown";
    const label = `${step.api || "unknown"}@${step.seq ?? "none"}`;
    const last = groups[groups.length - 1];
    if (last && last.phase === phase) {
      last.labels.push(label);
    } else {
      groups.push({phase, labels: [label]});
    }
  }
  return groups
    .map((group) => `${group.phase}[${group.labels.slice(0, 6).join(",") || "none"}]`)
    .join("->") || "none";
}

function renderMarkdownReport(report) {
  const suspicious = report.assets.filter((asset) => asset.score > 0).slice(0, 20);
  const topApis = report.trace.top_apis.slice(0, 15);
  const lines = [
    "# XTrace Local Report",
    "",
    `Trace: \`${report.trace.path}\``,
    `Events: ${report.trace.event_count}`,
    `Dynamic execution events: ${report.reverse.dynamic_execution_count}`,
    `VMP runtime events: ${report.vmp?.runtime_event_count || 0}`,
    `Fingerprint APIs: ${report.fingerprint.api_count}`,
    "",
    "## Top APIs",
    ""
  ];
  if (topApis.length) {
    for (const item of topApis) {
      lines.push(`- ${item.api}: ${item.count}`);
    }
  } else {
    lines.push("- none");
  }

  lines.push("", "## Suspicious JS Assets", "");
  if (suspicious.length) {
    for (const asset of suspicious) {
      const label = asset.url || asset.content_path || asset.asset_id;
      lines.push(`- ${label}: score=${asset.score}, signals=${asset.signals.join(",") || "none"}`);
    }
  } else {
    lines.push("- none");
  }

  lines.push("", "## VMP Signals", "");
  const vmpApis = report.vmp?.apis || [];
  const vmpAssets = report.vmp?.assets || [];
  const vmpFamilies = report.vmp?.families || [];
  const vmpExecutionProfiles = report.vmp?.execution_profiles || [];
  const vmpHotspots = report.vmp?.hotspots || [];
  const vmpAnalysisPoints = report.vmp?.analysis_points || [];
  const vmpHookCoverage = report.vmp?.hook_coverage || {};
  const vmpHookAnalysisPoints = report.vmp?.hook_analysis_points || vmpHookCoverage.hook_analysis_points || [];
  if (vmpApis.length) {
    lines.push("Runtime APIs:");
    for (const item of vmpApis) {
      lines.push(`- ${item.api}: ${item.count}`);
    }
  } else {
    lines.push("Runtime APIs: none");
  }
  if (vmpFamilies.length) {
    lines.push("", "Runtime Families:");
    for (const item of vmpFamilies) {
      lines.push(`- ${item.family}: ${item.count}`);
    }
  }
  if (vmpExecutionProfiles.length) {
    lines.push("", "VMP Execution Profiles:");
    for (const profile of vmpExecutionProfiles.slice(0, 8)) {
      const label = `${profile.function || "(anonymous)"}@${profile.stack_url || "unknown"}`;
      const hooks = (profile.hook_points || []).map((point) => point.type).join(",") || "none";
      const apis = (profile.apis || []).slice(0, 5).map((item) => `${item.api}:${item.count}`).join(",") || "none";
      lines.push(
        `- ${label} confidence=${profile.confidence || "low"} events=${profile.event_count} seq=${profile.seq_start ?? "none"}..${profile.seq_end ?? "none"} density=${profile.density_score ?? 0} hooks=${hooks} apis=${apis} asset=${profile.asset_id || "none"}`
      );
    }
  }
  if (vmpAnalysisPoints.length) {
    lines.push("", "VMP Analysis Points:");
    for (const point of vmpAnalysisPoints.slice(0, 12)) {
      const apis = (point.apis || []).map((item) => `${item.api}:${item.count}`).join(",") || "none";
      const stacks = (point.stack_urls || []).map((item) => `${item.stack_url}:${item.count}`).join(",") || "none";
      lines.push(
        `- ${point.type}: seq=${point.seq_start ?? "none"}..${point.seq_end ?? "none"} events=${point.event_count} apis=${apis} stacks=${stacks}`
      );
    }
  }
  if (vmpHookCoverage.observed_point_types?.length || vmpHookCoverage.missing_point_types?.length) {
    lines.push("", "VMP Hook Coverage:");
    lines.push(`- observed=${(vmpHookCoverage.observed_point_types || []).join(",") || "none"}`);
    lines.push(`- missing=${(vmpHookCoverage.missing_point_types || []).slice(0, VMP_HOOK_POINT_SPECS.length).join(",") || "none"}`);
    for (const gap of (vmpHookCoverage.hook_gaps || []).slice(0, 6)) {
      lines.push(
        `- gap ${gap.type}: priority=${gap.priority || "medium"} hooks=${(gap.suggested_hooks || []).slice(0, 5).join(",") || "none"}`
      );
    }
  }
  if (vmpHookAnalysisPoints.length) {
    lines.push("", "VMP Hook Analysis Points:");
    for (const point of vmpHookAnalysisPoints.slice(0, VMP_HOOK_POINT_SPECS.length)) {
      const apis = (point.observed_apis || [])
        .slice(0, 4)
        .map((item) => `${item.api}:${item.count}`)
        .join(",") || "none";
      lines.push(
        `- hook_point ${point.type} status=${point.status || "unknown"} next=${point.next_action || "unknown"} priority=${point.priority || "-"} observed_events=${point.observed_event_count ?? 0} apis=${apis} hooks=${(point.suggested_hooks || []).slice(0, 5).join(",") || "none"} goal=${point.analysis_goal || "unknown"}`
      );
    }
  }
  if (vmpHotspots.length) {
    lines.push("", "VMP Hotspots:");
    for (const hotspot of vmpHotspots.slice(0, 8)) {
      const label = hotspot.stack_url || hotspot.asset_path || hotspot.asset_id || "unknown";
      lines.push(
        `- ${label}: events=${hotspot.count} families=${hotspot.families.join(",") || "none"} asset=${hotspot.asset_id || "none"}`
      );
    }
  }
  const vmpSamples = report.vmp?.samples || {};
  if (Object.keys(vmpSamples).length) {
    lines.push("", "Runtime Samples:");
    for (const [api, samples] of Object.entries(vmpSamples).slice(0, 12)) {
      const preview = samples
        .slice(0, 3)
        .map((sample) => `seq=${sample.seq} args=${JSON.stringify(sample.args)}`)
        .join("; ");
      lines.push(`- ${api}: ${preview}`);
    }
  }
  lines.push("");
  if (vmpAssets.length) {
    lines.push("Assets:");
    for (const asset of vmpAssets.slice(0, 20)) {
      const label = asset.url || asset.content_path || asset.asset_id;
      lines.push(`- ${label}: score=${asset.score}, signals=${asset.signals.join(",") || "none"}`);
    }
  } else {
    lines.push("Assets: none");
  }

  lines.push("", "## Signature Flow", "");
  const signature = report.signature || {event_count: 0, api_counts: [], involved_assets: [], first_events: []};
  lines.push(`Events: ${signature.event_count}`);
  if (signature.api_counts.length) {
    lines.push("APIs:");
    for (const item of signature.api_counts.slice(0, 15)) {
      lines.push(`- ${item.api}: ${item.count}`);
    }
  } else {
    lines.push("APIs: none");
  }
  if (signature.involved_assets.length) {
    lines.push("", "Assets:");
    for (const asset of signature.involved_assets.slice(0, 12)) {
      const label = asset.url || asset.content_path || asset.asset_id;
      lines.push(`- ${label}: score=${asset.score}, signals=${asset.signals.join(",") || "none"}`);
    }
  }
  if (signature.first_events.length) {
    lines.push("", "First Events:");
    for (const event of signature.first_events.slice(0, 5)) {
      const top = event.stack[0];
      const where = top ? `${top.function || "(anonymous)"} ${top.url}:${top.line || 0}:${top.column || 0}` : "no stack";
      lines.push(`- seq=${event.seq} api=${event.api} terms=${event.terms.join(",")} top=${where}`);
    }
  }
  if (signature.agent_brief?.flows?.length) {
    lines.push("", "Agent Signature Brief:");
    lines.push(
      `- flows=${signature.agent_brief.summary.flow_count} unsigned_to_signed=${signature.agent_brief.summary.unsigned_to_signed_count} signed_only=${signature.agent_brief.summary.signed_only_count}`
    );
    for (const flow of signature.agent_brief.flows.slice(0, 8)) {
      const phases = flow.phases.map((phase) => `${phase.phase}:${phase.seq_start ?? "none"}..${phase.seq_end ?? "none"}`).join(",") || "none";
      const gaps = flow.gaps.join(",") || "none";
      const mutations = (flow.signature_mutations || [])
        .map((event) => `${event.api}@${event.seq}:${event.param}`)
        .join(",") || "none";
      const objectLinks = (flow.object_links || [])
        .map((link) => `${link.type}:${link.id}@${link.seqs.join(",")}`)
        .join(";") || "none";
      const vmpPoints = (flow.vmp_analysis_points || [])
        .map((point) => `${point.type}@${point.seq_start ?? "none"}..${point.seq_end ?? "none"}`)
        .join(",") || "none";
      const inferred = (flow.inferred_unsigned_param_names || []).join(",") || "none";
      lines.push(
        `- ${flow.id} match=${flow.match} evidence=${flow.evidence_level} signed_seq=${flow.signed_seq ?? "none"} params=${flow.signature_params.join(",") || "none"} inferred_unsigned_params=${inferred} mutations=${mutations} objects=${objectLinks} vmp_points=${vmpPoints} phases=${phases} gaps=${gaps}`
      );
    }
  }
  if (
    signature.agent_evidence_pack?.flows?.length ||
    signature.agent_evidence_pack?.signature_absent ||
    signature.agent_evidence_pack?.business_api_runtime_hints?.length
  ) {
    lines.push("", "Agent Evidence Pack:");
    const vmpHookAnalysis = signature.agent_evidence_pack.vmp_hook_analysis;
    const signatureAbsent = signature.agent_evidence_pack.signature_absent;
    if (signatureAbsent) {
      lines.push("", "Signature Capture Gap:");
      lines.push(
        `- reason=${signatureAbsent.reason} vmp_events=${signatureAbsent.vmp_runtime_event_count} targets=${signatureAbsent.target_terms.join(",")}`
      );
      const recommendations = (signatureAbsent.capture_recommendations || [])
        .map((item) => `${item.id}:${item.priority}`)
        .join(",") || "none";
      lines.push(`- recommend=${recommendations}`);
      for (const entry of (signatureAbsent.candidate_entrypoints || []).slice(0, 8)) {
        const apis = (entry.apis || [])
          .slice(0, 4)
          .map((item) => `${item.api}:${item.count}`)
          .join(",") || "none";
        const asset = entry.asset_id || "none";
        lines.push(
          `  - candidate_entry=${entry.function || "(anonymous)"}@${entry.stack_url || "unknown"} events=${entry.event_count} seq=${entry.seq_start ?? "none"}..${entry.seq_end ?? "none"} families=${entry.families.join(",") || "none"} apis=${apis} asset=${asset}`
        );
      }
      for (const asset of (signatureAbsent.candidate_assets || []).slice(0, 6)) {
        const label = asset.url || asset.content_path || asset.asset_id;
        lines.push(
          `  - candidate_asset=${label} score=${asset.score} signals=${asset.signals.join(",") || "none"}`
        );
      }
      for (const chain of (signatureAbsent.candidate_trace_chains || []).slice(0, 6)) {
        const hookPoints = (chain.hook_points || [])
          .slice(0, 6)
          .map((point) => `${point.type}@${point.seq_start ?? "none"}..${point.seq_end ?? "none"}`)
          .join(",") || "none";
        const gaps = (chain.request_context?.capture_gaps || []).join(",") || "none";
        const inferred = chain.inferred_initiator
          ? `${chain.inferred_initiator.function || "(anonymous)"}@${chain.inferred_initiator.stack_url || "unknown"}:${chain.inferred_initiator.confidence || "low"}:events${chain.inferred_initiator.event_count ?? 0}`
          : "none";
        lines.push(
          `  - candidate_chain=${chain.id || "unknown"} confidence=${chain.confidence || "low"} endpoint=${chain.endpoint || "unknown"} steps=${candidateTraceChainStepsSummary(chain)} hooks=${hookPoints} inferred_initiator=${inferred} gaps=${gaps}`
        );
      }
      for (const anchor of (signatureAbsent.network_anchors || []).slice(0, 6)) {
        const nearby = (anchor.nearby_vmp_candidates || [])
          .slice(0, 4)
          .map((candidate) => `${candidate.api}@${candidate.seq ?? "none"}:${candidate.relation}:${candidate.trace_distance}`)
          .join(",") || "none";
        const signals = (anchor.ranking_signals || []).join(",") || "none";
        const anchorPipeline = candidatePipelineSummary(anchor.candidate_signature_pipeline);
        const vmpPoints = (anchor.vmp_analysis_points || [])
          .slice(0, 6)
          .map((point) => `${point.type}@${point.seq_start ?? "none"}..${point.seq_end ?? "none"}`)
          .join(",") || "none";
        const context = anchor.request_context || {};
        const requestContext = [
          `initiator=${context.request_initiator || "none"}`,
          `sw=${context.originated_from_service_worker ? "true" : "false"}`,
          `user_gesture=${context.has_user_gesture ? "true" : "false"}`,
          `headers=${(context.header_names || []).join(",") || "none"}`,
          `upload=${context.upload_body ? `elements:${context.upload_body.element_count ?? "unknown"} bytes:${context.upload_body.total_bytes ?? "unknown"} memory:${context.upload_body.in_memory_bytes ?? "unknown"}` : "none"}`,
          `gaps=${(context.capture_gaps || []).join(",") || "none"}`,
          `renderer_link=${context.renderer_request_link ? `${context.renderer_request_link.api}@${context.renderer_request_link.seq ?? "none"}:${context.renderer_request_link.relation}:${context.renderer_request_link.trace_distance}:${context.renderer_request_link.function || "(anonymous)"}` : "none"}`,
          `inferred_initiator=${context.inferred_initiator ? `${context.inferred_initiator.function || "(anonymous)"}@${context.inferred_initiator.stack_url || "unknown"}:${context.inferred_initiator.confidence || "low"}:events${context.inferred_initiator.event_count ?? 0}` : "none"}`
        ].join(" ");
        lines.push(
          `  - network_anchor=${anchor.method || "GET"} ${anchor.endpoint || "unknown"} trace=${anchor.trace_index ?? "none"} seq=${anchor.seq ?? "none"} score=${anchor.evidence_score ?? 0} signals=${signals} nearby_vmp=${nearby} anchor_pipeline=${anchorPipeline} vmp_points=${vmpPoints} request_context=${requestContext}`
        );
      }
    }
    if (signature.agent_evidence_pack.business_api_runtime_hints?.length) {
      lines.push("", "Business API Runtime Hints:");
      for (const hint of signature.agent_evidence_pack.business_api_runtime_hints.slice(0, 8)) {
        lines.push(
          `- business_api_runtime_hint endpoint=${hint.endpoint || "unknown"} api=${hint.api || "unknown"} seq=${hint.seq ?? "none"} relevance=${hint.business_relevance || "unknown"} status=${hint.value_status || "unknown"} query_keys=${(hint.query_keys || []).join(",") || "none"} roles=${(hint.source_roles || []).join(",") || "none"} gaps=${(hint.evidence_gaps || []).join(",") || "none"} next=${(hint.next_actions || []).join(",") || "none"} sources=${(hint.source_stack_urls || []).slice(0, 4).join(",") || "none"}`
        );
      }
    }
    const nextCapturePlan = signature.agent_evidence_pack.next_capture_plan;
    if (nextCapturePlan) {
      lines.push("", "Next Capture Plan:");
      lines.push(
        `- priority=${nextCapturePlan.priority || "low"} targets=${(nextCapturePlan.target_terms || []).join(",") || "none"} flags=${(nextCapturePlan.recommended_flags || []).join(",") || "none"}`
      );
      for (const gap of (nextCapturePlan.gap_summary || []).slice(0, 8)) {
        lines.push(
          `- gap=${gap.gap || "unknown"} flows=${gap.flow_count ?? 0} priority=${gap.priority || "-"} next=${(gap.next_actions || []).join(",") || "none"}`
        );
      }
      for (const lowValue of (nextCapturePlan.low_value_endpoint_summary || []).slice(0, 6)) {
        lines.push(
          `- low_value_endpoint class=${lowValue.resource_class || "unknown"} endpoints=${lowValue.endpoint_count ?? 0} flows=${lowValue.flow_count ?? 0} examples=${(lowValue.examples || []).join(",") || "none"}`
        );
      }
      for (const hook of (nextCapturePlan.hook_focus || []).slice(0, 8)) {
        lines.push(
          `- hook_focus=${hook.type || "unknown"} missing_flows=${hook.missing_flow_count ?? 0} priority=${hook.priority || "-"} next=${hook.next_action || "unknown"} hooks=${(hook.suggested_hooks || []).slice(0, 5).join(",") || "none"}`
        );
      }
      for (const endpoint of (nextCapturePlan.focus_endpoints || []).slice(0, 6)) {
        lines.push(
          `- endpoint=${endpoint.endpoint || "unknown"} flows=${endpoint.flow_count ?? 0} statuses=${(endpoint.readiness_statuses || []).join(",") || "none"} gaps=${(endpoint.evidence_gaps || []).join(",") || "none"}`
        );
      }
      for (const asset of (nextCapturePlan.focus_assets || []).slice(0, 6)) {
        lines.push(
          `- asset=${asset.asset_id || "none"} stack=${asset.stack_url || "unknown"} flows=${asset.flow_count ?? 0} statuses=${(asset.readiness_statuses || []).join(",") || "none"} retrieval=${asset.retrieval_status || "none"} path=${asset.content_path || "none"} score=${asset.score ?? "none"} signals=${(asset.signals || []).slice(0, 8).join(",") || "none"} focus=${asset.asset_focus || "none"} role=${asset.asset_role || "none"}`
        );
      }
      for (const item of (nextCapturePlan.capture_checklist || []).slice(0, 8)) {
        lines.push(
          `- capture_check item=${item.id || "unknown"} status=${item.status || "unknown"} priority=${item.priority || "-"} next=${item.next_action || "none"} evidence=${(item.evidence || []).join(",") || "none"} targets=${(item.target_endpoint_patterns || []).join(",") || "none"} rejected=${(item.rejected_endpoint_summary || []).join(",") || "none"}`
        );
      }
      if (nextCapturePlan.capture_attempt_quality) {
        const quality = nextCapturePlan.capture_attempt_quality;
        lines.push(
          `- capture_attempt_quality status=${quality.status || "unknown"} readiness=${quality.readiness || "unknown"} actionable=${quality.actionable_endpoint_count ?? 0} core_assets=${quality.core_asset_count ?? 0} low_value_classes=${(quality.low_value_endpoint_classes || []).join(",") || "none"} missing=${(quality.missing_evidence || []).join(",") || "none"} next=${quality.next_action || "none"}`
        );
      }
      if (nextCapturePlan.capture_gate) {
        const gate = nextCapturePlan.capture_gate;
        lines.push(
          `- capture_gate id=${gate.id || "unknown"} status=${gate.status || "unknown"} actionable=${gate.observed_actionable_endpoint_count ?? 0} missing=${(gate.missing || []).join(",") || "none"} patterns=${(gate.target_endpoint_patterns || []).join(",") || "none"}`
        );
      }
      if (nextCapturePlan.business_api_capture_status) {
        const status = nextCapturePlan.business_api_capture_status;
        lines.push(
          `- business_api_capture_status status=${status.status || "unknown"} endpoints=${status.actionable_endpoint_count ?? 0} missing=${(status.missing_evidence || []).join(",") || "none"} next=${(status.next_actions || []).join(",") || "none"}`
        );
      }
      if (nextCapturePlan.business_api_capture_plan) {
        const plan = nextCapturePlan.business_api_capture_plan;
        lines.push(
          `- business_api_capture status=${plan.status || "unknown"} start_url=${plan.start_url || "about:blank"} avoid=${(plan.avoid_resource_classes || []).join(",") || "none"} core_assets=${(plan.core_assets || []).join(",") || "none"}`
        );
        for (const action of (plan.normal_user_actions || []).slice(0, 4)) {
          lines.push(`  - action=${action}`);
        }
        for (const criterion of (plan.success_criteria || []).slice(0, 4)) {
          lines.push(`  - success=${criterion}`);
        }
      }
      if (nextCapturePlan.rerun_recipe) {
        const recipe = nextCapturePlan.rerun_recipe;
        lines.push(
          `- rerun_recipe start_url=${recipe.start_url || "about:blank"} profile=${recipe.profile || "unknown"}`
        );
        lines.push(
          `- launcher_args=${(recipe.python_launcher_args || []).join(" ") || "none"}`
        );
      }
    }
    const parameterGenerationBrief = signature.agent_evidence_pack.parameter_generation_brief;
    if (parameterGenerationBrief?.parameters?.length) {
      lines.push("", "Parameter Generation Brief:");
      for (const entry of parameterGenerationBrief.parameters.slice(0, 8)) {
        lines.push(parameterGenerationBriefLine(entry));
      }
    }
    const coreAssetReviewPackage = signature.agent_evidence_pack.core_asset_review_package;
    if (coreAssetReviewPackage?.entries?.length) {
      lines.push("", "Core Asset Review Package:");
      for (const entry of coreAssetReviewPackage.entries.slice(0, 4)) {
        lines.push(
          `- core_asset=${entry.asset_id || "none"} role=${entry.asset_role || "none"} status=${entry.source_status || "unknown"} path=${entry.content_path || "none"} score=${entry.score ?? 0} focus=${(entry.review_focus || []).join(",") || "none"} signals=${(entry.signals || []).slice(0, 8).join(",") || "none"}`
        );
        for (const window of (entry.source_windows || []).slice(0, 8)) {
          lines.push(
            `  - source_window=${window.focus || "unknown"} lines=${window.line_start ?? "none"}-${window.line_end ?? "none"} priority=${window.priority || "-"} signals=${(window.analysis?.signals || []).slice(0, 6).join(",") || "none"} preview=${window.preview || ""}`
          );
        }
      }
    }
    if (vmpHookAnalysis?.points?.length || vmpHookAnalysis?.hook_gaps?.length) {
      lines.push("", "Global VMP Hook Analysis:");
      for (const point of (vmpHookAnalysis.points || []).slice(0, 8)) {
        const apis = (point.apis || [])
          .slice(0, 4)
          .map((item) => `${item.api}:${item.count}`)
          .join(",") || "none";
        const stacks = (point.stack_urls || [])
          .slice(0, 3)
          .map((item) => `${item.stack_url}:${item.count}`)
          .join(",") || "none";
        lines.push(
          `- ${point.type} flows=${point.flow_count} events=${point.event_count} seq=${point.seq_start ?? "none"}..${point.seq_end ?? "none"} families=${point.families.join(",") || "none"} apis=${apis} stacks=${stacks}`
        );
      }
      if (vmpHookAnalysis.hook_analysis_points?.length) {
        lines.push("", "Global VMP Hook Analysis Points:");
        for (const point of vmpHookAnalysis.hook_analysis_points.slice(0, VMP_HOOK_POINT_SPECS.length)) {
          const apis = (point.observed_apis || [])
            .slice(0, 4)
            .map((item) => `${item.api}:${item.count}`)
            .join(",") || "none";
          lines.push(
            `- hook_point ${point.type} status=${point.status || "unknown"} next=${point.next_action || "unknown"} priority=${point.priority || "-"} observed_flows=${point.observed_flows ?? 0} missing_flows=${point.missing_flows ?? 0} coverage=${point.coverage_ratio ?? 0} observed_events=${point.observed_event_count ?? 0} apis=${apis} hooks=${(point.suggested_hooks || []).slice(0, 5).join(",") || "none"} goal=${point.analysis_goal || "unknown"}`
          );
        }
      }
      if (vmpHookAnalysis.hook_gaps?.length) {
        lines.push("", "VMP Hook Gaps:");
        for (const gap of vmpHookAnalysis.hook_gaps.slice(0, VMP_HOOK_POINT_SPECS.length)) {
          const candidates = (gap.linking_candidates || [])
            .slice(0, 3)
            .map((candidate) => {
              const nearest = candidate.nearest_flows?.[0];
              return nearest
                ? `${candidate.api}@${candidate.seq}->${nearest.flow_id}:${nearest.relation}:${nearest.seq_distance}`
                : `${candidate.api}@${candidate.seq}`;
            })
            .join(",") || "none";
          lines.push(
            `- ${gap.type} missing_flows=${gap.missing_flow_count} priority=${gap.priority} source=${gap.gap_source || "unknown"} next=${gap.recommended_next_step || "unknown"} global_events=${gap.global_event_count || 0} hooks=${gap.suggested_hooks.join(",")} candidates=${candidates}`
          );
          for (const candidate of (gap.linking_candidates || []).slice(0, 2)) {
            const windowEvents = (candidate.context_window?.events || [])
              .map((event) => `${event.api}@${event.seq}:${event.window_role || "nearby"}`)
              .join(",") || "none";
            const sourceRefs = (candidate.context_window?.source_contexts || [])
              .map((context) => `${context.asset_id}:${context.line_start}-${context.line_end}`)
              .join(",") || "none";
            lines.push(
              `  - candidate_window=${candidate.api}@${candidate.seq} events=${windowEvents} sources=${sourceRefs}`
            );
          }
        }
      }
    }
    if (signature.agent_evidence_pack.signature_source_candidates?.length) {
      const reviewPackage = signature.agent_evidence_pack.agent_review_package;
      if (reviewPackage?.entries?.length) {
        lines.push("", "Agent Review Package:");
        const summary = reviewPackage.causality_summary || {};
        lines.push(
          `- causality_summary pre_request_chain=${summary.pre_request_chain ?? 0} mixed_pre_post_request=${summary.mixed_pre_post_request ?? 0} signed_or_unknown=${summary.signed_or_unknown ?? 0} post_request_activity=${summary.post_request_activity ?? 0} prioritized=${summary.prioritized_entry_count ?? 0} deprioritized=${summary.deprioritized_entry_count ?? 0}`
        );
        for (const entry of reviewPackage.entries.slice(0, 8)) {
          const lineRanges = (entry.line_ranges || [])
            .slice(0, 4)
            .map((range) => `${range.line_start}-${range.line_end}`)
            .join(",") || "none";
          lines.push(
            `- ${entry.id} candidate=${entry.source_candidate_id || "none"} causality=${entry.causality || "unknown"} priority=${entry.review_priority || "low"} function=${entry.function || "(anonymous)"} path=${entry.content_path || "none"} lines=${lineRanges} endpoints=${(entry.endpoints || []).join(",") || "none"} params=${(entry.target_params || []).join(",") || "none"} stages=${(entry.stages || []).slice(0, 8).join(",") || "none"} apis=${(entry.runtime_apis || []).slice(0, 8).join(",") || "none"} signals=${(entry.signals || []).slice(0, 8).join(",") || "none"} paths=${generationPathsSummary(entry.generation_paths)} warnings=${(entry.warnings || []).join(",") || "none"} next=${(entry.next_questions || []).join(",") || "none"}`
          );
        }
      }
      lines.push("", "Signature Source Candidates:");
      for (const candidate of signature.agent_evidence_pack.signature_source_candidates.slice(0, 8)) {
        lines.push(
          `- ${candidate.id} function=${candidate.function || "(anonymous)"} asset=${candidate.asset_id || "none"} refs=${(candidate.source_refs || []).slice(0, 4).join(",") || "none"} flows=${candidate.flow_count || 0} steps=${candidate.step_count || 0} score=${candidate.evidence_score || 0} relevance=${candidate.business_relevance || "unknown"} classes=${(candidate.resource_classes || []).join(",") || "none"} params=${(candidate.target_params || []).join(",") || "none"} stages=${(candidate.stages || []).slice(0, 8).join(",") || "none"} apis=${(candidate.runtime_apis || []).slice(0, 8).join(",") || "none"} signals=${(candidate.signals || []).slice(0, 8).join(",") || "none"} reasons=${(candidate.priority_reasons || []).join(",") || "none"}`
        );
      }
    }
    if (signature.agent_evidence_pack.vmp_scalar_ref_chains?.length) {
      lines.push("", "VMP Scalar Ref Chains:");
      for (const chain of signature.agent_evidence_pack.vmp_scalar_ref_chains.slice(0, 8)) {
        const refs = (chain.refs || []).slice(0, 8).join(",") || "none";
        const reasons = (chain.quality_reasons || []).slice(0, 8).join(",") || "none";
        const sources = (chain.source_context_refs || []).slice(0, 6).join(",") || "none";
        lines.push(
          `- ${chain.id} relation=${chain.relation || "scalar_ref_flow"} score=${chain.quality_score ?? 0} reasons=${reasons} steps=${chain.step_count || 0} seq=${chain.seq_start ?? "?"}-${chain.seq_end ?? "?"} apis=${(chain.apis || []).slice(0, 8).join(",") || "none"} sources=${sources} refs=${refs}`
        );
      }
    }
    if (signature.agent_evidence_pack.signature_material_flows?.length) {
      lines.push("", "Signature Material Flows:");
      for (const materialFlow of signature.agent_evidence_pack.signature_material_flows.slice(0, 8)) {
        const stages = materialStagesSummary(materialFlow.stages);
        const dataLinks = pipelineDataLinksSummary({data_links: materialFlow.data_links || []});
        const inferredDataLinks = pipelineInferredDataLinksSummary({
          inferred_data_links: materialFlow.inferred_data_links || []
        });
        const generationSteps = generationStepsSummary(materialFlow.generation_steps);
        const attachments = signatureAttachmentEventsSummary(materialFlow.signature_attachment_events || []);
        const attachmentGraph = parameterAttachmentGraphSummary(materialFlow.parameter_attachment_graph);
        const sourceRefs = (materialFlow.source_context_refs || []).slice(0, 6).join(",") || "none";
        const readiness = materialFlow.analysis_readiness || {};
        const readinessGaps = (readiness.evidence_gaps || []).slice(0, 6).join(",") || "none";
        const hookPoints = materialFlowHookPointsSummary(materialFlow.vmp_hook_points || []);
        const scalarChains = materialFlowScalarChainLinksSummary(materialFlow.vmp_scalar_chain_links || []);
        const agentSummary = agentGenerationSummary(materialFlow.agent_generation_summary);
        const agentStageTrace = agentStageTraceSummary(materialFlow.agent_stage_trace);
        lines.push(
          `- ${materialFlow.id} flow=${materialFlow.flow_id || "unknown"} confidence=${materialFlow.confidence || "low"} status=${materialFlow.evidence_status || "unknown"} readiness=${readiness.status || "unknown"} gaps=${readinessGaps} endpoint=${materialFlow.endpoint || "unknown"} params=${(materialFlow.target_params || []).join(",") || "none"} stages=${stages} generation_steps=${generationSteps} agent_stage_trace=${agentStageTrace} agent_generation=${agentSummary} data_links=${dataLinks} inferred_data_links=${inferredDataLinks} attachments=${attachments} attachment_graph=${attachmentGraph} sources=${sourceRefs} scalar_chains=${scalarChains} hook_points=${hookPoints}`
        );
      }
    }
    if (signature.agent_evidence_pack.global_stack_clusters?.length) {
      lines.push("", "Global Signature Stack Clusters:");
      for (const cluster of signature.agent_evidence_pack.global_stack_clusters.slice(0, 8)) {
        lines.push(
          `- ${cluster.function || "(anonymous)"}@${cluster.stack_url || "unknown"} flows=${cluster.flow_count} events=${cluster.event_count} phases=${cluster.phases.join(",") || "none"}`
        );
      }
    }
    if (signature.agent_evidence_pack.pipeline_patterns?.length) {
      lines.push("", "Pipeline Patterns:");
      for (const pattern of signature.agent_evidence_pack.pipeline_patterns.slice(0, 8)) {
        const stacks = (pattern.top_stack_clusters || [])
          .slice(0, 3)
          .map((cluster) => `${cluster.function || "(anonymous)"}@${cluster.stack_url || "unknown"}:${cluster.flow_count}`)
          .join(",") || "none";
        lines.push(
          `- ${pattern.pattern} flows=${pattern.flow_count} events=${pattern.event_count} stacks=${stacks}`
        );
      }
    }
    for (const flow of signature.agent_evidence_pack.flows.slice(0, 8)) {
      const coverage = Object.entries(flow.coverage || {})
        .filter(([, value]) => value)
        .map(([key]) => key)
        .join(",") || "none";
      const missing = Object.entries(flow.coverage || {})
        .filter(([, value]) => !value)
        .map(([key]) => key)
        .join(",") || "none";
      const windows = (flow.event_windows || [])
        .map((window) => `${window.phase}@${window.seq_start ?? "none"}..${window.seq_end ?? "none"}:${window.event_count}`)
        .join(",") || "none";
      const graph = (flow.graph?.nodes || [])
        .map((node) => node.phase)
        .join("->") || "none";
      const stacks = (flow.stack_clusters || [])
        .slice(0, 4)
        .map((cluster) => `${cluster.function || "(anonymous)"}@${cluster.stack_url || "unknown"}:${cluster.event_count}`)
        .join(",") || "none";
      const recommendations = (flow.capture_recommendations || [])
        .map((item) => `${item.id}:${item.priority}`)
        .join(",") || "none";
      const questions = (flow.next_questions || []).join(",") || "none";
      const flowVmpCandidates = (flow.vmp_linking_candidates || [])
        .slice(0, 4)
        .map((group) => {
          const candidates = (group.candidates || [])
            .slice(0, 3)
            .map((candidate) => `${candidate.api}@${candidate.seq}:${candidate.relation || "unknown"}:${candidate.seq_distance ?? "none"}`)
            .join(",");
          return `${group.type}[${candidates || "none"}]`;
        })
        .join(";") || "none";
      const candidatePhases = (flow.vmp_candidate_phases || [])
        .slice(0, 4)
        .map((phase) => `${phase.phase}:${phase.confidence}@${phase.seq_start ?? "none"}..${phase.seq_end ?? "none"}`)
        .join(",") || "none";
      const candidateGraph = (flow.candidate_graph?.edges || [])
        .slice(0, 6)
        .map((edge) => `${edge.from}->${edge.to}:${edge.relation}:${edge.seq_gap ?? "none"}`)
        .join(",") || "none";
      const suspectedSubflows = (flow.suspected_signature_subflows || [])
        .slice(0, 4)
        .map((subflow) => {
          const label = `${subflow.function || "(anonymous)"}@${subflow.stack_url || "unknown"}`;
          return `${label}:${subflow.confidence || "low"}:${(subflow.phases || []).join(">") || "none"}`;
        })
        .join(";") || "none";
      const subflowSources = (flow.suspected_signature_subflows || [])
        .flatMap((subflow) => subflow.source_context_refs || [])
        .slice(0, 8)
        .join(",") || "none";
      const subflowSourceAnalysis = (flow.suspected_signature_subflows || [])
        .flatMap((subflow) => subflow.source_contexts || [])
        .map((context) => sourceAnalysisSummary(context.analysis))
        .filter(Boolean)
        .slice(0, 3)
        .join(";") || "none";
      const candidatePipeline = (flow.suspected_signature_subflows || [])
        .map((subflow) => candidatePipelineSummary(subflow.candidate_signature_pipeline))
        .filter((summary) => summary && !summary.startsWith("none "))
        .slice(0, 3)
        .join(";") || "none";
      const dataLinks = (flow.suspected_signature_subflows || [])
        .map((subflow) => pipelineDataLinksSummary(subflow.candidate_signature_pipeline))
        .filter((summary) => summary && summary !== "none")
        .slice(0, 3)
        .join(";") || "none";
      lines.push(
        `- ${flow.id} evidence=${flow.evidence_level} seq=${flow.seq_range?.start ?? "none"}..${flow.seq_range?.end ?? "none"} coverage=${coverage} missing=${missing} graph=${graph} stacks=${stacks} recommend=${recommendations} windows=${windows} flow_vmp_candidates=${flowVmpCandidates} candidate_phases=${candidatePhases} candidate_graph=${candidateGraph} suspected_subflows=${suspectedSubflows} subflow_sources=${subflowSources} source_analysis=${subflowSourceAnalysis} candidate_pipeline=${candidatePipeline} data_links=${dataLinks} next=${questions}`
      );
    }
  }
  if (signature.flows?.length) {
    lines.push("", "Signature Transitions:");
    for (const flow of signature.flows.slice(0, 8)) {
      const added = flow.added_params.map((param) => param.name).join(",") || "none";
      const vmp = flow.preceding_vmp_events
        .map((event) => `${event.api}@${event.seq}${event.relation ? `:${event.relation}` : ""}`)
        .join(",") || "none";
      const timeline = (flow.timeline || [])
        .map((event) => `${event.role || "context"}:${event.api}@${event.seq}`)
        .join(",") || "none";
      const unsignedSeq = flow.unsigned_event?.seq ?? "none";
      const signedSeq = flow.signed_event?.seq ?? "none";
      lines.push(
        `- endpoint=${flow.endpoint} match=${flow.match || "unknown"} unsigned_seq=${unsignedSeq} signed_seq=${signedSeq} added=${added} vmp=${vmp} timeline=${timeline}`
      );
    }
  }

  lines.push("", "## Fingerprint APIs", "");
  if (report.fingerprint.apis.length) {
    for (const api of report.fingerprint.apis) {
      lines.push(`- ${api}`);
    }
  } else {
    lines.push("- none");
  }
  lines.push("");
  return lines.join("\n");
}

function appendTraceEventsWithIndex(events, parsed, startIndex) {
  let traceIndex = startIndex;
  for (const event of parsed || []) {
    if (event && typeof event === "object" && !Number.isFinite(event._trace_index)) {
      event._trace_index = traceIndex;
    }
    if (event && typeof event === "object" && !Number.isFinite(event._file_index)) {
      event._file_index = traceIndex;
    }
    events.push(event);
    traceIndex += 1;
  }
  return traceIndex;
}

function readTraceEvents(tracePath, options = {}) {
  if (!fs.existsSync(tracePath)) return [];
  const stat = fs.statSync(tracePath);
  const maxBytes = options.maxBytes || DEFAULT_TRACE_REPORT_MAX_BYTES;
  const length = Math.min(stat.size, maxBytes);
  const chunkBytes = Math.max(1, Math.min(options.chunkBytes || DEFAULT_TRACE_READ_CHUNK_BYTES, Math.max(length, 1)));
  const fd = fs.openSync(tracePath, "r");
  try {
    const events = [];
    const buffer = Buffer.allocUnsafe(chunkBytes);
    const decoder = new StringDecoder("utf8");
    let offset = 0;
    let pending = "";
    let traceIndex = 0;

    while (offset < length) {
      const bytesToRead = Math.min(chunkBytes, length - offset);
      const bytesRead = fs.readSync(fd, buffer, 0, bytesToRead, offset);
      if (bytesRead <= 0) break;
      offset += bytesRead;

      const text = pending + decoder.write(buffer.subarray(0, bytesRead));
      const lastNewline = text.lastIndexOf("\n");
      if (lastNewline === -1) {
        pending = text;
        continue;
      }

      const completeText = text.slice(0, lastNewline + 1);
      traceIndex = appendTraceEventsWithIndex(events, parseNdjsonLines(completeText), traceIndex);
      pending = text.slice(lastNewline + 1);
    }

    if (length >= stat.size) {
      pending += decoder.end();
      if (pending.trim()) {
        appendTraceEventsWithIndex(events, parseNdjsonLines(pending), traceIndex);
      }
    }
    return events;
  } finally {
    fs.closeSync(fd);
  }
}

function parseTraceLine(line, traceIndex) {
  try {
    const event = JSON.parse(line);
    if (event && typeof event === "object" && !Number.isFinite(event._trace_index)) {
      event._trace_index = traceIndex;
    }
    if (event && typeof event === "object" && !Number.isFinite(event._file_index)) {
      event._file_index = traceIndex;
    }
    return event;
  } catch (error) {
    return {
      _trace_index: traceIndex,
      schema_version: 0,
      api: "xtrace.parse_error",
      error: String(error),
      raw: line
    };
  }
}

function scanTraceLines(tracePath, options = {}, onLine) {
  if (!fs.existsSync(tracePath)) return 0;
  const stat = fs.statSync(tracePath);
  const maxBytes = options.maxBytes || stat.size;
  const length = Math.min(stat.size, maxBytes);
  const chunkBytes = Math.max(1, Math.min(options.chunkBytes || DEFAULT_TRACE_READ_CHUNK_BYTES, Math.max(length, 1)));
  const fd = fs.openSync(tracePath, "r");
  try {
    const buffer = Buffer.allocUnsafe(chunkBytes);
    const decoder = new StringDecoder("utf8");
    let offset = 0;
    let pending = "";
    let traceIndex = 0;

    while (offset < length) {
      const bytesToRead = Math.min(chunkBytes, length - offset);
      const bytesRead = fs.readSync(fd, buffer, 0, bytesToRead, offset);
      if (bytesRead <= 0) break;
      offset += bytesRead;

      const text = pending + decoder.write(buffer.subarray(0, bytesRead));
      const lines = text.split("\n");
      pending = lines.pop() || "";
      for (const line of lines) {
        if (!line.trim()) continue;
        onLine(line, traceIndex);
        traceIndex += 1;
      }
    }

    if (length >= stat.size) {
      pending += decoder.end();
      if (pending.trim()) {
        onLine(pending, traceIndex);
        traceIndex += 1;
      }
    }
    return traceIndex;
  } finally {
    fs.closeSync(fd);
  }
}

function scanTraceEvents(tracePath, options = {}, onEvent) {
  return scanTraceLines(tracePath, options, (line, traceIndex) => {
    onEvent(parseTraceLine(line, traceIndex), traceIndex);
  });
}

function eventContainsAnyTerm(event, terms) {
  const text = JSON.stringify([event?.args, event?.result, event?.error]);
  return (terms || []).some((term) => text.includes(term));
}

function lineContainsAnyString(line, values) {
  for (const value of values || []) {
    const needle = String(value || "");
    if (needle && line.includes(needle)) return true;
  }
  return false;
}

function collectCorrelationKeysFromValue(value, output = new Set(), depth = 0) {
  if (depth > 5 || value === null || value === undefined) return output;
  if (Array.isArray(value)) {
    for (const item of value) collectCorrelationKeysFromValue(item, output, depth + 1);
    return output;
  }
  if (typeof value !== "object") return output;
  for (const [key, raw] of Object.entries(value)) {
    if ((key === "network_correlation_key" || key === "request_correlation_key") &&
        (typeof raw === "number" || typeof raw === "string")) {
      const id = String(raw);
      if (id && id !== "0") output.add(id);
    }
    collectCorrelationKeysFromValue(raw, output, depth + 1);
  }
  return output;
}

function correlationKeysForEvent(event) {
  return collectCorrelationKeysFromValue([event?.args, event?.result, event?.error]);
}

function eventSharesCorrelationKey(event, correlationKeys) {
  if (!correlationKeys?.size) return false;
  for (const key of correlationKeysForEvent(event)) {
    if (correlationKeys.has(key)) return true;
  }
  return false;
}

function mergeTraceWindows(windows) {
  const sorted = [...windows].sort((a, b) => a.start - b.start || a.end - b.end);
  const merged = [];
  for (const window of sorted) {
    const last = merged[merged.length - 1];
    if (last && window.start <= last.end + 1) {
      last.end = Math.max(last.end, window.end);
    } else {
      merged.push({...window});
    }
  }
  return merged;
}

function traceIndexInWindows(traceIndex, windows) {
  return windows.some((window) => traceIndex >= window.start && traceIndex <= window.end);
}

function readTargetedTraceEvents(tracePath, options = {}) {
  const terms = options.targetTerms || SENSITIVE_PARAM_TERMS;
  const windowBefore = options.windowBefore ?? SIGNATURE_CONTEXT_LOOKBACK;
  const windowAfter = options.windowAfter ?? 3000;
  const anchors = [];
  const correlationKeys = new Set();

  scanTraceLines(tracePath, options, (line, traceIndex) => {
    if (!lineContainsAnyString(line, terms)) return;
    const event = parseTraceLine(line, traceIndex);
    if (!eventContainsAnyTerm(event, terms)) return;
    anchors.push(traceIndex);
    for (const key of correlationKeysForEvent(event)) correlationKeys.add(key);
  });
  if (!anchors.length) return [];

  const windows = mergeTraceWindows(anchors.map((anchor) => ({
    start: Math.max(0, anchor - windowBefore),
    end: anchor + windowAfter
  })));
  const events = [];
  let windowIndex = 0;

  scanTraceLines(tracePath, options, (line, traceIndex) => {
    while (windowIndex < windows.length && traceIndex > windows[windowIndex].end) {
      windowIndex += 1;
    }
    const currentWindow = windows[windowIndex];
    const inWindow = Boolean(currentWindow && traceIndex >= currentWindow.start);
    const mayShareCorrelationKey = !inWindow && lineContainsAnyString(line, correlationKeys);
    if (!inWindow && !mayShareCorrelationKey) return;
    const event = parseTraceLine(line, traceIndex);
    const sharesCorrelationKey = mayShareCorrelationKey && eventSharesCorrelationKey(event, correlationKeys);
    if (!inWindow && !sharesCorrelationKey) return;
    events.push(event);
  });

  return events;
}

function shouldUseTargetedSignatureReader(tracePath, options = {}) {
  if (options.targetedSignatureOnly !== undefined) {
    return Boolean(options.targetedSignatureOnly);
  }
  if (options.disableAutoTargetedSignatureReader) return false;
  if (!fs.existsSync(tracePath)) return false;
  const maxBytes = options.maxBytes || DEFAULT_TRACE_REPORT_MAX_BYTES;
  return fs.statSync(tracePath).size > maxBytes;
}

function targetedReaderOptions(options = {}) {
  const scanOptions = {...options};
  if (options.targetedMaxBytes !== undefined) {
    scanOptions.maxBytes = options.targetedMaxBytes;
  } else {
    delete scanOptions.maxBytes;
  }
  if (options.targetTerms === undefined) {
    scanOptions.targetTerms = SIGNATURE_TERMS;
  }
  if (options.windowBefore === undefined) {
    scanOptions.windowBefore = AUTO_TARGETED_SIGNATURE_LOOKBACK;
  }
  if (options.windowAfter === undefined) {
    scanOptions.windowAfter = AUTO_TARGETED_SIGNATURE_LOOKAHEAD;
  }
  return scanOptions;
}

function buildReportForTrace(tracePath, options = {}) {
  let rawEvents = options.events;
  if (!rawEvents) {
    const useTargeted = shouldUseTargetedSignatureReader(tracePath, options);
    rawEvents = useTargeted
      ? readTargetedTraceEvents(tracePath, targetedReaderOptions(options))
      : readTraceEvents(tracePath, options);
    if (useTargeted && options.targetedSignatureOnly === undefined && rawEvents.length === 0) {
      rawEvents = readTraceEvents(tracePath, options);
    }
  }
  const manifestAssets = options.assets || attachAssetContent(
    tracePath,
    readAssetManifest(tracePath, options),
    options
  );
  const externalAssets = retrieveExternalScriptAssets(tracePath, rawEvents, manifestAssets, options);
  const assets = [...manifestAssets, ...externalAssets];
  const events = attachStackAssetIds(rawEvents, assets);
  return buildLocalReport({tracePath, events, assets});
}

function writeLocalReport({tracePath, events, assets, report} = {}) {
  const finalReport = report || buildLocalReport({tracePath, events, assets});
  const dir = reportDirectoryForTrace(tracePath);
  fs.mkdirSync(dir, {recursive: true});
  const jsonPath = path.join(dir, "report.json");
  const markdownPath = path.join(dir, "report.md");
  const agentPack = buildAgentInputPack(finalReport);
  const agentAnalysis = buildAgentAnalysis(agentPack);
  const agentPackJsonPath = path.join(dir, "agent_pack.json");
  const agentPackMarkdownPath = path.join(dir, "agent_pack.md");
  const agentAnalysisJsonPath = path.join(dir, "agent_analysis.json");
  const agentAnalysisMarkdownPath = path.join(dir, "agent_analysis.md");
  fs.writeFileSync(jsonPath, JSON.stringify(finalReport, null, 2) + "\n", "utf8");
  fs.writeFileSync(markdownPath, renderMarkdownReport(finalReport), "utf8");
  fs.writeFileSync(agentPackJsonPath, JSON.stringify(agentPack, null, 2) + "\n", "utf8");
  fs.writeFileSync(agentPackMarkdownPath, renderAgentInputPackMarkdown(agentPack), "utf8");
  fs.writeFileSync(agentAnalysisJsonPath, JSON.stringify(agentAnalysis, null, 2) + "\n", "utf8");
  fs.writeFileSync(agentAnalysisMarkdownPath, renderAgentAnalysisMarkdown(agentAnalysis), "utf8");
  const reportForDisplay = {
    ...finalReport,
    agent_analysis: agentAnalysis
  };
  return {
    report: reportForDisplay,
    jsonPath,
    markdownPath,
    agentPack,
    agentPackJsonPath,
    agentPackMarkdownPath,
    agentAnalysis,
    agentAnalysisJsonPath,
    agentAnalysisMarkdownPath
  };
}

function generateReportForTrace(tracePath, options = {}) {
  const report = buildReportForTrace(tracePath, {
    retrieveExternalScripts: true,
    ...options
  });
  return writeLocalReport({tracePath, report});
}

module.exports = {
  DEFAULT_TRACE_REPORT_MAX_BYTES,
  analyzeJavaScriptSource,
  reportDirectoryForTrace,
  buildLocalReport,
  renderMarkdownReport,
  buildAgentInputPack,
  renderAgentInputPackMarkdown,
  buildAgentAnalysis,
  renderAgentAnalysisMarkdown,
  readTraceEvents,
  readTargetedTraceEvents,
  buildReportForTrace,
  writeLocalReport,
  generateReportForTrace,
  __testHooks: {
    buildRequestInputBundleForMaterialFlow
  }
};

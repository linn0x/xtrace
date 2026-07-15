const assert = require("node:assert/strict");
const test = require("node:test");
const {renderReportDetail, renderReportHtml} = require("../src/renderer/reportView");

test("renderReportDetail and HTML show top-level VMP hook coverage", () => {
  const report = {
    trace: {path: "/tmp/xtrace/logs/trace_vmp.ndjson", event_count: 3},
    reverse: {dynamic_execution_count: 0},
    vmp: {
      runtime_event_count: 3,
      hook_coverage: {
        observed_point_types: [
          "vmp_bytecode_or_register_access",
          "vmp_int_bitwise_pipeline"
        ],
        missing_point_types: [
          "vmp_string_decoder",
          "vmp_dynamic_dispatch"
        ],
        hook_gaps: [{
          type: "vmp_dynamic_dispatch",
          priority: "medium",
          reason: "dynamic dispatch hooks are missing in the VMP runtime trace",
          suggested_hooks: [
            "Reflect.apply",
            "Function.prototype.call"
          ],
          event_count: 0
        }]
      },
      hook_analysis_points: [{
        type: "vmp_dynamic_dispatch",
        status: "missing",
        priority: "medium",
        analysis_goal: "trace VM handler dispatch and indirect function invocation",
        families: ["dynamic_dispatch"],
        observed_event_count: 0,
        observed_apis: [],
        suggested_hooks: [
          "Reflect.apply",
          "Function.prototype.call"
        ],
        reason: "dynamic dispatch hooks are missing in the VMP runtime trace",
        next_action: "add_or_enable_hooks"
      }]
    },
    fingerprint: {api_count: 0},
    signature: {
      event_count: 0,
      agent_evidence_pack: {
        flows: []
      }
    }
  };

  const detail = renderReportDetail(report);
  const html = renderReportHtml(report);

  assert.match(detail, /VMP Hook Coverage/);
  assert.match(detail, /observed=vmp_bytecode_or_register_access,vmp_int_bitwise_pipeline/);
  assert.match(detail, /missing=vmp_string_decoder,vmp_dynamic_dispatch/);
  assert.match(detail, /gap=vmp_dynamic_dispatch priority=medium hooks=Reflect\.apply,Function\.prototype\.call/);
  assert.match(detail, /VMP Hook Analysis Points/);
  assert.match(detail, /hook_point=vmp_dynamic_dispatch status=missing priority=medium next=add_or_enable_hooks goal=trace VM handler dispatch and indirect function invocation/);
  assert.match(html, /VMP Hook Coverage/);
  assert.match(html, /VMP Hook Analysis Points/);
  assert.match(html, /add_or_enable_hooks/);
  assert.match(html, /vmp_bytecode_or_register_access,vmp_int_bitwise_pipeline/);
  assert.match(html, /Reflect\.apply,Function\.prototype\.call/);
});

test("renderReportDetail and HTML show signature material flows", () => {
  const report = {
    trace: {path: "/tmp/xtrace/logs/trace_material.ndjson", event_count: 4},
    reverse: {dynamic_execution_count: 0},
    vmp: {runtime_event_count: 2},
    fingerprint: {api_count: 0},
    signature: {
      event_count: 1,
      agent_evidence_pack: {
        signature_material_flows: [{
          id: "material_flow_1",
          flow_id: "signature_flow_1",
          endpoint: "https://www.example.test/api/list",
          confidence: "high",
          evidence_status: "observed_only",
          function: "sign<script>",
          stack_url: "https://cdn.example.test/runtime-sdk.js",
          asset_id: "sha1:material",
          seq_start: 10,
          seq_end: 13,
          target_params: ["X-Signature", "X-Secondary-Signature"],
          stages: [
            {stage: "input_url", runtime_apis: ["URL.constructor"], source_calls: [], source_signals: [], object_refs: ["url_object:11"]},
            {stage: "byte_buffer", runtime_apis: ["DataView.getUint32"], source_calls: ["view.getUint32"], source_signals: ["byte_buffer"], object_refs: ["data_view:21"]},
            {stage: "integer_mixing", runtime_apis: ["Math.imul"], source_calls: ["Math.imul"], source_signals: ["int_bitwise"], source_operators: ["^", ">>>"], source_constants: ["2654435761"], object_refs: ["data_view:21"]},
            {stage: "signed_request", runtime_apis: ["Request.constructor"], source_calls: [], source_signals: [], object_refs: ["url_object:11"]}
          ],
          data_links: [
            {from: "input_url", to: "signed_request", refs: ["url_object:11"]},
            {from: "byte_buffer", to: "integer_mixing", refs: ["data_view:21"]}
          ],
          analysis_readiness: {
            status: "partial",
            observed_stages: ["input_url", "byte_buffer", "integer_mixing", "signed_request"],
            missing_stages: ["signature_mutation"],
            evidence_gaps: ["signature_mutation_not_observed"],
            next_actions: ["capture_url_search_params_mutation_or_header_set"]
          },
          vmp_hook_points: [
            {
              type: "vmp_bytecode_or_register_access",
              status: "observed",
              observed_apis: ["DataView.getUint32"],
              next_action: "review_observed_events"
            },
            {
              type: "vmp_dynamic_dispatch",
              status: "source_observed",
              observed_apis: [],
              source_calls: ["Reflect.apply", "Function.prototype.call.call"],
              source_signals: ["prototype_call", "dynamic_dispatch"],
              next_action: "review_source_context_or_add_runtime_hook"
            }
          ],
          agent_generation_summary: {
            stage_chain: [
              "input_url",
              "byte_buffer",
              "dynamic_dispatch",
              "integer_mixing",
              "signed_request"
            ],
            summary_text: "input_url -> byte_buffer -> dynamic_dispatch -> integer_mixing -> signed_request",
            evidence_profile: "runtime_and_source",
            target_params: ["X-Signature", "X-Secondary-Signature"],
            runtime_apis: ["URL.constructor", "DataView.getUint32", "Math.imul", "Request.constructor"],
            source_calls: ["Reflect.apply", "Function.prototype.call.call"],
            source_observed_hooks: ["vmp_dynamic_dispatch"],
            runtime_observed_hooks: ["vmp_bytecode_or_register_access"],
            attachment_params: ["X-Signature", "X-Secondary-Signature"],
            data_link_count: 2,
            inferred_data_link_count: 0,
            readiness: "partial"
          },
          agent_stage_trace: [
            {
              order: 1,
              stage: "input_url",
              role: "input",
              apis: ["URL.constructor"],
              evidence: ["runtime_api", "source_context"],
              relation: "before_signed_request",
              distance_to_signed_request: 3,
              params: [],
              target_params: ["X-Signature", "X-Secondary-Signature"],
              param_relation: "flow_target",
              source_refs: ["sha1:material:2-6"],
              object_refs: ["url_object:11"]
            },
            {
              order: 2,
              stage: "byte_buffer",
              role: "material",
              apis: ["DataView.getUint32"],
              evidence: ["runtime_api", "object_ref"],
              relation: "before_signed_request",
              distance_to_signed_request: 2,
              params: [],
              target_params: ["X-Signature", "X-Secondary-Signature"],
              param_relation: "flow_target",
              source_refs: ["sha1:material:2-6"],
              object_refs: ["data_view:21"]
            },
            {
              order: 3,
              stage: "signed_request",
              role: "network_emit",
              apis: ["Request.constructor"],
              evidence: ["runtime_api", "value_ref"],
              relation: "signed_request",
              distance_to_signed_request: 0,
              params: ["X-Signature", "X-Secondary-Signature"],
              target_params: ["X-Signature", "X-Secondary-Signature"],
              param_relation: "direct_observed",
              source_refs: ["sha1:material:2-6"],
              object_refs: ["url_object:11"]
            }
          ],
          vmp_scalar_chain_links: [{
            chain_id: "vmp_scalar_chain_1",
            stage: "integer_mixing",
            relation: "shared_value_ref",
            confidence: "high",
            shared_refs: ["number:79.000000"],
            apis: ["Bitwise.xor", "Math.imul"],
            quality_score: 900,
            quality_reasons: ["multiply_xor_unsigned_shift"],
            operation_trace: [
              {
                seq: 81,
                trace_index: 10,
                api: "Bitwise.xor",
                input_refs: ["number:88.000000", "number:23.000000"],
                result_ref: "number:79.000000",
                source_context_refs: ["sha1:runtime-sdk:9-9"]
              },
              {
                seq: 82,
                trace_index: 11,
                api: "Math.imul",
                input_refs: ["number:79.000000", "number:16777619.000000"],
                result_ref: "number:1325431901.000000",
                source_context_refs: ["sha1:runtime-sdk:9-9"]
              }
            ]
          }],
          source_context_refs: ["sha1:material:2-6"]
        }],
        flows: []
      }
    }
  };

  const detail = renderReportDetail(report);
  const html = renderReportHtml(report);

  assert.match(detail, /Signature Material Flows/);
  assert.match(detail, /material_flow_1 flow=signature_flow_1 confidence=high status=observed_only seq=10\.\.13/);
  assert.match(detail, /readiness=partial gaps=signature_mutation_not_observed next=capture_url_search_params_mutation_or_header_set/);
  assert.match(detail, /hook_points=vmp_bytecode_or_register_access:observed\[runtime:DataView\.getUint32\],vmp_dynamic_dispatch:source_observed\[source:Reflect\.apply\|Function\.prototype\.call\.call signals:prototype_call\|dynamic_dispatch\]/);
  assert.match(detail, /stages=input_url\[URL\.constructor\]->byte_buffer\[DataView\.getUint32\]->integer_mixing\[Math\.imul\]->signed_request\[Request\.constructor\]/);
  assert.match(detail, /agent_generation=chain=input_url->byte_buffer->dynamic_dispatch->integer_mixing->signed_request evidence=runtime_and_source runtime=URL\.constructor\|DataView\.getUint32\|Math\.imul\|Request\.constructor source_hooks=vmp_dynamic_dispatch runtime_hooks=vmp_bytecode_or_register_access params=X-Signature\|X-Secondary-Signature/);
  assert.match(detail, /scalar_chains=vmp_scalar_chain_1:integer_mixing:shared_value_ref\[high\] refs=number:79\.000000 apis=Bitwise\.xor\|Math\.imul score=900 ops=81:Bitwise\.xor\(number:88\.000000\|number:23\.000000->number:79\.000000\)->82:Math\.imul\(number:79\.000000\|number:16777619\.000000->number:1325431901\.000000\)/);
  assert.match(detail, /agent_stage_trace=1:input_url\(input\)\[URL\.constructor\] evidence=runtime_api\|source_context relation=before_signed_request d=3 params=none target_params=X-Signature\|X-Secondary-Signature param_relation=flow_target sources=sha1:material:2-6 refs=url_object:11 -> 2:byte_buffer\(material\)\[DataView\.getUint32\] evidence=runtime_api\|object_ref relation=before_signed_request d=2 params=none target_params=X-Signature\|X-Secondary-Signature param_relation=flow_target sources=sha1:material:2-6 refs=data_view:21 -> 3:signed_request\(network_emit\)\[Request\.constructor\] evidence=runtime_api\|value_ref relation=signed_request d=0 params=X-Signature\|X-Secondary-Signature target_params=X-Signature\|X-Secondary-Signature param_relation=direct_observed sources=sha1:material:2-6 refs=url_object:11/);
  assert.match(detail, /data_links=input_url->signed_request:url_object:11,byte_buffer->integer_mixing:data_view:21/);
  assert.match(html, /Signature Material Flows/);
  assert.match(html, /readiness=partial/);
  assert.match(html, /signature_mutation_not_observed/);
  assert.match(html, /vmp_dynamic_dispatch:source_observed\[source:Reflect\.apply\|Function\.prototype\.call\.call signals:prototype_call\|dynamic_dispatch\]/);
  assert.match(html, /agent_generation=chain=input_url-&gt;byte_buffer-&gt;dynamic_dispatch-&gt;integer_mixing-&gt;signed_request evidence=runtime_and_source runtime=URL\.constructor\|DataView\.getUint32\|Math\.imul\|Request\.constructor source_hooks=vmp_dynamic_dispatch runtime_hooks=vmp_bytecode_or_register_access params=X-Signature\|X-Secondary-Signature/);
  assert.match(html, /scalar_chains=vmp_scalar_chain_1:integer_mixing:shared_value_ref\[high\] refs=number:79\.000000 apis=Bitwise\.xor\|Math\.imul score=900 ops=81:Bitwise\.xor\(number:88\.000000\|number:23\.000000-&gt;number:79\.000000\)-&gt;82:Math\.imul\(number:79\.000000\|number:16777619\.000000-&gt;number:1325431901\.000000\)/);
  assert.match(html, /agent_stage_trace=1:input_url\(input\)\[URL\.constructor\] evidence=runtime_api\|source_context relation=before_signed_request d=3 params=none target_params=X-Signature\|X-Secondary-Signature param_relation=flow_target sources=sha1:material:2-6 refs=url_object:11 -&gt; 2:byte_buffer\(material\)\[DataView\.getUint32\]/);
  assert.match(html, /sign&lt;script&gt;@https:\/\/cdn\.example\.test\/runtime-sdk\.js/);
  assert.match(html, /input_url\[URL\.constructor\]-&gt;byte_buffer\[DataView\.getUint32\]-&gt;integer_mixing\[Math\.imul\]-&gt;signed_request\[Request\.constructor\]/);
  assert.doesNotMatch(html, /<script>/);
});

test("renderReportDetail and HTML show business API runtime hints", () => {
  const report = {
    trace: {path: "/tmp/xtrace/logs/trace_example.ndjson", event_count: 2},
    reverse: {dynamic_execution_count: 0},
    vmp: {runtime_event_count: 1},
    fingerprint: {api_count: 0},
    signature: {
      event_count: 0,
      agent_evidence_pack: {
        business_api_runtime_hints: [{
          endpoint: "https://www.example.test/api/records/list/",
          api: "decodeURIComponent",
          seq: 629407,
          business_relevance: "business_api_candidate",
          value_status: "truncated_preview",
          query_keys: ["client_time", "app_id", "app_name", "sessionToken"],
          source_roles: ["core_signature_asset", "application_caller"],
          evidence_gaps: ["full_url_value_truncated", "query_keys_incomplete"],
          next_actions: ["capture_full_url_value", "capture_network_anchor_for_endpoint"],
          source_stack_urls: [
            "https://cdn.example.test/obj/generic_web_runtime/runtime-sdk/1.0.0.374/runtime-sdk.js",
            "https://cdn.example.test/obj/generic_web_runtime/example/webapp/main/react-v18/webapp-desktop/feed-prefetch.c2241f3b.js"
          ]
        }],
        flows: []
      }
    }
  };

  const detail = renderReportDetail(report);
  const html = renderReportHtml(report);

  assert.match(detail, /Business API Runtime Hints/);
  assert.match(detail, /business_api_runtime_hint endpoint=https:\/\/www\.example\.test\/api\/records\/list\/ api=decodeURIComponent seq=629407 relevance=business_api_candidate status=truncated_preview query_keys=client_time,app_id,app_name,sessionToken roles=core_signature_asset,application_caller gaps=full_url_value_truncated,query_keys_incomplete next=capture_full_url_value,capture_network_anchor_for_endpoint/);
  assert.match(html, /Business API Runtime Hints/);
  assert.match(html, /business_api_runtime_hint endpoint=https:\/\/www\.example\.test\/api\/records\/list\//);
  assert.match(html, /full_url_value_truncated,query_keys_incomplete/);
});

test("renderReportDetail and HTML show VMP scalar ref chains", () => {
  const report = {
    trace: {path: "/tmp/xtrace/logs/trace_scalar_chain.ndjson", event_count: 5},
    reverse: {dynamic_execution_count: 0},
    vmp: {runtime_event_count: 3},
    fingerprint: {api_count: 0},
    signature: {
      event_count: 1,
      agent_evidence_pack: {
        vmp_scalar_ref_chains: [{
          id: "vmp_scalar_chain_1",
          relation: "scalar_ref_flow",
          seq_start: 40,
          seq_end: 42,
          step_count: 3,
          quality_score: 100,
          quality_reasons: ["multiply_xor_unsigned_shift", "source_context"],
          source_context_refs: ["sha1:runtime-sdk:9-9"],
          apis: ["Bitwise.xor", "Math.imul", "Shift.unsignedRight"],
          refs: ["number:1.000000", "number:3.000000", "number:51.000000"],
          steps: [
            {seq: 40, api: "Bitwise.xor", input_refs: ["number:1.000000", "number:2.000000"], result_ref: "number:3.000000"},
            {seq: 41, api: "Math.imul", input_refs: ["number:3.000000", "number:17.000000"], result_ref: "number:51.000000"},
            {seq: 42, api: "Shift.unsignedRight", input_refs: ["number:51.000000", "number:0.000000"], result_ref: "number:51.000000"}
          ]
        }],
        flows: []
      }
    }
  };

  const detail = renderReportDetail(report);
  const html = renderReportHtml(report);

  assert.match(detail, /VMP Scalar Ref Chains/);
  assert.match(detail, /scalar_chain=vmp_scalar_chain_1 relation=scalar_ref_flow score=100 reasons=multiply_xor_unsigned_shift,source_context steps=3 seq=40\.\.42 apis=Bitwise\.xor,Math\.imul,Shift\.unsignedRight sources=sha1:runtime-sdk:9-9 refs=number:1\.000000,number:3\.000000,number:51\.000000/);
  assert.match(detail, /step=40:Bitwise\.xor in=number:1\.000000\|number:2\.000000 out=number:3\.000000 -> 41:Math\.imul in=number:3\.000000\|number:17\.000000 out=number:51\.000000/);
  assert.match(html, /VMP Scalar Ref Chains/);
  assert.match(html, /scalar_chain=vmp_scalar_chain_1 relation=scalar_ref_flow score=100 reasons=multiply_xor_unsigned_shift,source_context steps=3 seq=40\.\.42/);
  assert.match(html, /40:Bitwise\.xor in=number:1\.000000\|number:2\.000000 out=number:3\.000000 -&gt; 41:Math\.imul/);
  assert.doesNotMatch(detail + html, /secret-one/);
});

test("renderReportDetail and HTML show agent next capture focus", () => {
  const report = {
    trace: {path: "/tmp/xtrace/logs/trace_agent_focus.ndjson", event_count: 10},
    reverse: {dynamic_execution_count: 0},
    vmp: {runtime_event_count: 3},
    fingerprint: {api_count: 0},
    signature: {
      event_count: 2,
      agent_evidence_pack: {
        flows: []
      }
    },
    agent_analysis: {
      next_capture_focus: [
        {
          action: "capture_url_search_params_mutation_or_header_set",
          priority: "high",
          reason: "signature_mutation_missing_runtime_or_source_context",
          params: ["X-Signature", "X-Secondary-Signature"],
          stages: ["signature_mutation"],
          gaps: ["runtime_api_not_observed", "source_context_not_available"],
          endpoints: ["https://www.example.test/api/feed"],
          hook_targets: ["URLSearchParams.set", "URL.href.set"],
          hook_target_statuses: [
            {target: "URLSearchParams.set", status: "missing", observed_stages: []},
            {target: "URL.href.set", status: "missing", observed_stages: []}
          ],
          source_refs: [],
          object_refs: ["url_object:9"],
          value_refs: ["target_params:X-Signature|X-Secondary-Signature"]
        },
        {
          action: "expand_vmp_runtime_hooks",
          priority: "high",
          reason: "vmp_stage_runtime_api_missing",
          params: ["X-Signature"],
          stages: ["dynamic_dispatch", "integer_mixing"],
          gaps: ["runtime_api_not_observed"],
          endpoints: ["https://www.example.test/api/feed"],
          hook_targets: ["Reflect.apply", "Bitwise.xor"],
          hook_target_statuses: [
            {target: "Reflect.apply", status: "missing", observed_stages: []},
            {target: "Bitwise.xor", status: "observed_elsewhere", observed_stages: ["integer_mixing_probe"]}
          ],
          source_refs: ["sha1:sdk:2-4"],
          object_refs: ["target:11"],
          value_refs: []
        }
      ],
      native_capture_requirements: [
        {
          action: "capture_vmp_register_state_refs",
          priority: "high",
          native_layer: "v8",
          reason: "vmp_register_state_refs_missing",
          params: ["X-Signature"],
          stages: ["dynamic_dispatch", "integer_mixing", "signature_mutation"],
          gaps: ["vmp_register_ref_not_observed"],
          endpoints: ["https://www.example.test/api/feed"],
          missing_hook_targets: [],
          missing_ref_types: ["vmp.register_ref", "vmp.handler.return_ref", "Bitwise.input_ref"],
          implementation_targets: ["v8:vmp.register_ref", "v8:vmp.handler.return_ref", "v8:Bitwise.input_ref"],
          source_hints: [
            {
              path: "chromium/src/v8/src/runtime/runtime-typedarray.cc",
              reason: "vmp runtime ref serialization and dispatch result args"
            },
            {
              path: "chromium/src/v8/src/builtins/arm64/builtins-arm64.cc",
              reason: "arm64 dynamic dispatch boundary register capture"
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
        }
      ]
    }
  };

  const detail = renderReportDetail(report);
  const html = renderReportHtml(report);

  assert.match(detail, /Agent Next Capture Focus/);
  assert.match(detail, /focus=capture_url_search_params_mutation_or_header_set priority=high reason=signature_mutation_missing_runtime_or_source_context params=X-Signature,X-Secondary-Signature stages=signature_mutation gaps=runtime_api_not_observed,source_context_not_available endpoint=https:\/\/www\.example\.test\/api\/feed/);
  assert.match(detail, /focus=expand_vmp_runtime_hooks priority=high reason=vmp_stage_runtime_api_missing params=X-Signature stages=dynamic_dispatch,integer_mixing gaps=runtime_api_not_observed endpoint=https:\/\/www\.example\.test\/api\/feed hooks=Reflect\.apply,Bitwise\.xor hook_status=Reflect\.apply:missing,Bitwise\.xor:observed_elsewhere sources=sha1:sdk:2-4 refs=target:11/);
  assert.match(detail, /hooks=URLSearchParams\.set,URL\.href\.set/);
  assert.match(detail, /hook_status=URLSearchParams\.set:missing,URL\.href\.set:missing/);
  assert.match(detail, /hooks=Reflect\.apply,Bitwise\.xor/);
  assert.match(html, /Agent Next Capture Focus/);
  assert.match(html, /capture_url_search_params_mutation_or_header_set/);
  assert.match(html, /signature_mutation_missing_runtime_or_source_context/);
  assert.match(html, /X-Signature,X-Secondary-Signature/);
  assert.match(html, /sha1:sdk:2-4/);
  assert.match(html, /URLSearchParams\.set,URL\.href\.set/);
  assert.match(detail, /Agent Native Capture Requirements/);
  assert.match(detail, /native=capture_vmp_register_state_refs layer=v8 priority=high reason=vmp_register_state_refs_missing params=X-Signature stages=dynamic_dispatch,integer_mixing,signature_mutation gaps=vmp_register_ref_not_observed/);
  assert.match(detail, /targets=v8:vmp\.register_ref,v8:vmp\.handler\.return_ref,v8:Bitwise\.input_ref/);
  assert.match(detail, /source_hints=chromium\/src\/v8\/src\/runtime\/runtime-typedarray\.cc,chromium\/src\/v8\/src\/builtins\/arm64\/builtins-arm64\.cc/);
  assert.match(detail, /validator=--schema-version 1,--require-vmp-next-hook-fields,--require-vmp-family dynamic_dispatch,--require-vmp-family int_bitwise/);
  assert.match(html, /Agent Native Capture Requirements/);
  assert.match(html, /capture_vmp_register_state_refs/);
  assert.match(html, /chromium\/src\/v8\/src\/runtime\/runtime-typedarray\.cc/);
  assert.match(html, /--require-vmp-next-hook-fields/);
});

test("renderReportDetail and HTML show agent parameter generation paths", () => {
  const report = {
    trace: {path: "/tmp/xtrace/logs/trace_agent_paths.ndjson", event_count: 12},
    reverse: {dynamic_execution_count: 0},
    vmp: {runtime_event_count: 4},
    fingerprint: {api_count: 0},
    signature: {
      event_count: 2,
      agent_evidence_pack: {
        flows: []
      }
    },
    agent_analysis: {
      summary: {
        hypothesis_summary: {
          status_counts: {
            partial_pre_signature_runtime_chain: 1
          },
          primary_pattern_counts: {
            xor_imul_urshift_mixing: 1
          },
          strong_chain_count: 0,
          partial_chain_count: 1,
          needs_more_evidence_count: 0,
          unresolved_hypothesis_gap_count: 1
        },
        blocking_gap_summary: {
          total_observation_count: 5,
          gap_counts: {
            runtime_api_not_observed: 2,
            signature_mutation_not_observed: 1,
            source_context_not_available: 1,
            source_only_edge: 1
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
              hook_targets: ["Reflect.apply", "URLSearchParams.set"],
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
              hook_targets: ["URLSearchParams.set", "Headers.set"],
              source_refs: ["sha1:sdk:2-4"],
              object_refs: [],
              value_refs: []
            }
          ]
        },
        readiness_summary: {
          ready_count: 0,
          partial_count: 1,
          insufficient_count: 0,
          average_score: 58
        }
      },
      parameters: [{
        param: "X-Signature",
        conclusion: "attachment_observed_with_runtime_chain",
        evidence_level: "high",
        endpoint: "https://www.example.test/api/feed",
        chain_summary: "input_url -> dynamic_dispatch -> signature_mutation -> signed_request",
        chain_quality: {
          status: "partial",
          step_count: 3,
          expected_edge_count: 2,
          edge_count: 2,
          high_confidence_edge_count: 1,
          medium_confidence_edge_count: 1,
          source_only_edge_count: 1,
          missing_edge_count: 0
        },
        generation_hypothesis: {
          status: "partial_pre_signature_runtime_chain",
          evidence_level: "high",
          chain_quality: "partial",
          direct_attachment_observed: true,
          pre_signature_pattern_observed: true,
          primary_pattern: "xor_imul_urshift_mixing",
          primary_pattern_confidence: "high",
          primary_operation_signature: "Bitwise.xor -> Math.imul -> Shift.unsignedRight",
          stage_chain: ["input_url", "dynamic_dispatch", "signature_mutation"],
          evidence_refs: ["vmp_scalar_chain_1", "sha1:runtime-sdk:9-9", "number:79.000000"],
          remaining_gaps: ["signature_mutation_not_observed"],
          next_actions: ["review_source_refs"]
        },
        candidate_generation_summary: {
          stage_chain: ["input_url", "dynamic_dispatch", "signature_mutation", "signed_request"],
          evidence_profile: "runtime_and_source",
          readiness: "partial_needs_targeted_capture",
          target_params: ["X-Signature"],
          runtime_apis: ["URL.constructor", "Reflect.apply", "URLSearchParams.set"],
          source_calls: ["Reflect.apply", "Function.prototype.call"],
          source_observed_hooks: ["vmp_dynamic_dispatch"],
          runtime_observed_hooks: ["vmp_int_bitwise_pipeline"],
          key_refs: {
            url_objects: ["url_object:7", "url_object:9"],
            search_params: ["search_params:9"],
            buffers: ["array_buffer:20", "data_view:21"],
            network_requests: ["network_request:sha1:feed"],
            target_params: ["X-Signature"],
            url_shapes: ["url_shape:feed"]
          },
          attachment: {
            observed: true,
            stage: "signature_mutation",
            apis: ["URLSearchParams.set"],
            target_params: ["X-Signature"],
            object_refs: ["url_object:9", "search_params:9"],
            value_refs: ["target_params:X-Signature"],
            source_refs: ["sha1:sdk:2-4"]
          },
          source_windows: [{
            ref: "sha1:sdk:2-4",
            content_path: "assets/trace_agent_paths/runtime-sdk.js",
            line_start: 2,
            line_end: 4,
            preview: "const sig = url.searchParams.set('X-Signature', '<redacted>')",
            stages: ["input_url", "dynamic_dispatch", "signature_mutation"],
            source_candidate_ids: ["source_candidate_1"],
            review_entry_ids: ["review_entry_1"]
          }],
          logic_hypothesis: {
            agent_logic_trace: {
              summary: "X-Signature generation: input_material -> vmp_execution -> mixing_or_hash -> signature_attachment; status=partial_runtime_source_path",
              steps: [
                {
                  order: 1,
                  phase: "input_material",
                  status: "observed",
                  confidence: "high",
                  claim: "input material observed for X-Signature across input_url",
                  runtime_apis: ["URL.constructor"],
                  target_params: ["X-Signature"],
                  evidence: ["runtime_api:URL.constructor"],
                  source_refs: ["sha1:sdk:1-3"],
                  object_refs: ["url_object:7"],
                  value_refs: [],
                  request_input_categories: ["url_query", "request_headers", "request_body", "cookies", "storage"],
                  request_inputs: [
                    {
                      category: "url_query",
                      target_params: ["X-Signature"],
                      query_keys: ["X-Signature", "cursor"],
                      value_refs: ["string_ref:native-signed-url"],
                      evidence_refs: ["url:XMLHttpRequest.send@10"]
                    },
                    {
                      category: "request_headers",
                      target_params: ["X-Signature"],
                      header_names: ["x-signature"],
                      value_refs: ["string_ref:native-header-xsignature"],
                      evidence_refs: ["headers:XMLHttpRequest.setRequestHeader@9"]
                    },
                    {
                      category: "request_body",
                      target_params: ["X-Secondary-Signature"],
                      body_size: 42,
                      value_refs: ["string_ref:native-xhr-body"],
                      evidence_refs: ["body:XMLHttpRequest.send@10"]
                    },
                    {
                      category: "cookies",
                      names: ["sessionToken"],
                      evidence_refs: ["cookie:document.cookie.get@3"]
                    },
                    {
                      category: "storage",
                      keys: ["fp_seed"],
                      value_refs: ["storage:local:fp_seed"],
                      evidence_refs: ["storage:localStorage.getItem@2"]
                    }
                  ]
                },
                {
                  order: 2,
                  phase: "vmp_execution",
                  status: "observed",
                  confidence: "medium",
                  claim: "VMP dispatch and handler execution observed for X-Signature across dynamic_dispatch",
                  runtime_apis: ["Reflect.apply"],
                  source_calls: ["Reflect.apply"],
                  source_refs: ["sha1:sdk:4-8"]
                },
                {
                  order: 3,
                  phase: "mixing_or_hash",
                  status: "observed",
                  confidence: "medium",
                  claim: "integer mixing or digest observed for X-Signature across integer_mixing",
                  runtime_apis: ["Math.imul"],
                  evidence: ["runtime_api:Math.imul"],
                  value_refs: ["number:mix"]
                },
                {
                  order: 4,
                  phase: "signature_attachment",
                  status: "observed",
                  confidence: "high",
                  claim: "signature attachment and request send observed for X-Signature across signature_mutation",
                  runtime_apis: ["URLSearchParams.set"],
                  target_params: ["X-Signature"],
                  evidence: ["runtime_api:URLSearchParams.set"],
                  object_refs: ["url_object:9", "search_params:9"],
                  value_refs: ["target_params:X-Signature"]
                }
              ],
              edges: [
                {
                  from_phase: "mixing_or_hash",
                  to_phase: "signature_attachment",
                  from_stage: "integer_mixing",
                  to_stage: "signature_mutation",
                  relation: "inferred_data_link",
                  confidence: "medium",
                  refs: ["number:mix"],
                  evidence: ["inferred_data_link"]
                },
                {
                  from_phase: "signature_attachment",
                  to_phase: "signature_attachment",
                  from_stage: "signature_mutation",
                  to_stage: "signed_request",
                  relation: "target_param_ref",
                  confidence: "high",
                  refs: ["target_params:X-Signature", "url_object:9"],
                  evidence: ["target_param_ref"]
                }
              ],
              final_attachment: {
                observed: true,
                target_params: ["X-Signature"],
                apis: ["URLSearchParams.set"],
                evidence_mode: "direct_runtime_api"
              }
            }
          }
        },
        analysis_readiness: {
          summary: {
            status: "partial_needs_targeted_capture",
            score: 58,
            passed_count: 3,
            partial_count: 2,
            failed_count: 2,
            primary_next_action: "capture_url_search_params_mutation_or_header_set"
          },
          checklist: [
            {
              item: "unsigned_input_observed",
              status: "pass",
              evidence_refs: ["stage:input_url", "api:URL.constructor"],
              gaps: [],
              next_actions: []
            },
            {
              item: "transform_runtime_observed",
              status: "partial",
              evidence_refs: ["stage:dynamic_dispatch", "source:sha1:sdk:2-4"],
              gaps: ["runtime_api_not_observed"],
              next_actions: ["expand_vmp_runtime_hooks"]
            },
            {
              item: "signature_attachment_observed",
              status: "partial",
              evidence_refs: ["stage:signature_mutation", "target_params:X-Signature"],
              gaps: ["runtime_api_not_observed", "source_context_not_available"],
              next_actions: ["capture_url_search_params_mutation_or_header_set"]
            }
          ],
          next_probe_plan: {
            action: "capture_url_search_params_mutation_or_header_set",
            reason: "close_signature_attachment_runtime_gap",
            stages: ["signature_mutation", "dynamic_dispatch"],
            gaps: ["runtime_api_not_observed", "source_context_not_available"],
            hook_targets: ["URLSearchParams.set", "Reflect.apply"],
            source_refs: ["sha1:sdk:2-4"],
            object_refs: ["url_object:9"],
            value_refs: ["target_params:X-Signature"]
          }
        },
        generation_graph: {
          node_count: 3,
          edge_count: 2,
          unresolved_edge_count: 1,
          entry_node_id: "step_1_input_url",
          exit_node_id: "step_3_signature_mutation",
          readiness_status: "partial_needs_targeted_capture",
          primary_next_probe: "capture_url_search_params_mutation_or_header_set",
          nodes: [],
          edges: [],
          unresolved_edges: [{
            id: "gap_1_2",
            from: "step_1_input_url",
            to: "step_2_dynamic_dispatch",
            status: "unresolved",
            gap: "source_only_edge",
            priority: "medium",
            next_actions: ["capture_object_ids_for_data_links"]
          }],
          operation_subgraphs: [{
            id: "opgraph_vmp_scalar_chain_1",
            pattern: "xor_imul_urshift_mixing",
            operation_count: 3
          }],
          dataflow_summary: {
            status: "vmp_output_reaches_signature_attachment",
            vmp_output_link_count: 1,
            attachment_to_request_link_observed: false,
            linked_output_refs: ["number:79.000000"],
            links: [{
              opgraph_id: "opgraph_vmp_scalar_chain_1",
              output_ref: "number:79.000000",
              to_node_id: "step_3_signature_mutation",
              to_stage: "signature_mutation",
              relation: "vmp_output_ref_on_signature_stage",
              confidence: "high"
            }],
            request_links: [],
            bridge_links: [{
              opgraph_id: "opgraph_vmp_scalar_chain_1",
              from_node_id: "step_2_dynamic_dispatch",
              to_node_id: "step_3_signature_mutation",
              relation: "temporal_runtime_order",
              confidence: "low",
              refs: ["trace_distance:3->1"]
            }],
            encoding_boundary_links: [{
              opgraph_id: "opgraph_vmp_scalar_chain_1",
              output_ref: "number:79.000000",
              from_node_id: "step_2_dynamic_dispatch",
              via_node_id: "step_2_text_or_string_decode",
              via_stage: "text_or_string_decode",
              to_node_id: "step_3_signature_mutation",
              relation: "vmp_output_to_signature_via_string_boundary",
              confidence: "high",
              refs: ["number:79.000000", "string_ref:x-signature-material"]
            }],
            gaps: ["signature_to_request_link_not_observed"],
            next_actions: ["capture_url_search_params_mutation_or_header_set"]
          }
        },
        generation_edge_gaps: [{
          from_order: 1,
          to_order: 2,
          from_stage: "input_url",
          to_stage: "dynamic_dispatch",
          gap: "source_only_edge",
          reason: "only_shared_source_context_no_runtime_data_ref",
          priority: "medium",
          next_actions: ["capture_object_ids_for_data_links"],
          source_refs: ["sha1:sdk:2-4"],
          object_refs: [],
          value_refs: []
        }],
        unresolved_gaps: ["signature_mutation_not_observed"],
        generation_edges: [
          {
            from_order: 1,
            to_order: 2,
            from_stage: "input_url",
            to_stage: "dynamic_dispatch",
            relation: "shared_source_ref",
            confidence: "medium",
            refs: [],
            source_refs: ["sha1:sdk:2-4"],
            evidence: ["shared_source_ref"]
          },
          {
            from_order: 2,
            to_order: 3,
            from_stage: "dynamic_dispatch",
            to_stage: "signature_mutation",
            relation: "value_to_object_ref",
            confidence: "high",
            refs: ["target:11"],
            source_refs: [],
            evidence: ["value_to_object_ref"]
          }
        ],
        vmp_operation_patterns: [{
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
          confidence: "high",
          quality_score: 1551,
          shared_refs: ["number:79.000000", "number:1325431901.000000"],
          evidence_refs: ["number:88.000000", "number:23.000000", "number:79.000000"],
          source_context_refs: ["sha1:runtime-sdk:9-9"]
        }],
        generation_path: [
          {
            order: 1,
            stage: "input_url",
            role: "input",
            apis: ["URL.constructor"],
            param_relation: "flow_target",
            relation_to_signed_request: "before_signed_request",
            distance_to_signed_request: 4,
            evidence_flags: ["runtime_api_observed", "source_context_observed"],
            evidence_gaps: [],
            recommended_next_actions: ["review_step_source_context"],
            source_evidence: [{
              ref: "sha1:sdk:2-4",
              content_path: "assets/trace_agent_paths/runtime-sdk.js",
              line_start: 2,
              line_end: 4,
              preview: "const sig = url.searchParams.set('X-Signature', '<redacted>')"
            }],
            object_refs: ["url_object:7"],
            value_refs: ["url_shape:feed"]
          },
          {
            order: 2,
            stage: "dynamic_dispatch",
            role: "transform",
            apis: [],
            param_relation: "flow_target",
            relation_to_signed_request: "before_signed_request",
            distance_to_signed_request: 3,
            evidence_flags: ["source_context_observed", "data_refs_observed"],
            evidence_gaps: ["runtime_api_not_observed"],
            recommended_next_actions: ["expand_vmp_runtime_hooks"],
            source_calls: ["Reflect.apply", "Function.prototype.call"],
            source_signals: ["dynamic_dispatch", "prototype_call"],
            source_operators: ["^"],
            source_constants: ["123"],
            source_evidence: [{
              ref: "sha1:sdk:2-4",
              content_path: "assets/trace_agent_paths/runtime-sdk.js",
              line_start: 2,
              line_end: 4,
              preview: "const sig = url.searchParams.set('X-Signature', '<redacted>')"
            }],
            object_refs: ["target:11"],
            value_refs: []
          },
          {
            order: 3,
            stage: "signature_mutation",
            role: "parameter_attachment",
            apis: [],
            param_relation: "direct_observed",
            relation_to_signed_request: "before_signed_request",
            distance_to_signed_request: 1,
            evidence_flags: ["target_param_observed", "data_refs_observed"],
            evidence_gaps: ["runtime_api_not_observed", "source_context_not_available"],
            recommended_next_actions: [
              "capture_url_search_params_mutation_or_header_set",
              "expand_vmp_runtime_hooks"
            ],
            source_evidence: [],
            object_refs: ["url_object:9"],
            value_refs: ["target_params:X-Signature"]
          }
        ]
      }]
    }
  };

  const detail = renderReportDetail(report);
  const html = renderReportHtml(report);

  assert.match(detail, /Agent Parameter Generation Paths/);
  assert.match(detail, /Hypotheses: strong=0 partial=1 needs_more=0 gaps=1 patterns=xor_imul_urshift_mixing:1/);
  assert.match(detail, /Readiness: ready=0 partial=1 insufficient=0 avg=58/);
  assert.match(detail, /Blocking gaps: total=5 top=runtime_api_not_observed:2\[high\],signature_mutation_not_observed:1\[high\] actions=capture_url_search_params_mutation_or_header_set:3,expand_vmp_runtime_hooks:2,capture_or_retrieve_script_asset:1,capture_object_ids_for_data_links:1/);
  assert.match(detail, /Agent Blocking Gaps/);
  assert.match(detail, /blocker=runtime_api_not_observed count=2 priority=high params=X-Signature stages=dynamic_dispatch,signature_mutation actions=expand_vmp_runtime_hooks,capture_url_search_params_mutation_or_header_set hooks=Reflect\.apply,URLSearchParams\.set endpoint=https:\/\/www\.example\.test\/api\/feed refs=url_object:9,url_object:9,target_params:X-Signature sources=sha1:sdk:2-4/);
  assert.match(detail, /parameter_path X-Signature conclusion=attachment_observed_with_runtime_chain evidence=high endpoint=https:\/\/www\.example\.test\/api\/feed chain=input_url -> dynamic_dispatch -> signature_mutation -> signed_request chain_quality=partial edges=2\/2 high=1 medium=1 source_only=1 temporal=0 nearby=0 missing=0 gaps=signature_mutation_not_observed/);
  assert.match(detail, /candidate_generation=chain=input_url->dynamic_dispatch->signature_mutation->signed_request evidence=runtime_and_source readiness=partial_needs_targeted_capture dataflow=unknown params=X-Signature runtime=URL\.constructor\|Reflect\.apply\|URLSearchParams\.set source_hooks=vmp_dynamic_dispatch runtime_hooks=vmp_int_bitwise_pipeline refs=url_object:7\|url_object:9\|search_params:9\|array_buffer:20\|data_view:21 attachment=observed:signature_mutation:URLSearchParams\.set:X-Signature gaps=none next=none/);
  assert.match(detail, /candidate_source=sha1:sdk:2-4 path=assets\/trace_agent_paths\/runtime-sdk\.js lines=2-4 stages=input_url\|dynamic_dispatch\|signature_mutation preview=const sig = url\.searchParams\.set\('X-Signature', '<redacted>'\)/);
  assert.match(detail, /logic_trace=X-Signature generation: input_material -> vmp_execution -> mixing_or_hash -> signature_attachment; status=partial_runtime_source_path/);
  assert.match(detail, /logic_step=1:input_material\[observed\/high\] claim=input material observed for X-Signature across input_url apis=URL\.constructor calls=none params=X-Signature refs=url_object:7\|sha1:sdk:1-3 evidence=runtime_api:URL\.constructor/);
  assert.match(detail, /request_inputs=url_query\(params=X-Signature query=X-Signature\|cursor refs=string_ref:native-signed-url\);request_headers\(params=X-Signature headers=x-signature refs=string_ref:native-header-xsignature\);request_body\(params=X-Secondary-Signature body_size=42 refs=string_ref:native-xhr-body\);cookies\(names=sessionToken\);storage\(keys=fp_seed refs=storage:local:fp_seed\)/);
  assert.match(detail, /logic_edges=mixing_or_hash->signature_attachment:inferred_data_link\[medium\] stages=integer_mixing->signature_mutation refs=number:mix evidence=inferred_data_link;signature_attachment->signature_attachment:target_param_ref\[high\] stages=signature_mutation->signed_request refs=target_params:X-Signature\|url_object:9 evidence=target_param_ref/);
  assert.match(detail, /logic_attachment=observed:true params=X-Signature apis=URLSearchParams\.set mode=direct_runtime_api/);
  assert.match(detail, /hypothesis=partial_pre_signature_runtime_chain pattern=xor_imul_urshift_mixing quality=partial direct_attachment=true pre_signature_pattern=true gaps=signature_mutation_not_observed next=review_source_refs/);
  assert.match(detail, /readiness=partial_needs_targeted_capture score=58 passed=3 partial=2 failed=2 primary=capture_url_search_params_mutation_or_header_set checklist=unsigned_input_observed:pass,transform_runtime_observed:partial,signature_attachment_observed:partial next_probe=capture_url_search_params_mutation_or_header_set reason=close_signature_attachment_runtime_gap hooks=URLSearchParams\.set,Reflect\.apply gaps=runtime_api_not_observed,source_context_not_available/);
  assert.match(detail, /generation_graph=nodes=3 edges=2 unresolved=1 opgraphs=1 ops=xor_imul_urshift_mixing:3 flow=vmp_output_reaches_signature_attachment links=1 request=false bridges=1 boundary=1 entry=step_1_input_url exit=step_3_signature_mutation readiness=partial_needs_targeted_capture next=capture_url_search_params_mutation_or_header_set gaps=source_only_edge:medium/);
  assert.match(detail, /step=1:input_url role=input apis=URL\.constructor relation=before_signed_request d=4 flags=runtime_api_observed,source_context_observed gaps=none next=review_step_source_context source=sha1:sdk:2-4@assets\/trace_agent_paths\/runtime-sdk\.js:2-4 preview=const sig = url\.searchParams\.set\('X-Signature', '<redacted>'\) refs=url_object:7,url_shape:feed/);
  assert.match(detail, /step=2:dynamic_dispatch role=transform apis=none relation=before_signed_request d=3 flags=source_context_observed,data_refs_observed gaps=runtime_api_not_observed next=expand_vmp_runtime_hooks source=sha1:sdk:2-4@assets\/trace_agent_paths\/runtime-sdk\.js:2-4 preview=const sig = url\.searchParams\.set\('X-Signature', '<redacted>'\) source_meta=calls=Reflect\.apply,Function\.prototype\.call signals=dynamic_dispatch,prototype_call ops=\^ consts=123 refs=target:11/);
  assert.match(detail, /step=3:signature_mutation role=parameter_attachment apis=none relation=before_signed_request d=1 flags=target_param_observed,data_refs_observed gaps=runtime_api_not_observed,source_context_not_available next=capture_url_search_params_mutation_or_header_set,expand_vmp_runtime_hooks source=none refs=url_object:9,target_params:X-Signature/);
  assert.match(detail, /generation_edges=1:input_url->2:dynamic_dispatch:shared_source_ref\[medium\] refs=none sources=sha1:sdk:2-4 evidence=shared_source_ref;2:dynamic_dispatch->3:signature_mutation:value_to_object_ref\[high\] refs=target:11 sources=none evidence=value_to_object_ref/);
  assert.match(detail, /generation_edge_gaps=1:input_url->2:dynamic_dispatch:source_only_edge\[medium\] reason=only_shared_source_context_no_runtime_data_ref next=capture_object_ids_for_data_links sources=sha1:sdk:2-4 refs=none/);
  assert.match(detail, /vmp_patterns=xor_imul_urshift_mixing\[high\]:Bitwise\.xor -> Math\.imul -> Shift\.unsignedRight seq=11\.\.13 trace=3\.\.5 relation=before_signature_mutation d_sig=2 refs=number:79\.000000\|number:1325431901\.000000/);
  assert.match(html, /Agent Parameter Generation Paths/);
  assert.match(html, /Hypotheses: strong=0 partial=1 needs_more=0 gaps=1 patterns=xor_imul_urshift_mixing:1/);
  assert.match(html, /Readiness: ready=0 partial=1 insufficient=0 avg=58/);
  assert.match(html, /Blocking gaps: total=5 top=runtime_api_not_observed:2\[high\],signature_mutation_not_observed:1\[high\] actions=capture_url_search_params_mutation_or_header_set:3,expand_vmp_runtime_hooks:2,capture_or_retrieve_script_asset:1,capture_object_ids_for_data_links:1/);
  assert.match(html, /Agent Blocking Gaps/);
  assert.match(html, /blocker=runtime_api_not_observed count=2 priority=high params=X-Signature stages=dynamic_dispatch,signature_mutation actions=expand_vmp_runtime_hooks,capture_url_search_params_mutation_or_header_set hooks=Reflect\.apply,URLSearchParams\.set endpoint=https:\/\/www\.example\.test\/api\/feed refs=url_object:9,url_object:9,target_params:X-Signature sources=sha1:sdk:2-4/);
  assert.match(html, /parameter_path X-Signature/);
  assert.match(html, /candidate_generation=chain=input_url-&gt;dynamic_dispatch-&gt;signature_mutation-&gt;signed_request evidence=runtime_and_source readiness=partial_needs_targeted_capture dataflow=unknown params=X-Signature runtime=URL\.constructor\|Reflect\.apply\|URLSearchParams\.set source_hooks=vmp_dynamic_dispatch runtime_hooks=vmp_int_bitwise_pipeline refs=url_object:7\|url_object:9\|search_params:9\|array_buffer:20\|data_view:21 attachment=observed:signature_mutation:URLSearchParams\.set:X-Signature gaps=none next=none/);
  assert.match(html, /candidate_source=sha1:sdk:2-4 path=assets\/trace_agent_paths\/runtime-sdk\.js lines=2-4 stages=input_url\|dynamic_dispatch\|signature_mutation preview=const sig = url\.searchParams\.set\(&#39;X-Signature&#39;, &#39;&lt;redacted&gt;&#39;\)/);
  assert.match(html, /logic_trace=X-Signature generation: input_material -&gt; vmp_execution -&gt; mixing_or_hash -&gt; signature_attachment; status=partial_runtime_source_path/);
  assert.match(html, /logic_step=1:input_material\[observed\/high\] claim=input material observed for X-Signature across input_url apis=URL\.constructor calls=none params=X-Signature refs=url_object:7\|sha1:sdk:1-3 evidence=runtime_api:URL\.constructor/);
  assert.match(html, /request_inputs=url_query\(params=X-Signature query=X-Signature\|cursor refs=string_ref:native-signed-url\);request_headers\(params=X-Signature headers=x-signature refs=string_ref:native-header-xsignature\);request_body\(params=X-Secondary-Signature body_size=42 refs=string_ref:native-xhr-body\);cookies\(names=sessionToken\);storage\(keys=fp_seed refs=storage:local:fp_seed\)/);
  assert.match(html, /logic_edges=mixing_or_hash-&gt;signature_attachment:inferred_data_link\[medium\] stages=integer_mixing-&gt;signature_mutation refs=number:mix evidence=inferred_data_link;signature_attachment-&gt;signature_attachment:target_param_ref\[high\] stages=signature_mutation-&gt;signed_request refs=target_params:X-Signature\|url_object:9 evidence=target_param_ref/);
  assert.match(html, /logic_attachment=observed:true params=X-Signature apis=URLSearchParams\.set mode=direct_runtime_api/);
  assert.match(html, /hypothesis=partial_pre_signature_runtime_chain pattern=xor_imul_urshift_mixing quality=partial direct_attachment=true pre_signature_pattern=true gaps=signature_mutation_not_observed next=review_source_refs/);
  assert.match(html, /readiness=partial_needs_targeted_capture score=58 passed=3 partial=2 failed=2 primary=capture_url_search_params_mutation_or_header_set checklist=unsigned_input_observed:pass,transform_runtime_observed:partial,signature_attachment_observed:partial next_probe=capture_url_search_params_mutation_or_header_set reason=close_signature_attachment_runtime_gap hooks=URLSearchParams\.set,Reflect\.apply gaps=runtime_api_not_observed,source_context_not_available/);
  assert.match(html, /generation_graph=nodes=3 edges=2 unresolved=1 opgraphs=1 ops=xor_imul_urshift_mixing:3 flow=vmp_output_reaches_signature_attachment links=1 request=false bridges=1 boundary=1 entry=step_1_input_url exit=step_3_signature_mutation readiness=partial_needs_targeted_capture next=capture_url_search_params_mutation_or_header_set gaps=source_only_edge:medium/);
  assert.match(html, /chain_quality=partial edges=2\/2 high=1 medium=1 source_only=1 temporal=0 nearby=0 missing=0/);
  assert.match(html, /step=2:dynamic_dispatch/);
  assert.match(html, /runtime_api_not_observed/);
  assert.match(html, /capture_url_search_params_mutation_or_header_set/);
  assert.match(html, /assets\/trace_agent_paths\/runtime-sdk\.js/);
  assert.match(html, /preview=const sig = url\.searchParams\.set\(&#39;X-Signature&#39;, &#39;&lt;redacted&gt;&#39;\)/);
  assert.match(html, /source_meta=calls=Reflect\.apply,Function\.prototype\.call signals=dynamic_dispatch,prototype_call ops=\^ consts=123/);
  assert.match(html, /generation_edges=1:input_url-&gt;2:dynamic_dispatch:shared_source_ref\[medium\] refs=none sources=sha1:sdk:2-4 evidence=shared_source_ref;2:dynamic_dispatch-&gt;3:signature_mutation:value_to_object_ref\[high\] refs=target:11 sources=none evidence=value_to_object_ref/);
  assert.match(html, /generation_edge_gaps=1:input_url-&gt;2:dynamic_dispatch:source_only_edge\[medium\] reason=only_shared_source_context_no_runtime_data_ref next=capture_object_ids_for_data_links sources=sha1:sdk:2-4 refs=none/);
  assert.match(html, /vmp_patterns=xor_imul_urshift_mixing\[high\]:Bitwise\.xor -&gt; Math\.imul -&gt; Shift\.unsignedRight seq=11\.\.13 trace=3\.\.5 relation=before_signature_mutation d_sig=2 refs=number:79\.000000\|number:1325431901\.000000/);
});

test("renderReportDetail and HTML show agent review package entries", () => {
  const report = {
    trace: {path: "/tmp/xtrace/logs/trace_review.ndjson", event_count: 5},
    reverse: {dynamic_execution_count: 0},
    vmp: {runtime_event_count: 3},
    fingerprint: {api_count: 0},
    signature: {
      event_count: 1,
      agent_evidence_pack: {
        parameter_generation_brief: {
          version: 1,
          purpose: "agent_parameter_generation_brief",
          parameter_count: 1,
          parameters: [{
            param: "X-Signature",
            status: "attachment_observed",
            best_flow_id: "material_flow_1",
            endpoint: "https://www.example.test/api/list",
            confidence: "high",
            evidence_status: "observed_only",
            readiness: "strong",
            flow_ids: ["material_flow_1"],
            source_candidate_ids: ["source_candidate_1"],
            review_entry_ids: ["review_entry_1"],
            source_refs: ["sha1:sign-source:2-6"],
            evidence_gaps: [],
            next_questions: ["which_inputs_feed_this_source_window"],
            generation_trace: [
              {
                order: 1,
                stage: "input_url",
                role: "input",
                apis: ["URL.constructor"],
                target_params: ["X-Signature"],
                param_relation: "flow_target",
                relation: "before_signed_request",
                distance_to_signed_request: 2,
                source_refs: ["sha1:sign-source:2-6"]
              },
              {
                order: 2,
                stage: "signature_mutation",
                role: "parameter_attachment",
                apis: ["URLSearchParams.set"],
                target_params: ["X-Signature"],
                param_relation: "direct_observed",
                relation: "before_signed_request",
                distance_to_signed_request: 1,
                source_refs: ["sha1:sign-source:2-6"]
              },
              {
                order: 3,
                stage: "signed_request",
                role: "network_emit",
                apis: ["Request.constructor"],
                target_params: ["X-Signature"],
                param_relation: "direct_observed",
                relation: "signed_request",
                distance_to_signed_request: 0,
                source_refs: ["sha1:sign-source:2-6"]
              }
            ]
          }]
        },
        agent_review_package: {
          version: 1,
          purpose: "agent_source_review_package",
          entry_count: 1,
          causality_summary: {
            pre_request_chain: 1,
            mixed_pre_post_request: 0,
            signed_or_unknown: 0,
            post_request_activity: 0,
            prioritized_entry_count: 1,
            deprioritized_entry_count: 0
          },
          entries: [{
            id: "review_entry_1",
            source_candidate_id: "source_candidate_1",
            causality: "pre_request_chain",
            review_priority: "high",
            warnings: [],
            function: "sign<script>",
            asset_id: "sha1:sign-source",
            content_path: "assets/trace_demo/runtime-sdk.js",
            line_ranges: [{line_start: 2, line_end: 6}],
            endpoints: ["https://www.example.test/api/list"],
            target_params: ["X-Signature"],
            stages: ["input_url", "integer_mixing", "signed_request"],
            runtime_apis: ["TextEncoder.encode", "Bitwise.xor", "Request.constructor"],
            signals: ["text_codec", "int_bitwise"],
            calls: ["TextEncoder", "encode"],
            operators: ["^"],
            generation_paths: [{
              id: "generation_path_1",
              causality: "pre_request_chain",
              stage_summary: "input_url[URL.constructor@10]->integer_mixing[Bitwise.xor@11]->signed_request[Request.constructor@12]",
              step_count: 3
            }],
            review_reasons: ["target_param_seen", "near_signed_request"],
            next_questions: [
              "which_inputs_feed_this_source_window",
              "which_request_endpoint_uses_this_candidate"
            ]
          }]
        },
        flows: []
      }
    }
  };

  const detail = renderReportDetail(report);
  const html = renderReportHtml(report);

  assert.match(detail, /Agent Review Package/);
  assert.match(detail, /Parameter Generation Brief/);
  assert.match(detail, /parameter X-Signature status=attachment_observed flow=material_flow_1 endpoint=https:\/\/www\.example\.test\/api\/list readiness=strong trace=input_url\[URL\.constructor d=2 target=X-Signature relation=flow_target\]->signature_mutation\[URLSearchParams\.set d=1 target=X-Signature relation=direct_observed\]->signed_request\[Request\.constructor d=0 target=X-Signature relation=direct_observed\] sources=sha1:sign-source:2-6 candidates=source_candidate_1 reviews=review_entry_1/);
  assert.match(detail, /causality_summary pre_request_chain=1 mixed_pre_post_request=0 signed_or_unknown=0 post_request_activity=0 prioritized=1 deprioritized=0/);
  assert.match(detail, /review_entry_1 candidate=source_candidate_1 causality=pre_request_chain priority=high function=sign<script> path=assets\/trace_demo\/runtime-sdk\.js lines=2-6/);
  assert.match(detail, /endpoints=https:\/\/www\.example\.test\/api\/list params=X-Signature/);
  assert.match(detail, /apis=TextEncoder\.encode,Bitwise\.xor,Request\.constructor signals=text_codec,int_bitwise/);
  assert.match(detail, /paths=generation_path_1:pre_request_chain:input_url\[URL\.constructor@10\]->integer_mixing\[Bitwise\.xor@11\]->signed_request\[Request\.constructor@12\]/);
  assert.match(detail, /next=which_inputs_feed_this_source_window,which_request_endpoint_uses_this_candidate/);
  assert.match(html, /Agent Review Package/);
  assert.match(html, /Parameter Generation Brief/);
  assert.match(html, /parameter X-Signature status=attachment_observed flow=material_flow_1 endpoint=https:\/\/www\.example\.test\/api\/list readiness=strong trace=input_url\[URL\.constructor d=2 target=X-Signature relation=flow_target\]-&gt;signature_mutation\[URLSearchParams\.set d=1 target=X-Signature relation=direct_observed\]-&gt;signed_request\[Request\.constructor d=0 target=X-Signature relation=direct_observed\]/);
  assert.match(html, /pre_request_chain=1/);
  assert.match(html, /priority=high/);
  assert.match(html, /review_entry_1/);
  assert.match(html, /source_candidate_1/);
  assert.match(html, /assets\/trace_demo\/runtime-sdk\.js/);
  assert.match(html, /lines=2-6/);
  assert.match(html, /generation_path_1:pre_request_chain:input_url\[URL\.constructor@10\]-&gt;integer_mixing\[Bitwise\.xor@11\]-&gt;signed_request\[Request\.constructor@12\]/);
  assert.match(html, /sign&lt;script&gt;/);
  assert.doesNotMatch(html, /sign<script>/);
});

test("renderReportDetail summarizes agent evidence candidate windows", () => {
  const report = {
    trace: {
      path: "/tmp/xtrace/logs/trace_demo.ndjson",
      event_count: 42
    },
    reverse: {
      dynamic_execution_count: 2
    },
    vmp: {
      runtime_event_count: 5
    },
    fingerprint: {
      api_count: 3
    },
    signature: {
      event_count: 1,
      agent_evidence_pack: {
        flows: [{
          id: "signature_flow_1",
          vmp_candidate_phases: [{
            phase: "candidate_vmp_bytecode_or_register_access",
            type: "vmp_bytecode_or_register_access",
            confidence: "high",
            seq_start: 9,
            seq_end: 9,
            candidate_count: 1
          }],
          candidate_graph: {
            nodes: [{
              id: "c1",
              phase: "candidate_vmp_bytecode_or_register_access",
              confidence: "high",
              seq_start: 9,
              seq_end: 9,
              candidate_count: 1
            }],
            edges: [
              {from: "n1", to: "c1", relation: "candidate_after", seq_gap: 1},
              {from: "c1", to: "n2", relation: "candidate_before", seq_gap: 1}
            ]
          },
          suspected_signature_subflows: [{
            id: "candidate_subflow_1",
            evidence_status: "mixed_observed_and_candidate",
            confidence: "high",
            function: "sign",
            stack_url: "https://cdn.example.test/runtime-sdk.js",
            seq_start: 8,
            seq_end: 10,
            phases: [
              "unsigned_url",
              "candidate_vmp_bytecode_or_register_access",
              "signed_request"
            ],
            observed_apis: [
              {api: "Request.constructor", count: 1},
              {api: "URL.constructor", count: 1}
            ],
            candidate_apis: [{api: "DataView.getUint32", count: 1}],
            candidate_phase_count: 1,
            source_context_refs: ["sha1:runtime-sdk:20-22"],
            source_contexts: [{
              asset_id: "sha1:runtime-sdk",
              line_start: 20,
              line_end: 22,
              preview: "function sign(input) {\n  return \"X-Signature=<redacted>\";\n}",
              analysis: {
                signals: ["byte_buffer", "int_bitwise"],
                calls: ["DataView.prototype.getUint32.call"],
                properties: ["vm.seed"],
                operators: ["^", ">>>"]
              }
            }],
            candidate_signature_pipeline: {
              confidence: "high",
              stage_count: 4,
              data_links: [
                {from: "input_url", to: "signed_request", refs: ["url_object:11", "search_params:12"]},
                {from: "byte_buffer", to: "integer_mixing", refs: ["data_view:21"]}
              ],
              stages: [
                {stage: "input_url", runtime_apis: ["URL.constructor"], source_calls: [], source_signals: [], source_operators: [], source_constants: []},
                {stage: "byte_buffer", runtime_apis: ["DataView.getUint32"], source_calls: ["DataView.prototype.getUint32.call"], source_signals: ["byte_buffer"], source_operators: [], source_constants: []},
                {stage: "integer_mixing", runtime_apis: ["Math.imul"], source_calls: ["Math.imul"], source_signals: ["int_bitwise"], source_operators: ["^", ">>>"], source_constants: ["2654435761"]},
                {stage: "signed_request", runtime_apis: ["Request.constructor"], source_calls: [], source_signals: [], source_operators: [], source_constants: []}
              ]
            }
          }],
          vmp_linking_candidates: [{
            type: "vmp_bytecode_or_register_access",
            gap_source: "captured_outside_signature_flow",
            recommended_next_step: "improve_flow_linking",
            candidate_count: 1,
            candidates: [{
              seq: 9,
              api: "DataView.getUint32",
              family: "byte_buffer",
              relation: "same_origin_nearby",
              seq_distance: 1,
              context_window: {
                events: [
                  {seq: 8, api: "URL.constructor", window_role: "nearby"},
                  {seq: 9, api: "DataView.getUint32", window_role: "candidate"},
                  {seq: 10, api: "Request.constructor", window_role: "nearby"}
                ],
                source_contexts: [{asset_id: "sha1:runtime-sdk", line_start: 20, line_end: 22}]
              }
            }]
          }]
        }],
        vmp_hook_analysis: {
          hook_gaps: [{
            type: "vmp_string_decoder",
            priority: "medium",
            gap_source: "captured_outside_signature_flow",
            recommended_next_step: "improve_flow_linking",
            missing_flow_count: 1,
            global_event_count: 1,
            linking_candidates: [{
              seq: 1,
              api: "atob",
              family: "base64",
              nearest_flows: [{
                flow_id: "signature_flow_1",
                relation: "same_origin_nearby",
                seq_distance: 9
              }],
              context_window: {
                events: [
                  {seq: 0, api: "localStorage.getItem", window_role: "nearby"},
                  {seq: 1, api: "atob", window_role: "candidate"},
                  {seq: 2, api: "document.cookie.get", window_role: "nearby"}
                ],
                source_contexts: [{
                  asset_id: "sha1:other",
                  line_start: 1,
                  line_end: 4
                }]
              }
            }]
          }]
        }
      }
    }
  };

  const detail = renderReportDetail(report);

  assert.match(detail, /Trace: \/tmp\/xtrace\/logs\/trace_demo\.ndjson/);
  assert.match(detail, /Agent Evidence Pack/);
  assert.match(detail, /vmp_string_decoder missing_flows=1 source=captured_outside_signature_flow next=improve_flow_linking/);
  assert.match(detail, /atob@1 -> signature_flow_1 same_origin_nearby distance=9/);
  assert.match(detail, /window=localStorage\.getItem@0:nearby, atob@1:candidate, document\.cookie\.get@2:nearby/);
  assert.match(detail, /sources=sha1:other:1-4/);
  assert.match(detail, /Flow VMP Linking Candidates/);
  assert.match(detail, /signature_flow_1 vmp_bytecode_or_register_access candidates=1 source=captured_outside_signature_flow/);
  assert.match(detail, /DataView\.getUint32@9 same_origin_nearby distance=1/);
  assert.match(detail, /Candidate Graph/);
  assert.match(detail, /signature_flow_1 candidate_vmp_bytecode_or_register_access high seq=9\.\.9 candidates=1/);
  assert.match(detail, /n1->c1 candidate_after gap=1/);
  assert.match(detail, /Suspected Signature Subflows/);
  assert.match(detail, /candidate_subflow_1 sign@https:\/\/cdn\.example\.test\/runtime-sdk\.js high seq=8\.\.10/);
  assert.match(detail, /phases=unsigned_url>candidate_vmp_bytecode_or_register_access>signed_request/);
  assert.match(detail, /sources=sha1:runtime-sdk:20-22/);
  assert.match(detail, /source_analysis=signals:byte_buffer,int_bitwise calls:DataView\.prototype\.getUint32\.call props:vm\.seed ops:\^,>>>/);
  assert.match(detail, /candidate_pipeline=input_url\[URL\.constructor\]->byte_buffer\[DataView\.getUint32\]->integer_mixing\[Math\.imul\]->signed_request\[Request\.constructor\] confidence=high/);
  assert.match(detail, /data_links=input_url->signed_request:url_object:11\|search_params:12,byte_buffer->integer_mixing:data_view:21/);
  assert.match(detail, /source_preview=function sign\(input\) \{ \/ return "X-Signature=<redacted>"; \/ \}/);
  assert.doesNotMatch(detail, /secret/);
});

test("renderReportDetail and HTML show signature-absent candidate entrypoints", () => {
  const report = {
    trace: {path: "/tmp/xtrace/logs/trace_absent.ndjson", event_count: 120},
    reverse: {dynamic_execution_count: 1},
    vmp: {runtime_event_count: 50},
    fingerprint: {api_count: 0},
    signature: {
      event_count: 0,
      agent_evidence_pack: {
        signature_absent: {
          reason: "signature_terms_not_observed",
          target_terms: ["X-Signature", "X-Secondary-Signature"],
          vmp_runtime_event_count: 50,
          candidate_entrypoints: [{
            function: "sign<script>",
            stack_url: "https://cdn.example.test/secsdk.js",
            event_count: 42,
            seq_start: 10,
            seq_end: 80,
            families: ["int_bitwise", "text_codec"],
            apis: [
              {api: "Bitwise.and", count: 30},
              {api: "TextEncoder.encode", count: 12}
            ],
            asset_id: "sha1:secsdk"
          }],
          candidate_assets: [{
            asset_id: "sha1:secsdk",
            url: "https://cdn.example.test/secsdk.js",
            score: 12,
            signals: ["vmp_handler_table", "dynamic_execution"]
          }],
          candidate_trace_chains: [{
            id: "absent_candidate_chain_1",
            endpoint: "https://www.example.test/api/feed/list",
            confidence: "high",
            steps: [
              {phase: "request_construction", api: "Request.constructor", seq: 400},
              {phase: "vmp_hash_or_signature_pipeline", api: "TextEncoder.encode", seq: 401},
              {phase: "vmp_hash_or_signature_pipeline", api: "SubtleCrypto.digest", seq: 402},
              {phase: "signed_request", api: "BrowserNetwork.request", seq: 10}
            ],
            hook_points: [
              {type: "vmp_hash_or_signature_pipeline", seq_start: 401, seq_end: 402}
            ],
            inferred_initiator: {
              function: "vmDispatch",
              stack_url: "https://cdn.example.test/runtime-sdk.js",
              confidence: "medium",
              event_count: 3
            },
            request_context: {capture_gaps: ["renderer_stack_missing"]}
          }],
          capture_recommendations: [
            {id: "trigger_signed_request_paths", priority: "high"},
            {id: "rerun_with_interactive_profile", priority: "medium"}
          ]
        },
        next_capture_plan: {
          priority: "high",
          target_terms: ["X-Signature", "X-Secondary-Signature"],
          recommended_flags: [
            "--xtrace-categories=reverse,fingerprint",
            "--xtrace-capture-values=full",
            "--xtrace-capture-assets=full"
          ],
          gap_summary: [{
            gap: "signature_terms_not_observed",
            flow_count: 2,
            priority: "high",
            next_actions: ["capture_signature_terms_or_mutation"]
          }],
          low_value_endpoint_summary: [{
            resource_class: "telemetry_endpoint",
            endpoint_count: 2,
            flow_count: 3,
            examples: [
              "https://telemetry.example.test/monitor_browser/collect",
              "https://www.example.test/cdn-sw-probe"
            ]
          }],
          hook_focus: [{
            type: "vmp_string_decoder",
            missing_flow_count: 2,
            priority: "medium",
            next_action: "add_or_link_hooks",
            suggested_hooks: ["String.fromCharCode", "atob"]
          }],
          focus_endpoints: [{
            endpoint: "https://www.example.test/api/feed/list",
            flow_count: 2,
            readiness_statuses: ["candidate"],
            evidence_gaps: ["signature_terms_not_observed"]
          }],
          focus_assets: [{
            asset_id: "sha1:secsdk",
            stack_url: "https://cdn.example.test/secsdk.js",
            flow_count: 1,
            readiness_statuses: ["candidate"]
          }],
          business_api_capture_status: {
            status: "captured",
            priority: "high",
            actionable_endpoint_count: 1,
            endpoints: [{
              endpoint: "https://www.example.test/api/feed/list",
              flow_count: 2,
              readiness_statuses: ["candidate"],
              evidence_gaps: ["signature_terms_not_observed"]
            }],
            success_criteria_met: ["observed endpoint is not document_request, static_resource, or telemetry_endpoint"],
            missing_evidence: ["signature_terms_not_observed"],
            next_actions: ["capture_signature_terms_or_mutation"]
          },
          capture_gate: {
            id: "business_api_anchor",
            status: "passed",
            priority: "high",
            target_endpoint_patterns: ["https://www.example.test/api/feed/list"],
            observed_actionable_endpoint_count: 1,
            missing: [],
            remaining_analysis_gaps: ["signature_terms_not_observed"],
            tail_filters: {
              categories: ["network"],
              apis: ["BrowserNetwork.request", "fetch", "XMLHttpRequest.open", "XMLHttpRequest.send"],
              exclude_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"]
            }
          },
          capture_checklist: [{
            id: "complete_material_linking",
            status: "pending",
            priority: "high",
            evidence: ["signature_terms_not_observed"],
            next_action: "capture_signature_terms_or_mutation"
          }],
          capture_attempt_quality: {
            status: "core_sdk_observed_without_business_api",
            readiness: "not_ready_for_signature_generation_analysis",
            actionable_endpoint_count: 0,
            core_asset_count: 2,
            low_value_endpoint_classes: ["document_request", "static_resource", "telemetry_endpoint"],
            missing_evidence: ["business_api_anchor_not_captured", "signature_terms_not_observed"],
            next_action: "perform_normal_in_page_actions_until_business_api_request"
          },
          business_api_capture_plan: {
            status: "needs_business_api_anchor",
            priority: "high",
            start_url: "https://www.example.test/",
            avoid_resource_classes: ["document_request", "static_resource", "telemetry_endpoint"],
            core_assets: ["sha1:secsdk@https://cdn.example.test/secsdk.js"],
            normal_user_actions: ["perform normal in-page actions that request feed, search, detail, or pagination data"],
            success_criteria: ["observed endpoint is not document_request, static_resource, or telemetry_endpoint"],
            required_evidence: ["BrowserNetwork.request"]
          },
          rerun_recipe: {
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
              "/path/to/xtrace/chromium/src/out/XTrace/Chromium.app",
              "--url",
              "https://www.example.test/api/feed/list"
            ],
            focus: {
              target_terms: ["X-Signature", "X-Secondary-Signature"],
              endpoints: ["https://www.example.test/api/feed/list"],
              assets: ["sha1:secsdk@https://cdn.example.test/secsdk.js"],
              gaps: ["signature_terms_not_observed"],
              hooks: ["vmp_string_decoder"]
            }
          }
        },
        core_asset_review_package: {
          purpose: "agent_core_asset_source_review",
          entry_count: 1,
          entries: [{
            asset_id: "sha1:runtime-sdk",
            url: "https://cdn.example.test/runtime-sdk.js",
            content_path: "assets/trace_demo/runtime-sdk.js",
            asset_role: "security_sdk_signature_generator",
            source_status: "available",
            score: 14,
            signals: ["vmp_dynamic_dispatch", "fingerprint_api_refs"],
            review_focus: ["url_signature_boundary", "vmp_runtime_surface"],
            source_windows: [{
              focus: "url_signature_boundary",
              priority: "high",
              line_start: 3,
              line_end: 3,
              analysis: {signals: ["url_signature", "text_codec"]},
              preview: "u.searchParams.set('X-Signature','<redacted>')"
            }]
          }]
        },
        flows: []
      }
    }
  };

  const detail = renderReportDetail(report);
  const html = renderReportHtml(report);

  assert.match(detail, /Signature Capture Gap/);
  assert.match(detail, /reason=signature_terms_not_observed vmp_events=50 targets=X-Signature,X-Secondary-Signature/);
  assert.match(detail, /candidate_entry=sign<script>@https:\/\/cdn\.example\.test\/secsdk\.js events=42 seq=10\.\.80 families=int_bitwise,text_codec/);
  assert.match(detail, /candidate_asset=https:\/\/cdn\.example\.test\/secsdk\.js score=12 signals=vmp_handler_table,dynamic_execution/);
  assert.match(detail, /candidate_chain=absent_candidate_chain_1 confidence=high endpoint=https:\/\/www\.example\.test\/api\/feed\/list steps=request_construction\[Request\.constructor@400\]->vmp_hash_or_signature_pipeline\[TextEncoder\.encode@401,SubtleCrypto\.digest@402\]->signed_request\[BrowserNetwork\.request@10\]/);
  assert.match(detail, /inferred_initiator=vmDispatch@https:\/\/cdn\.example\.test\/runtime-sdk\.js:medium:events3/);
  assert.match(detail, /recommend=trigger_signed_request_paths:high,rerun_with_interactive_profile:medium/);
  assert.match(detail, /Next Capture Plan/);
  assert.match(detail, /priority=high targets=X-Signature,X-Secondary-Signature flags=--xtrace-categories=reverse,fingerprint,--xtrace-capture-values=full,--xtrace-capture-assets=full/);
  assert.match(detail, /gap=signature_terms_not_observed flows=2 priority=high next=capture_signature_terms_or_mutation/);
  assert.match(detail, /low_value_endpoint class=telemetry_endpoint endpoints=2 flows=3 examples=https:\/\/telemetry\.example\.test\/monitor_browser\/collect,https:\/\/www\.example\.test\/cdn-sw-probe/);
  assert.match(detail, /capture_check item=complete_material_linking status=pending priority=high next=capture_signature_terms_or_mutation evidence=signature_terms_not_observed/);
  assert.match(detail, /capture_attempt_quality status=core_sdk_observed_without_business_api readiness=not_ready_for_signature_generation_analysis actionable=0 core_assets=2 low_value_classes=document_request,static_resource,telemetry_endpoint missing=business_api_anchor_not_captured,signature_terms_not_observed next=perform_normal_in_page_actions_until_business_api_request/);
  assert.match(detail, /hook_focus=vmp_string_decoder missing_flows=2 priority=medium next=add_or_link_hooks hooks=String\.fromCharCode,atob/);
  assert.match(detail, /endpoint=https:\/\/www\.example\.test\/api\/feed\/list flows=2 statuses=candidate gaps=signature_terms_not_observed/);
  assert.match(detail, /capture_gate id=business_api_anchor status=passed actionable=1 missing=none patterns=https:\/\/www\.example\.test\/api\/feed\/list/);
  assert.match(detail, /business_api_capture_status status=captured endpoints=1 missing=signature_terms_not_observed next=capture_signature_terms_or_mutation/);
  assert.match(detail, /business_api_capture status=needs_business_api_anchor start_url=https:\/\/www\.example\.test\/ avoid=document_request,static_resource,telemetry_endpoint core_assets=sha1:secsdk@https:\/\/cdn\.example\.test\/secsdk\.js/);
  assert.match(detail, /success=observed endpoint is not document_request, static_resource, or telemetry_endpoint/);
  assert.match(detail, /rerun_recipe start_url=https:\/\/www\.example\.test\/api\/feed\/list profile=interactive_full_capture/);
  assert.match(detail, /launcher_args=run --chromium \/path\/to\/xtrace\/chromium\/src\/out\/XTrace\/Chromium\.app --url https:\/\/www\.example\.test\/api\/feed\/list/);
  assert.match(detail, /Core Asset Review Package/);
  assert.match(detail, /core_asset=sha1:runtime-sdk role=security_sdk_signature_generator status=available/);
  assert.match(detail, /source_window=url_signature_boundary lines=3-3 priority=high signals=url_signature,text_codec/);
  assert.match(html, /Signature Capture Gap/);
  assert.match(html, /Next Capture Plan/);
  assert.match(html, /low_value_endpoint class=telemetry_endpoint endpoints=2 flows=3 examples=https:\/\/telemetry\.example\.test\/monitor_browser\/collect,https:\/\/www\.example\.test\/cdn-sw-probe/);
  assert.match(html, /capture_check item=complete_material_linking status=pending priority=high next=capture_signature_terms_or_mutation evidence=signature_terms_not_observed/);
  assert.match(html, /capture_attempt_quality status=core_sdk_observed_without_business_api readiness=not_ready_for_signature_generation_analysis actionable=0 core_assets=2 low_value_classes=document_request,static_resource,telemetry_endpoint missing=business_api_anchor_not_captured,signature_terms_not_observed next=perform_normal_in_page_actions_until_business_api_request/);
  assert.match(html, /capture_gate id=business_api_anchor status=passed actionable=1 missing=none patterns=https:\/\/www\.example\.test\/api\/feed\/list/);
  assert.match(html, /business_api_capture_status status=captured endpoints=1 missing=signature_terms_not_observed next=capture_signature_terms_or_mutation/);
  assert.match(html, /business_api_capture status=needs_business_api_anchor/);
  assert.match(html, /core_assets=sha1:secsdk@https:\/\/cdn\.example\.test\/secsdk\.js/);
  assert.match(html, /Core Asset Review Package/);
  assert.match(html, /core_asset=sha1:runtime-sdk role=security_sdk_signature_generator/);
  assert.match(html, /X-Signature&#39;,&#39;&lt;redacted&gt;/);
  assert.match(html, /rerun_recipe start_url=https:\/\/www\.example\.test\/api\/feed\/list/);
  assert.match(html, /signature_terms_not_observed/);
  assert.match(html, /sign&lt;script&gt;@https:\/\/cdn\.example\.test\/secsdk\.js/);
  assert.match(html, /candidate_asset=https:\/\/cdn\.example\.test\/secsdk\.js/);
  assert.match(html, /absent_candidate_chain_1/);
  assert.match(html, /request_construction\[Request\.constructor@400\]-&gt;vmp_hash_or_signature_pipeline\[TextEncoder\.encode@401,SubtleCrypto\.digest@402\]-&gt;signed_request\[BrowserNetwork\.request@10\]/);
  assert.match(html, /inferred_initiator=vmDispatch@https:\/\/cdn\.example\.test\/runtime-sdk\.js:medium:events3/);
  assert.doesNotMatch(html, /<script>/);
});

test("renderReportHtml renders grouped candidate windows and escapes trace content", () => {
  const report = {
    trace: {path: "/tmp/trace.ndjson", event_count: 4},
    reverse: {dynamic_execution_count: 0},
    vmp: {runtime_event_count: 1},
    fingerprint: {api_count: 0},
    signature: {
      event_count: 1,
      agent_evidence_pack: {
          flows: [{
            id: "signature_flow_1",
            vmp_candidate_phases: [{
              phase: "candidate_vmp_bytecode_or_register_access",
              type: "vmp_bytecode_or_register_access",
              confidence: "high",
              seq_start: 9,
              seq_end: 9,
              candidate_count: 1
            }],
            candidate_graph: {
              nodes: [{
                id: "c1",
                phase: "candidate_vmp_bytecode_or_register_access",
                confidence: "high",
                seq_start: 9,
                seq_end: 9,
                candidate_count: 1
              }],
              edges: [
                {from: "n1", to: "c1", relation: "candidate_after", seq_gap: 1},
                {from: "c1", to: "n2", relation: "candidate_before", seq_gap: 1}
              ]
            },
            suspected_signature_subflows: [{
              id: "candidate_subflow_1",
              evidence_status: "mixed_observed_and_candidate",
              confidence: "high",
              function: "sign<script>",
              stack_url: "https://cdn.example.test/runtime-sdk.js",
              seq_start: 8,
              seq_end: 10,
              phases: [
                "unsigned_url",
                "candidate_vmp_bytecode_or_register_access",
                "signed_request"
              ],
              observed_apis: [
                {api: "Request.constructor", count: 1},
                {api: "URL.constructor", count: 1}
              ],
              candidate_apis: [{api: "DataView.getUint32", count: 1}],
              candidate_phase_count: 1,
              source_context_refs: ["sha1:runtime-sdk:20-22"],
              source_contexts: [{
                asset_id: "sha1:runtime-sdk",
                line_start: 20,
                line_end: 22,
                preview: "function sign<script>() {\n  return \"X-Signature=<redacted>\";\n}",
                analysis: {
                  signals: ["byte_buffer", "int_bitwise"],
                  calls: ["DataView.prototype.getUint32.call"],
                  properties: ["vm.seed"],
                operators: ["^", ">>>"]
              }
            }],
            candidate_signature_pipeline: {
              confidence: "high",
              stage_count: 4,
              data_links: [
                {from: "input_url", to: "signed_request", refs: ["url_object:11", "search_params:12"]},
                {from: "byte_buffer", to: "integer_mixing", refs: ["data_view:21"]}
              ],
              stages: [
                {stage: "input_url", runtime_apis: ["URL.constructor"], source_calls: [], source_signals: [], source_operators: [], source_constants: []},
                {stage: "byte_buffer", runtime_apis: ["DataView.getUint32"], source_calls: ["DataView.prototype.getUint32.call"], source_signals: ["byte_buffer"], source_operators: [], source_constants: []},
                {stage: "integer_mixing", runtime_apis: ["Math.imul"], source_calls: ["Math.imul"], source_signals: ["int_bitwise"], source_operators: ["^", ">>>"], source_constants: ["2654435761"]},
                {stage: "signed_request", runtime_apis: ["Request.constructor"], source_calls: [], source_signals: [], source_operators: [], source_constants: []}
              ]
            }
          }],
            vmp_linking_candidates: [{
              type: "vmp_bytecode_or_register_access",
              gap_source: "captured_outside_signature_flow",
              recommended_next_step: "improve_flow_linking",
              candidate_count: 1,
              candidates: [{
                seq: 9,
                api: "DataView.getUint32",
                relation: "same_origin_nearby",
                seq_distance: 1,
                context_window: {
                  events: [
                    {seq: 9, api: "DataView.getUint32", window_role: "candidate"}
                  ],
                  source_contexts: [{asset_id: "sha1:runtime-sdk", line_start: 20, line_end: 22}]
                }
              }]
            }]
          }],
        pipeline_patterns: [{
          pattern: "unsigned_url -> vmp_hash_or_signature_pipeline -> signed_request",
          flow_count: 1,
          event_count: 3
        }],
        global_stack_clusters: [{
          function: "sign<script>",
          stack_url: "https://cdn.example.test/runtime-sdk.js",
          flow_count: 1,
          event_count: 3
        }],
        vmp_hook_analysis: {
          hook_gaps: [{
            type: "vmp_string_decoder",
            priority: "medium",
            gap_source: "captured_outside_signature_flow",
            recommended_next_step: "improve_flow_linking",
            missing_flow_count: 1,
            global_event_count: 1,
            linking_candidates: [{
              seq: 7,
              api: "atob<script>",
              nearest_flows: [{
                flow_id: "signature_flow_1",
                relation: "same_stack_nearby",
                seq_distance: 2
              }],
              context_window: {
                events: [
                  {seq: 6, api: "URL.constructor", window_role: "nearby"},
                  {seq: 7, api: "atob<script>", window_role: "candidate"},
                  {seq: 8, api: "XMLHttpRequest.send", window_role: "nearby"}
                ],
                source_contexts: [{asset_id: "sha1:runtime-sdk", line_start: 10, line_end: 12}]
              }
            }]
          }]
        }
      }
    }
  };

  const html = renderReportHtml(report);

  assert.match(html, /class="report-view"/);
  assert.match(html, /VMP Hook Gaps/);
  assert.match(html, /class="report-card gap-card"/);
  assert.match(html, /vmp_string_decoder/);
  assert.match(html, /class="candidate-window"/);
  assert.match(html, /atob&lt;script&gt;@7/);
  assert.match(html, /URL\.constructor@6/);
  assert.match(html, /sha1:runtime-sdk:10-12/);
  assert.match(html, /Pipeline Patterns/);
  assert.match(html, /Global Stack Clusters/);
  assert.match(html, /Flow VMP Linking Candidates/);
  assert.match(html, /signature_flow_1/);
  assert.match(html, /DataView\.getUint32@9/);
  assert.match(html, /Candidate Graph/);
  assert.match(html, /candidate_vmp_bytecode_or_register_access/);
  assert.match(html, /n1-&gt;c1 candidate_after gap=1/);
  assert.match(html, /Suspected Signature Subflows/);
  assert.match(html, /candidate_subflow_1/);
  assert.match(html, /sign&lt;script&gt;@https:\/\/cdn\.example\.test\/runtime-sdk\.js/);
  assert.match(html, /unsigned_url&gt;candidate_vmp_bytecode_or_register_access&gt;signed_request/);
  assert.match(html, /sources=sha1:runtime-sdk:20-22/);
  assert.match(html, /source_analysis=signals:byte_buffer,int_bitwise calls:DataView\.prototype\.getUint32\.call props:vm\.seed ops:\^,&gt;&gt;&gt;/);
  assert.match(html, /candidate_pipeline=input_url\[URL\.constructor\]-&gt;byte_buffer\[DataView\.getUint32\]-&gt;integer_mixing\[Math\.imul\]-&gt;signed_request\[Request\.constructor\] confidence=high/);
  assert.match(html, /data_links=input_url-&gt;signed_request:url_object:11\|search_params:12,byte_buffer-&gt;integer_mixing:data_view:21/);
  assert.match(html, /function sign&lt;script&gt;\(\) \{/);
  assert.doesNotMatch(html, /<script>/);
});

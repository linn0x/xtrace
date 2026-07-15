(function attachReportView(root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.xtraceReportView = api;
  }
})(typeof window !== "undefined" ? window : globalThis, function createReportView() {
  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function valueOrDash(value) {
    return value === undefined || value === null || value === "" ? "-" : String(value);
  }

  function sourceContextLabel(context) {
    return `${context.asset_id || "asset"}:${context.line_start ?? "-"}-${context.line_end ?? "-"}`;
  }

  function sourceContextLabels(group) {
    const labels = new Set(group.source_context_refs || []);
    for (const context of group.source_contexts || []) {
      labels.add(sourceContextLabel(context));
    }
    return [...labels].join(",") || "none";
  }

  function sourceContextPreview(context) {
    return String(context.preview || "")
      .replace(/\s*\r?\n\s*/g, " / ")
      .trim();
  }

  function sourceContextPreviews(group) {
    return (group.source_contexts || [])
      .map(sourceContextPreview)
      .filter(Boolean);
  }

  function sourceAnalysisSummary(analysis) {
    if (!analysis) return "";
    const signals = (analysis.signals || []).slice(0, 6).join(",") || "none";
    const calls = (analysis.calls || []).slice(0, 6).join(",") || "none";
    const props = (analysis.properties || []).slice(0, 6).join(",") || "none";
    const ops = (analysis.operators || []).slice(0, 6).join(",") || "none";
    return `signals:${signals} calls:${calls} props:${props} ops:${ops}`;
  }

  function sourceAnalyses(group) {
    return (group.source_contexts || [])
      .map((context) => sourceAnalysisSummary(context.analysis))
      .filter(Boolean);
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

  function agentGenerationSummary(summary) {
    if (!summary) return "none";
    const chain = (summary.stage_chain || []).slice(0, 12).join("->") || "none";
    const runtime = (summary.runtime_apis || []).slice(0, 8).join("|") || "none";
    const sourceHooks = (summary.source_observed_hooks || []).slice(0, 8).join("|") || "none";
    const runtimeHooks = (summary.runtime_observed_hooks || []).slice(0, 8).join("|") || "none";
    const params = (summary.target_params || []).slice(0, 8).join("|") || "none";
    const attachments = (summary.attachment_params || []).slice(0, 8).join("|") || "none";
    const source = (summary.source_calls || []).slice(0, 6).join("|") || "none";
    return `chain=${chain} evidence=${summary.evidence_profile || "unknown"} runtime=${runtime} source_hooks=${sourceHooks} runtime_hooks=${runtimeHooks} params=${params} attachments=${attachments} links=${summary.data_link_count ?? 0}/${summary.inferred_data_link_count ?? 0} source=${source}`;
  }

  function agentHypothesisSummary(summary) {
    if (!summary) return null;
    const patterns = Object.entries(summary.primary_pattern_counts || {})
      .map(([pattern, count]) => `${pattern}:${count}`)
      .join(",") || "none";
    return `strong=${summary.strong_chain_count ?? 0} partial=${summary.partial_chain_count ?? 0} needs_more=${summary.needs_more_evidence_count ?? 0} gaps=${summary.unresolved_hypothesis_gap_count ?? 0} patterns=${patterns}`;
  }

  function agentBlockingGapSummary(summary) {
    if (!summary) return null;
    const top = (summary.top_blockers || [])
      .slice(0, 6)
      .map((blocker) => `${blocker.gap || "unknown"}:${blocker.count ?? 0}[${blocker.priority || "medium"}]`)
      .join(",") || "none";
    const actions = Object.entries(summary.action_counts || {})
      .map(([action, count]) => `${action}:${count}`)
      .join(",") || "none";
    return `total=${summary.total_observation_count ?? 0} top=${top} actions=${actions}`;
  }

  function agentReadinessSummary(summary) {
    if (!summary) return null;
    return `ready=${summary.ready_count ?? 0} partial=${summary.partial_count ?? 0} insufficient=${summary.insufficient_count ?? 0} avg=${summary.average_score ?? 0}`;
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

  function formatParameterGenerationEntry(entry) {
    return `- parameter ${entry.param || "unknown"} status=${entry.status || "unknown"} flow=${entry.best_flow_id || "none"} endpoint=${entry.endpoint || "unknown"} readiness=${entry.readiness || "unknown"} trace=${parameterGenerationTraceSummary(entry.generation_trace)} sources=${(entry.source_refs || []).slice(0, 6).join(",") || "none"} candidates=${(entry.source_candidate_ids || []).slice(0, 6).join(",") || "none"} reviews=${(entry.review_entry_ids || []).slice(0, 6).join(",") || "none"} gaps=${(entry.evidence_gaps || []).join(",") || "none"} next=${(entry.next_questions || []).slice(0, 6).join(",") || "none"}`;
  }

  function renderParameterGenerationEntryHtml(entry) {
    return `
      <div class="report-card">
        <div class="source-line">${escapeHtml(formatParameterGenerationEntry(entry))}</div>
      </div>
    `;
  }

  function agentPathSourceSummary(step) {
    const source = (step.source_evidence || [])[0];
    if (!source) return "none";
    return `${source.ref || "source"}@${source.content_path || "none"}:${source.line_start ?? "none"}-${source.line_end ?? "none"}`;
  }

  function agentPathSourcePreview(step) {
    const source = (step.source_evidence || []).find((item) => item?.preview);
    return source?.preview || "none";
  }

  function agentPathSourceMeta(step) {
    const parts = [];
    const calls = (step.source_calls || []).slice(0, 6).join(",");
    const signals = (step.source_signals || []).slice(0, 6).join(",");
    const operators = (step.source_operators || []).slice(0, 6).join(",");
    const constants = (step.source_constants || []).slice(0, 6).join(",");
    if (calls) parts.push(`calls=${calls}`);
    if (signals) parts.push(`signals=${signals}`);
    if (operators) parts.push(`ops=${operators}`);
    if (constants) parts.push(`consts=${constants}`);
    return parts.join(" ");
  }

  function agentPathRefsSummary(step) {
    return [...(step.object_refs || []), ...(step.value_refs || [])].slice(0, 8).join(",") || "none";
  }

  function formatAgentParameterPathStep(step) {
    const apis = (step.apis || []).slice(0, 6).join(",") || "none";
    const preview = agentPathSourcePreview(step);
    const previewText = preview === "none" ? "" : ` preview=${preview}`;
    const sourceMeta = agentPathSourceMeta(step);
    const sourceMetaText = sourceMeta ? ` source_meta=${sourceMeta}` : "";
    return `step=${step.order ?? "?"}:${step.stage || "unknown"} role=${step.role || "context"} apis=${apis} relation=${step.relation_to_signed_request || "unknown"} d=${step.distance_to_signed_request ?? "unknown"} flags=${(step.evidence_flags || []).join(",") || "none"} gaps=${(step.evidence_gaps || []).join(",") || "none"} next=${(step.recommended_next_actions || []).join(",") || "none"} source=${agentPathSourceSummary(step)}${previewText}${sourceMetaText} refs=${agentPathRefsSummary(step)}`;
  }

  function agentGenerationEdgesSummary(edges) {
    return (edges || [])
      .slice(0, 8)
      .map((edge) => `${edge.from_order ?? "?"}:${edge.from_stage || "unknown"}->${edge.to_order ?? "?"}:${edge.to_stage || "unknown"}:${edge.relation || "related"}[${edge.confidence || "unknown"}] refs=${(edge.refs || []).slice(0, 4).join("|") || "none"} sources=${(edge.source_refs || []).slice(0, 4).join("|") || "none"} evidence=${(edge.evidence || []).slice(0, 4).join("|") || "none"}`)
      .join(";") || "none";
  }

  function agentChainQualitySummary(quality) {
    if (!quality) return "unknown";
    return `${quality.status || "unknown"} edges=${quality.edge_count ?? 0}/${quality.expected_edge_count ?? 0} high=${quality.high_confidence_edge_count ?? 0} medium=${quality.medium_confidence_edge_count ?? 0} source_only=${quality.source_only_edge_count ?? 0} temporal=${quality.temporal_only_edge_count ?? 0} nearby=${quality.nearby_runtime_only_edge_count ?? 0} missing=${quality.missing_edge_count ?? 0}`;
  }

  function agentGenerationEdgeGapsSummary(gaps) {
    return (gaps || [])
      .slice(0, 8)
      .map((gap) => `${gap.from_order ?? "?"}:${gap.from_stage || "unknown"}->${gap.to_order ?? "?"}:${gap.to_stage || "unknown"}:${gap.gap || "unknown"}[${gap.priority || "medium"}] reason=${gap.reason || "unknown"} next=${(gap.next_actions || []).slice(0, 4).join("|") || "none"} sources=${(gap.source_refs || []).slice(0, 4).join("|") || "none"} refs=${[...(gap.object_refs || []), ...(gap.value_refs || [])].slice(0, 4).join("|") || "none"}`)
      .join(";") || "none";
  }

  function agentVmpOperationPatternsSummary(patterns) {
    return (patterns || [])
      .slice(0, 6)
      .map((pattern) => `${pattern.pattern || "unknown"}[${pattern.confidence || "unknown"}]:${pattern.operation_signature || "unknown"} seq=${pattern.seq_start ?? "?"}..${pattern.seq_end ?? "?"} trace=${pattern.trace_start ?? "?"}..${pattern.trace_end ?? "?"} relation=${pattern.relation_to_signature_mutation || "unknown"} d_sig=${pattern.distance_to_signature_mutation ?? "?"} refs=${(pattern.shared_refs || []).slice(0, 4).join("|") || "none"}`)
      .join(";") || "none";
  }

  function agentGenerationHypothesisSummary(hypothesis) {
    if (!hypothesis) return "none";
    return `${hypothesis.status || "unknown"} pattern=${hypothesis.primary_pattern || "none"} quality=${hypothesis.chain_quality || "unknown"} direct_attachment=${hypothesis.direct_attachment_observed ? "true" : "false"} pre_signature_pattern=${hypothesis.pre_signature_pattern_observed ? "true" : "false"} gaps=${(hypothesis.remaining_gaps || []).slice(0, 6).join("|") || "none"} next=${(hypothesis.next_actions || []).slice(0, 6).join("|") || "none"}`;
  }

  function agentCandidateGenerationRefs(summary) {
    const refs = summary?.key_refs || {};
    return [
      ...(refs.url_objects || []).slice(0, 2),
      ...(refs.search_params || []).slice(0, 2),
      ...(refs.buffers || []).slice(0, 3)
    ].join("|") || "none";
  }

  function agentCandidateGenerationAttachment(summary) {
    const attachment = summary?.attachment || {};
    if (!attachment.observed) return "missing";
    const apis = (attachment.apis || []).slice(0, 3).join("|") || "unknown";
    const params = (attachment.target_params || []).slice(0, 4).join("|") || "none";
    return `observed:${attachment.stage || "unknown"}:${apis}:${params}`;
  }

  function agentCandidateGenerationSummary(summary) {
    if (!summary) return "none";
    const chain = (summary.stage_chain || []).slice(0, 12).join("->") || "none";
    const runtime = (summary.runtime_apis || []).slice(0, 8).join("|") || "none";
    const sourceHooks = (summary.source_observed_hooks || []).slice(0, 8).join("|") || "none";
    const runtimeHooks = (summary.runtime_observed_hooks || []).slice(0, 8).join("|") || "none";
    const params = (summary.target_params || []).slice(0, 8).join("|") || "none";
    const gaps = (summary.unresolved_gaps || []).slice(0, 8).join("|") || "none";
    const next = (summary.next_actions || []).slice(0, 8).join("|") || "none";
    return `chain=${chain} evidence=${summary.evidence_profile || "unknown"} readiness=${summary.readiness || "unknown"} dataflow=${summary.dataflow_status || "unknown"} params=${params} runtime=${runtime} source_hooks=${sourceHooks} runtime_hooks=${runtimeHooks} refs=${agentCandidateGenerationRefs(summary)} attachment=${agentCandidateGenerationAttachment(summary)} gaps=${gaps} next=${next}`;
  }

  function agentCandidateSourceWindowSummary(window) {
    const stages = (window.stages || []).slice(0, 6).join("|") || "none";
    const preview = window.preview ? ` preview=${window.preview}` : "";
    return `candidate_source=${window.ref || "unknown"} path=${window.content_path || "none"} lines=${window.line_start ?? "none"}-${window.line_end ?? "none"} stages=${stages}${preview}`;
  }

  function agentLogicTraceRefs(step) {
    return [
      ...(step.object_refs || []),
      ...(step.value_refs || []),
      ...(step.source_refs || [])
    ].slice(0, 8).join("|") || "none";
  }

  function agentLogicTraceRequestInputSummary(step) {
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

  function agentLogicTraceStepSummary(step) {
    const apis = (step.runtime_apis || []).slice(0, 6).join("|") || "none";
    const calls = (step.source_calls || []).slice(0, 6).join("|") || "none";
    const params = (step.target_params || []).slice(0, 6).join("|") || "none";
    const evidence = (step.evidence || []).slice(0, 6).join("|") || "none";
    return `${step.order ?? "?"}:${step.phase || "unknown"}[${step.status || "unknown"}/${step.confidence || "unknown"}] claim=${step.claim || "unknown"} apis=${apis} calls=${calls} params=${params} refs=${agentLogicTraceRefs(step)} evidence=${evidence}${agentLogicTraceRequestInputSummary(step)}`;
  }

  function agentLogicTraceEdgesSummary(edges) {
    return (edges || [])
      .slice(0, 8)
      .map((edge) => {
        const fromPhase = edge.from_phase || "unknown";
        const toPhase = edge.to_phase || "unknown";
        const fromStage = edge.from_stage || "unknown";
        const toStage = edge.to_stage || "unknown";
        const refs = (edge.refs || []).slice(0, 6).join("|") || "none";
        const evidence = (edge.evidence || []).slice(0, 6).join("|") || "none";
        return `${fromPhase}->${toPhase}:${edge.relation || "related"}[${edge.confidence || "unknown"}] stages=${fromStage}->${toStage} refs=${refs} evidence=${evidence}`;
      })
      .join(";") || "none";
  }

  function agentLogicTraceFinalAttachmentSummary(attachment) {
    if (!attachment) return "none";
    const params = (attachment.target_params || []).slice(0, 6).join("|") || "none";
    const apis = (attachment.apis || []).slice(0, 6).join("|") || "none";
    return `observed:${attachment.observed ? "true" : "false"} params=${params} apis=${apis} mode=${attachment.evidence_mode || "unknown"}`;
  }

  function formatAgentLogicTrace(trace) {
    if (!trace) return [];
    const lines = [`logic_trace=${trace.summary || "unknown"}`];
    for (const step of (trace.steps || []).slice(0, 8)) {
      lines.push(`logic_step=${agentLogicTraceStepSummary(step)}`);
    }
    if ((trace.edges || []).length) {
      lines.push(`logic_edges=${agentLogicTraceEdgesSummary(trace.edges)}`);
    }
    if (trace.final_attachment) {
      lines.push(`logic_attachment=${agentLogicTraceFinalAttachmentSummary(trace.final_attachment)}`);
    }
    return lines;
  }

  function agentAnalysisReadinessSummary(readiness) {
    if (!readiness) return "none";
    const summary = readiness.summary || {};
    const checklist = (readiness.checklist || [])
      .slice(0, 8)
      .map((item) => `${item.item || "unknown"}:${item.status || "unknown"}`)
      .join(",") || "none";
    const plan = readiness.next_probe_plan || {};
    const nextProbe = `next_probe=${plan.action || "none"} reason=${plan.reason || "none"} hooks=${(plan.hook_targets || []).slice(0, 8).join(",") || "none"} gaps=${(plan.gaps || []).slice(0, 8).join(",") || "none"}`;
    return `${summary.status || "unknown"} score=${summary.score ?? 0} passed=${summary.passed_count ?? 0} partial=${summary.partial_count ?? 0} failed=${summary.failed_count ?? 0} primary=${summary.primary_next_action || "unknown"} checklist=${checklist} ${nextProbe}`;
  }

  function agentGenerationGraphSummary(graph) {
    if (!graph) return "none";
    const gaps = (graph.unresolved_edges || [])
      .slice(0, 6)
      .map((edge) => `${edge.gap || "unknown"}:${edge.priority || "medium"}`)
      .join(",") || "none";
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
    return `nodes=${graph.node_count ?? 0} edges=${graph.edge_count ?? 0} unresolved=${graph.unresolved_edge_count ?? 0} opgraphs=${(graph.operation_subgraphs || []).length} ops=${ops} flow=${flow.status || "unknown"} links=${flow.vmp_output_link_count ?? 0} request=${flow.attachment_to_request_link_observed ? "true" : "false"}${bridges}${boundary} entry=${graph.entry_node_id || "none"} exit=${graph.exit_node_id || "none"} readiness=${graph.readiness_status || "unknown"} next=${graph.primary_next_probe || "none"} gaps=${gaps}`;
  }

  function formatAgentParameterPath(parameter) {
    const lines = [
      `- parameter_path ${parameter.param || "unknown"} conclusion=${parameter.conclusion || "unknown"} evidence=${parameter.evidence_level || "low"} endpoint=${parameter.endpoint || "unknown"} chain=${parameter.chain_summary || "unknown"} chain_quality=${agentChainQualitySummary(parameter.chain_quality)} gaps=${(parameter.unresolved_gaps || []).join(",") || "none"}`
    ];
    if (parameter.candidate_generation_summary) {
      lines.push(`  - candidate_generation=${agentCandidateGenerationSummary(parameter.candidate_generation_summary)}`);
      for (const sourceWindow of (parameter.candidate_generation_summary.source_windows || []).slice(0, 4)) {
        lines.push(`  - ${agentCandidateSourceWindowSummary(sourceWindow)}`);
      }
      for (const logicLine of formatAgentLogicTrace(parameter.candidate_generation_summary.logic_hypothesis?.agent_logic_trace)) {
        lines.push(`  - ${logicLine}`);
      }
    }
    if (parameter.generation_hypothesis) {
      lines.push(`  - hypothesis=${agentGenerationHypothesisSummary(parameter.generation_hypothesis)}`);
    }
    if (parameter.analysis_readiness) {
      lines.push(`  - readiness=${agentAnalysisReadinessSummary(parameter.analysis_readiness)}`);
    }
    if (parameter.generation_graph) {
      lines.push(`  - generation_graph=${agentGenerationGraphSummary(parameter.generation_graph)}`);
    }
    for (const step of (parameter.generation_path || []).slice(0, 8)) {
      lines.push(`  - ${formatAgentParameterPathStep(step)}`);
    }
    if ((parameter.generation_edges || []).length) {
      lines.push(`  - generation_edges=${agentGenerationEdgesSummary(parameter.generation_edges)}`);
    }
    if ((parameter.generation_edge_gaps || []).length) {
      lines.push(`  - generation_edge_gaps=${agentGenerationEdgeGapsSummary(parameter.generation_edge_gaps)}`);
    }
    if ((parameter.vmp_operation_patterns || []).length) {
      lines.push(`  - vmp_patterns=${agentVmpOperationPatternsSummary(parameter.vmp_operation_patterns)}`);
    }
    return lines.join("\n");
  }

  function renderAgentParameterPathHtml(parameter) {
    const stepRows = (parameter.generation_path || []).slice(0, 8).map((step) => `
      <div class="source-line nested">${escapeHtml(formatAgentParameterPathStep(step))}</div>
    `).join("");
    const edgeRows = (parameter.generation_edges || []).length
      ? `<div class="source-line nested">${escapeHtml(`generation_edges=${agentGenerationEdgesSummary(parameter.generation_edges)}`)}</div>`
      : "";
    const edgeGapRows = (parameter.generation_edge_gaps || []).length
      ? `<div class="source-line nested">${escapeHtml(`generation_edge_gaps=${agentGenerationEdgeGapsSummary(parameter.generation_edge_gaps)}`)}</div>`
      : "";
    const hypothesisRow = parameter.generation_hypothesis
      ? `<div class="source-line nested">${escapeHtml(`hypothesis=${agentGenerationHypothesisSummary(parameter.generation_hypothesis)}`)}</div>`
      : "";
    const readinessRow = parameter.analysis_readiness
      ? `<div class="source-line nested">${escapeHtml(`readiness=${agentAnalysisReadinessSummary(parameter.analysis_readiness)}`)}</div>`
      : "";
    const graphRow = parameter.generation_graph
      ? `<div class="source-line nested">${escapeHtml(`generation_graph=${agentGenerationGraphSummary(parameter.generation_graph)}`)}</div>`
      : "";
    const candidateSummaryRow = parameter.candidate_generation_summary
      ? `<div class="source-line nested">${escapeHtml(`candidate_generation=${agentCandidateGenerationSummary(parameter.candidate_generation_summary)}`)}</div>`
      : "";
    const candidateSourceRows = (parameter.candidate_generation_summary?.source_windows || []).slice(0, 4).map((sourceWindow) => `
      <div class="source-line nested">${escapeHtml(agentCandidateSourceWindowSummary(sourceWindow))}</div>
    `).join("");
    const logicTraceRows = formatAgentLogicTrace(parameter.candidate_generation_summary?.logic_hypothesis?.agent_logic_trace).map((line) => `
      <div class="source-line nested">${escapeHtml(line)}</div>
    `).join("");
    const vmpPatternRows = (parameter.vmp_operation_patterns || []).length
      ? `<div class="source-line nested">${escapeHtml(`vmp_patterns=${agentVmpOperationPatternsSummary(parameter.vmp_operation_patterns)}`)}</div>`
      : "";
    return `
      <div class="report-card">
        <div class="source-line">${escapeHtml(`parameter_path ${parameter.param || "unknown"} conclusion=${parameter.conclusion || "unknown"} evidence=${parameter.evidence_level || "low"} endpoint=${parameter.endpoint || "unknown"} chain=${parameter.chain_summary || "unknown"} chain_quality=${agentChainQualitySummary(parameter.chain_quality)} gaps=${(parameter.unresolved_gaps || []).join(",") || "none"}`)}</div>
        ${candidateSummaryRow}
        ${candidateSourceRows}
        ${logicTraceRows}
        ${hypothesisRow}
        ${readinessRow}
        ${graphRow}
        ${stepRows || "<div class=\"empty-inline\">steps=none</div>"}
        ${edgeRows}
        ${edgeGapRows}
        ${vmpPatternRows}
      </div>
    `;
  }

  function formatTopLine(report) {
    const lines = [
      `Trace: ${valueOrDash(report?.trace?.path)}`,
      `Events: ${report?.trace?.event_count ?? 0}`,
      `Dynamic: ${report?.reverse?.dynamic_execution_count ?? 0}`,
      `VMP: ${report?.vmp?.runtime_event_count ?? 0}`,
      `Fingerprint APIs: ${report?.fingerprint?.api_count ?? 0}`,
      `Signature events: ${report?.signature?.event_count ?? 0}`
    ];
    const hypothesisSummary = agentHypothesisSummary(report?.agent_analysis?.summary?.hypothesis_summary);
    if (hypothesisSummary) {
      lines.push(`Hypotheses: ${hypothesisSummary}`);
    }
    const readinessSummary = agentReadinessSummary(report?.agent_analysis?.summary?.readiness_summary);
    if (readinessSummary) {
      lines.push(`Readiness: ${readinessSummary}`);
    }
    const blockingSummary = agentBlockingGapSummary(report?.agent_analysis?.summary?.blocking_gap_summary);
    if (blockingSummary) {
      lines.push(`Blocking gaps: ${blockingSummary}`);
    }
    return lines;
  }

  function formatCandidate(candidate) {
    const nearest = candidate.nearest_flows?.[0];
    const relation = nearest
      ? `${nearest.flow_id} ${nearest.relation} distance=${nearest.seq_distance}`
      : "no-nearest-flow";
    const events = (candidate.context_window?.events || [])
      .map((event) => `${event.api || "unknown"}@${event.seq ?? "-"}:${event.window_role || "nearby"}`)
      .join(", ") || "none";
    const sources = (candidate.context_window?.source_contexts || [])
      .map((context) => `${context.asset_id || "asset"}:${context.line_start ?? "-"}-${context.line_end ?? "-"}`)
      .join(", ") || "none";
    return [
      `  - ${candidate.api || "unknown"}@${candidate.seq ?? "-"} -> ${relation}`,
      `    window=${events}`,
      `    sources=${sources}`
    ].join("\n");
  }

  function formatHookGap(gap) {
    const candidates = (gap.linking_candidates || []).slice(0, 4);
    const lines = [
      `- ${gap.type || "unknown"} missing_flows=${gap.missing_flow_count ?? 0} source=${gap.gap_source || "unknown"} next=${gap.recommended_next_step || "unknown"} global_events=${gap.global_event_count ?? 0} priority=${gap.priority || "-"}`
    ];
    if (candidates.length) {
      for (const candidate of candidates) {
        lines.push(formatCandidate(candidate));
      }
    } else {
      lines.push("  - candidates=none");
    }
    return lines.join("\n");
  }

  function formatSignatureAbsent(absent) {
    const lines = [
      "Signature Capture Gap",
      `- reason=${absent.reason || "unknown"} vmp_events=${absent.vmp_runtime_event_count ?? 0} targets=${(absent.target_terms || []).join(",") || "none"}`
    ];
    const recommendations = (absent.capture_recommendations || [])
      .map((item) => `${item.id || "unknown"}:${item.priority || "-"}`)
      .join(",") || "none";
    lines.push(`- recommend=${recommendations}`);
    for (const entry of (absent.candidate_entrypoints || []).slice(0, 8)) {
      const apis = (entry.apis || [])
        .slice(0, 4)
        .map((item) => `${item.api}:${item.count}`)
        .join(",") || "none";
      lines.push(
        `  - candidate_entry=${entry.function || "(anonymous)"}@${entry.stack_url || "unknown"} events=${entry.event_count ?? 0} seq=${entry.seq_start ?? "-"}..${entry.seq_end ?? "-"} families=${(entry.families || []).join(",") || "none"} apis=${apis} asset=${entry.asset_id || "none"}`
      );
    }
    for (const asset of (absent.candidate_assets || []).slice(0, 6)) {
      const label = asset.url || asset.content_path || asset.asset_id || "unknown";
      lines.push(
        `  - candidate_asset=${label} score=${asset.score ?? 0} signals=${(asset.signals || []).join(",") || "none"}`
      );
    }
    for (const chain of (absent.candidate_trace_chains || []).slice(0, 6)) {
      const hooks = (chain.hook_points || [])
        .slice(0, 6)
        .map((point) => `${point.type}@${point.seq_start ?? "-"}..${point.seq_end ?? "-"}`)
        .join(",") || "none";
      const gaps = (chain.request_context?.capture_gaps || []).join(",") || "none";
      const inferred = inferredInitiatorSummary(chain.inferred_initiator);
      lines.push(
        `  - candidate_chain=${chain.id || "unknown"} confidence=${chain.confidence || "low"} endpoint=${chain.endpoint || "unknown"} steps=${candidateTraceChainStepsSummary(chain)} hooks=${hooks} inferred_initiator=${inferred} gaps=${gaps}`
      );
    }
    return lines.join("\n");
  }

  function flowCandidateGroups(flows) {
    const groups = [];
    for (const flow of flows || []) {
      for (const group of flow.vmp_linking_candidates || []) {
        if (!(group.candidates || []).length) continue;
        groups.push({...group, flow_id: flow.id || "unknown"});
      }
    }
    return groups;
  }

  function formatFlowCandidateGroup(group) {
    const lines = [
      `- ${group.flow_id} ${group.type || "unknown"} candidates=${group.candidate_count ?? (group.candidates || []).length} source=${group.gap_source || "unknown"} next=${group.recommended_next_step || "unknown"}`
    ];
    for (const candidate of (group.candidates || []).slice(0, 4)) {
      lines.push(
        `  - ${candidate.api || "unknown"}@${candidate.seq ?? "-"} ${candidate.relation || "unknown"} distance=${candidate.seq_distance ?? "-"}`
      );
    }
    return lines.join("\n");
  }

  function flowCandidateGraphGroups(flows) {
    const groups = [];
    for (const flow of flows || []) {
      const phases = flow.vmp_candidate_phases || [];
      const edges = flow.candidate_graph?.edges || [];
      if (!phases.length && !edges.length) continue;
      groups.push({flow_id: flow.id || "unknown", phases, edges});
    }
    return groups;
  }

  function flowSuspectedSubflowGroups(flows) {
    const groups = [];
    for (const flow of flows || []) {
      for (const subflow of flow.suspected_signature_subflows || []) {
        groups.push({...subflow, flow_id: flow.id || "unknown"});
      }
    }
    return groups;
  }

  function formatCandidateGraphGroup(group) {
    const lines = [`- ${group.flow_id}`];
    for (const phase of (group.phases || []).slice(0, 4)) {
      lines.push(
        `  - ${group.flow_id} ${phase.phase || "unknown"} ${phase.confidence || "-"} seq=${phase.seq_start ?? "-"}..${phase.seq_end ?? "-"} candidates=${phase.candidate_count ?? 0}`
      );
    }
    for (const edge of (group.edges || []).slice(0, 6)) {
      lines.push(
        `  - ${edge.from || "?"}->${edge.to || "?"} ${edge.relation || "unknown"} gap=${edge.seq_gap ?? "-"}`
      );
    }
    return lines.join("\n");
  }

  function formatSuspectedSubflow(group) {
    const lines = [
      `- ${group.id || "subflow"} ${group.function || "(anonymous)"}@${group.stack_url || "unknown"} ${group.confidence || "-"} seq=${group.seq_start ?? "-"}..${group.seq_end ?? "-"} status=${group.evidence_status || "unknown"}`,
      `  phases=${(group.phases || []).join(">") || "none"}`,
      `  observed=${(group.observed_apis || []).map((item) => `${item.api}:${item.count}`).join(",") || "none"}`,
      `  candidate=${(group.candidate_apis || []).map((item) => `${item.api}:${item.count}`).join(",") || "none"}`,
      `  sources=${sourceContextLabels(group)}`
    ];
    for (const preview of sourceContextPreviews(group).slice(0, 2)) {
      lines.push(`  source_preview=${preview}`);
    }
    for (const analysis of sourceAnalyses(group).slice(0, 2)) {
      lines.push(`  source_analysis=${analysis}`);
    }
    if (group.candidate_signature_pipeline) {
      lines.push(`  candidate_pipeline=${candidatePipelineSummary(group.candidate_signature_pipeline)}`);
      lines.push(`  data_links=${pipelineDataLinksSummary(group.candidate_signature_pipeline)}`);
    }
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

  function inferredInitiatorSummary(initiator) {
    if (!initiator) return "none";
    return `${initiator.function || "(anonymous)"}@${initiator.stack_url || "unknown"}:${initiator.confidence || "low"}:events${initiator.event_count ?? 0}`;
  }

  function renderMetric(label, value) {
    return `
      <div class="report-metric">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(value)}</strong>
      </div>
    `;
  }

  function renderCandidateHtml(candidate) {
    const nearest = candidate.nearest_flows?.[0];
    const relation = nearest
      ? `${nearest.flow_id} ${nearest.relation} distance=${nearest.seq_distance}`
      : "no-nearest-flow";
    const events = (candidate.context_window?.events || [])
      .map((event) => `
        <span class="event-chip ${event.window_role === "candidate" ? "candidate" : ""}">
          ${escapeHtml(event.api || "unknown")}@${escapeHtml(event.seq ?? "-")}:${escapeHtml(event.window_role || "nearby")}
        </span>
      `)
      .join("");
    const sources = (candidate.context_window?.source_contexts || [])
      .map((context) => `${context.asset_id || "asset"}:${context.line_start ?? "-"}-${context.line_end ?? "-"}`)
      .join(", ") || "none";

    return `
      <div class="candidate-window">
        <div class="candidate-title">
          <strong>${escapeHtml(candidate.api || "unknown")}@${escapeHtml(candidate.seq ?? "-")}</strong>
          <span>${escapeHtml(relation)}</span>
        </div>
        <div class="event-chip-row">${events || "<span class=\"empty-inline\">events=none</span>"}</div>
        <div class="source-line">sources=${escapeHtml(sources)}</div>
      </div>
    `;
  }

  function renderHookGapHtml(gap) {
    const candidates = (gap.linking_candidates || []).slice(0, 4);
    return `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(gap.type || "unknown")}</strong>
          <span>${escapeHtml(gap.priority || "-")}</span>
        </div>
        <div class="card-meta">
          missing_flows=${escapeHtml(gap.missing_flow_count ?? 0)}
          source=${escapeHtml(gap.gap_source || "unknown")}
          next=${escapeHtml(gap.recommended_next_step || "unknown")}
          global_events=${escapeHtml(gap.global_event_count ?? 0)}
        </div>
        <div class="candidate-list">
          ${candidates.length ? candidates.map(renderCandidateHtml).join("") : "<div class=\"empty-inline\">candidates=none</div>"}
        </div>
      </div>
    `;
  }

  function hasVmpHookCoverage(report) {
    const coverage = report?.vmp?.hook_coverage || {};
    return Boolean(
      (coverage.observed_point_types || []).length ||
      (coverage.missing_point_types || []).length ||
      (coverage.hook_gaps || []).length
    );
  }

  function formatVmpHookCoverage(coverage) {
    const lines = [
      "VMP Hook Coverage",
      `- observed=${(coverage.observed_point_types || []).join(",") || "none"}`,
      `- missing=${(coverage.missing_point_types || []).join(",") || "none"}`
    ];
    for (const gap of (coverage.hook_gaps || []).slice(0, 6)) {
      lines.push(
        `- gap=${gap.type || "unknown"} priority=${gap.priority || "-"} hooks=${(gap.suggested_hooks || []).slice(0, 5).join(",") || "none"} reason=${gap.reason || "unknown"}`
      );
    }
    return lines.join("\n");
  }

  function renderVmpHookCoverageHtml(coverage) {
    const gaps = (coverage.hook_gaps || []).slice(0, 6).map((gap) => `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(gap.type || "unknown")}</strong>
          <span>${escapeHtml(gap.priority || "-")}</span>
        </div>
        <div class="card-meta">
          hooks=${escapeHtml((gap.suggested_hooks || []).slice(0, 5).join(",") || "none")}
        </div>
        <div class="source-line">reason=${escapeHtml(gap.reason || "unknown")}</div>
      </div>
    `).join("");

    return `
      <section class="report-section">
        <h3>VMP Hook Coverage</h3>
        <div class="report-card gap-card">
          <div class="source-line">observed=${escapeHtml((coverage.observed_point_types || []).join(",") || "none")}</div>
          <div class="source-line">missing=${escapeHtml((coverage.missing_point_types || []).join(",") || "none")}</div>
        </div>
        ${gaps || "<div class=\"empty-inline\">gaps=none</div>"}
      </section>
    `;
  }

  function formatVmpHookAnalysisPoints(points, title = "VMP Hook Analysis Points") {
    const lines = [title];
    for (const point of (points || []).slice(0, 8)) {
      const apis = (point.observed_apis || [])
        .slice(0, 4)
        .map((item) => `${item.api}:${item.count}`)
        .join(",") || "none";
      lines.push(
        `- hook_point=${point.type || "unknown"} status=${point.status || "unknown"} priority=${point.priority || "-"} next=${point.next_action || "unknown"} goal=${point.analysis_goal || "unknown"} observed_events=${point.observed_event_count ?? 0} observed_flows=${point.observed_flows ?? "-"} missing_flows=${point.missing_flows ?? "-"} apis=${apis} hooks=${(point.suggested_hooks || []).slice(0, 5).join(",") || "none"}`
      );
    }
    return lines.join("\n");
  }

  function renderVmpHookAnalysisPointsHtml(points, title = "VMP Hook Analysis Points") {
    const cards = (points || []).slice(0, 8).map((point) => {
      const apis = (point.observed_apis || [])
        .slice(0, 4)
        .map((item) => `${item.api}:${item.count}`)
        .join(",") || "none";
      return `
        <div class="report-card gap-card">
          <div class="card-head">
            <strong>${escapeHtml(point.type || "unknown")}</strong>
            <span>${escapeHtml(point.status || "unknown")}</span>
          </div>
          <div class="card-meta">
            priority=${escapeHtml(point.priority || "-")}
            next=${escapeHtml(point.next_action || "unknown")}
            observed_events=${escapeHtml(point.observed_event_count ?? 0)}
            observed_flows=${escapeHtml(point.observed_flows ?? "-")}
            missing_flows=${escapeHtml(point.missing_flows ?? "-")}
          </div>
          <div class="source-line">goal=${escapeHtml(point.analysis_goal || "unknown")}</div>
          <div class="source-line">apis=${escapeHtml(apis)}</div>
          <div class="source-line">hooks=${escapeHtml((point.suggested_hooks || []).slice(0, 5).join(",") || "none")}</div>
        </div>
      `;
    }).join("");

    return `
      <section class="report-section">
        <h3>${escapeHtml(title)}</h3>
        ${cards || "<div class=\"empty-inline\">hook_points=none</div>"}
      </section>
    `;
  }

  function vmpScalarChainStepsSummary(chain) {
    return (chain.steps || [])
      .slice(0, 8)
      .map((step) => {
        const inputs = (step.input_refs || []).slice(0, 4).join("|") || "none";
        return `${step.seq ?? "?"}:${step.api || "unknown"} in=${inputs} out=${step.result_ref || "none"}`;
      })
      .join(" -> ") || "none";
  }

  function formatVmpScalarRefChain(chain) {
    const refs = (chain.refs || []).slice(0, 8).join(",") || "none";
    const apis = (chain.apis || []).slice(0, 8).join(",") || "none";
    const reasons = (chain.quality_reasons || []).slice(0, 8).join(",") || "none";
    const sources = (chain.source_context_refs || []).slice(0, 6).join(",") || "none";
    return [
      `- scalar_chain=${chain.id || "vmp_scalar_chain"} relation=${chain.relation || "scalar_ref_flow"} score=${chain.quality_score ?? 0} reasons=${reasons} steps=${chain.step_count ?? (chain.steps || []).length} seq=${chain.seq_start ?? "?"}..${chain.seq_end ?? "?"} apis=${apis} sources=${sources} refs=${refs}`,
      `  step=${vmpScalarChainStepsSummary(chain)}`
    ].join("\n");
  }

  function renderVmpScalarRefChainHtml(chain) {
    return `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(chain.id || "vmp_scalar_chain")}</strong>
          <span>${escapeHtml(chain.relation || "scalar_ref_flow")}</span>
        </div>
        <div class="source-line">${escapeHtml(formatVmpScalarRefChain(chain))}</div>
      </div>
    `;
  }

  function materialFlowReadinessSummary(flow) {
    const readiness = flow.analysis_readiness || {};
    return `readiness=${readiness.status || "unknown"} gaps=${(readiness.evidence_gaps || []).join(",") || "none"} next=${(readiness.next_actions || []).join(",") || "none"}`;
  }

  function materialFlowHookPointsSummary(flow) {
    return (flow.vmp_hook_points || [])
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
        return `${point.type || "unknown"}:${point.status || "unknown"}[${evidence.join(" ") || "none"}]`;
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

  function materialFlowScalarChainsSummary(flow) {
    return (flow.vmp_scalar_chain_links || [])
      .slice(0, 6)
      .map((link) => {
        const refs = (link.shared_refs || []).slice(0, 4).join("|") || "none";
        const apis = (link.apis || []).slice(0, 6).join("|") || "none";
        const ops = scalarOperationTraceSummary(link.operation_trace || []);
        return `${link.chain_id || "unknown"}:${link.stage || "unknown"}:${link.relation || "related"}[${link.confidence || "unknown"}] refs=${refs} apis=${apis} score=${link.quality_score ?? 0} ops=${ops}`;
      })
      .join(",") || "none";
  }

  function formatMaterialFlow(flow) {
    return [
      `- ${flow.id || "material_flow"} flow=${flow.flow_id || "unknown"} confidence=${flow.confidence || "low"} status=${flow.evidence_status || "unknown"} seq=${flow.seq_start ?? "-"}..${flow.seq_end ?? "-"} endpoint=${flow.endpoint || "unknown"}`,
      `  function=${flow.function || "(anonymous)"}@${flow.stack_url || "unknown"} asset=${flow.asset_id || "none"} params=${(flow.target_params || []).join(",") || "none"}`,
      `  ${materialFlowReadinessSummary(flow)}`,
      `  hook_points=${materialFlowHookPointsSummary(flow)}`,
      `  stages=${materialStagesSummary(flow.stages)}`,
      `  generation_steps=${generationStepsSummary(flow.generation_steps)}`,
      `  agent_stage_trace=${agentStageTraceSummary(flow.agent_stage_trace)}`,
      `  agent_generation=${agentGenerationSummary(flow.agent_generation_summary)}`,
      `  data_links=${pipelineDataLinksSummary({data_links: flow.data_links || []})}`,
      `  inferred_data_links=${pipelineInferredDataLinksSummary({inferred_data_links: flow.inferred_data_links || []})}`,
      `  attachments=${signatureAttachmentEventsSummary(flow.signature_attachment_events || [])}`,
      `  attachment_graph=${parameterAttachmentGraphSummary(flow.parameter_attachment_graph)}`,
      `  scalar_chains=${materialFlowScalarChainsSummary(flow)}`,
      `  sources=${(flow.source_context_refs || []).join(",") || "none"}`
    ].join("\n");
  }

  function renderMaterialFlowHtml(flow) {
    return `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(flow.id || "material_flow")}</strong>
          <span>${escapeHtml(flow.confidence || "low")}</span>
        </div>
        <div class="card-meta">
          flow=${escapeHtml(flow.flow_id || "unknown")}
          status=${escapeHtml(flow.evidence_status || "unknown")}
          seq=${escapeHtml(flow.seq_start ?? "-")}..${escapeHtml(flow.seq_end ?? "-")}
          endpoint=${escapeHtml(flow.endpoint || "unknown")}
        </div>
        <div class="source-line">${escapeHtml(flow.function || "(anonymous)")}@${escapeHtml(flow.stack_url || "unknown")} asset=${escapeHtml(flow.asset_id || "none")}</div>
        <div class="source-line">params=${escapeHtml((flow.target_params || []).join(",") || "none")}</div>
        <div class="source-line">${escapeHtml(materialFlowReadinessSummary(flow))}</div>
        <div class="source-line">hook_points=${escapeHtml(materialFlowHookPointsSummary(flow))}</div>
        <div class="source-line">stages=${escapeHtml(materialStagesSummary(flow.stages))}</div>
        <div class="source-line">generation_steps=${escapeHtml(generationStepsSummary(flow.generation_steps))}</div>
        <div class="source-line">agent_stage_trace=${escapeHtml(agentStageTraceSummary(flow.agent_stage_trace))}</div>
        <div class="source-line">agent_generation=${escapeHtml(agentGenerationSummary(flow.agent_generation_summary))}</div>
        <div class="source-line">data_links=${escapeHtml(pipelineDataLinksSummary({data_links: flow.data_links || []}))}</div>
        <div class="source-line">inferred_data_links=${escapeHtml(pipelineInferredDataLinksSummary({inferred_data_links: flow.inferred_data_links || []}))}</div>
        <div class="source-line">attachments=${escapeHtml(signatureAttachmentEventsSummary(flow.signature_attachment_events || []))}</div>
        <div class="source-line">attachment_graph=${escapeHtml(parameterAttachmentGraphSummary(flow.parameter_attachment_graph))}</div>
        <div class="source-line">scalar_chains=${escapeHtml(materialFlowScalarChainsSummary(flow))}</div>
        <div class="source-line">sources=${escapeHtml((flow.source_context_refs || []).join(",") || "none")}</div>
      </div>
    `;
  }

  function formatBusinessApiRuntimeHint(hint) {
    return `- business_api_runtime_hint endpoint=${hint.endpoint || "unknown"} api=${hint.api || "unknown"} seq=${hint.seq ?? "none"} relevance=${hint.business_relevance || "unknown"} status=${hint.value_status || "unknown"} query_keys=${(hint.query_keys || []).join(",") || "none"} roles=${(hint.source_roles || []).join(",") || "none"} gaps=${(hint.evidence_gaps || []).join(",") || "none"} next=${(hint.next_actions || []).join(",") || "none"} sources=${(hint.source_stack_urls || []).slice(0, 4).join(",") || "none"}`;
  }

  function formatBusinessApiRuntimeHints(hints) {
    return [
      "Business API Runtime Hints",
      ...(hints || []).slice(0, 8).map(formatBusinessApiRuntimeHint)
    ].join("\n");
  }

  function renderBusinessApiRuntimeHintHtml(hint) {
    return `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(hint.endpoint || "unknown")}</strong>
          <span>${escapeHtml(hint.value_status || "unknown")}</span>
        </div>
        <div class="source-line">${escapeHtml(formatBusinessApiRuntimeHint(hint))}</div>
      </div>
    `;
  }

  function renderBusinessApiRuntimeHintsHtml(hints) {
    return `
      <section class="report-section">
        <h3>Business API Runtime Hints</h3>
        ${(hints || []).length ? hints.slice(0, 8).map(renderBusinessApiRuntimeHintHtml).join("") : "<div class=\"empty-inline\">none</div>"}
      </section>
    `;
  }

  function formatSourceCandidate(candidate) {
    return `- ${candidate.id || "source_candidate"} function=${candidate.function || "(anonymous)"} asset=${candidate.asset_id || "none"} refs=${(candidate.source_refs || []).slice(0, 4).join(",") || "none"} flows=${candidate.flow_count || 0} steps=${candidate.step_count || 0} score=${candidate.evidence_score || 0} params=${(candidate.target_params || []).join(",") || "none"} stages=${(candidate.stages || []).slice(0, 8).join(",") || "none"} apis=${(candidate.runtime_apis || []).slice(0, 8).join(",") || "none"} signals=${(candidate.signals || []).slice(0, 8).join(",") || "none"} reasons=${(candidate.priority_reasons || []).join(",") || "none"}`;
  }

  function reviewEntryLineRanges(entry) {
    return (entry.line_ranges || [])
      .slice(0, 4)
      .map((range) => `${range.line_start ?? "?"}-${range.line_end ?? "?"}`)
      .join(",") || "none";
  }

  function reviewEntryGenerationPaths(entry) {
    return (entry.generation_paths || [])
      .slice(0, 4)
      .map((path) => `${path.id || "generation_path"}:${path.causality || "unknown"}:${path.stage_summary || "none"}`)
      .join(";") || "none";
  }

  function formatReviewCausalitySummary(summary = {}) {
    return `causality_summary pre_request_chain=${summary.pre_request_chain ?? 0} mixed_pre_post_request=${summary.mixed_pre_post_request ?? 0} signed_or_unknown=${summary.signed_or_unknown ?? 0} post_request_activity=${summary.post_request_activity ?? 0} prioritized=${summary.prioritized_entry_count ?? 0} deprioritized=${summary.deprioritized_entry_count ?? 0}`;
  }

  function formatReviewEntry(entry) {
    return `- ${entry.id || "review_entry"} candidate=${entry.source_candidate_id || "none"} causality=${entry.causality || "unknown"} priority=${entry.review_priority || "low"} function=${entry.function || "(anonymous)"} path=${entry.content_path || "none"} lines=${reviewEntryLineRanges(entry)} endpoints=${(entry.endpoints || []).join(",") || "none"} params=${(entry.target_params || []).join(",") || "none"} stages=${(entry.stages || []).slice(0, 8).join(",") || "none"} apis=${(entry.runtime_apis || []).slice(0, 8).join(",") || "none"} signals=${(entry.signals || []).slice(0, 8).join(",") || "none"} paths=${reviewEntryGenerationPaths(entry)} warnings=${(entry.warnings || []).join(",") || "none"} next=${(entry.next_questions || []).join(",") || "none"}`;
  }

  function renderReviewEntryHtml(entry) {
    return `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(entry.id || "review_entry")}</strong>
          <span>priority=${escapeHtml(entry.review_priority || "low")}</span>
        </div>
        <div class="card-meta">
          candidate=${escapeHtml(entry.source_candidate_id || "none")}
          causality=${escapeHtml(entry.causality || "unknown")}
          function=${escapeHtml(entry.function || "(anonymous)")}
        </div>
        <div class="card-meta">
          path=${escapeHtml(entry.content_path || "none")}
          lines=${escapeHtml(reviewEntryLineRanges(entry))}
        </div>
        <div class="source-line">endpoints=${escapeHtml((entry.endpoints || []).join(",") || "none")}</div>
        <div class="source-line">params=${escapeHtml((entry.target_params || []).join(",") || "none")}</div>
        <div class="source-line">stages=${escapeHtml((entry.stages || []).slice(0, 8).join(",") || "none")}</div>
        <div class="source-line">apis=${escapeHtml((entry.runtime_apis || []).slice(0, 8).join(",") || "none")}</div>
        <div class="source-line">signals=${escapeHtml((entry.signals || []).slice(0, 8).join(",") || "none")}</div>
        <div class="source-line">paths=${escapeHtml(reviewEntryGenerationPaths(entry))}</div>
        <div class="source-line">warnings=${escapeHtml((entry.warnings || []).join(",") || "none")}</div>
        <div class="source-line">next=${escapeHtml((entry.next_questions || []).join(",") || "none")}</div>
      </div>
    `;
  }

  function renderSourceCandidateHtml(candidate) {
    return `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(candidate.id || "source_candidate")}</strong>
          <span>score=${escapeHtml(candidate.evidence_score || 0)}</span>
        </div>
        <div class="card-meta">
          function=${escapeHtml(candidate.function || "(anonymous)")}
          asset=${escapeHtml(candidate.asset_id || "none")}
          flows=${escapeHtml(candidate.flow_count || 0)}
          steps=${escapeHtml(candidate.step_count || 0)}
        </div>
        <div class="source-line">refs=${escapeHtml((candidate.source_refs || []).slice(0, 4).join(",") || "none")}</div>
        <div class="source-line">params=${escapeHtml((candidate.target_params || []).join(",") || "none")}</div>
        <div class="source-line">stages=${escapeHtml((candidate.stages || []).slice(0, 8).join(",") || "none")}</div>
        <div class="source-line">apis=${escapeHtml((candidate.runtime_apis || []).slice(0, 8).join(",") || "none")}</div>
        <div class="source-line">signals=${escapeHtml((candidate.signals || []).slice(0, 8).join(",") || "none")}</div>
        <div class="source-line">reasons=${escapeHtml((candidate.priority_reasons || []).join(",") || "none")}</div>
      </div>
    `;
  }

  function renderSignatureAbsentHtml(absent) {
    const recommendations = (absent.capture_recommendations || [])
      .map((item) => `${item.id || "unknown"}:${item.priority || "-"}`)
      .join(",") || "none";
    const entryRows = (absent.candidate_entrypoints || []).slice(0, 8).map((entry) => {
      const apis = (entry.apis || [])
        .slice(0, 4)
        .map((item) => `${item.api}:${item.count}`)
        .join(",") || "none";
      return `
        <div class="candidate-window">
          <div class="candidate-title">
            <strong>${escapeHtml(entry.function || "(anonymous)")}@${escapeHtml(entry.stack_url || "unknown")}</strong>
            <span>events=${escapeHtml(entry.event_count ?? 0)} seq=${escapeHtml(entry.seq_start ?? "-")}..${escapeHtml(entry.seq_end ?? "-")}</span>
          </div>
          <div class="source-line">families=${escapeHtml((entry.families || []).join(",") || "none")} apis=${escapeHtml(apis)} asset=${escapeHtml(entry.asset_id || "none")}</div>
        </div>
      `;
    }).join("");
    const assetRows = (absent.candidate_assets || []).slice(0, 6).map((asset) => {
      const label = asset.url || asset.content_path || asset.asset_id || "unknown";
      return `<div class="source-line">candidate_asset=${escapeHtml(label)} score=${escapeHtml(asset.score ?? 0)} signals=${escapeHtml((asset.signals || []).join(",") || "none")}</div>`;
    }).join("");
    const chainRows = (absent.candidate_trace_chains || []).slice(0, 6).map((chain) => {
      const hooks = (chain.hook_points || [])
        .slice(0, 6)
        .map((point) => `${point.type}@${point.seq_start ?? "-"}..${point.seq_end ?? "-"}`)
        .join(",") || "none";
      const gaps = (chain.request_context?.capture_gaps || []).join(",") || "none";
      const inferred = inferredInitiatorSummary(chain.inferred_initiator);
      return `
        <div class="candidate-window">
          <div class="candidate-title">
            <strong>${escapeHtml(chain.id || "unknown")}</strong>
            <span>${escapeHtml(chain.confidence || "low")}</span>
          </div>
          <div class="source-line">endpoint=${escapeHtml(chain.endpoint || "unknown")}</div>
          <div class="source-line">steps=${escapeHtml(candidateTraceChainStepsSummary(chain))}</div>
          <div class="source-line">hooks=${escapeHtml(hooks)} inferred_initiator=${escapeHtml(inferred)} gaps=${escapeHtml(gaps)}</div>
        </div>
      `;
    }).join("");

    return `
      <section class="report-section">
        <h3>Signature Capture Gap</h3>
        <div class="report-card gap-card">
          <div class="card-meta">
            reason=${escapeHtml(absent.reason || "unknown")}
            vmp_events=${escapeHtml(absent.vmp_runtime_event_count ?? 0)}
            targets=${escapeHtml((absent.target_terms || []).join(",") || "none")}
          </div>
          <div class="source-line">recommend=${escapeHtml(recommendations)}</div>
          <div class="candidate-list">${entryRows || "<div class=\"empty-inline\">candidate_entry=none</div>"}</div>
          ${assetRows || "<div class=\"empty-inline\">candidate_asset=none</div>"}
          <div class="candidate-list">${chainRows || "<div class=\"empty-inline\">candidate_chain=none</div>"}</div>
        </div>
      </section>
    `;
  }

  function renderFlowCandidateGroupHtml(group) {
    const candidates = (group.candidates || []).slice(0, 4);
    return `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(group.flow_id || "unknown")} ${escapeHtml(group.type || "unknown")}</strong>
          <span>${escapeHtml(group.candidate_count ?? candidates.length)}</span>
        </div>
        <div class="card-meta">
          source=${escapeHtml(group.gap_source || "unknown")}
          next=${escapeHtml(group.recommended_next_step || "unknown")}
        </div>
        <div class="candidate-list">
          ${candidates.length ? candidates.map((candidate) => `
            <div class="candidate-window">
              <div class="candidate-title">
                <strong>${escapeHtml(candidate.api || "unknown")}@${escapeHtml(candidate.seq ?? "-")}</strong>
                <span>${escapeHtml(candidate.relation || "unknown")} distance=${escapeHtml(candidate.seq_distance ?? "-")}</span>
              </div>
            </div>
          `).join("") : "<div class=\"empty-inline\">candidates=none</div>"}
        </div>
      </div>
    `;
  }

  function renderCandidateGraphGroupHtml(group) {
    const phaseRows = (group.phases || []).slice(0, 4).map((phase) => `
      <div class="report-row">
        <strong>${escapeHtml(phase.phase || "unknown")}</strong>
        <span>${escapeHtml(phase.confidence || "-")} seq=${escapeHtml(phase.seq_start ?? "-")}..${escapeHtml(phase.seq_end ?? "-")} candidates=${escapeHtml(phase.candidate_count ?? 0)}</span>
      </div>
    `).join("");
    const edgeRows = (group.edges || []).slice(0, 6).map((edge) => `
      <div class="report-row">
        <strong>${escapeHtml(`${edge.from || "?"}->${edge.to || "?"} ${edge.relation || "unknown"} gap=${edge.seq_gap ?? "-"}`)}</strong>
      </div>
    `).join("");

    return `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(group.flow_id || "unknown")}</strong>
          <span>${escapeHtml((group.phases || []).length)}</span>
        </div>
        ${phaseRows || "<div class=\"empty-inline\">phases=none</div>"}
        ${edgeRows || "<div class=\"empty-inline\">edges=none</div>"}
      </div>
    `;
  }

  function renderSuspectedSubflowHtml(group) {
    const phases = (group.phases || []).join(">") || "none";
    const observed = (group.observed_apis || []).map((item) => `${item.api}:${item.count}`).join(",") || "none";
    const candidate = (group.candidate_apis || []).map((item) => `${item.api}:${item.count}`).join(",") || "none";
    const previews = sourceContextPreviews(group).slice(0, 2);
    const analyses = sourceAnalyses(group).slice(0, 2);
    const pipeline = group.candidate_signature_pipeline
      ? candidatePipelineSummary(group.candidate_signature_pipeline)
      : "";
    return `
      <div class="report-card gap-card">
        <div class="card-head">
          <strong>${escapeHtml(group.id || "subflow")}</strong>
          <span>${escapeHtml(group.confidence || "-")}</span>
        </div>
        <div class="card-meta">
          ${escapeHtml(group.function || "(anonymous)")}@${escapeHtml(group.stack_url || "unknown")}
          seq=${escapeHtml(group.seq_start ?? "-")}..${escapeHtml(group.seq_end ?? "-")}
          status=${escapeHtml(group.evidence_status || "unknown")}
        </div>
        <div class="source-line">phases=${escapeHtml(phases)}</div>
        <div class="source-line">observed=${escapeHtml(observed)}</div>
        <div class="source-line">candidate=${escapeHtml(candidate)}</div>
        <div class="source-line">sources=${escapeHtml(sourceContextLabels(group))}</div>
        ${analyses.map((analysis) => `<div class="source-line">source_analysis=${escapeHtml(analysis)}</div>`).join("")}
        ${pipeline ? `<div class="source-line">candidate_pipeline=${escapeHtml(pipeline)}</div>` : ""}
        ${group.candidate_signature_pipeline ? `<div class="source-line">data_links=${escapeHtml(pipelineDataLinksSummary(group.candidate_signature_pipeline))}</div>` : ""}
        ${previews.map((preview) => `<pre class="source-preview">${escapeHtml(preview)}</pre>`).join("")}
      </div>
    `;
  }

  function renderPatternHtml(pattern) {
    return `
      <div class="report-row">
        <strong>${escapeHtml(pattern.pattern || "unknown")}</strong>
        <span>flows=${escapeHtml(pattern.flow_count ?? 0)} events=${escapeHtml(pattern.event_count ?? 0)}</span>
      </div>
    `;
  }

  function renderClusterHtml(cluster) {
    return `
      <div class="report-row">
        <strong>${escapeHtml(cluster.function || "(anonymous)")}</strong>
        <span>${escapeHtml(cluster.stack_url || "unknown")} flows=${escapeHtml(cluster.flow_count ?? 0)} events=${escapeHtml(cluster.event_count ?? 0)}</span>
      </div>
    `;
  }

  function formatNextCapturePlan(plan) {
    const lines = [
      "Next Capture Plan",
      `- priority=${plan.priority || "low"} targets=${(plan.target_terms || []).join(",") || "none"} flags=${(plan.recommended_flags || []).join(",") || "none"}`
    ];
    for (const gap of (plan.gap_summary || []).slice(0, 8)) {
      lines.push(
        `- gap=${gap.gap || "unknown"} flows=${gap.flow_count ?? 0} priority=${gap.priority || "-"} next=${(gap.next_actions || []).join(",") || "none"}`
      );
    }
    for (const lowValue of (plan.low_value_endpoint_summary || []).slice(0, 6)) {
      lines.push(
        `- low_value_endpoint class=${lowValue.resource_class || "unknown"} endpoints=${lowValue.endpoint_count ?? 0} flows=${lowValue.flow_count ?? 0} examples=${(lowValue.examples || []).join(",") || "none"}`
      );
    }
    for (const hook of (plan.hook_focus || []).slice(0, 8)) {
      lines.push(
        `- hook_focus=${hook.type || "unknown"} missing_flows=${hook.missing_flow_count ?? 0} priority=${hook.priority || "-"} next=${hook.next_action || "unknown"} hooks=${(hook.suggested_hooks || []).slice(0, 5).join(",") || "none"}`
      );
    }
    for (const endpoint of (plan.focus_endpoints || []).slice(0, 6)) {
      lines.push(
        `- endpoint=${endpoint.endpoint || "unknown"} flows=${endpoint.flow_count ?? 0} statuses=${(endpoint.readiness_statuses || []).join(",") || "none"} gaps=${(endpoint.evidence_gaps || []).join(",") || "none"}`
      );
    }
    for (const asset of (plan.focus_assets || []).slice(0, 6)) {
      lines.push(
        `- asset=${asset.asset_id || "none"} stack=${asset.stack_url || "unknown"} flows=${asset.flow_count ?? 0} statuses=${(asset.readiness_statuses || []).join(",") || "none"} retrieval=${asset.retrieval_status || "none"} path=${asset.content_path || "none"} score=${asset.score ?? "none"} signals=${(asset.signals || []).slice(0, 8).join(",") || "none"} focus=${asset.asset_focus || "none"} role=${asset.asset_role || "none"}`
      );
    }
    for (const item of (plan.capture_checklist || []).slice(0, 8)) {
      lines.push(
        `- capture_check item=${item.id || "unknown"} status=${item.status || "unknown"} priority=${item.priority || "-"} next=${item.next_action || "none"} evidence=${(item.evidence || []).join(",") || "none"} targets=${(item.target_endpoint_patterns || []).join(",") || "none"} rejected=${(item.rejected_endpoint_summary || []).join(",") || "none"}`
      );
    }
    if (plan.capture_attempt_quality) {
      const quality = plan.capture_attempt_quality;
      lines.push(
        `- capture_attempt_quality status=${quality.status || "unknown"} readiness=${quality.readiness || "unknown"} actionable=${quality.actionable_endpoint_count ?? 0} core_assets=${quality.core_asset_count ?? 0} low_value_classes=${(quality.low_value_endpoint_classes || []).join(",") || "none"} missing=${(quality.missing_evidence || []).join(",") || "none"} next=${quality.next_action || "none"}`
      );
    }
    if (plan.capture_gate) {
      const gate = plan.capture_gate;
      lines.push(
        `- capture_gate id=${gate.id || "unknown"} status=${gate.status || "unknown"} actionable=${gate.observed_actionable_endpoint_count ?? 0} missing=${(gate.missing || []).join(",") || "none"} patterns=${(gate.target_endpoint_patterns || []).join(",") || "none"}`
      );
    }
    if (plan.business_api_capture_status) {
      const status = plan.business_api_capture_status;
      lines.push(
        `- business_api_capture_status status=${status.status || "unknown"} endpoints=${status.actionable_endpoint_count ?? 0} missing=${(status.missing_evidence || []).join(",") || "none"} next=${(status.next_actions || []).join(",") || "none"}`
      );
    }
    if (plan.business_api_capture_plan) {
      const businessPlan = plan.business_api_capture_plan;
      lines.push(
        `- business_api_capture status=${businessPlan.status || "unknown"} start_url=${businessPlan.start_url || "about:blank"} avoid=${(businessPlan.avoid_resource_classes || []).join(",") || "none"} core_assets=${(businessPlan.core_assets || []).join(",") || "none"}`
      );
      for (const action of (businessPlan.normal_user_actions || []).slice(0, 4)) {
        lines.push(`  - action=${action}`);
      }
      for (const criterion of (businessPlan.success_criteria || []).slice(0, 4)) {
        lines.push(`  - success=${criterion}`);
      }
    }
    if (plan.rerun_recipe) {
      lines.push(
        `- rerun_recipe start_url=${plan.rerun_recipe.start_url || "about:blank"} profile=${plan.rerun_recipe.profile || "unknown"}`
      );
      lines.push(
        `- launcher_args=${(plan.rerun_recipe.python_launcher_args || []).join(" ") || "none"}`
      );
    }
    return lines.join("\n");
  }

  function renderNextCapturePlanHtml(plan) {
    const gapRows = (plan.gap_summary || []).slice(0, 8).map((gap) => `
      <div class="source-line">gap=${escapeHtml(gap.gap || "unknown")} flows=${escapeHtml(gap.flow_count ?? 0)} priority=${escapeHtml(gap.priority || "-")} next=${escapeHtml((gap.next_actions || []).join(",") || "none")}</div>
    `).join("");
    const lowValueRows = (plan.low_value_endpoint_summary || []).slice(0, 6).map((lowValue) => `
      <div class="source-line">low_value_endpoint class=${escapeHtml(lowValue.resource_class || "unknown")} endpoints=${escapeHtml(lowValue.endpoint_count ?? 0)} flows=${escapeHtml(lowValue.flow_count ?? 0)} examples=${escapeHtml((lowValue.examples || []).join(",") || "none")}</div>
    `).join("");
    const hookRows = (plan.hook_focus || []).slice(0, 8).map((hook) => `
      <div class="source-line">hook_focus=${escapeHtml(hook.type || "unknown")} missing_flows=${escapeHtml(hook.missing_flow_count ?? 0)} priority=${escapeHtml(hook.priority || "-")} next=${escapeHtml(hook.next_action || "unknown")} hooks=${escapeHtml((hook.suggested_hooks || []).slice(0, 5).join(",") || "none")}</div>
    `).join("");
    const endpointRows = (plan.focus_endpoints || []).slice(0, 6).map((endpoint) => `
      <div class="source-line">endpoint=${escapeHtml(endpoint.endpoint || "unknown")} flows=${escapeHtml(endpoint.flow_count ?? 0)} statuses=${escapeHtml((endpoint.readiness_statuses || []).join(",") || "none")} gaps=${escapeHtml((endpoint.evidence_gaps || []).join(",") || "none")}</div>
    `).join("");
    const assetRows = (plan.focus_assets || []).slice(0, 6).map((asset) => `
      <div class="source-line">asset=${escapeHtml(asset.asset_id || "none")} stack=${escapeHtml(asset.stack_url || "unknown")} flows=${escapeHtml(asset.flow_count ?? 0)} statuses=${escapeHtml((asset.readiness_statuses || []).join(",") || "none")} retrieval=${escapeHtml(asset.retrieval_status || "none")} path=${escapeHtml(asset.content_path || "none")} score=${escapeHtml(asset.score ?? "none")} signals=${escapeHtml((asset.signals || []).slice(0, 8).join(",") || "none")} focus=${escapeHtml(asset.asset_focus || "none")} role=${escapeHtml(asset.asset_role || "none")}</div>
    `).join("");
    const checklistRows = (plan.capture_checklist || []).slice(0, 8).map((item) => `
      <div class="source-line">capture_check item=${escapeHtml(item.id || "unknown")} status=${escapeHtml(item.status || "unknown")} priority=${escapeHtml(item.priority || "-")} next=${escapeHtml(item.next_action || "none")} evidence=${escapeHtml((item.evidence || []).join(",") || "none")} targets=${escapeHtml((item.target_endpoint_patterns || []).join(",") || "none")} rejected=${escapeHtml((item.rejected_endpoint_summary || []).join(",") || "none")}</div>
    `).join("");
    const captureQuality = plan.capture_attempt_quality || null;
    const captureQualityRows = captureQuality ? `
      <div class="source-line">capture_attempt_quality status=${escapeHtml(captureQuality.status || "unknown")} readiness=${escapeHtml(captureQuality.readiness || "unknown")} actionable=${escapeHtml(captureQuality.actionable_endpoint_count ?? 0)} core_assets=${escapeHtml(captureQuality.core_asset_count ?? 0)} low_value_classes=${escapeHtml((captureQuality.low_value_endpoint_classes || []).join(",") || "none")} missing=${escapeHtml((captureQuality.missing_evidence || []).join(",") || "none")} next=${escapeHtml(captureQuality.next_action || "none")}</div>
    ` : "";
    const captureGate = plan.capture_gate || null;
    const captureGateRows = captureGate ? `
      <div class="source-line">capture_gate id=${escapeHtml(captureGate.id || "unknown")} status=${escapeHtml(captureGate.status || "unknown")} actionable=${escapeHtml(captureGate.observed_actionable_endpoint_count ?? 0)} missing=${escapeHtml((captureGate.missing || []).join(",") || "none")} patterns=${escapeHtml((captureGate.target_endpoint_patterns || []).join(",") || "none")}</div>
    ` : "";
    const businessStatus = plan.business_api_capture_status || null;
    const businessStatusRows = businessStatus ? `
      <div class="source-line">business_api_capture_status status=${escapeHtml(businessStatus.status || "unknown")} endpoints=${escapeHtml(businessStatus.actionable_endpoint_count ?? 0)} missing=${escapeHtml((businessStatus.missing_evidence || []).join(",") || "none")} next=${escapeHtml((businessStatus.next_actions || []).join(",") || "none")}</div>
    ` : "";
    const businessPlan = plan.business_api_capture_plan || null;
    const businessRows = businessPlan ? `
      <div class="source-line">business_api_capture status=${escapeHtml(businessPlan.status || "unknown")} start_url=${escapeHtml(businessPlan.start_url || "about:blank")} avoid=${escapeHtml((businessPlan.avoid_resource_classes || []).join(",") || "none")} core_assets=${escapeHtml((businessPlan.core_assets || []).join(",") || "none")}</div>
      ${(businessPlan.normal_user_actions || []).slice(0, 4).map((action) => `<div class="source-line nested">action=${escapeHtml(action)}</div>`).join("")}
      ${(businessPlan.success_criteria || []).slice(0, 4).map((criterion) => `<div class="source-line nested">success=${escapeHtml(criterion)}</div>`).join("")}
    ` : "";
    const recipe = plan.rerun_recipe || null;
    const recipeRows = recipe ? `
      <div class="source-line">rerun_recipe start_url=${escapeHtml(recipe.start_url || "about:blank")} profile=${escapeHtml(recipe.profile || "unknown")}</div>
      <div class="source-line">launcher_args=${escapeHtml((recipe.python_launcher_args || []).join(" ") || "none")}</div>
    ` : "";

    return `
      <section class="report-section">
        <h3>Next Capture Plan</h3>
        <div class="report-card gap-card">
          <div class="source-line">priority=${escapeHtml(plan.priority || "low")} targets=${escapeHtml((plan.target_terms || []).join(",") || "none")}</div>
          <div class="source-line">flags=${escapeHtml((plan.recommended_flags || []).join(",") || "none")}</div>
          ${gapRows || "<div class=\"empty-inline\">gaps=none</div>"}
          ${lowValueRows || "<div class=\"empty-inline\">low_value_endpoints=none</div>"}
          ${hookRows || "<div class=\"empty-inline\">hook_focus=none</div>"}
          ${endpointRows || "<div class=\"empty-inline\">endpoints=none</div>"}
          ${assetRows || "<div class=\"empty-inline\">assets=none</div>"}
          ${checklistRows || "<div class=\"empty-inline\">capture_checklist=none</div>"}
          ${captureQualityRows}
          ${captureGateRows}
          ${businessStatusRows}
          ${businessRows}
          ${recipeRows}
        </div>
      </section>
    `;
  }

  function formatAgentNextCaptureFocus(focusItems) {
    const lines = ["Agent Next Capture Focus"];
    for (const focus of (focusItems || []).slice(0, 8)) {
      const hookStatuses = (focus.hook_target_statuses || [])
        .slice(0, 8)
        .map((item) => `${item.target}:${item.status}`)
        .join(",") || "none";
      lines.push(
        `- focus=${focus.action || "unknown"} priority=${focus.priority || "medium"} reason=${focus.reason || "unknown"} params=${(focus.params || []).join(",") || "none"} stages=${(focus.stages || []).join(",") || "none"} gaps=${(focus.gaps || []).join(",") || "none"} endpoint=${(focus.endpoints || [])[0] || "none"} hooks=${(focus.hook_targets || []).slice(0, 8).join(",") || "none"} hook_status=${hookStatuses} sources=${(focus.source_refs || []).slice(0, 4).join(",") || "none"} refs=${[...(focus.object_refs || []), ...(focus.value_refs || [])].slice(0, 6).join(",") || "none"}`
      );
    }
    return lines.join("\n");
  }

  function formatAgentNativeCaptureRequirements(requirements) {
    const lines = ["Agent Native Capture Requirements"];
    for (const requirement of (requirements || []).slice(0, 8)) {
      lines.push(
        `- native=${requirement.action || "unknown"} layer=${requirement.native_layer || "unknown"} priority=${requirement.priority || "medium"} reason=${requirement.reason || "unknown"} params=${(requirement.params || []).join(",") || "none"} stages=${(requirement.stages || []).join(",") || "none"} gaps=${(requirement.gaps || []).join(",") || "none"} refs=${(requirement.missing_ref_types || []).slice(0, 8).join(",") || "none"} hooks=${(requirement.missing_hook_targets || []).slice(0, 8).join(",") || "none"} targets=${(requirement.implementation_targets || []).slice(0, 8).join(",") || "none"} source_hints=${(requirement.source_hints || []).slice(0, 6).map((hint) => hint.path || "").filter(Boolean).join(",") || "none"} validator=${(requirement.validator_hints?.flags || []).join(",") || "none"} endpoint=${(requirement.endpoints || [])[0] || "none"}`
      );
    }
    return lines.join("\n");
  }

  function formatAgentBlockingGaps(summary) {
    const lines = ["Agent Blocking Gaps"];
    for (const blocker of (summary?.top_blockers || []).slice(0, 8)) {
      lines.push(
        `- blocker=${blocker.gap || "unknown"} count=${blocker.count ?? 0} priority=${blocker.priority || "medium"} params=${(blocker.params || []).join(",") || "none"} stages=${(blocker.stages || []).join(",") || "none"} actions=${(blocker.actions || []).join(",") || "none"} hooks=${(blocker.hook_targets || []).slice(0, 8).join(",") || "none"} endpoint=${(blocker.endpoints || [])[0] || "none"} refs=${[...(blocker.object_refs || []), ...(blocker.value_refs || [])].slice(0, 8).join(",") || "none"} sources=${(blocker.source_refs || []).slice(0, 6).join(",") || "none"}`
      );
    }
    return lines.join("\n");
  }

  function renderAgentNextCaptureFocusHtml(focusItems) {
    const rows = (focusItems || []).slice(0, 8).map((focus) => `
      <div class="source-line">focus=${escapeHtml(focus.action || "unknown")} priority=${escapeHtml(focus.priority || "medium")} reason=${escapeHtml(focus.reason || "unknown")} params=${escapeHtml((focus.params || []).join(",") || "none")} stages=${escapeHtml((focus.stages || []).join(",") || "none")} gaps=${escapeHtml((focus.gaps || []).join(",") || "none")} endpoint=${escapeHtml((focus.endpoints || [])[0] || "none")} hooks=${escapeHtml((focus.hook_targets || []).slice(0, 8).join(",") || "none")} hook_status=${escapeHtml((focus.hook_target_statuses || []).slice(0, 8).map((item) => `${item.target}:${item.status}`).join(",") || "none")} sources=${escapeHtml((focus.source_refs || []).slice(0, 4).join(",") || "none")} refs=${escapeHtml([...(focus.object_refs || []), ...(focus.value_refs || [])].slice(0, 6).join(",") || "none")}</div>
    `).join("");
    return `
      <section class="report-section">
        <h3>Agent Next Capture Focus</h3>
        <div class="report-card gap-card">
          ${rows || "<div class=\"empty-inline\">none</div>"}
        </div>
      </section>
    `;
  }

  function renderAgentNativeCaptureRequirementsHtml(requirements) {
    const rows = (requirements || []).slice(0, 8).map((requirement) => `
      <div class="source-line">native=${escapeHtml(requirement.action || "unknown")} layer=${escapeHtml(requirement.native_layer || "unknown")} priority=${escapeHtml(requirement.priority || "medium")} reason=${escapeHtml(requirement.reason || "unknown")} params=${escapeHtml((requirement.params || []).join(",") || "none")} stages=${escapeHtml((requirement.stages || []).join(",") || "none")} gaps=${escapeHtml((requirement.gaps || []).join(",") || "none")} refs=${escapeHtml((requirement.missing_ref_types || []).slice(0, 8).join(",") || "none")} hooks=${escapeHtml((requirement.missing_hook_targets || []).slice(0, 8).join(",") || "none")} targets=${escapeHtml((requirement.implementation_targets || []).slice(0, 8).join(",") || "none")} source_hints=${escapeHtml((requirement.source_hints || []).slice(0, 6).map((hint) => hint.path || "").filter(Boolean).join(",") || "none")} validator=${escapeHtml((requirement.validator_hints?.flags || []).join(",") || "none")} endpoint=${escapeHtml((requirement.endpoints || [])[0] || "none")}</div>
    `).join("");
    return `
      <section class="report-section">
        <h3>Agent Native Capture Requirements</h3>
        <div class="report-card gap-card">
          ${rows || "<div class=\"empty-inline\">none</div>"}
        </div>
      </section>
    `;
  }

  function renderAgentBlockingGapsHtml(summary) {
    const rows = (summary?.top_blockers || []).slice(0, 8).map((blocker) => `
      <div class="source-line">blocker=${escapeHtml(blocker.gap || "unknown")} count=${escapeHtml(blocker.count ?? 0)} priority=${escapeHtml(blocker.priority || "medium")} params=${escapeHtml((blocker.params || []).join(",") || "none")} stages=${escapeHtml((blocker.stages || []).join(",") || "none")} actions=${escapeHtml((blocker.actions || []).join(",") || "none")} hooks=${escapeHtml((blocker.hook_targets || []).slice(0, 8).join(",") || "none")} endpoint=${escapeHtml((blocker.endpoints || [])[0] || "none")} refs=${escapeHtml([...(blocker.object_refs || []), ...(blocker.value_refs || [])].slice(0, 8).join(",") || "none")} sources=${escapeHtml((blocker.source_refs || []).slice(0, 6).join(",") || "none")}</div>
    `).join("");
    return `
      <section class="report-section">
        <h3>Agent Blocking Gaps</h3>
        <div class="report-card gap-card">
          ${rows || "<div class=\"empty-inline\">none</div>"}
        </div>
      </section>
    `;
  }

  function formatCoreAssetReviewPackage(pack) {
    const lines = ["Core Asset Review Package"];
    for (const entry of (pack.entries || []).slice(0, 4)) {
      lines.push(
        `- core_asset=${entry.asset_id || "none"} role=${entry.asset_role || "none"} status=${entry.source_status || "unknown"} path=${entry.content_path || "none"} score=${entry.score ?? 0} focus=${(entry.review_focus || []).join(",") || "none"} signals=${(entry.signals || []).slice(0, 8).join(",") || "none"}`
      );
      for (const window of (entry.source_windows || []).slice(0, 8)) {
        lines.push(
          `  - source_window=${window.focus || "unknown"} lines=${window.line_start ?? "none"}-${window.line_end ?? "none"} priority=${window.priority || "-"} signals=${(window.analysis?.signals || []).slice(0, 6).join(",") || "none"} preview=${window.preview || ""}`
        );
      }
    }
    return lines.join("\n");
  }

  function renderCoreAssetReviewPackageHtml(pack) {
    const rows = (pack.entries || []).slice(0, 4).map((entry) => {
      const windows = (entry.source_windows || []).slice(0, 8).map((window) => `
        <div class="source-line nested">source_window=${escapeHtml(window.focus || "unknown")} lines=${escapeHtml(window.line_start ?? "none")}-${escapeHtml(window.line_end ?? "none")} priority=${escapeHtml(window.priority || "-")} signals=${escapeHtml((window.analysis?.signals || []).slice(0, 6).join(",") || "none")} preview=${escapeHtml(window.preview || "")}</div>
      `).join("");
      return `
        <div class="source-line">core_asset=${escapeHtml(entry.asset_id || "none")} role=${escapeHtml(entry.asset_role || "none")} status=${escapeHtml(entry.source_status || "unknown")} path=${escapeHtml(entry.content_path || "none")} score=${escapeHtml(entry.score ?? 0)} focus=${escapeHtml((entry.review_focus || []).join(",") || "none")} signals=${escapeHtml((entry.signals || []).slice(0, 8).join(",") || "none")}</div>
        ${windows}
      `;
    }).join("");
    return `
      <section class="report-section">
        <h3>Core Asset Review Package</h3>
        <div class="report-card gap-card">
          ${rows || "<div class=\"empty-inline\">core_assets=none</div>"}
        </div>
      </section>
    `;
  }

  function renderReportHtml(report) {
    if (!report) return "<div class=\"report-view empty-report\">No report loaded.</div>";
    const pack = report.signature?.agent_evidence_pack || {};
    const hookGaps = pack.vmp_hook_analysis?.hook_gaps || [];
    const patterns = pack.pipeline_patterns || [];
    const clusters = pack.global_stack_clusters || [];
    const flows = pack.flows || [];
    const materialFlows = pack.signature_material_flows || [];
    const vmpScalarRefChains = pack.vmp_scalar_ref_chains || [];
    const businessApiRuntimeHints = pack.business_api_runtime_hints || [];
    const sourceCandidates = pack.signature_source_candidates || [];
    const reviewEntries = pack.agent_review_package?.entries || [];
    const parameterGenerationBrief = pack.parameter_generation_brief || null;
    const coreAssetReviewPackage = pack.core_asset_review_package || null;
    const agentBlockingGaps = report.agent_analysis?.summary?.blocking_gap_summary || null;
    const agentNextCaptureFocus = report.agent_analysis?.next_capture_focus || [];
    const agentNativeCaptureRequirements = report.agent_analysis?.native_capture_requirements || [];
    const agentParameters = report.agent_analysis?.parameters || [];
    const signatureAbsent = pack.signature_absent || null;
    const nextCapturePlan = pack.next_capture_plan || null;
    const topVmpHookAnalysisPoints = report.vmp?.hook_analysis_points ||
      report.vmp?.hook_coverage?.hook_analysis_points ||
      [];
    const globalVmpHookAnalysisPoints = pack.vmp_hook_analysis?.hook_analysis_points || [];
    const flowCandidates = flowCandidateGroups(flows);
    const candidateGraphs = flowCandidateGraphGroups(flows);
    const suspectedSubflows = flowSuspectedSubflowGroups(flows);
    const showVmpHookCoverage = hasVmpHookCoverage(report);
    const hypothesisSummary = agentHypothesisSummary(report.agent_analysis?.summary?.hypothesis_summary);
    const readinessSummary = agentReadinessSummary(report.agent_analysis?.summary?.readiness_summary);
    const blockingSummary = agentBlockingGapSummary(agentBlockingGaps);

    return `
      <div class="report-view">
        <section class="report-section">
          <h3>Summary</h3>
          <div class="report-metrics">
            ${renderMetric("Trace", report.trace?.path || "-")}
            ${renderMetric("Events", report.trace?.event_count ?? 0)}
            ${renderMetric("VMP", report.vmp?.runtime_event_count ?? 0)}
            ${renderMetric("Signature", report.signature?.event_count ?? 0)}
            ${renderMetric("Flows", flows.length)}
          </div>
          ${hypothesisSummary ? `<div class="source-line">Hypotheses: ${escapeHtml(hypothesisSummary)}</div>` : ""}
          ${readinessSummary ? `<div class="source-line">Readiness: ${escapeHtml(readinessSummary)}</div>` : ""}
          ${blockingSummary ? `<div class="source-line">Blocking gaps: ${escapeHtml(blockingSummary)}</div>` : ""}
        </section>
        ${showVmpHookCoverage ? renderVmpHookCoverageHtml(report.vmp.hook_coverage) : ""}
        ${topVmpHookAnalysisPoints.length ? renderVmpHookAnalysisPointsHtml(topVmpHookAnalysisPoints) : ""}
        <section class="report-section">
          <h3>Parameter Generation Brief</h3>
          ${parameterGenerationBrief?.parameters?.length ? parameterGenerationBrief.parameters.slice(0, 8).map(renderParameterGenerationEntryHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        ${agentBlockingGaps?.top_blockers?.length ? renderAgentBlockingGapsHtml(agentBlockingGaps) : ""}
        ${agentNextCaptureFocus.length ? renderAgentNextCaptureFocusHtml(agentNextCaptureFocus) : ""}
        ${agentNativeCaptureRequirements.length ? renderAgentNativeCaptureRequirementsHtml(agentNativeCaptureRequirements) : ""}
        <section class="report-section">
          <h3>Agent Parameter Generation Paths</h3>
          ${agentParameters.length ? agentParameters.slice(0, 8).map(renderAgentParameterPathHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        <section class="report-section">
          <h3>Agent Review Package</h3>
          <div class="source-line">${escapeHtml(formatReviewCausalitySummary(pack.agent_review_package?.causality_summary || {}))}</div>
          ${reviewEntries.length ? reviewEntries.slice(0, 8).map(renderReviewEntryHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        <section class="report-section">
          <h3>Signature Source Candidates</h3>
          ${sourceCandidates.length ? sourceCandidates.slice(0, 8).map(renderSourceCandidateHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        <section class="report-section">
          <h3>Signature Material Flows</h3>
          ${materialFlows.length ? materialFlows.slice(0, 8).map(renderMaterialFlowHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        <section class="report-section">
          <h3>VMP Scalar Ref Chains</h3>
          ${vmpScalarRefChains.length ? vmpScalarRefChains.slice(0, 8).map(renderVmpScalarRefChainHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        ${businessApiRuntimeHints.length ? renderBusinessApiRuntimeHintsHtml(businessApiRuntimeHints) : ""}
        ${globalVmpHookAnalysisPoints.length ? renderVmpHookAnalysisPointsHtml(globalVmpHookAnalysisPoints, "Global VMP Hook Analysis Points") : ""}
        <section class="report-section">
          <h3>VMP Hook Gaps</h3>
          ${hookGaps.length ? hookGaps.slice(0, 8).map(renderHookGapHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        ${signatureAbsent ? renderSignatureAbsentHtml(signatureAbsent) : ""}
        ${nextCapturePlan ? renderNextCapturePlanHtml(nextCapturePlan) : ""}
        ${coreAssetReviewPackage?.entries?.length ? renderCoreAssetReviewPackageHtml(coreAssetReviewPackage) : ""}
        <section class="report-section">
          <h3>Flow VMP Linking Candidates</h3>
          ${flowCandidates.length ? flowCandidates.slice(0, 8).map(renderFlowCandidateGroupHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        <section class="report-section">
          <h3>Candidate Graph</h3>
          ${candidateGraphs.length ? candidateGraphs.slice(0, 8).map(renderCandidateGraphGroupHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        <section class="report-section">
          <h3>Suspected Signature Subflows</h3>
          ${suspectedSubflows.length ? suspectedSubflows.slice(0, 8).map(renderSuspectedSubflowHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        <section class="report-section">
          <h3>Pipeline Patterns</h3>
          ${patterns.length ? patterns.slice(0, 6).map(renderPatternHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
        <section class="report-section">
          <h3>Global Stack Clusters</h3>
          ${clusters.length ? clusters.slice(0, 6).map(renderClusterHtml).join("") : "<div class=\"empty-inline\">none</div>"}
        </section>
      </div>
    `;
  }

  function renderReportDetail(report) {
    if (!report) return "No report loaded.";
    const pack = report.signature?.agent_evidence_pack || {};
    const hookGaps = pack.vmp_hook_analysis?.hook_gaps || [];
    const patterns = pack.pipeline_patterns || [];
    const clusters = pack.global_stack_clusters || [];
    const flows = pack.flows || [];
    const materialFlows = pack.signature_material_flows || [];
    const vmpScalarRefChains = pack.vmp_scalar_ref_chains || [];
    const businessApiRuntimeHints = pack.business_api_runtime_hints || [];
    const sourceCandidates = pack.signature_source_candidates || [];
    const reviewEntries = pack.agent_review_package?.entries || [];
    const parameterGenerationBrief = pack.parameter_generation_brief || null;
    const coreAssetReviewPackage = pack.core_asset_review_package || null;
    const agentBlockingGaps = report.agent_analysis?.summary?.blocking_gap_summary || null;
    const agentNextCaptureFocus = report.agent_analysis?.next_capture_focus || [];
    const agentNativeCaptureRequirements = report.agent_analysis?.native_capture_requirements || [];
    const agentParameters = report.agent_analysis?.parameters || [];
    const signatureAbsent = pack.signature_absent || null;
    const nextCapturePlan = pack.next_capture_plan || null;
    const topVmpHookAnalysisPoints = report.vmp?.hook_analysis_points ||
      report.vmp?.hook_coverage?.hook_analysis_points ||
      [];
    const globalVmpHookAnalysisPoints = pack.vmp_hook_analysis?.hook_analysis_points || [];
    const flowCandidates = flowCandidateGroups(flows);
    const candidateGraphs = flowCandidateGraphGroups(flows);
    const suspectedSubflows = flowSuspectedSubflowGroups(flows);
    const showVmpHookCoverage = hasVmpHookCoverage(report);
    const lines = [
      ...formatTopLine(report),
      "",
      "Agent Evidence Pack",
      `Flows: ${flows.length}`,
      ""
    ];

    if (signatureAbsent) {
      lines.push(formatSignatureAbsent(signatureAbsent), "");
    }

    if (nextCapturePlan) {
      lines.push(formatNextCapturePlan(nextCapturePlan), "");
    }

    if (agentBlockingGaps?.top_blockers?.length) {
      lines.push(formatAgentBlockingGaps(agentBlockingGaps), "");
    }

    if (agentNextCaptureFocus.length) {
      lines.push(formatAgentNextCaptureFocus(agentNextCaptureFocus), "");
    }

    if (agentNativeCaptureRequirements.length) {
      lines.push(formatAgentNativeCaptureRequirements(agentNativeCaptureRequirements), "");
    }

    if (agentParameters.length) {
      lines.push("Agent Parameter Generation Paths");
      for (const parameter of agentParameters.slice(0, 8)) {
        lines.push(formatAgentParameterPath(parameter));
      }
      lines.push("");
    }

    if (coreAssetReviewPackage?.entries?.length) {
      lines.push(formatCoreAssetReviewPackage(coreAssetReviewPackage), "");
    }

    if (showVmpHookCoverage) {
      lines.push(formatVmpHookCoverage(report.vmp.hook_coverage), "");
    }

    if (topVmpHookAnalysisPoints.length) {
      lines.push(formatVmpHookAnalysisPoints(topVmpHookAnalysisPoints), "");
    }

    if (parameterGenerationBrief?.parameters?.length) {
      lines.push("Parameter Generation Brief");
      for (const entry of parameterGenerationBrief.parameters.slice(0, 8)) {
        lines.push(formatParameterGenerationEntry(entry));
      }
      lines.push("");
    }

    if (reviewEntries.length) {
      lines.push("Agent Review Package");
      lines.push(formatReviewCausalitySummary(pack.agent_review_package?.causality_summary || {}));
      for (const entry of reviewEntries.slice(0, 8)) {
        lines.push(formatReviewEntry(entry));
      }
      lines.push("");
    }

    if (sourceCandidates.length) {
      lines.push("Signature Source Candidates");
      for (const candidate of sourceCandidates.slice(0, 8)) {
        lines.push(formatSourceCandidate(candidate));
      }
      lines.push("");
    }

    if (materialFlows.length) {
      lines.push("Signature Material Flows");
      for (const flow of materialFlows.slice(0, 8)) {
        lines.push(formatMaterialFlow(flow));
      }
      lines.push("");
    }

    if (vmpScalarRefChains.length) {
      lines.push("VMP Scalar Ref Chains");
      for (const chain of vmpScalarRefChains.slice(0, 8)) {
        lines.push(formatVmpScalarRefChain(chain));
      }
      lines.push("");
    }

    if (businessApiRuntimeHints.length) {
      lines.push(formatBusinessApiRuntimeHints(businessApiRuntimeHints), "");
    }

    if (globalVmpHookAnalysisPoints.length) {
      lines.push(formatVmpHookAnalysisPoints(globalVmpHookAnalysisPoints, "Global VMP Hook Analysis Points"), "");
    }

    if (hookGaps.length) {
      lines.push("VMP Hook Gaps");
      for (const gap of hookGaps.slice(0, 8)) {
        lines.push(formatHookGap(gap));
      }
      lines.push("");
    }

    if (flowCandidates.length) {
      lines.push("Flow VMP Linking Candidates");
      for (const group of flowCandidates.slice(0, 8)) {
        lines.push(formatFlowCandidateGroup(group));
      }
      lines.push("");
    }

    if (candidateGraphs.length) {
      lines.push("Candidate Graph");
      for (const group of candidateGraphs.slice(0, 8)) {
        lines.push(formatCandidateGraphGroup(group));
      }
      lines.push("");
    }

    if (suspectedSubflows.length) {
      lines.push("Suspected Signature Subflows");
      for (const group of suspectedSubflows.slice(0, 8)) {
        lines.push(formatSuspectedSubflow(group));
      }
      lines.push("");
    }

    if (patterns.length) {
      lines.push("Pipeline Patterns");
      for (const pattern of patterns.slice(0, 6)) {
        lines.push(`- ${pattern.pattern} flows=${pattern.flow_count} events=${pattern.event_count}`);
      }
      lines.push("");
    }

    if (clusters.length) {
      lines.push("Global Stack Clusters");
      for (const cluster of clusters.slice(0, 6)) {
        lines.push(`- ${cluster.function || "(anonymous)"}@${cluster.stack_url || "unknown"} flows=${cluster.flow_count} events=${cluster.event_count}`);
      }
      lines.push("");
    }

    return lines.join("\n").trimEnd();
  }

  return {
    renderReportDetail,
    renderReportHtml
  };
});

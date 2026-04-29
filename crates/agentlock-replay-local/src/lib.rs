use std::collections::BTreeMap;

use agentlock_core::{
    BehaviorContract, CheckResult, DeterministicCheck, LoadedBundle, ReplayReport, ReplayRun,
    ReplaySummary, TraceEvent, TraceEventKind,
};
use anyhow::Result;
use chrono::Utc;

pub trait ReplayProvider {
    fn name(&self) -> &'static str;
    fn replay(
        &self,
        bundle: &LoadedBundle,
        traces: &[TraceEvent],
        runs: u32,
    ) -> Result<ReplayReport>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalDeterministicProvider;

impl ReplayProvider for LocalDeterministicProvider {
    fn name(&self) -> &'static str {
        "local-deterministic"
    }

    fn replay(
        &self,
        bundle: &LoadedBundle,
        traces: &[TraceEvent],
        runs: u32,
    ) -> Result<ReplayReport> {
        run_local_replay(bundle, traces, runs)
    }
}

pub fn run_local_replay(
    bundle: &LoadedBundle,
    traces: &[TraceEvent],
    runs: u32,
) -> Result<ReplayReport> {
    anyhow::ensure!(runs > 0, "--runs must be greater than zero");

    let grouped = group_traces(traces);
    let mut report_runs = Vec::new();

    for run_index in 1..=runs {
        for (trace_id, events) in &grouped {
            let checks = evaluate_trace(&bundle.behavior_contract, events);
            let passed = checks.iter().all(|check| check.passed);
            report_runs.push(ReplayRun {
                run_index,
                trace_id: trace_id.clone(),
                passed,
                checks,
            });
        }
    }

    let total_checks = report_runs
        .iter()
        .map(|run| run.checks.len())
        .sum::<usize>();
    let passed_checks = report_runs
        .iter()
        .flat_map(|run| run.checks.iter())
        .filter(|check| check.passed)
        .count();
    let failed_checks = total_checks.saturating_sub(passed_checks);

    Ok(ReplayReport {
        report_version: 1,
        provider: "local-deterministic".to_owned(),
        bundle_hash: String::new(),
        contract_id: bundle.behavior_contract.contract.id.clone(),
        generated_at: Utc::now(),
        summary: ReplaySummary {
            runs_requested: runs,
            traces: grouped.len(),
            total_checks,
            passed_checks,
            failed_checks,
            contract_passed: failed_checks == 0,
        },
        runs: report_runs,
    })
}

fn group_traces(traces: &[TraceEvent]) -> BTreeMap<String, Vec<TraceEvent>> {
    let mut grouped = BTreeMap::new();
    for trace in traces {
        grouped
            .entry(trace.trace_id.clone())
            .or_insert_with(Vec::new)
            .push(trace.clone());
    }

    for events in grouped.values_mut() {
        events.sort_by_key(|event| event.step);
    }

    grouped
}

fn evaluate_trace(contract: &BehaviorContract, events: &[TraceEvent]) -> Vec<CheckResult> {
    contract
        .contract
        .checks
        .iter()
        .map(|check| evaluate_check(check, events))
        .collect()
}

fn evaluate_check(check: &DeterministicCheck, events: &[TraceEvent]) -> CheckResult {
    match check {
        DeterministicCheck::RequireFinalOutput { id, .. } => {
            let passed = final_outputs(events).next().is_some();
            CheckResult {
                id: id.clone(),
                passed,
                message: if passed {
                    "found at least one assistant output event".to_owned()
                } else {
                    "missing assistant output event".to_owned()
                },
            }
        }
        DeterministicCheck::RequiredToolCalls {
            id,
            tools,
            min_calls,
            ..
        } => {
            let count = tool_calls(events)
                .filter(|tool| tools.iter().any(|expected| expected == *tool))
                .count() as u32;
            let required = min_calls.unwrap_or(1);
            let passed = count >= required;
            CheckResult {
                id: id.clone(),
                passed,
                message: if passed {
                    format!("observed {count} required tool call(s)")
                } else {
                    format!("expected at least {required} required tool call(s), observed {count}")
                },
            }
        }
        DeterministicCheck::ForbiddenToolCalls { id, tools, .. } => {
            let observed = tool_calls(events)
                .filter(|tool| tools.iter().any(|forbidden| forbidden == *tool))
                .cloned()
                .collect::<Vec<_>>();
            let passed = observed.is_empty();
            CheckResult {
                id: id.clone(),
                passed,
                message: if passed {
                    "no forbidden tool calls observed".to_owned()
                } else {
                    format!("forbidden tool calls observed: {}", observed.join(", "))
                },
            }
        }
        DeterministicCheck::RequiredOutputContainsAll { id, values, .. } => {
            let haystack = final_outputs(events)
                .collect::<Vec<_>>()
                .join("\n")
                .to_lowercase();
            let missing = values
                .iter()
                .filter(|value| !haystack.contains(&value.to_lowercase()))
                .cloned()
                .collect::<Vec<_>>();
            let passed = missing.is_empty();
            CheckResult {
                id: id.clone(),
                passed,
                message: if passed {
                    "assistant output contains all required values".to_owned()
                } else {
                    format!("assistant output is missing: {}", missing.join(", "))
                },
            }
        }
        DeterministicCheck::ForbiddenOutputContainsAny { id, values, .. } => {
            let haystack = final_outputs(events)
                .collect::<Vec<_>>()
                .join("\n")
                .to_lowercase();
            let observed = values
                .iter()
                .filter(|value| haystack.contains(&value.to_lowercase()))
                .cloned()
                .collect::<Vec<_>>();
            let passed = observed.is_empty();
            CheckResult {
                id: id.clone(),
                passed,
                message: if passed {
                    "assistant output avoids all forbidden values".to_owned()
                } else {
                    format!(
                        "assistant output contains forbidden values: {}",
                        observed.join(", ")
                    )
                },
            }
        }
        DeterministicCheck::MaxToolCalls { id, max, .. } => {
            let count = tool_calls(events).count() as u32;
            let passed = count <= *max;
            CheckResult {
                id: id.clone(),
                passed,
                message: if passed {
                    format!("tool call count {count} is within limit {max}")
                } else {
                    format!("tool call count {count} exceeds limit {max}")
                },
            }
        }
        DeterministicCheck::MaxTotalEvents { id, max, .. } => {
            let count = events.len() as u32;
            let passed = count <= *max;
            CheckResult {
                id: id.clone(),
                passed,
                message: if passed {
                    format!("event count {count} is within limit {max}")
                } else {
                    format!("event count {count} exceeds limit {max}")
                },
            }
        }
    }
}

fn tool_calls(events: &[TraceEvent]) -> impl Iterator<Item = &String> {
    events.iter().filter_map(|event| match event.event {
        TraceEventKind::ToolCall => event.tool.as_ref(),
        _ => None,
    })
}

fn final_outputs(events: &[TraceEvent]) -> impl Iterator<Item = &str> {
    events.iter().filter_map(|event| match event.event {
        TraceEventKind::AssistantOutput => Some(event.content.as_str()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use agentlock_core::{
        AgentLock, AgentMetadata, BehaviorContract, ContractDefinition, DeterministicCheck, Genome,
        LoadedBundle, ModelConfig, TraceEvent, TraceEventKind,
    };
    use anyhow::Result;

    use super::run_local_replay;

    #[test]
    fn replay_evaluates_contract_checks() -> Result<()> {
        let bundle = LoadedBundle {
            root: std::path::PathBuf::from("."),
            genome: Genome {
                schema_version: 1,
                agent: AgentMetadata {
                    id: "agent".to_owned(),
                    name: "Agent".to_owned(),
                    version: "0.1.0".to_owned(),
                    description: None,
                },
                model: ModelConfig {
                    provider: "local".to_owned(),
                    model: "stub".to_owned(),
                    temperature: Some(0.0),
                    max_input_tokens: None,
                    max_output_tokens: Some(32),
                },
                tools: Vec::new(),
                knowledge_snapshots: Vec::new(),
            },
            agent_lock: AgentLock {
                schema_version: 1,
                agent_id: "agent".to_owned(),
                behavior_contract_id: "contract".to_owned(),
                tracked_files: Vec::new(),
            },
            behavior_contract: BehaviorContract {
                schema_version: 1,
                contract: ContractDefinition {
                    id: "contract".to_owned(),
                    description: None,
                    policies: Vec::new(),
                    checks: vec![
                        DeterministicCheck::RequireFinalOutput {
                            id: "answer".to_owned(),
                            description: None,
                        },
                        DeterministicCheck::RequiredOutputContainsAll {
                            id: "contains".to_owned(),
                            description: None,
                            values: vec!["approved".to_owned()],
                        },
                    ],
                },
            },
            prompts: BTreeMap::new(),
        };
        let traces = vec![TraceEvent {
            trace_id: "trace-1".to_owned(),
            step: 1,
            event: TraceEventKind::AssistantOutput,
            role: Some("assistant".to_owned()),
            tool: None,
            content: "approved".to_owned(),
            metadata: None,
        }];

        let report = run_local_replay(&bundle, &traces, 2)?;
        assert_eq!(report.summary.runs_requested, 2);
        assert!(report.summary.contract_passed);
        Ok(())
    }
}

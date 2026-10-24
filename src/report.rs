//! A self-contained, read-only human view of an investigation revision.

use crate::workflow::State;
use std::collections::BTreeSet;

pub fn render(state: &State) -> String {
    let variables: BTreeSet<&str> = state
        .known_values
        .iter()
        .map(|value| value.variable.as_str())
        .collect();
    let inferences: Vec<_> = variables
        .into_iter()
        .filter_map(|variable| crate::inference::infer_unsigned_field(state, variable).ok())
        .collect();
    let mut view = serde_json::to_value(state).expect("state is serializable");
    view["corpus_summary"] = serde_json::to_value(crate::query::corpus_summary(state))
        .expect("corpus summary is serializable");
    view["field_inferences"] =
        serde_json::to_value(inferences).expect("inferences are serializable");
    let frame_variables: BTreeSet<&str> = state
        .frame_known_values
        .iter()
        .map(|value| value.variable.as_str())
        .collect();
    let mut frame_inferences = Vec::new();
    let mut frame_inference_errors = Vec::new();
    for variable in frame_variables {
        match crate::inference::infer_frame_unsigned_field(state, variable) {
            Ok(inference) => frame_inferences.push(inference),
            Err(error) => frame_inference_errors
                .push(serde_json::json!({"variable": variable, "error": error})),
        }
    }
    view["frame_field_inferences"] =
        serde_json::to_value(frame_inferences).expect("frame inferences are serializable");
    view["frame_field_errors"] = serde_json::Value::Array(frame_inference_errors);
    match crate::clustering::cluster_observations(state, None, true) {
        Ok(report) => {
            view["cluster_report"] =
                serde_json::to_value(report).expect("cluster report is serializable");
            view["cluster_error"] = serde_json::Value::Null;
        }
        Err(error) => {
            view["cluster_report"] = serde_json::Value::Null;
            view["cluster_error"] = serde_json::Value::String(error);
        }
    }
    let mut cluster_validations = Vec::new();
    for experiment in state.experiments.iter().take(8) {
        let discovery = state
            .trials
            .iter()
            .find(|trial| trial.experiment_id == experiment.id && trial.role == "discovery");
        let validation = state
            .trials
            .iter()
            .find(|trial| trial.experiment_id == experiment.id && trial.role == "validation");
        if let (Some(discovery), Some(validation)) = (discovery, validation)
            && let Ok(result) =
                crate::clustering::validate_clusters(state, &discovery.id, &validation.id, true)
        {
            cluster_validations.push(serde_json::json!({
                "experiment_id": experiment.id,
                "result": result,
            }));
        }
    }
    view["cluster_validations"] = serde_json::Value::Array(cluster_validations);
    let mut exchange_reports = Vec::new();
    for capture in state.captures.iter().take(8) {
        match crate::exchanges::pair_exchanges(state, &capture.id, None, 0, 12) {
            Ok(result) => exchange_reports.push(serde_json::json!({
                "capture_id": capture.id,
                "result": result,
            })),
            Err(error) => exchange_reports.push(serde_json::json!({
                "capture_id": capture.id,
                "error": error,
            })),
        }
    }
    view["exchange_reports"] = serde_json::Value::Array(exchange_reports);
    let mut exchange_validations = Vec::new();
    for discovery in state.captures.iter().take(8) {
        let Some(discovery_trial) = state
            .trials
            .iter()
            .find(|trial| trial.id == discovery.trial_id)
        else {
            continue;
        };
        if discovery_trial.role != "discovery" {
            continue;
        }
        for validation in state.captures.iter().take(8) {
            let Some(validation_trial) = state
                .trials
                .iter()
                .find(|trial| trial.id == validation.trial_id)
            else {
                continue;
            };
            if validation_trial.role != "validation"
                || discovery_trial.experiment_id != validation_trial.experiment_id
                || discovery.format != validation.format
            {
                continue;
            }
            if let Ok(result) =
                crate::exchanges::validate_exchanges(state, &discovery.id, &validation.id, None)
            {
                exchange_validations.push(result);
            }
            if exchange_validations.len() >= 8 {
                break;
            }
        }
        if exchange_validations.len() >= 8 {
            break;
        }
    }
    view["exchange_validations"] =
        serde_json::to_value(exchange_validations).expect("exchange validations are serializable");
    let mut framing_inferences = Vec::new();
    let mut framing_previews = Vec::new();
    let mut tlv_inferences = Vec::new();
    let mut varint_inferences = Vec::new();
    let mut varint_previews = Vec::new();
    let mut delimiter_inferences = Vec::new();
    let mut delimiter_previews = Vec::new();
    for experiment in state.experiments.iter().take(8) {
        let discovery = state
            .trials
            .iter()
            .find(|trial| trial.experiment_id == experiment.id && trial.role == "discovery");
        let validation = state
            .trials
            .iter()
            .find(|trial| trial.experiment_id == experiment.id && trial.role == "validation");
        let (Some(discovery), Some(validation)) = (discovery, validation) else {
            continue;
        };
        if let Ok(inference) =
            crate::framing::infer_length_prefix(state, &discovery.id, &validation.id)
        {
            if inference.candidate_count == 1
                && let Some(candidate) = inference.candidates.first()
                && candidate.validation_matches == inference.validation_count
                && let Some(observation) = state.observations.iter().find(|observation| {
                    state.captures.iter().any(|capture| {
                        capture.id == observation.capture_id && capture.trial_id == discovery.id
                    })
                })
                && let Ok(probe) =
                    crate::framing::probe_observation(state, &observation.id, candidate.config)
            {
                framing_previews.push(serde_json::json!({
                    "experiment_id": experiment.id,
                    "probe": probe,
                }));
            }
            framing_inferences.push(serde_json::json!({
                "experiment_id": experiment.id,
                "inference": inference,
            }));
        }
        if let Ok(inference) = crate::tlv::infer_tlv(state, &discovery.id, &validation.id)
            && inference.candidate_count > 0
        {
            tlv_inferences.push(serde_json::json!({
                "experiment_id": experiment.id,
                "inference": inference,
            }));
        }
        if let Ok(inference) = crate::varint::infer_varint(state, &discovery.id, &validation.id)
            && inference.candidate_count > 0
        {
            let validated: Vec<_> = inference
                .candidates
                .iter()
                .filter(|candidate| candidate.validation_matches == inference.validation_count)
                .collect();
            if inference.candidate_count <= inference.reported_candidate_limit
                && validated.len() == 1
                && let Some(observation) = state.observations.iter().find(|observation| {
                    state.captures.iter().any(|capture| {
                        capture.id == observation.capture_id && capture.trial_id == discovery.id
                    })
                })
                && let Ok(probe) =
                    crate::varint::probe_varint(state, &observation.id, validated[0].config)
            {
                varint_previews.push(serde_json::json!({
                    "experiment_id": experiment.id,
                    "probe": probe,
                }));
            }
            varint_inferences.push(serde_json::json!({
                "experiment_id": experiment.id,
                "inference": inference,
            }));
        }
        if let Ok(inference) =
            crate::delimiter::infer_delimiter(state, &discovery.id, &validation.id)
            && inference.candidate_count > 0
        {
            if inference.fully_validated_candidate_count == 1
                && let Some(candidate) = inference
                    .candidates
                    .iter()
                    .find(|candidate| candidate.validation_matches == inference.validation_count)
                && let Some(observation) = state.observations.iter().find(|observation| {
                    state.captures.iter().any(|capture| {
                        capture.id == observation.capture_id && capture.trial_id == discovery.id
                    })
                })
                && let Ok(probe) = crate::delimiter::probe_observation(
                    state,
                    &observation.id,
                    candidate.config.clone(),
                )
            {
                delimiter_previews.push(serde_json::json!({
                    "experiment_id": experiment.id,
                    "probe": probe,
                }));
            }
            delimiter_inferences.push(serde_json::json!({
                "experiment_id": experiment.id,
                "inference": inference,
            }));
        }
    }
    view["framing_inferences"] = serde_json::Value::Array(framing_inferences);
    view["framing_previews"] = serde_json::Value::Array(framing_previews);
    view["tlv_inferences"] = serde_json::Value::Array(tlv_inferences);
    view["varint_inferences"] = serde_json::Value::Array(varint_inferences);
    view["varint_previews"] = serde_json::Value::Array(varint_previews);
    view["delimiter_inferences"] = serde_json::Value::Array(delimiter_inferences);
    view["delimiter_previews"] = serde_json::Value::Array(delimiter_previews);
    let data = serde_json::to_string(&view)
        .expect("state is serializable")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    TEMPLATE.replace("__STATE_JSON__", &data)
}

const TEMPLATE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Protocol Informatics v2 · Investigation</title>
<style>
:root { color-scheme: dark; font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; background:#101722; color:#e9eef5 }
* { box-sizing:border-box }
body { margin:0; padding:24px; max-width:1500px; margin-inline:auto }
header { border-bottom:1px solid #344257; margin-bottom:20px; padding-bottom:16px }
h1 { margin:0; font-size:1.6rem } h2 { font-size:1.1rem; margin:0 0 12px }
.muted { color:#9aaec4 } .metrics { display:flex; gap:12px; flex-wrap:wrap; margin-top:14px }
.metric,.panel { background:#182333; border:1px solid #344257; border-radius:10px; padding:14px }
.metric strong { display:block; font-size:1.35rem; color:#94d7ff }
.layout { display:grid; grid-template-columns:minmax(280px,1fr) minmax(460px,2fr); gap:16px }
.stack { display:grid; gap:16px; align-content:start }
input,select { background:#0e1622; color:#e9eef5; border:1px solid #4a607a; border-radius:6px; padding:8px; width:100% }
.filters { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:12px }
.search { margin-bottom:12px }
.row { border-top:1px solid #344257; padding:9px 0; cursor:pointer }
.row:hover,.row.selected { background:#233951 }
.row button { all:unset; cursor:pointer; display:block; width:100% }
.small { font-size:.84rem } .pill { display:inline-block; border:1px solid #5c789a; border-radius:12px; padding:1px 7px; margin:2px; font-size:.75rem }
code,pre { font-family:ui-monospace, SFMono-Regular, Menlo, monospace }
pre { overflow:auto; white-space:pre-wrap; word-break:break-all; background:#0e1622; border-radius:7px; padding:12px }
.bytes { display:flex; flex-wrap:wrap; gap:4px; margin-top:12px }
.byte { width:2.1em; text-align:center; padding:4px 0; background:#243448; border-radius:3px; font-family:ui-monospace,monospace }
.byte.changed { background:#75502c; color:#fff0c9 }
.byte.candidate { outline:2px solid #5cd6ab; background:#174c43 }
.byte.packet-start { box-shadow:inset 3px 0 #8bb8ff }
.byte.record-start { border-left:3px solid #f0c674 }
.byte-nav { display:flex; gap:10px; align-items:center; margin-top:12px }
.byte-nav button { background:#243448; color:#e9eef5; border:1px solid #4a607a; border-radius:5px; padding:4px 8px; cursor:pointer }
.byte-nav button:disabled { opacity:.4; cursor:default }
.legend { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px }
.bar-track { height:5px; background:#0e1622; border-radius:4px; overflow:hidden; margin:3px 0 8px }
.bar-fill { height:100%; background:#79bce6 }
@media(max-width:850px) { .layout { grid-template-columns:1fr } }
</style>
</head>
<body>
<header><div class="muted">Protocol Informatics v2 · investigation revision <span id="revision"></span></div><h1 id="question"></h1><div class="metrics" id="metrics"></div></header>
<main class="layout">
  <div class="stack">
    <section class="panel"><h2>Corpus overview</h2><div id="corpusSummary"></div></section>
    <section class="panel"><h2>Hypotheses</h2><div id="hypotheses"></div></section>
    <section class="panel"><h2>Experiments and trials</h2><div id="experiments"></div></section>
    <section class="panel"><h2>Capture command runs</h2><div id="captureRuns"></div></section>
    <section class="panel"><h2>Tagged action windows</h2><div id="tagWindows"></div></section>
    <section class="panel"><h2>Capture scope tags</h2><div id="captureTags"></div></section>
    <section class="panel"><h2>Candidate exchanges</h2><div id="exchanges"></div></section>
    <section class="panel"><h2>Held-out exchange bytes</h2><div id="exchangeValidation"></div></section>
    <section class="panel"><h2>Candidate format groups</h2><div id="clusters"></div></section>
    <section class="panel"><h2>Held-out grouping</h2><div id="clusterValidation"></div></section>
    <section class="panel"><h2>Candidate fields</h2><div id="fieldCandidates"></div></section>
    <section class="panel"><h2>Candidate record framing</h2><div id="framingCandidates"></div></section>
    <section class="panel"><h2>Candidate typed records</h2><div id="tlvCandidates"></div></section>
    <section class="panel"><h2>Candidate variable-length records</h2><div id="varintCandidates"></div></section>
    <section class="panel"><h2>Candidate delimiter records</h2><div id="delimiterCandidates"></div></section>
    <section class="panel"><h2>Committed frames</h2><div id="committedFrames"></div></section>
    <section class="panel"><h2>Frame fields</h2><div id="frameFields"></div></section>
    <section class="panel"><h2>Analyses</h2><div id="analyses"></div></section>
    <section class="panel"><h2>Decisions</h2><div id="decisions"></div></section>
  </div>
  <div class="stack">
    <section class="panel"><h2>Observations</h2><div class="filters"><select id="trialFilter"><option value="">All trials</option></select><select id="clusterFilter"><option value="">All groups</option></select></div><input id="search" class="search" placeholder="ID, tag, direction, or hex bytes"><div id="observations"></div></section>
    <section class="panel"><h2>Byte inspector</h2><div id="detail" class="muted">Select an observation to inspect its bytes and source.</div></section>
    <section class="panel"><h2>Compare observations</h2><div class="filters"><select id="leftCompare"><option value="">First observation</option></select><select id="rightCompare"><option value="">Second observation</option></select></div><div id="comparison" class="muted">Choose two observations to highlight changed bytes.</div></section>
  </div>
</main>
<script>
const state = __STATE_JSON__;
const byId = id => document.getElementById(id);
const node = (tag, text, className) => { const el=document.createElement(tag); el.textContent=text; if(className) el.className=className; return el; };
const captureById = new Map(state.captures.map(x=>[x.id,x]));
const trialById = new Map(state.trials.map(x=>[x.id,x]));
const clusterById = new Map((state.cluster_report?.clusters||[]).map(x=>[x.id,x]));
const framingPreviewById = new Map((state.framing_previews||[]).map(x=>[x.probe.observation_id,x.probe]));
for(const item of state.varint_previews||[]) if(!framingPreviewById.has(item.probe.observation_id)) framingPreviewById.set(item.probe.observation_id,item.probe);
const committedRuns = [...(state.framing_runs||[]), ...(state.varint_runs||[])];
for(const run of committedRuns) framingPreviewById.set(run.observation_id,{records:run.records,committed:true,key:run.key});
const frameById = new Map(committedRuns.flatMap(run=>run.records.map(frame=>[frame.id,{frame,run}])));
const tagsFor = id => state.tags.filter(x=>x.observation_id===id);
const valuesFor = id => state.known_values.filter(x=>x.observation_id===id);
const fieldOverlays = state.field_inferences.flatMap(inference => {
  const preferred=inference.candidates.filter(candidate=>candidate.preferred);
  const observationIds=new Set(state.known_values.filter(value=>value.variable===inference.variable).map(value=>value.observation_id));
  return !inference.truncated&&inference.preferred_candidate_count===1 ? [{variable:inference.variable,observationIds,...preferred[0]}] : [];
});
const frameFieldOverlays = (state.frame_field_inferences||[]).flatMap(inference => {
  const preferred=inference.candidates.filter(candidate=>candidate.preferred);
  if(inference.truncated||inference.preferred_candidate_count!==1) return [];
  const frameIds=new Set(state.frame_known_values.filter(value=>value.variable===inference.variable).map(value=>value.frame_id));
  return [...frameIds].flatMap(id=>{const target=frameById.get(id); return target?[{variable:inference.variable,frameId:id,observationId:target.run.observation_id,start:target.frame.start+preferred[0].start,end:target.frame.start+preferred[0].end}]:[];});
});
byId('revision').textContent=state.revision;
byId('question').textContent=state.question;
for(const [label,count] of [['Observations',state.observations.length],['Captures',state.captures.length],['Frames',state.corpus_summary.counts.frames],['Trials',state.trials.length],['Hypotheses',state.hypotheses.length],['Experiments',state.experiments.length]]) {
  const box=node('div','', 'metric'); box.append(node('strong',String(count)),node('span',label)); byId('metrics').append(box);
}
const corpus=state.corpus_summary, lengths=corpus.observation_lengths_bytes;
byId('corpusSummary').append(node('div',corpus.counts.observation_bytes+' observed bytes · '+corpus.counts.tagged_observations+'/'+corpus.counts.observations+' tagged observations · '+(corpus.counts.observations-corpus.missing_timestamp_observations)+' timestamped','small'));
byId('corpusSummary').append(node('div','Message length (bytes): '+(lengths.min===null?'no observations':lengths.min+' min · '+lengths.median+' median · '+lengths.p90+' p90 · '+lengths.max+' max'),'small muted'));
if(corpus.stream_gap_observations) byId('corpusSummary').append(node('div',corpus.stream_gap_observations+' TCP run(s) follow a sequence gap','small muted'));
for(const format of corpus.formats) byId('corpusSummary').append(node('div',format.format+': '+format.observations+' observations from '+format.captures+' capture(s)','small'));
for(const direction of corpus.top_directions.slice(0,8)) {
  const row=node('div','', 'small'); row.append(node('span',direction.direction+' · '+direction.observations));
  const track=node('div','', 'bar-track'), fill=node('div','', 'bar-fill'); fill.style.width=(corpus.counts.observations?100*direction.observations/corpus.counts.observations:0)+'%'; track.append(fill); row.append(track); byId('corpusSummary').append(row);
}
if(corpus.top_directions.length>8||corpus.directions_omitted) byId('corpusSummary').append(node('div','Additional directions: '+Math.max(0,corpus.top_directions.length-8)+' in the JSON summary, '+corpus.directions_omitted+' omitted ('+corpus.other_direction_observations+' observations)','small muted'));
for(const h of state.hypotheses) {
  const row=node('div','', 'row'); row.append(node('strong',h.id+' · '+h.claim),node('div','Agent/analyst rating: '+(h.score===null?'unscored':h.score.toFixed(3))+' · evidence: '+h.evidence.length+' · counterexamples: '+h.counterexamples.length,'small muted')); byId('hypotheses').append(row);
}
for(const inference of state.field_inferences) {
  const row=node('div','', 'row');
  row.append(node('strong',inference.variable),node('div',inference.discovery_count+' discovery values · '+inference.validation_count+' held-out values · '+inference.candidate_count+' candidate(s) · '+inference.preferred_candidate_count+' shortest validated','small muted'));
  for(const candidate of inference.candidates.slice(0,5)) row.append(node('div','['+candidate.start+', '+candidate.end+') '+candidate.byte_order+' · held-out '+candidate.validation_matches+'/'+candidate.validation_total+(candidate.preferred?' · shortest validated':''),'small'));
  byId('fieldCandidates').append(row);
}
if(!state.field_inferences.length) byId('fieldCandidates').append(node('div','Annotate controlled values to search for exact numeric fields.','small muted'));
for(const item of state.framing_inferences||[]) {
  const inference=item.inference, row=node('div','', 'row');
  row.append(node('strong',item.experiment_id+' · '+inference.candidate_count+' model(s)'),node('div',inference.discovery_count+' discovery observation(s) · '+inference.validation_count+' held-out observation(s)','small muted'));
  for(const candidate of inference.candidates.slice(0,5)) {
    const config=candidate.config;
    row.append(node('div','start '+config.start_offset+' · field +'+config.prefix_offset+' / '+config.prefix_width+' byte(s) '+config.byte_order+' · '+config.length_mode+' · align '+config.alignment+' · held-out '+candidate.validation_matches+'/'+inference.validation_count,'small'));
    for(const failed of candidate.validation_counterexamples.slice(0,3)) row.append(node('div','↳ '+failed.observation_id+' stopped at '+failed.next_offset+' ('+failed.status+')','small muted'));
  }
  const preview=(state.framing_previews||[]).find(x=>x.experiment_id===item.experiment_id)?.probe;
  if(preview) {
    row.append(node('div','Proposed records in '+preview.observation_id+': '+preview.records.map(record=>'['+record.start+', '+record.end+')').join(' '),'small muted'));
    const button=node('button','Inspect proposed records','small'); button.onclick=()=>{ const observation=state.observations.find(x=>x.id===preview.observation_id); if(observation) showDetail(observation); }; row.append(button);
  }
  byId('framingCandidates').append(row);
}
if(!(state.framing_inferences||[]).length) byId('framingCandidates').append(node('div','Use discovery and validation trials to test length-prefix record boundaries.','small muted'));
for(const item of state.tlv_inferences||[]) {
  const inference=item.inference, row=node('div','', 'row');
  row.append(node('strong',item.experiment_id+' · '+inference.candidate_count+' typed model(s)'),node('div',inference.discovery_count+' discovery · '+inference.validation_count+' held-out observations','small muted'));
  for(const candidate of inference.candidates.slice(0,5)) {
    const config=candidate.config;
    row.append(node('div','start '+config.start_offset+' · '+config.type_width+' byte type · '+config.length_width+' byte '+config.byte_order+' '+config.length_mode+' length · align '+config.alignment+' · held-out '+candidate.validation_matches+'/'+inference.validation_count,'small'));
    row.append(node('div',candidate.distinct_discovery_types+' discovery type(s), '+candidate.recurring_discovery_types+' recurring · '+candidate.validation_elements_with_seen_types+'/'+candidate.validation_elements+' held-out elements use seen types','small muted'));
    for(const profile of candidate.type_profiles.slice(0,8)) row.append(node('div','type '+profile.type_hex+' · discovery '+profile.discovery_occurrences+' in '+profile.discovery_observations+' observations · held-out '+profile.validation_occurrences+' · value bytes '+profile.minimum_value_length+'–'+profile.maximum_value_length,'small'));
    if(candidate.type_profiles_truncated) row.append(node('div','Type list truncated; use infer-tlv for bounded JSON results.','small muted'));
    for(const failed of candidate.validation_counterexamples.slice(0,3)) row.append(node('div','↳ '+failed.observation_id+' stopped at '+failed.next_offset+' ('+failed.status+')','small muted'));
  }
  byId('tlvCandidates').append(row);
}
if(!(state.tlv_inferences||[]).length) byId('tlvCandidates').append(node('div','Probe or infer typed length-value records from controlled trials.','small muted'));
for(const item of state.varint_inferences||[]) {
  const inference=item.inference, row=node('div','', 'row');
  row.append(node('strong',item.experiment_id+' · '+inference.candidate_count+' variable-length model(s)'),node('div',inference.discovery_count+' discovery · '+inference.validation_count+' held-out observations','small muted'));
  for(const candidate of inference.candidates.slice(0,5)) {
    const config=candidate.config;
    row.append(node('div','start '+config.start_offset+' · field +'+config.field_offset+' · unsigned LEB128 '+config.length_mode+' length · align '+config.alignment+' · held-out '+candidate.validation_matches+'/'+inference.validation_count,'small'));
    row.append(node('div',candidate.discovery_records+' discovery records · '+candidate.discovery_multibyte_prefixes+' multibyte prefixes','small muted'));
    for(const failed of candidate.validation_counterexamples.slice(0,3)) row.append(node('div','↳ '+failed.observation_id+' stopped at '+failed.next_offset+' ('+failed.status+')','small muted'));
  }
  const preview=(state.varint_previews||[]).find(x=>x.experiment_id===item.experiment_id)?.probe;
  if(preview) {
    row.append(node('div','Proposed records in '+preview.observation_id+': '+preview.records.map(record=>'['+record.start+', '+record.end+')').join(' '),'small muted'));
    const button=node('button','Inspect proposed records','small'); button.onclick=()=>{ const observation=state.observations.find(x=>x.id===preview.observation_id); if(observation) showDetail(observation); }; row.append(button);
  }
  byId('varintCandidates').append(row);
}
if(!(state.varint_inferences||[]).length) byId('varintCandidates').append(node('div','Cross a varint width boundary in discovery trials to test this model.','small muted'));
for(const item of state.delimiter_inferences||[]) {
  const inference=item.inference, row=node('div','', 'row');
  row.append(node('strong',item.experiment_id+' · '+inference.candidate_count+' delimiter model(s)'),node('div',inference.discovery_count+' discovery · '+inference.validation_count+' held-out observations · '+inference.fully_validated_candidate_count+' fully validated','small muted'));
  for(const candidate of inference.candidates.slice(0,5)) {
    row.append(node('div','start '+candidate.config.start_offset+' · delimiter 0x'+candidate.config.delimiter_hex+' · '+candidate.discovery_records+' discovery records · held-out '+candidate.validation_matches+'/'+inference.validation_count,'small'));
    for(const failed of candidate.validation_counterexamples.slice(0,3)) row.append(node('div','↳ '+failed.observation_id+' stopped at '+failed.next_offset+' ('+failed.status+')','small muted'));
  }
  const preview=(state.delimiter_previews||[]).find(x=>x.experiment_id===item.experiment_id)?.probe;
  if(preview) {
    row.append(node('div','Proposed records in '+preview.observation_id+': '+preview.records.map(record=>'['+record.start+', '+record.payload_end+') payload, ['+record.payload_end+', '+record.end+') delimiter').join(' '),'small muted'));
    const button=node('button','Inspect source bytes','small'); button.onclick=()=>{const observation=state.observations.find(x=>x.id===preview.observation_id); if(observation) showDetail(observation);}; row.append(button);
  }
  byId('delimiterCandidates').append(row);
}
if(!(state.delimiter_inferences||[]).length) byId('delimiterCandidates').append(node('div','Probe or infer short terminators across controlled trials.','small muted'));
for(const run of committedRuns) {
  const row=node('div','', 'row');
  const model=run.id.startsWith('varint-') ? 'unsigned LEB128 '+run.config.length_mode+' length · field +'+run.config.field_offset : run.config.prefix_width+' byte '+run.config.byte_order+' '+run.config.length_mode+' length';
  row.append(node('strong',run.id+' · '+run.key),node('div',run.observation_id+' · '+run.records.length+' frames · '+model+' · alignment '+run.config.alignment,'small muted'));
  for(const frame of run.records.slice(0,20)) row.append(node('div',frame.id+' ['+frame.start+', '+frame.end+')'+(frame.logical_end<frame.end?' · padding ['+frame.logical_end+', '+frame.end+')':'')+' '+state.frame_known_values.filter(value=>value.frame_id===frame.id).map(value=>value.variable+'='+value.value+' ('+value.set+')').join(' · '),'small'));
  if(run.records.length>20) row.append(node('div','Additional frames are available through the frames command.','small muted'));
  const button=node('button','Inspect source bytes','small'); button.onclick=()=>{const observation=state.observations.find(x=>x.id===run.observation_id); if(observation) showDetail(observation);}; row.append(button);
  byId('committedFrames').append(row);
}
if(!committedRuns.length) byId('committedFrames').append(node('div','Commit a complete framing model to preserve record boundaries and stable frame IDs.','small muted'));
for(const inference of state.frame_field_inferences||[]) {
  const row=node('div','', 'row');
  row.append(node('strong',inference.variable),node('div',inference.discovery_count+' discovery frames · '+inference.validation_count+' held-out frames · '+inference.candidate_count+' candidate(s) · '+inference.preferred_candidate_count+' shortest validated','small muted'));
  for(const candidate of inference.candidates.slice(0,5)) row.append(node('div','frame ['+candidate.start+', '+candidate.end+') '+candidate.byte_order+' · held-out '+candidate.validation_matches+'/'+candidate.validation_total+(candidate.preferred?' · shortest validated':''),'small'));
  byId('frameFields').append(row);
}
for(const failure of state.frame_field_errors||[]) byId('frameFields').append(node('div',failure.variable+': '+failure.error,'small muted'));
if(!(state.frame_field_inferences||[]).length&&!(state.frame_field_errors||[]).length) byId('frameFields').append(node('div','Annotate committed frames with controlled values to locate fields inside records.','small muted'));
for(const experiment of state.experiments) {
  const row=node('div','', 'row'); row.append(node('strong',experiment.id+' · '+experiment.question),node('div','Prediction: '+experiment.prediction,'small muted'));
  for(const trial of state.trials.filter(x=>x.experiment_id===experiment.id)) {
    const captures=state.captures.filter(x=>x.trial_id===trial.id);
    row.append(node('div',trial.id+' · '+trial.role+' · '+trial.changed_factor+' · '+captures.length+' capture(s)','small'));
    for(const action of state.actions.filter(x=>x.trial_id===trial.id)) row.append(node('div','↳ '+action.id+' · '+action.kind+': '+action.detail+(action.timestamp_ns===null?'':' · UTC ns '+action.timestamp_ns),'small muted'));
  }
  byId('experiments').append(row);
}
for(const run of state.capture_runs) {
  const row=node('div','', 'row');
  row.append(node('strong',run.id+' · '+run.key),node('div',run.status+(run.stop_requested?' · stop requested':'')+' · '+run.trial_id+' · '+run.format+' · limit '+run.timeout_ms+' ms','small muted'));
  if(run.capture_id) row.append(node('div','Capture '+run.capture_id,'small'));
  if(run.error) row.append(node('div',run.error,'small'));
  byId('captureRuns').append(row);
}
if(!state.capture_runs.length) byId('captureRuns').append(node('div','No command runs recorded.','small muted'));
for(const window of state.window_tags) {
  const row=node('div','', 'row');
  row.append(node('strong',window.id+' · '+window.key),node('div',window.phase+': '+window.label+' · '+window.observation_ids.length+' observation(s)','small'),node('div','Action '+window.action_id+' · UTC ns ['+window.start_ns+', '+window.end_ns+')','small muted'));
  byId('tagWindows').append(row);
}
if(!state.window_tags.length) byId('tagWindows').append(node('div','No action windows tagged.','small muted'));
for(const batch of state.capture_tag_batches||[]) {
  const row=node('div','', 'row');
  const start=batch.start_index||0;
  row.append(node('strong',batch.id+' · '+batch.key),node('div',batch.phase+': '+batch.label+' · observations '+start+'–'+(start+batch.observation_ids.length-1),'small'),node('div','Action '+batch.action_id+' · capture '+batch.capture_id,'small muted'));
  byId('captureTags').append(row);
}
if(!(state.capture_tag_batches||[]).length) byId('captureTags').append(node('div','No captures tagged to an action.','small muted'));
for(const item of state.exchange_reports||[]) {
  const row=node('div','', 'row');
  if(item.error) {
    row.append(node('strong',item.capture_id),node('div',item.error,'small muted'));
  } else {
    const result=item.result;
    row.append(node('strong',item.capture_id+' · '+result.pair_count+' candidate pair(s)'),node('div',result.ambiguous_count+' ambiguous · '+result.unpaired_count+' unpaired · '+result.max_lag_ms+' ms window','small muted'),node('div','Varying equal bytes are measurements, not confirmed echo fields.','small muted'));
    for(const group of result.orientation_summaries.slice(0,5)) {
      const shared=group.varying_equal_ranges.map(range=>'['+range.start+', '+range.end+')').join(', ')||'none';
      row.append(node('div',group.earlier_direction+' · '+group.pair_count+' pair(s) · varying equal bytes '+shared,'small'));
    }
    for(const pair of result.pairs.slice(0,6)) {
      const button=node('button',pair.earlier_observation_id+' → '+pair.later_observation_id+' · '+pair.lag_ns+' ns','small');
      button.onclick=()=>{byId('leftCompare').value=pair.earlier_observation_id;byId('rightCompare').value=pair.later_observation_id;renderComparison();byId('comparison').scrollIntoView({behavior:'smooth',block:'nearest'});};
      row.append(button);
    }
    if(result.pair_count>result.pairs.length) row.append(node('div','Use pair-exchanges to page the remaining pairs.','small muted'));
  }
  byId('exchanges').append(row);
}
if(!(state.exchange_reports||[]).length) byId('exchanges').append(node('div','No captures available for exchange pairing.','small muted'));
for(const result of state.exchange_validations||[]) {
  const row=node('div','', 'row');
  row.append(node('strong',result.discovery_capture_id+' → '+result.validation_capture_id),node('div',result.supported_offset_count+' supported · '+result.contradicted_offset_count+' contradicted · '+result.untested_offset_count+' untested candidate byte(s)','small'),node('div',result.discovery_pair_count+' discovery pair(s) · '+result.validation_pair_count+' held-out pair(s) · '+result.validation_ambiguous_count+' ambiguous · '+result.unmatched_validation_pair_count+' pair(s) outside candidate directions','small muted'));
  const priority={contradicted:0,untested:1,supported:2};
  const visible=result.checks.slice().sort((a,b)=>(priority[a.status]-priority[b.status])||a.offset-b.offset).slice(0,12);
  for(const check of visible) {
    row.append(node('div','byte '+check.offset+' · '+check.status+' · '+check.matching_pair_count+'/'+check.tested_pair_count+' paired messages equal · '+check.earlier_direction,'small'));
    for(const failed of check.counterexamples.slice(0,2)) {
      const button=node('button',failed.earlier_observation_id+' → '+failed.later_observation_id+' · '+failed.reason+' ('+failed.earlier_byte+' vs '+failed.later_byte+')','small');
      button.onclick=()=>{byId('leftCompare').value=failed.earlier_observation_id;byId('rightCompare').value=failed.later_observation_id;renderComparison();byId('comparison').scrollIntoView({behavior:'smooth',block:'nearest'});};
      row.append(button);
    }
  }
  if(result.checks.length>visible.length) row.append(node('div','Use validate-exchanges for the remaining candidate bytes.','small muted'));
  row.append(node('div','Byte equality is provisional evidence; a checksum can also match.','small muted'));
  byId('exchangeValidation').append(row);
}
if(!(state.exchange_validations||[]).length) byId('exchangeValidation').append(node('div','Separate discovery and validation captures in one experiment to test paired byte equality.','small muted'));
if(state.cluster_report) {
  const sample=state.cluster_report;
  byId('clusters').append(node('div','Analyzed '+sample.observation_count+' of '+sample.selected_observation_count+' selected observations · '+sample.sampling_method+(sample.sampling_strata_count?' · '+sample.sampling_strata_count+' strata':''),'small muted'));
  for(const cluster of state.cluster_report.clusters) {
    const row=node('div','', 'row');
    row.append(node('strong',cluster.id+' · '+cluster.member_count+' observation(s)'),node('div','Representative '+cluster.representative_observation_id+' · lengths '+cluster.minimum_length+'–'+cluster.maximum_length,'small muted'));
    const rules=cluster.split_rules.map(rule=>rule.kind==='direction'?'direction '+(rule.value||'unknown'):'byte['+rule.offset+']=0x'+rule.value.toString(16).padStart(2,'0')).join(' · ');
    row.append(node('div',rules||'No distinguishing rule','small'));
    row.append(node('div','Stable header bytes: '+(cluster.stable_header_bytes.map(item=>item.offset+':'+item.value.toString(16).padStart(2,'0')).join(' ')||'none'),'small muted'));
    const option=node('option',cluster.id+' · '+cluster.member_count); option.value=cluster.id; byId('clusterFilter').append(option);
    const button=node('button','Show observations','small'); button.onclick=()=>{byId('clusterFilter').value=cluster.id;renderObservations();}; row.append(button);
    byId('clusters').append(row);
  }
} else byId('clusters').append(node('div',state.cluster_error||'No groups available.','small muted'));
for(const item of state.cluster_validations||[]) {
  const result=item.result, row=node('div','', 'row');
  row.append(node('strong',item.experiment_id+' · '+result.cluster_count+' discovery group(s)'),node('div',result.assigned_count+' assigned · '+result.ambiguous_count+' ambiguous · '+result.unassigned_count+' unassigned of '+result.validation_count+' evaluated held-out observations','small muted'),node('div','Discovery '+result.discovery_count+'/'+result.discovery_total+' ('+result.discovery_sampling_method+') · validation '+result.validation_count+'/'+result.validation_total+' ('+result.validation_sampling_method+')','small muted'),node('div',result.reported_observation_count+' detailed rows returned · '+result.omitted_observation_count+' omitted · counterexamples prioritized','small muted'));
  const priority={unassigned:0,ambiguous:1,assigned:2};
  const visible=result.observations.slice().sort((a,b)=>(priority[a.status]-priority[b.status])||a.observation_id.localeCompare(b.observation_id)).slice(0,12);
  for(const observation of visible) {
    const label=observation.assigned_cluster_id||observation.candidates.map(candidate=>candidate.cluster_id).join(', ')||'no compatible group';
    row.append(node('div',observation.observation_id+' · '+observation.status+' · '+label,'small'));
    if(observation.status==='unassigned') for(const rejected of observation.rejections.slice(0,3)) row.append(node('div','↳ '+rejected.cluster_id+' rejected: '+(rejected.insufficient_discovery_members?'fewer than 3 discovery members · ':'')+(rejected.direction_mismatch?'direction · ':'')+'header offsets '+(rejected.stable_byte_mismatch_offsets.join(', ')||'none'),'small muted'));
  }
  if(result.observations.length>visible.length) row.append(node('div','More of the returned details are available through validate-clusters.','small muted'));
  byId('clusterValidation').append(row);
}
if(!(state.cluster_validations||[]).length) byId('clusterValidation').append(node('div','Use discovery and validation trials to test proposed groups on held-out messages.','small muted'));
for(const analysis of state.analyses) {
  const row=node('div','', 'row');
  const scope=analysis.scope?.kind==='cluster'?'group '+analysis.scope.cluster_id:analysis.scope?.kind==='trial'?'trial '+analysis.scope.trial_id:analysis.scope?.kind||'legacy selection';
  row.append(node('strong',analysis.id),node('div',scope+' · '+analysis.observation_ids.length+' observations · '+analysis.aligned_width+' columns','small'));
  row.append(node('div',analysis.method_version||'method version not recorded','small muted'));
  byId('analyses').append(row);
}
if(!state.analyses.length) byId('analyses').append(node('div','No analyses recorded.','small muted'));
for(const decision of state.decisions) { const row=node('div','', 'row'); row.append(node('strong',decision.id),node('div',decision.text)); byId('decisions').append(row); }
for(const trial of state.trials) { const option=node('option',trial.id+' · '+trial.role); option.value=trial.id; byId('trialFilter').append(option); }
for(const observation of state.observations) {
  for(const target of ['leftCompare','rightCompare']) { const option=node('option',observation.id); option.value=observation.id; byId(target).append(option); }
}
function byteRow(label, values, peer) {
  const wrapper=node('div','', 'small'); wrapper.append(node('strong',label));
  const row=node('div','', 'bytes');
  for(let i=0;i<values.length;i++) row.append(node('span',values[i],values[i]===peer[i]?'byte':'byte changed'));
  wrapper.append(row); return wrapper;
}
function renderComparison() {
  const left=state.observations.find(x=>x.id===byId('leftCompare').value);
  const right=state.observations.find(x=>x.id===byId('rightCompare').value);
  const target=byId('comparison'); target.replaceChildren();
  if(!left||!right) { target.append(node('span','Choose two observations to highlight changed bytes.','muted')); return; }
  const width=Math.max(left.bytes_hex.length,right.bytes_hex.length)/2;
  let changedCount=0; const changedPreview=[];
  for(let i=0;i<width;i++) if(left.bytes_hex.slice(2*i,2*i+2)!==right.bytes_hex.slice(2*i,2*i+2)) { changedCount++; if(changedPreview.length<100) changedPreview.push(i); }
  target.append(node('div',changedCount+' changed byte position(s): '+(changedPreview.length?changedPreview.join(', ')+(changedCount>100?' …':''):'none'),'small muted'));
  const rows=node('div',''); const navigation=node('div','', 'byte-nav small'); const previous=node('button','Previous'), next=node('button','Next'), status=node('span','');
  let page=0; const pageSize=256;
  function draw() {
    const start=page*pageSize, end=Math.min(width,start+pageSize);
    const a=left.bytes_hex.slice(2*start,2*end).match(/../g)||[], b=right.bytes_hex.slice(2*start,2*end).match(/../g)||[];
    rows.replaceChildren(byteRow(left.id+' ['+start+', '+end+')',a,b),byteRow(right.id+' ['+start+', '+end+')',b,a));
    status.textContent='Bytes ['+start+', '+end+') of '+width; previous.disabled=page===0; next.disabled=end>=width;
  }
  previous.onclick=()=>{page--;draw();}; next.onclick=()=>{page++;draw();};
  if(width>pageSize) { navigation.append(previous,status,next); target.append(navigation); }
  target.append(rows); draw();
}
byId('leftCompare').onchange=renderComparison; byId('rightCompare').onchange=renderComparison;
const firstBaseline=state.observations.find(o=>trialById.get(captureById.get(o.capture_id).trial_id).role==='baseline');
const firstVariant=state.observations.find(o=>trialById.get(captureById.get(o.capture_id).trial_id).role==='variant');
if(firstBaseline&&firstVariant) { byId('leftCompare').value=firstBaseline.id; byId('rightCompare').value=firstVariant.id; }
renderComparison();
function showDetail(observation) {
  const capture=captureById.get(observation.capture_id);
  const trial=trialById.get(capture.trial_id);
  const framing=framingPreviewById.get(observation.id);
  const detail=byId('detail'); detail.replaceChildren();
  detail.append(node('strong',observation.id),node('div','Trial '+trial.id+' ('+trial.role+') · capture '+capture.id,'small'));
  detail.append(node('div','Source '+capture.source+' · '+capture.format+' · source index '+observation.source_index+(observation.source_offset===null?'':' · file offset '+observation.source_offset),'small muted'));
  if(observation.direction) detail.append(node('div',observation.direction+(observation.source_port===null?'':' · ports '+observation.source_port+' → '+observation.destination_port)+(observation.tcp_sequence===null?'':' · TCP seq '+observation.tcp_sequence),'small muted'));
  if(observation.source_spans?.length) {
    detail.append(node('div','Contiguous TCP run from '+observation.source_spans.length+' source span(s)'+(observation.stream_gap_before?' · gap before this run':''),'small muted'));
    const sources=node('details',''); sources.append(node('summary','Byte provenance'));
    for(const span of observation.source_spans) sources.append(node('div','Message ['+span.message_start+', '+span.message_end+') ← packet '+span.packet_index+' at file offset '+span.file_offset,'small muted'));
    detail.append(sources);
  }
  for(const tag of tagsFor(observation.id)) detail.append(node('span',tag.phase+': '+tag.label+(tag.action_id?' · '+tag.action_id:''),'pill'));
  for(const value of valuesFor(observation.id)) detail.append(node('span',value.variable+'='+value.value+' ('+value.set+')','pill'));
  if(framing) detail.append(node('div',(framing.committed?'Committed':'Candidate')+' record spans: '+framing.records.map(record=>'['+record.start+', '+record.end+')').join(' '),'small muted'));
  const total=observation.bytes_hex.length/2, pageSize=256;
  const bytes=node('div','', 'bytes'); const navigation=node('div','', 'byte-nav small');
  const previous=node('button','Previous'), next=node('button','Next'), status=node('span','');
  let page=0;
  function draw() {
    const start=page*pageSize, end=Math.min(total,start+pageSize); bytes.replaceChildren();
    for(let offset=start;offset<end;offset++) {
      const overlay=fieldOverlays.find(field=>field.observationIds.has(observation.id)&&offset>=field.start&&offset<field.end)||frameFieldOverlays.find(field=>field.observationId===observation.id&&offset>=field.start&&offset<field.end);
      const source=observation.source_spans?.find(span=>offset>=span.message_start&&offset<span.message_end);
      const packetStart=source&&source.message_start===offset&&offset!==0;
      const recordStart=framing?.records.find(record=>record.start===offset);
      const cell=node('span',observation.bytes_hex.slice(2*offset,2*offset+2),(overlay?'byte candidate':'byte')+(packetStart?' packet-start':'')+(recordStart?' record-start':''));
      cell.title=(overlay?overlay.variable+' candidate ['+overlay.start+', '+overlay.end+')':'byte '+offset)+(recordStart?' · '+(framing.committed?'committed':'proposed')+' record '+recordStart.index:'')+(source?' · packet '+source.packet_index+' · file offset '+(source.file_offset+offset-source.message_start):'');
      bytes.append(cell);
    }
    status.textContent='Bytes ['+start+', '+end+') of '+total; previous.disabled=page===0; next.disabled=end>=total;
  }
  previous.onclick=()=>{page--;draw();}; next.onclick=()=>{page++;draw();};
  if(total>pageSize) { navigation.append(previous,status,next); detail.append(navigation); }
  detail.append(bytes); draw();
  if(observation.source_spans?.length>1) detail.append(node('div','Blue left edge marks the first byte contributed by another packet. Hover a byte for its source offset.','small muted legend'));
  if(framing) detail.append(node('div','Gold left edge marks a '+(framing.committed?'committed record boundary.':'proposed record boundary supported by the held-out framing check.'),'small muted legend'));
  detail.append(node('div','Green outline marks the unique shortest candidate matching held-out values. Longer encodings may also fit; boundaries and meaning need protocol-level confirmation.','small muted legend'));
}
function renderObservations() {
  const selected=byId('trialFilter').value, cluster=clusterById.get(byId('clusterFilter').value), search=byId('search').value.toLowerCase();
  const list=byId('observations'); list.replaceChildren();
  const matches=state.observations.filter(o=>{ const c=captureById.get(o.capture_id); const labels=tagsFor(o.id).map(t=>t.label+' '+t.phase).join(' ')+valuesFor(o.id).map(v=>v.variable+'='+v.value).join(' '); return (!selected||c.trial_id===selected) && (!cluster||cluster.member_observation_ids.includes(o.id)) && (o.id+' '+o.bytes_hex+' '+(o.direction||'')+' '+(o.source_port??'')+' '+(o.destination_port??'')+' '+(o.tcp_sequence??'')+' '+labels).toLowerCase().includes(search); });
  list.append(node('div',matches.length+' of '+state.observations.length+' observations','small muted'));
  for(const o of matches) { const row=node('div','', 'row'); const button=node('button',o.id+' · '+(o.bytes_hex.slice(0,80).match(/../g)||[]).join(' ')); button.onclick=()=>showDetail(o); row.append(button,node('div',(o.direction||'')+(o.source_port===null?'':' · '+o.source_port+' → '+o.destination_port)+' '+tagsFor(o.id).map(t=>'['+t.phase+': '+t.label+']').join(' '),'small muted')); list.append(row); }
}
byId('trialFilter').onchange=renderObservations; byId('clusterFilter').onchange=renderObservations; byId('search').oninput=renderObservations; renderObservations();
if(state.observations.length) showDetail(state.observations[0]);
</script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_untrusted_question_in_embedded_data() {
        let mut state = crate::workflow::create_test_state();
        state.question = "</script><script>alert(1)</script>".into();
        let html = render(&state);
        assert!(!html.contains("</script><script>alert(1)</script>"));
        assert!(html.contains("\\u003c/script\\u003e"));
    }
}

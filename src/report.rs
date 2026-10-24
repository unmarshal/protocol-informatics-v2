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
    view["field_inferences"] =
        serde_json::to_value(inferences).expect("inferences are serializable");
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
.byte-nav { display:flex; gap:10px; align-items:center; margin-top:12px }
.byte-nav button { background:#243448; color:#e9eef5; border:1px solid #4a607a; border-radius:5px; padding:4px 8px; cursor:pointer }
.byte-nav button:disabled { opacity:.4; cursor:default }
.legend { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px }
@media(max-width:850px) { .layout { grid-template-columns:1fr } }
</style>
</head>
<body>
<header><div class="muted">Protocol Informatics v2 · investigation revision <span id="revision"></span></div><h1 id="question"></h1><div class="metrics" id="metrics"></div></header>
<main class="layout">
  <div class="stack">
    <section class="panel"><h2>Hypotheses</h2><div id="hypotheses"></div></section>
    <section class="panel"><h2>Experiments and trials</h2><div id="experiments"></div></section>
    <section class="panel"><h2>Candidate format groups</h2><div id="clusters"></div></section>
    <section class="panel"><h2>Candidate fields</h2><div id="fieldCandidates"></div></section>
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
const tagsFor = id => state.tags.filter(x=>x.observation_id===id);
const valuesFor = id => state.known_values.filter(x=>x.observation_id===id);
const fieldOverlays = state.field_inferences.flatMap(inference => {
  const preferred=inference.candidates.filter(candidate=>candidate.preferred);
  const observationIds=new Set(state.known_values.filter(value=>value.variable===inference.variable).map(value=>value.observation_id));
  return !inference.truncated&&inference.preferred_candidate_count===1 ? [{variable:inference.variable,observationIds,...preferred[0]}] : [];
});
byId('revision').textContent=state.revision;
byId('question').textContent=state.question;
for(const [label,count] of [['Observations',state.observations.length],['Captures',state.captures.length],['Hypotheses',state.hypotheses.length],['Experiments',state.experiments.length]]) {
  const box=node('div','', 'metric'); box.append(node('strong',String(count)),node('span',label)); byId('metrics').append(box);
}
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
for(const experiment of state.experiments) {
  const row=node('div','', 'row'); row.append(node('strong',experiment.id+' · '+experiment.question),node('div','Prediction: '+experiment.prediction,'small muted'));
  for(const trial of state.trials.filter(x=>x.experiment_id===experiment.id)) {
    const captures=state.captures.filter(x=>x.trial_id===trial.id);
    row.append(node('div',trial.id+' · '+trial.role+' · '+trial.changed_factor+' · '+captures.length+' capture(s)','small'));
    for(const action of state.actions.filter(x=>x.trial_id===trial.id)) row.append(node('div','↳ '+action.kind+': '+action.detail,'small muted'));
  }
  byId('experiments').append(row);
}
if(state.cluster_report) {
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
  const detail=byId('detail'); detail.replaceChildren();
  detail.append(node('strong',observation.id),node('div','Trial '+trial.id+' ('+trial.role+') · capture '+capture.id,'small'));
  detail.append(node('div','Source '+capture.source+' · '+capture.format+' · source index '+observation.source_index+(observation.source_offset===null?'':' · file offset '+observation.source_offset),'small muted'));
  if(observation.direction) detail.append(node('div',observation.direction+(observation.source_port===null?'':' · UDP ports '+observation.source_port+' → '+observation.destination_port),'small muted'));
  for(const tag of tagsFor(observation.id)) detail.append(node('span',tag.phase+': '+tag.label,'pill'));
  for(const value of valuesFor(observation.id)) detail.append(node('span',value.variable+'='+value.value+' ('+value.set+')','pill'));
  const total=observation.bytes_hex.length/2, pageSize=256;
  const bytes=node('div','', 'bytes'); const navigation=node('div','', 'byte-nav small');
  const previous=node('button','Previous'), next=node('button','Next'), status=node('span','');
  let page=0;
  function draw() {
    const start=page*pageSize, end=Math.min(total,start+pageSize); bytes.replaceChildren();
    for(let offset=start;offset<end;offset++) {
      const overlay=fieldOverlays.find(field=>field.observationIds.has(observation.id)&&offset>=field.start&&offset<field.end);
      const cell=node('span',observation.bytes_hex.slice(2*offset,2*offset+2),overlay?'byte candidate':'byte');
      cell.title=overlay?overlay.variable+' candidate ['+overlay.start+', '+overlay.end+')':'byte '+offset;
      bytes.append(cell);
    }
    status.textContent='Bytes ['+start+', '+end+') of '+total; previous.disabled=page===0; next.disabled=end>=total;
  }
  previous.onclick=()=>{page--;draw();}; next.onclick=()=>{page++;draw();};
  if(total>pageSize) { navigation.append(previous,status,next); detail.append(navigation); }
  detail.append(bytes); draw();
  detail.append(node('div','Green outline marks the unique shortest candidate matching held-out values. Longer encodings may also fit; boundaries and meaning need protocol-level confirmation.','small muted legend'));
}
function renderObservations() {
  const selected=byId('trialFilter').value, cluster=clusterById.get(byId('clusterFilter').value), search=byId('search').value.toLowerCase();
  const list=byId('observations'); list.replaceChildren();
  const matches=state.observations.filter(o=>{ const c=captureById.get(o.capture_id); const labels=tagsFor(o.id).map(t=>t.label+' '+t.phase).join(' ')+valuesFor(o.id).map(v=>v.variable+'='+v.value).join(' '); return (!selected||c.trial_id===selected) && (!cluster||cluster.member_observation_ids.includes(o.id)) && (o.id+' '+o.bytes_hex+' '+(o.direction||'')+' '+(o.source_port??'')+' '+(o.destination_port??'')+' '+labels).toLowerCase().includes(search); });
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

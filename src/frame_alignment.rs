//! Bounded alignment of one provisional committed-frame group.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::clustering;
use crate::workflow::{State, from_hex};
use crate::{CpuAligner, analyze_best};

const MAX_ALIGNED_FRAMES: usize = 32;
const MAX_FRAME_BYTES: usize = 4096;
const MAX_ALIGNMENT_CELLS: u128 = 25_000_000;

#[derive(Debug, Serialize)]
pub struct FrameAlignmentReport {
    pub revision: u64,
    pub coordinate_system: &'static str,
    pub source_model: String,
    pub cluster_id: String,
    pub trial_id: Option<String>,
    pub direction_mode: &'static str,
    pub run_keys: Vec<String>,
    pub selected_frame_count: usize,
    pub aligned_frame_count: usize,
    pub omitted_frame_count: usize,
    pub sampling_method: &'static str,
    pub maximum_aligned_frames: usize,
    pub maximum_frame_bytes: usize,
    pub maximum_alignment_cells: u128,
    pub frame_ids: Vec<String>,
    pub reference_frame_id: String,
    pub analysis: Value,
}

pub fn align_frame_cluster(
    state: &State,
    model: &str,
    cluster_id: &str,
    trial_id: Option<&str>,
    respect_direction: bool,
    run_keys: Option<&[String]>,
) -> Result<FrameAlignmentReport, String> {
    let grouping = clustering::cluster_frames(state, model, trial_id, respect_direction, run_keys)?;
    let cluster = grouping
        .clusters
        .iter()
        .find(|cluster| cluster.id == cluster_id)
        .ok_or_else(|| {
            format!(
                "unknown frame cluster {cluster_id} at revision {}",
                state.revision
            )
        })?;
    let selected_frame_count = cluster.member_frame_ids.len();
    let (frame_ids, sampling_method) = if selected_frame_count <= MAX_ALIGNED_FRAMES {
        (cluster.member_frame_ids.clone(), "all")
    } else {
        let mut chosen = BTreeSet::new();
        chosen.insert(cluster.representative_frame_id.as_str());
        for outlier in &cluster.farthest_members {
            chosen.insert(outlier.frame_id.as_str());
        }
        let mut ranked: Vec<_> = cluster.member_frame_ids.iter().collect();
        ranked.sort_by(|left, right| {
            Sha256::digest(left.as_bytes())
                .cmp(&Sha256::digest(right.as_bytes()))
                .then_with(|| left.cmp(right))
        });
        for id in ranked {
            if chosen.len() == MAX_ALIGNED_FRAMES {
                break;
            }
            chosen.insert(id.as_str());
        }
        (
            cluster
                .member_frame_ids
                .iter()
                .filter(|id| chosen.contains(id.as_str()))
                .cloned()
                .collect(),
            "representative_outliers_then_hash_v1",
        )
    };
    let observations: BTreeMap<_, _> = state
        .observations
        .iter()
        .map(|observation| (observation.id.as_str(), observation))
        .collect();
    let mut samples = Vec::with_capacity(frame_ids.len());
    for id in &frame_ids {
        let (_, observation_id, bounds) = state
            .frame_by_id(id)
            .ok_or_else(|| format!("unknown frame {id}"))?;
        let observation = observations
            .get(observation_id)
            .ok_or_else(|| format!("unknown observation {observation_id}"))?;
        let bytes = from_hex(&observation.bytes_hex)?;
        let logical = bytes
            .get(bounds.start..bounds.logical_end)
            .ok_or_else(|| format!("frame {id} exceeds parent observation"))?;
        if logical.is_empty() || logical.len() > MAX_FRAME_BYTES {
            return Err(format!(
                "frame {id} has {} logical bytes; alignment requires 1 to {MAX_FRAME_BYTES}",
                logical.len()
            ));
        }
        samples.push(logical.to_vec());
    }
    let maximum_length = samples.iter().map(Vec::len).max().unwrap_or_default();
    let cell_estimate: u128 = samples
        .iter()
        .map(|sample| (maximum_length as u128 + 1) * (sample.len() as u128 + 1))
        .sum();
    if cell_estimate > MAX_ALIGNMENT_CELLS {
        return Err(format!(
            "alignment would examine about {cell_estimate} pairwise cells; maximum is {MAX_ALIGNMENT_CELLS}"
        ));
    }
    let analysis = analyze_best(&samples, &CpuAligner).map_err(|error| error.to_string())?;
    let reference_frame_id = frame_ids[analysis.reference_index].clone();
    let analysis = serde_json::from_str(&analysis.to_json()).map_err(|error| error.to_string())?;
    Ok(FrameAlignmentReport {
        revision: state.revision,
        coordinate_system: "logical_frame_bytes",
        source_model: model.into(),
        cluster_id: cluster_id.into(),
        trial_id: trial_id.map(str::to_owned),
        direction_mode: if respect_direction {
            "respect"
        } else {
            "ignore"
        },
        run_keys: grouping.run_keys,
        selected_frame_count,
        aligned_frame_count: frame_ids.len(),
        omitted_frame_count: selected_frame_count - frame_ids.len(),
        sampling_method,
        maximum_aligned_frames: MAX_ALIGNED_FRAMES,
        maximum_frame_bytes: MAX_FRAME_BYTES,
        maximum_alignment_cells: MAX_ALIGNMENT_CELLS,
        frame_ids,
        reference_frame_id,
        analysis,
    })
}

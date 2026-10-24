//! Conservative, inspectable message-format grouping. A low-cardinality byte
//! only splits a group when another stable byte or length differs between the
//! proposed children. Clusters are provisional format hypotheses.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::workflow::{State, from_hex};

const MAX_OBSERVATIONS: usize = 512;
const MAX_CLUSTERS: usize = 32;
const MAX_DEPTH: usize = 4;
const MAX_HEADER_BYTES: usize = 16;
const MAX_DISTANCE_BYTES: usize = 256;
const MIN_CHILD_SIZE: usize = 3;
const MIN_EVIDENCE_SEPARATION: usize = 4;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SplitRule {
    Direction {
        value: Option<String>,
    },
    Byte {
        offset: usize,
        value: u8,
        evidence_offsets: Vec<usize>,
        evidence_length: bool,
    },
}

#[derive(Debug, Serialize)]
pub struct StableByte {
    pub offset: usize,
    pub value: u8,
}

#[derive(Debug, Serialize)]
pub struct OutlierCandidate {
    pub observation_id: String,
    pub distance_to_representative: f64,
}

#[derive(Debug, Serialize)]
pub struct Cluster {
    pub id: String,
    pub member_observation_ids: Vec<String>,
    pub representative_observation_id: String,
    pub member_count: usize,
    pub minimum_length: usize,
    pub maximum_length: usize,
    pub split_rules: Vec<SplitRule>,
    pub stable_header_bytes: Vec<StableByte>,
    pub farthest_members: Vec<OutlierCandidate>,
}

#[derive(Debug, Serialize)]
pub struct ClusterReport {
    pub revision: u64,
    pub method: &'static str,
    pub provisional: bool,
    pub direction_mode: &'static str,
    pub trial_id: Option<String>,
    pub observation_count: usize,
    pub maximum_observations: usize,
    pub maximum_header_bytes: usize,
    pub maximum_distance_bytes: usize,
    pub minimum_evidence_separation: usize,
    pub clusters: Vec<Cluster>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Assigned,
    Ambiguous,
    Unassigned,
}

#[derive(Debug, Serialize)]
pub struct ClusterMatch {
    pub cluster_id: String,
    pub distance_to_representative: f64,
}

#[derive(Debug, Serialize)]
pub struct RejectedCluster {
    pub cluster_id: String,
    pub insufficient_discovery_members: bool,
    pub direction_mismatch: bool,
    pub stable_byte_mismatch_offsets: Vec<usize>,
}

#[derive(Debug, Serialize)]
pub struct ValidationObservation {
    pub observation_id: String,
    pub status: ValidationStatus,
    pub assigned_cluster_id: Option<String>,
    pub compatible_cluster_count: usize,
    pub candidates_truncated: bool,
    pub candidates: Vec<ClusterMatch>,
    pub rejected_cluster_count: usize,
    pub rejections_truncated: bool,
    pub rejections: Vec<RejectedCluster>,
}

#[derive(Debug, Serialize)]
pub struct ClusterValidation {
    pub revision: u64,
    pub method: &'static str,
    pub provisional: bool,
    pub discovery_trial_id: String,
    pub validation_trial_id: String,
    pub direction_mode: &'static str,
    pub discovery_count: usize,
    pub validation_count: usize,
    pub cluster_count: usize,
    pub assigned_count: usize,
    pub ambiguous_count: usize,
    pub unassigned_count: usize,
    pub ambiguity_distance_margin: f64,
    pub maximum_reported_candidates_per_observation: usize,
    pub clusters: Vec<Cluster>,
    pub observations: Vec<ValidationObservation>,
}

const AMBIGUITY_DISTANCE_MARGIN: f64 = 0.05;
const MAX_REPORTED_MATCHES: usize = 5;

pub fn validate_clusters(
    state: &State,
    discovery_trial_id: &str,
    validation_trial_id: &str,
    respect_direction: bool,
) -> Result<ClusterValidation, String> {
    let discovery_trial = state
        .trials
        .iter()
        .find(|trial| trial.id == discovery_trial_id)
        .ok_or_else(|| format!("unknown trial {discovery_trial_id}"))?;
    let validation_trial = state
        .trials
        .iter()
        .find(|trial| trial.id == validation_trial_id)
        .ok_or_else(|| format!("unknown trial {validation_trial_id}"))?;
    if discovery_trial_id == validation_trial_id
        || discovery_trial.experiment_id != validation_trial.experiment_id
    {
        return Err("discovery and validation must be distinct trials of one experiment".into());
    }
    let report = cluster_observations(state, Some(discovery_trial_id), respect_direction)?;
    let validation: Vec<_> = state
        .observations
        .iter()
        .filter(|observation| {
            state.captures.iter().any(|capture| {
                capture.id == observation.capture_id && capture.trial_id == validation_trial_id
            })
        })
        .collect();
    if validation.is_empty() || validation.len() > MAX_OBSERVATIONS {
        return Err(format!(
            "validation trial needs 1 to {MAX_OBSERVATIONS} observations"
        ));
    }
    let mut representatives = BTreeMap::new();
    for cluster in &report.clusters {
        let representative = state
            .observations
            .iter()
            .find(|observation| observation.id == cluster.representative_observation_id)
            .ok_or_else(|| {
                format!(
                    "unknown representative {}",
                    cluster.representative_observation_id
                )
            })?;
        representatives.insert(cluster.id.as_str(), from_hex(&representative.bytes_hex)?);
    }
    let mut observations = Vec::new();
    let mut assigned_count = 0;
    let mut ambiguous_count = 0;
    let mut unassigned_count = 0;
    for observation in validation {
        let bytes = from_hex(&observation.bytes_hex)?;
        let mut candidates = Vec::new();
        let mut rejections = Vec::new();
        for cluster in &report.clusters {
            let enough_members = cluster.member_count >= MIN_CHILD_SIZE;
            let direction_fits = cluster.split_rules.iter().all(|rule| match rule {
                SplitRule::Direction { value } => value == &observation.direction,
                SplitRule::Byte { .. } => true,
            });
            let stable_byte_mismatch_offsets: Vec<_> = cluster
                .stable_header_bytes
                .iter()
                .filter(|stable| bytes.get(stable.offset) != Some(&stable.value))
                .map(|stable| stable.offset)
                .collect();
            if enough_members && direction_fits && stable_byte_mismatch_offsets.is_empty() {
                let representative = representatives
                    .get(cluster.id.as_str())
                    .expect("every cluster has a representative");
                candidates.push(ClusterMatch {
                    cluster_id: cluster.id.clone(),
                    distance_to_representative: sample_distance(&bytes, representative),
                });
            } else {
                rejections.push(RejectedCluster {
                    cluster_id: cluster.id.clone(),
                    insufficient_discovery_members: !enough_members,
                    direction_mismatch: !direction_fits,
                    stable_byte_mismatch_offsets,
                });
            }
        }
        candidates.sort_by(|a, b| {
            a.distance_to_representative
                .total_cmp(&b.distance_to_representative)
                .then_with(|| a.cluster_id.cmp(&b.cluster_id))
        });
        let compatible_cluster_count = candidates.len();
        let status = if candidates.is_empty() {
            unassigned_count += 1;
            ValidationStatus::Unassigned
        } else if candidates.len() > 1
            && candidates[1].distance_to_representative - candidates[0].distance_to_representative
                <= AMBIGUITY_DISTANCE_MARGIN
        {
            ambiguous_count += 1;
            ValidationStatus::Ambiguous
        } else {
            assigned_count += 1;
            ValidationStatus::Assigned
        };
        let assigned_cluster_id =
            (status == ValidationStatus::Assigned).then(|| candidates[0].cluster_id.clone());
        candidates.truncate(MAX_REPORTED_MATCHES);
        rejections.sort_by(|a, b| {
            (usize::from(a.insufficient_discovery_members)
                + usize::from(a.direction_mismatch)
                + a.stable_byte_mismatch_offsets.len())
            .cmp(
                &(usize::from(b.insufficient_discovery_members)
                    + usize::from(b.direction_mismatch)
                    + b.stable_byte_mismatch_offsets.len()),
            )
            .then_with(|| a.cluster_id.cmp(&b.cluster_id))
        });
        let rejected_cluster_count = rejections.len();
        rejections.truncate(MAX_REPORTED_MATCHES);
        observations.push(ValidationObservation {
            observation_id: observation.id.clone(),
            status,
            assigned_cluster_id,
            compatible_cluster_count,
            candidates_truncated: compatible_cluster_count > MAX_REPORTED_MATCHES,
            candidates,
            rejected_cluster_count,
            rejections_truncated: rejected_cluster_count > MAX_REPORTED_MATCHES,
            rejections,
        });
    }
    Ok(ClusterValidation {
        revision: state.revision,
        method: "stable_header_and_medoid_held_out_v1",
        provisional: true,
        discovery_trial_id: discovery_trial_id.into(),
        validation_trial_id: validation_trial_id.into(),
        direction_mode: report.direction_mode,
        discovery_count: report.observation_count,
        validation_count: observations.len(),
        cluster_count: report.clusters.len(),
        assigned_count,
        ambiguous_count,
        unassigned_count,
        ambiguity_distance_margin: AMBIGUITY_DISTANCE_MARGIN,
        maximum_reported_candidates_per_observation: MAX_REPORTED_MATCHES,
        clusters: report.clusters,
        observations,
    })
}

struct Sample {
    id: String,
    direction: Option<String>,
    bytes: Vec<u8>,
}

struct Partition {
    members: Vec<usize>,
    rules: Vec<SplitRule>,
}

struct Split {
    offset: usize,
    groups: BTreeMap<u8, Vec<usize>>,
    evidence_offsets: Vec<usize>,
    evidence_length: bool,
}

pub fn cluster_observations(
    state: &State,
    trial_id: Option<&str>,
    respect_direction: bool,
) -> Result<ClusterReport, String> {
    if let Some(id) = trial_id
        && !state.trials.iter().any(|trial| trial.id == id)
    {
        return Err(format!("unknown trial {id}"));
    }
    let selected: Vec<_> = state
        .observations
        .iter()
        .filter(|observation| {
            trial_id.is_none_or(|id| {
                state
                    .captures
                    .iter()
                    .any(|capture| capture.id == observation.capture_id && capture.trial_id == id)
            })
        })
        .collect();
    if selected.is_empty() {
        return Err("no observations selected".into());
    }
    if selected.len() > MAX_OBSERVATIONS {
        return Err(format!(
            "clustering supports at most {MAX_OBSERVATIONS} observations per query"
        ));
    }
    let samples: Vec<Sample> = selected
        .iter()
        .map(|observation| {
            Ok(Sample {
                id: observation.id.clone(),
                direction: observation.direction.clone(),
                bytes: from_hex(&observation.bytes_hex)?,
            })
        })
        .collect::<Result<_, String>>()?;
    let mut partitions = if respect_direction {
        let mut groups = BTreeMap::<Option<String>, Vec<usize>>::new();
        for (index, sample) in samples.iter().enumerate() {
            groups
                .entry(sample.direction.clone())
                .or_default()
                .push(index);
        }
        groups
            .into_iter()
            .map(|(direction, members)| Partition {
                members,
                rules: vec![SplitRule::Direction { value: direction }],
            })
            .collect::<Vec<_>>()
    } else {
        vec![Partition {
            members: (0..samples.len()).collect(),
            rules: Vec::new(),
        }]
    };
    if partitions.len() > MAX_CLUSTERS {
        return Err(format!("direction groups exceed {MAX_CLUSTERS} clusters"));
    }
    for _ in 0..MAX_DEPTH {
        let mut next = Vec::new();
        let mut changed = false;
        let partition_count = partitions.len();
        for (position, partition) in partitions.into_iter().enumerate() {
            if let Some(split) = choose_split(&samples, &partition.members)
                && next.len() + split.groups.len() + partition_count - position - 1 <= MAX_CLUSTERS
            {
                for (value, members) in split.groups {
                    let mut rules = partition.rules.clone();
                    rules.push(SplitRule::Byte {
                        offset: split.offset,
                        value,
                        evidence_offsets: split.evidence_offsets.clone(),
                        evidence_length: split.evidence_length,
                    });
                    next.push(Partition { members, rules });
                }
                changed = true;
            } else {
                next.push(partition);
            }
        }
        partitions = next;
        if !changed {
            break;
        }
    }
    let mut clusters: Vec<_> = partitions
        .into_iter()
        .map(|partition| summarize(&samples, partition))
        .collect();
    clusters.sort_by(|left, right| {
        left.member_observation_ids[0].cmp(&right.member_observation_ids[0])
    });
    Ok(ClusterReport {
        revision: state.revision,
        method: "direction_then_correlated_discriminator_v1",
        provisional: true,
        direction_mode: if respect_direction {
            "respect"
        } else {
            "ignore"
        },
        trial_id: trial_id.map(str::to_owned),
        observation_count: samples.len(),
        maximum_observations: MAX_OBSERVATIONS,
        maximum_header_bytes: MAX_HEADER_BYTES,
        maximum_distance_bytes: MAX_DISTANCE_BYTES,
        minimum_evidence_separation: MIN_EVIDENCE_SEPARATION,
        clusters,
    })
}

fn choose_split(samples: &[Sample], members: &[usize]) -> Option<Split> {
    if members.len() < MIN_CHILD_SIZE * 2 {
        return None;
    }
    let header_length = members
        .iter()
        .map(|index| samples[*index].bytes.len())
        .min()?
        .min(MAX_HEADER_BYTES);
    let mut best: Option<Split> = None;
    let mut best_score = 0;
    for offset in 0..header_length {
        let mut groups = BTreeMap::<u8, Vec<usize>>::new();
        for index in members {
            groups
                .entry(samples[*index].bytes[offset])
                .or_default()
                .push(*index);
        }
        if groups.len() < 2
            || groups.len() > 4
            || groups.values().any(|group| group.len() < MIN_CHILD_SIZE)
        {
            continue;
        }
        let mut evidence_offsets = Vec::new();
        for other_offset in 0..header_length {
            if other_offset.abs_diff(offset) < MIN_EVIDENCE_SEPARATION {
                continue;
            }
            let constants: Option<Vec<u8>> = groups
                .values()
                .map(|group| {
                    let first = samples[group[0]].bytes[other_offset];
                    group
                        .iter()
                        .all(|index| samples[*index].bytes[other_offset] == first)
                        .then_some(first)
                })
                .collect();
            if let Some(constants) = constants
                && constants.iter().copied().collect::<BTreeSet<_>>().len() == groups.len()
            {
                evidence_offsets.push(other_offset);
            }
        }
        let lengths: Option<Vec<usize>> = groups
            .values()
            .map(|group| {
                let first = samples[group[0]].bytes.len();
                group
                    .iter()
                    .all(|index| samples[*index].bytes.len() == first)
                    .then_some(first)
            })
            .collect();
        let evidence_length = lengths.is_some_and(|values| {
            values.into_iter().collect::<BTreeSet<_>>().len() == groups.len()
        });
        let score = evidence_offsets.len() + usize::from(evidence_length);
        if score > best_score {
            best_score = score;
            best = Some(Split {
                offset,
                groups,
                evidence_offsets,
                evidence_length,
            });
        }
    }
    best
}

fn sample_distance(left: &[u8], right: &[u8]) -> f64 {
    let left_prefix = &left[..left.len().min(MAX_DISTANCE_BYTES)];
    let right_prefix = &right[..right.len().min(MAX_DISTANCE_BYTES)];
    let width = left_prefix.len().max(right_prefix.len());
    let positional = if width == 0 {
        0.0
    } else {
        let changed = (0..width)
            .filter(|index| left_prefix.get(*index) != right_prefix.get(*index))
            .count();
        changed as f64 / width as f64
    };
    let length_width = left.len().max(right.len());
    let length_penalty = if length_width == 0 {
        0.0
    } else {
        left.len().abs_diff(right.len()) as f64 / length_width as f64
    };
    0.8 * positional + 0.2 * length_penalty
}

fn summarize(samples: &[Sample], partition: Partition) -> Cluster {
    let mut members = partition.members;
    members.sort_by(|left, right| samples[*left].id.cmp(&samples[*right].id));
    let mut representative = members[0];
    let mut best_sum = f64::INFINITY;
    for candidate in &members {
        let total: f64 = members
            .iter()
            .map(|other| sample_distance(&samples[*candidate].bytes, &samples[*other].bytes))
            .sum();
        if total < best_sum {
            best_sum = total;
            representative = *candidate;
        }
    }
    let minimum_length = members
        .iter()
        .map(|index| samples[*index].bytes.len())
        .min()
        .unwrap_or(0);
    let maximum_length = members
        .iter()
        .map(|index| samples[*index].bytes.len())
        .max()
        .unwrap_or(0);
    let stable_header_bytes = (0..minimum_length.min(MAX_HEADER_BYTES))
        .filter_map(|offset| {
            let first = samples[members[0]].bytes[offset];
            members
                .iter()
                .all(|index| samples[*index].bytes[offset] == first)
                .then_some(StableByte {
                    offset,
                    value: first,
                })
        })
        .collect();
    let mut farthest_members: Vec<_> = members
        .iter()
        .filter(|index| **index != representative)
        .map(|index| OutlierCandidate {
            observation_id: samples[*index].id.clone(),
            distance_to_representative: sample_distance(
                &samples[representative].bytes,
                &samples[*index].bytes,
            ),
        })
        .collect();
    farthest_members.sort_by(|left, right| {
        right
            .distance_to_representative
            .total_cmp(&left.distance_to_representative)
            .then_with(|| left.observation_id.cmp(&right.observation_id))
    });
    farthest_members.truncate(3);
    let member_observation_ids: Vec<_> = members
        .iter()
        .map(|index| samples[*index].id.clone())
        .collect();
    let mut digest = Sha256::new();
    for id in &member_observation_ids {
        digest.update(id.as_bytes());
        digest.update([0]);
    }
    let hash = format!("{:x}", digest.finalize());
    Cluster {
        id: format!("cluster-{}", &hash[..12]),
        member_count: members.len(),
        representative_observation_id: samples[representative].id.clone(),
        member_observation_ids,
        minimum_length,
        maximum_length,
        split_rules: partition.rules,
        stable_header_bytes,
        farthest_members,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::Observation;

    #[test]
    fn splits_only_when_a_second_field_supports_the_type_byte() {
        let mut state = crate::workflow::create_test_state();
        for (index, bytes) in [
            "01a0b0c01001",
            "01a1b1c11002",
            "01a2b2c21003",
            "02d0e0f02004",
            "02d1e1f12005",
            "02d2e2f22006",
        ]
        .into_iter()
        .enumerate()
        {
            state.observations.push(Observation {
                id: format!("obs-{index}"),
                capture_id: "capture".into(),
                source_index: index,
                source_offset: None,
                timestamp_ns: None,
                direction: None,
                source_port: None,
                destination_port: None,
                tcp_sequence: None,
                stream_gap_before: false,
                source_spans: Vec::new(),
                bytes_hex: bytes.into(),
            });
        }
        let report = cluster_observations(&state, None, false).unwrap();
        assert_eq!(report.clusters.len(), 2);
        assert_eq!(report.clusters[0].member_count, 3);
        assert_eq!(report.clusters[1].member_count, 3);
        assert!(matches!(
            &report.clusters[0].split_rules[0],
            SplitRule::Byte {
                offset: 0,
                evidence_offsets,
                ..
            } if evidence_offsets == &[4]
        ));
    }

    #[test]
    fn does_not_split_a_counter_without_independent_format_evidence() {
        let mut state = crate::workflow::create_test_state();
        for index in 0..8 {
            state.observations.push(Observation {
                id: format!("obs-{index}"),
                capture_id: "capture".into(),
                source_index: index,
                source_offset: None,
                timestamp_ns: None,
                direction: None,
                source_port: None,
                destination_port: None,
                tcp_sequence: None,
                stream_gap_before: false,
                source_spans: Vec::new(),
                bytes_hex: format!("aa{index:02x}55"),
            });
        }
        let report = cluster_observations(&state, None, false).unwrap();
        assert_eq!(report.clusters.len(), 1);
        assert_eq!(report.clusters[0].member_count, 8);
    }
}

//! Conservative, inspectable message-format grouping. A low-cardinality byte
//! only splits a group when another stable byte or length differs between the
//! proposed children. Clusters are provisional format hypotheses.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::workflow::{Observation, State, from_hex};

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
    pub selected_observation_count: usize,
    pub observation_count: usize,
    pub sampling_method: &'static str,
    pub sampling_strata_count: usize,
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

#[derive(Debug, Clone, Serialize)]
pub struct ClusterMatch {
    pub cluster_id: String,
    pub distance_to_representative: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RejectedCluster {
    pub cluster_id: String,
    pub insufficient_discovery_members: bool,
    pub direction_mismatch: bool,
    pub stable_byte_mismatch_offsets: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
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
    pub discovery_total: usize,
    pub discovery_sampling_method: &'static str,
    pub validation_count: usize,
    pub validation_total: usize,
    pub validation_sampling_method: &'static str,
    pub maximum_full_validation_observations: usize,
    pub cluster_count: usize,
    pub assigned_count: usize,
    pub ambiguous_count: usize,
    pub unassigned_count: usize,
    pub ambiguity_distance_margin: f64,
    pub maximum_reported_candidates_per_observation: usize,
    pub maximum_reported_observations: usize,
    pub reported_observation_count: usize,
    pub omitted_observation_count: usize,
    pub reported_counterexample_count: usize,
    pub detail_selection_method: &'static str,
    pub clusters: Vec<Cluster>,
    pub observations: Vec<ValidationObservation>,
}

const AMBIGUITY_DISTANCE_MARGIN: f64 = 0.05;
const MAX_REPORTED_MATCHES: usize = 5;
const MAX_FULL_VALIDATION_OBSERVATIONS: usize = 10_000;
const MAX_REPORTED_VALIDATION_OBSERVATIONS: usize = 512;

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
    if validation.is_empty() {
        return Err("validation trial has no observations".into());
    }
    let validation_total = validation.len();
    let (validation, validation_sampling_method) =
        if validation_total <= MAX_FULL_VALIDATION_OBSERVATIONS {
            (validation, "all")
        } else {
            let (sample, method, _) = sample_observations(&validation);
            (sample, method)
        };
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
    let validation_count = observations.len();
    let (observations, detail_selection_method) =
        select_validation_details(observations, MAX_REPORTED_VALIDATION_OBSERVATIONS);
    let reported_observation_count = observations.len();
    let reported_counterexample_count = observations
        .iter()
        .filter(|observation| observation.status != ValidationStatus::Assigned)
        .count();
    Ok(ClusterValidation {
        revision: state.revision,
        method: "stable_header_and_medoid_held_out_v3",
        provisional: true,
        discovery_trial_id: discovery_trial_id.into(),
        validation_trial_id: validation_trial_id.into(),
        direction_mode: report.direction_mode,
        discovery_count: report.observation_count,
        discovery_total: report.selected_observation_count,
        discovery_sampling_method: report.sampling_method,
        validation_count,
        validation_total,
        validation_sampling_method,
        maximum_full_validation_observations: MAX_FULL_VALIDATION_OBSERVATIONS,
        cluster_count: report.clusters.len(),
        assigned_count,
        ambiguous_count,
        unassigned_count,
        ambiguity_distance_margin: AMBIGUITY_DISTANCE_MARGIN,
        maximum_reported_candidates_per_observation: MAX_REPORTED_MATCHES,
        maximum_reported_observations: MAX_REPORTED_VALIDATION_OBSERVATIONS,
        reported_observation_count,
        omitted_observation_count: validation_count - reported_observation_count,
        reported_counterexample_count,
        detail_selection_method,
        clusters: report.clusters,
        observations,
    })
}

fn select_validation_details(
    observations: Vec<ValidationObservation>,
    limit: usize,
) -> (Vec<ValidationObservation>, &'static str) {
    if observations.len() <= limit {
        return (observations, "all");
    }
    let mut chosen = Vec::with_capacity(limit);
    for status in [ValidationStatus::Unassigned, ValidationStatus::Ambiguous] {
        let remaining = limit - chosen.len();
        chosen.extend(
            observations
                .iter()
                .enumerate()
                .filter_map(|(index, observation)| (observation.status == status).then_some(index))
                .take(remaining),
        );
    }
    if chosen.len() < limit {
        let mut assigned: Vec<_> = observations
            .iter()
            .enumerate()
            .filter(|(_, observation)| observation.status == ValidationStatus::Assigned)
            .map(|(index, observation)| {
                (
                    Sha256::digest(observation.observation_id.as_bytes()).to_vec(),
                    index,
                )
            })
            .collect();
        assigned.sort_unstable_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| {
                observations[left.1]
                    .observation_id
                    .cmp(&observations[right.1].observation_id)
            })
        });
        let remaining = limit - chosen.len();
        chosen.extend(assigned.into_iter().take(remaining).map(|(_, index)| index));
    }
    chosen.sort_unstable();
    (
        chosen
            .into_iter()
            .map(|index| observations[index].clone())
            .collect(),
        "counterexamples_then_hash_v1",
    )
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

fn sample_observations<'a>(
    observations: &[&'a Observation],
) -> (Vec<&'a Observation>, &'static str, usize) {
    if observations.len() <= MAX_OBSERVATIONS {
        return (observations.to_vec(), "all", 0);
    }
    let digests: Vec<[u8; 32]> = observations
        .iter()
        .map(|observation| Sha256::digest(observation.id.as_bytes()).into())
        .collect();
    let rank = |left: &usize, right: &usize| {
        digests[*left]
            .cmp(&digests[*right])
            .then_with(|| observations[*left].id.cmp(&observations[*right].id))
    };
    let mut strata = BTreeMap::<(Option<String>, usize), Vec<usize>>::new();
    for (index, observation) in observations.iter().enumerate() {
        strata
            .entry((
                observation.direction.clone(),
                observation.bytes_hex.len() / 2,
            ))
            .or_default()
            .push(index);
    }
    let strata_count = strata.len();
    if strata_count > MAX_OBSERVATIONS {
        let mut indices: Vec<_> = (0..observations.len()).collect();
        indices.sort_unstable_by(rank);
        indices.truncate(MAX_OBSERVATIONS);
        indices.sort_unstable();
        return (
            indices
                .into_iter()
                .map(|index| observations[index])
                .collect(),
            "hash_v1",
            strata_count,
        );
    }
    let slots = MAX_OBSERVATIONS - strata_count;
    let extra_capacity = observations.len() - strata_count;
    let mut groups: Vec<_> = strata
        .into_values()
        .map(|indices| {
            let capacity = indices.len() - 1;
            let numerator = (slots as u128) * (capacity as u128);
            let extra = (numerator / extra_capacity as u128) as usize;
            let remainder = numerator % extra_capacity as u128;
            (indices, 1 + extra, remainder)
        })
        .collect();
    let assigned: usize = groups.iter().map(|(_, quota, _)| *quota).sum();
    let mut remainder_order: Vec<_> = (0..groups.len()).collect();
    remainder_order.sort_unstable_by(|left, right| {
        groups[*right]
            .2
            .cmp(&groups[*left].2)
            .then_with(|| left.cmp(right))
    });
    for group in remainder_order
        .into_iter()
        .take(MAX_OBSERVATIONS - assigned)
    {
        groups[group].1 += 1;
    }
    let mut chosen = Vec::with_capacity(MAX_OBSERVATIONS);
    for (mut indices, quota, _) in groups {
        indices.sort_unstable_by(rank);
        chosen.extend(indices.into_iter().take(quota));
    }
    chosen.sort_unstable();
    (
        chosen
            .into_iter()
            .map(|index| observations[index])
            .collect(),
        "direction_length_stratified_hash_v1",
        strata_count,
    )
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
    let selected_observation_count = selected.len();
    let (selected, sampling_method, sampling_strata_count) = sample_observations(&selected);
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
        method: "direction_then_correlated_discriminator_v2",
        provisional: true,
        direction_mode: if respect_direction {
            "respect"
        } else {
            "ignore"
        },
        trial_id: trial_id.map(str::to_owned),
        selected_observation_count,
        observation_count: samples.len(),
        sampling_method,
        sampling_strata_count,
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

    #[test]
    fn many_length_strata_use_disclosed_deterministic_fallback() {
        let observations: Vec<_> = (0..513)
            .map(|index| Observation {
                id: format!("obs-{index:04}"),
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
                bytes_hex: "aa".repeat(index + 1),
            })
            .collect();
        let selected: Vec<_> = observations.iter().collect();
        let (first, method, strata) = sample_observations(&selected);
        let (again, _, _) = sample_observations(&selected);
        assert_eq!(method, "hash_v1");
        assert_eq!(strata, 513);
        assert_eq!(first.len(), 512);
        assert_eq!(
            first.iter().map(|item| &item.id).collect::<Vec<_>>(),
            again.iter().map(|item| &item.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detail_budget_keeps_a_late_unassigned_example_after_ambiguities() {
        let mut observations: Vec<_> = (0..600)
            .map(|index| ValidationObservation {
                observation_id: format!("ambiguous-{index:04}"),
                status: ValidationStatus::Ambiguous,
                assigned_cluster_id: None,
                compatible_cluster_count: 2,
                candidates_truncated: false,
                candidates: Vec::new(),
                rejected_cluster_count: 0,
                rejections_truncated: false,
                rejections: Vec::new(),
            })
            .collect();
        observations.push(ValidationObservation {
            observation_id: "late-unassigned".into(),
            status: ValidationStatus::Unassigned,
            assigned_cluster_id: None,
            compatible_cluster_count: 0,
            candidates_truncated: false,
            candidates: Vec::new(),
            rejected_cluster_count: 2,
            rejections_truncated: false,
            rejections: Vec::new(),
        });
        let (details, method) = select_validation_details(observations, 512);
        assert_eq!(method, "counterexamples_then_hash_v1");
        assert_eq!(details.len(), 512);
        assert!(
            details
                .iter()
                .any(|item| item.observation_id == "late-unassigned")
        );
    }
}

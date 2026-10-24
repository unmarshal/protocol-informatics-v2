//! Provisional request/reply candidates from timing and reciprocal flow metadata.
//! Byte equality is measured only after pairing, never used to force a match.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::workflow::{Observation, State, from_hex};

const DEFAULT_MAX_LAG_MS: u64 = 1_000;
const MAX_LAG_MS: u64 = 600_000;
const MAX_OBSERVATIONS: usize = 10_000;
const MAX_PAGE_SIZE: usize = 100;
const MAX_PREVIEW: usize = 20;
const MAX_ORIENTATIONS: usize = 20;
const MAX_COMPARE_PREFIX_BYTES: usize = 64;
const MIN_VARYING_EQUAL_PAIRS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    source: String,
    destination: String,
    source_port: Option<u16>,
    destination_port: Option<u16>,
}

impl FlowKey {
    fn from_observation(observation: &Observation) -> Option<Self> {
        let (source, destination) = observation.direction.as_deref()?.split_once(" -> ")?;
        if source.is_empty() || destination.is_empty() {
            return None;
        }
        Some(Self {
            source: source.into(),
            destination: destination.into(),
            source_port: observation.source_port,
            destination_port: observation.destination_port,
        })
    }

    fn reverse(&self) -> Self {
        Self {
            source: self.destination.clone(),
            destination: self.source.clone(),
            source_port: self.destination_port,
            destination_port: self.source_port,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Serialize)]
pub struct ExchangePair {
    pub earlier_observation_id: String,
    pub later_observation_id: String,
    pub earlier_direction: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub lag_ns: String,
    pub compared_prefix_bytes: usize,
    pub equal_byte_ranges: Vec<ByteRange>,
}

#[derive(Debug, Serialize)]
pub struct AmbiguousExchange {
    pub observation_id: String,
    pub reason: &'static str,
    pub predecessor_count: usize,
    pub predecessor_ids: Vec<String>,
    pub predecessor_ids_omitted: usize,
}

#[derive(Debug, Serialize)]
pub struct OrientationSummary {
    pub earlier_direction: String,
    pub pair_count: usize,
    pub minimum_compared_prefix_bytes: usize,
    pub varying_equal_ranges: Vec<ByteRange>,
}

#[derive(Debug, Serialize)]
pub struct ExchangeReport {
    pub revision: u64,
    pub method: &'static str,
    pub provisional: bool,
    pub capture_id: String,
    pub capture_format: String,
    pub observation_count: usize,
    pub maximum_observations: usize,
    pub max_lag_ms: u64,
    pub pair_count: usize,
    pub ambiguous_count: usize,
    pub unpaired_count: usize,
    pub untimed_count: usize,
    pub unavailable_direction_count: usize,
    pub self_reversing_flow_count: usize,
    pub pair_offset: usize,
    pub pair_limit: usize,
    pub next_pair_offset: Option<usize>,
    pub pairs: Vec<ExchangePair>,
    pub ambiguous_preview: Vec<AmbiguousExchange>,
    pub ambiguous_preview_omitted: usize,
    pub unpaired_observation_ids: Vec<String>,
    pub unpaired_ids_omitted: usize,
    pub orientation_summaries: Vec<OrientationSummary>,
    pub orientation_summaries_omitted: usize,
    pub maximum_compared_prefix_bytes: usize,
    pub minimum_pairs_for_varying_equal: usize,
}

fn prefix_bytes(observation: &Observation) -> Result<Vec<u8>, String> {
    let end = observation
        .bytes_hex
        .len()
        .min(MAX_COMPARE_PREFIX_BYTES * 2);
    from_hex(&observation.bytes_hex[..end])
}

fn ranges(indices: impl IntoIterator<Item = usize>) -> Vec<ByteRange> {
    let mut result: Vec<ByteRange> = Vec::new();
    for index in indices {
        if let Some(last) = result.last_mut()
            && last.end == index
        {
            last.end += 1;
            continue;
        }
        result.push(ByteRange {
            start: index,
            end: index + 1,
        });
    }
    result
}

fn equal_ranges(left: &[u8], right: &[u8]) -> Vec<ByteRange> {
    ranges((0..left.len().min(right.len())).filter(|index| left[*index] == right[*index]))
}

fn orientation_summaries(
    observations: &[&Observation],
    pairs: &[(usize, usize)],
) -> Result<(Vec<OrientationSummary>, usize), String> {
    let mut groups = BTreeMap::<String, Vec<(usize, usize)>>::new();
    for &(earlier, later) in pairs {
        groups
            .entry(observations[earlier].direction.clone().unwrap_or_default())
            .or_default()
            .push((earlier, later));
    }
    let total_groups = groups.len();
    let mut summaries = Vec::new();
    for (direction, group) in groups.into_iter().take(MAX_ORIENTATIONS) {
        let mut equal_counts = [0_usize; MAX_COMPARE_PREFIX_BYTES];
        let mut values: Vec<BTreeSet<u8>> = vec![BTreeSet::new(); MAX_COMPARE_PREFIX_BYTES];
        let mut minimum_compared = MAX_COMPARE_PREFIX_BYTES;
        for &(earlier, later) in &group {
            let left = prefix_bytes(observations[earlier])?;
            let right = prefix_bytes(observations[later])?;
            let width = left.len().min(right.len());
            minimum_compared = minimum_compared.min(width);
            for offset in 0..width {
                if left[offset] == right[offset] {
                    equal_counts[offset] += 1;
                    values[offset].insert(left[offset]);
                }
            }
        }
        let varying_equal_ranges = if group.len() >= MIN_VARYING_EQUAL_PAIRS {
            ranges((0..minimum_compared).filter(|offset| {
                equal_counts[*offset] == group.len() && values[*offset].len() >= 2
            }))
        } else {
            Vec::new()
        };
        summaries.push(OrientationSummary {
            earlier_direction: direction,
            pair_count: group.len(),
            minimum_compared_prefix_bytes: minimum_compared,
            varying_equal_ranges,
        });
    }
    Ok((summaries, total_groups.saturating_sub(MAX_ORIENTATIONS)))
}

pub fn pair_exchanges(
    state: &State,
    capture_id: &str,
    max_lag_ms: Option<u64>,
    offset: usize,
    limit: usize,
) -> Result<ExchangeReport, String> {
    let capture = state
        .captures
        .iter()
        .find(|capture| capture.id == capture_id)
        .ok_or_else(|| format!("unknown capture {capture_id}"))?;
    let max_lag_ms = max_lag_ms.unwrap_or(DEFAULT_MAX_LAG_MS);
    if max_lag_ms == 0 || max_lag_ms > MAX_LAG_MS {
        return Err(format!("max lag must be 1 to {MAX_LAG_MS} milliseconds"));
    }
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(format!("pair page limit must be 1 to {MAX_PAGE_SIZE}"));
    }
    let observations: Vec<_> = state
        .observations
        .iter()
        .filter(|observation| observation.capture_id == capture_id)
        .collect();
    if observations.len() > MAX_OBSERVATIONS {
        return Err(format!(
            "exchange pairing supports at most {MAX_OBSERVATIONS} observations per capture"
        ));
    }
    let mut ordered: Vec<_> = (0..observations.len()).collect();
    ordered.sort_by(|left, right| {
        observations[*left]
            .timestamp_ns
            .cmp(&observations[*right].timestamp_ns)
            .then_with(|| {
                observations[*left]
                    .source_index
                    .cmp(&observations[*right].source_index)
            })
            .then_with(|| observations[*left].id.cmp(&observations[*right].id))
    });
    let mut pending = BTreeMap::<FlowKey, VecDeque<usize>>::new();
    let mut paired = vec![false; observations.len()];
    let mut pairs = Vec::<(usize, usize)>::new();
    let mut ambiguous_preview = Vec::new();
    let mut ambiguous_count = 0;
    let mut untimed_count = 0;
    let mut unavailable_direction_count = 0;
    let mut self_reversing_flow_count = 0;
    let max_lag_ns = max_lag_ms * 1_000_000;
    for index in ordered {
        let observation = observations[index];
        let Some(timestamp) = observation.timestamp_ns else {
            untimed_count += 1;
            continue;
        };
        let Some(flow) = FlowKey::from_observation(observation) else {
            unavailable_direction_count += 1;
            continue;
        };
        let reverse = flow.reverse();
        if flow == reverse {
            self_reversing_flow_count += 1;
            continue;
        }
        let predecessors = pending.entry(reverse).or_default();
        while let Some(first) = predecessors.front() {
            if timestamp.saturating_sub(observations[*first].timestamp_ns.unwrap()) > max_lag_ns {
                predecessors.pop_front();
            } else {
                break;
            }
        }
        if predecessors.len() == 1 {
            let earlier = predecessors[0];
            if observations[earlier].timestamp_ns.unwrap() < timestamp {
                predecessors.pop_front();
                paired[earlier] = true;
                paired[index] = true;
                pairs.push((earlier, index));
                continue;
            }
        }
        if !predecessors.is_empty() {
            ambiguous_count += 1;
            if ambiguous_preview.len() < MAX_PREVIEW {
                ambiguous_preview.push(AmbiguousExchange {
                    observation_id: observation.id.clone(),
                    reason: if predecessors.len() == 1 {
                        "same_timestamp"
                    } else {
                        "multiple_predecessors"
                    },
                    predecessor_count: predecessors.len(),
                    predecessor_ids: predecessors
                        .iter()
                        .take(5)
                        .map(|candidate| observations[*candidate].id.clone())
                        .collect(),
                    predecessor_ids_omitted: predecessors.len().saturating_sub(5),
                });
            }
            continue;
        }
        pending.entry(flow).or_default().push_back(index);
    }
    let pair_count = pairs.len();
    if offset > pair_count {
        return Err("pair offset exceeds pair count".into());
    }
    let pair_page = pairs
        .iter()
        .skip(offset)
        .take(limit)
        .map(|(earlier, later)| {
            let left = observations[*earlier];
            let right = observations[*later];
            let left_bytes = prefix_bytes(left)?;
            let right_bytes = prefix_bytes(right)?;
            Ok(ExchangePair {
                earlier_observation_id: left.id.clone(),
                later_observation_id: right.id.clone(),
                earlier_direction: left.direction.clone().unwrap_or_default(),
                source_port: left.source_port,
                destination_port: left.destination_port,
                lag_ns: (right.timestamp_ns.unwrap() - left.timestamp_ns.unwrap()).to_string(),
                compared_prefix_bytes: left_bytes.len().min(right_bytes.len()),
                equal_byte_ranges: equal_ranges(&left_bytes, &right_bytes),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let unpaired: Vec<_> = observations
        .iter()
        .enumerate()
        .filter_map(|(index, observation)| (!paired[index]).then_some(observation.id.clone()))
        .collect();
    let (orientation_summaries, orientation_summaries_omitted) =
        orientation_summaries(&observations, &pairs)?;
    Ok(ExchangeReport {
        revision: state.revision,
        method: "unique_reciprocal_predecessor_v1",
        provisional: true,
        capture_id: capture_id.into(),
        capture_format: capture.format.clone(),
        observation_count: observations.len(),
        maximum_observations: MAX_OBSERVATIONS,
        max_lag_ms,
        pair_count,
        ambiguous_count,
        unpaired_count: unpaired.len(),
        untimed_count,
        unavailable_direction_count,
        self_reversing_flow_count,
        pair_offset: offset,
        pair_limit: limit,
        next_pair_offset: (offset + pair_page.len() < pair_count)
            .then_some(offset + pair_page.len()),
        pairs: pair_page,
        ambiguous_preview_omitted: ambiguous_count.saturating_sub(ambiguous_preview.len()),
        ambiguous_preview,
        unpaired_observation_ids: unpaired.iter().take(MAX_PREVIEW).cloned().collect(),
        unpaired_ids_omitted: unpaired.len().saturating_sub(MAX_PREVIEW),
        orientation_summaries,
        orientation_summaries_omitted,
        maximum_compared_prefix_bytes: MAX_COMPARE_PREFIX_BYTES,
        minimum_pairs_for_varying_equal: MIN_VARYING_EQUAL_PAIRS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::Capture;

    fn observation(
        id: &str,
        index: usize,
        time: Option<u64>,
        direction: Option<&str>,
        ports: (Option<u16>, Option<u16>),
    ) -> Observation {
        Observation {
            id: id.into(),
            capture_id: "cap-test".into(),
            source_index: index,
            source_offset: None,
            timestamp_ns: time,
            direction: direction.map(str::to_owned),
            source_port: ports.0,
            destination_port: ports.1,
            tcp_sequence: None,
            stream_gap_before: false,
            source_spans: Vec::new(),
            bytes_hex: "0102".into(),
        }
    }

    fn state(observations: Vec<Observation>) -> State {
        let mut state = crate::workflow::create_test_state();
        state.captures.push(Capture {
            id: "cap-test".into(),
            trial_id: "trial-test".into(),
            format: "pcap-udp".into(),
            source: "test".into(),
            sha256: String::new(),
            artifact: String::new(),
            observation_count: observations.len(),
            run_key: None,
        });
        state.observations = observations;
        state
    }

    #[test]
    fn multiple_predecessors_remain_ambiguous() {
        let state = state(vec![
            observation("first", 0, Some(1), Some("a -> b"), (None, None)),
            observation("second", 1, Some(2), Some("a -> b"), (None, None)),
            observation("reply", 2, Some(3), Some("b -> a"), (None, None)),
        ]);
        let report = pair_exchanges(&state, "cap-test", Some(1), 0, 10).unwrap();
        assert_eq!(report.pair_count, 0);
        assert_eq!(report.ambiguous_count, 1);
        assert_eq!(report.unpaired_count, 3);
        assert_eq!(report.ambiguous_preview[0].predecessor_count, 2);
        assert_eq!(report.ambiguous_preview[0].reason, "multiple_predecessors");
    }

    #[test]
    fn reciprocal_ports_separate_concurrent_flows() {
        let state = state(vec![
            observation("first", 0, Some(1), Some("a -> b"), (Some(40001), Some(53))),
            observation(
                "second",
                1,
                Some(2),
                Some("a -> b"),
                (Some(40002), Some(53)),
            ),
            observation("reply", 2, Some(3), Some("b -> a"), (Some(53), Some(40002))),
        ]);
        let report = pair_exchanges(&state, "cap-test", Some(1), 0, 10).unwrap();
        assert_eq!(report.pair_count, 1);
        assert_eq!(report.ambiguous_count, 0);
        assert_eq!(report.unpaired_observation_ids, ["first"]);
        assert_eq!(report.pairs[0].earlier_observation_id, "second");
        assert_eq!(report.pairs[0].later_observation_id, "reply");
    }

    #[test]
    fn identical_timestamps_do_not_imply_order() {
        let state = state(vec![
            observation("first", 0, Some(1), Some("a -> b"), (None, None)),
            observation("reverse", 1, Some(1), Some("b -> a"), (None, None)),
        ]);
        let report = pair_exchanges(&state, "cap-test", Some(1), 0, 10).unwrap();
        assert_eq!(report.pair_count, 0);
        assert_eq!(report.ambiguous_preview[0].reason, "same_timestamp");
    }
}

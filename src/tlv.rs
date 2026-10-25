//! Typed length-value views over the bounded framing engine.
//! Type bytes are reported as raw hex; recurring codes are evidence, not semantics.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::framing::{
    ByteOrder, FramedRecord, FramingConfig, FramingCounterexample, FramingStatus, LengthMode,
    infer_length_prefix_for_offsets, probe_observation, trial_observations,
};
use crate::workflow::{State, from_hex, to_hex};

const MAX_REPORTED_TYPE_PROFILES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TlvConfig {
    pub start_offset: usize,
    pub type_width: usize,
    pub length_width: usize,
    pub byte_order: ByteOrder,
    pub length_mode: LengthMode,
    pub alignment: usize,
}

impl TlvConfig {
    pub fn validate(self) -> Result<Self, String> {
        if !matches!(self.type_width, 1 | 2) {
            return Err("TLV type width must be 1 or 2 bytes".into());
        }
        self.framing().validate()?;
        Ok(self)
    }

    pub fn framing(self) -> FramingConfig {
        FramingConfig {
            start_offset: self.start_offset,
            prefix_offset: self.type_width,
            prefix_width: self.length_width,
            byte_order: self.byte_order,
            length_mode: self.length_mode,
            alignment: self.alignment,
            length_adjustment: 0,
        }
    }

    fn from_framing(config: FramingConfig) -> Self {
        Self {
            start_offset: config.start_offset,
            type_width: config.prefix_offset,
            length_width: config.prefix_width,
            byte_order: config.byte_order,
            length_mode: config.length_mode,
            alignment: config.alignment,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TlvElement {
    #[serde(flatten)]
    pub record: FramedRecord,
    pub type_start: usize,
    pub type_end: usize,
    pub type_hex: String,
    pub value_start: usize,
    pub value_end: usize,
    pub value_length: usize,
}

#[derive(Debug, Serialize)]
pub struct TlvProbe {
    pub revision: u64,
    pub observation_id: String,
    pub coordinate_system: &'static str,
    pub observation_length: usize,
    pub config: TlvConfig,
    pub status: FramingStatus,
    pub next_offset: usize,
    pub remaining_bytes: usize,
    pub element_count: usize,
    pub elements: Vec<TlvElement>,
}

pub fn probe_tlv(
    state: &State,
    observation_id: &str,
    config: TlvConfig,
) -> Result<TlvProbe, String> {
    let config = config.validate()?;
    let framed = probe_observation(state, observation_id, config.framing())?;
    let observation = state
        .observations
        .iter()
        .find(|observation| observation.id == observation_id)
        .ok_or_else(|| format!("unknown observation {observation_id}"))?;
    let bytes = from_hex(&observation.bytes_hex)?;
    let elements = framed
        .records
        .into_iter()
        .map(|record| {
            let type_start = record.start;
            let type_end = type_start + config.type_width;
            let value_start = record.length_field_end;
            let value_end = record.logical_end;
            TlvElement {
                type_hex: to_hex(&bytes[type_start..type_end]),
                value_length: value_end - value_start,
                record,
                type_start,
                type_end,
                value_start,
                value_end,
            }
        })
        .collect();
    Ok(TlvProbe {
        revision: framed.revision,
        observation_id: observation_id.into(),
        coordinate_system: framed.coordinate_system,
        observation_length: framed.observation_length,
        config,
        status: framed.status,
        next_offset: framed.next_offset,
        remaining_bytes: framed.remaining_bytes,
        element_count: framed.record_count,
        elements,
    })
}

#[derive(Debug, Serialize)]
pub struct TlvTypeProfile {
    pub type_hex: String,
    pub discovery_occurrences: usize,
    pub discovery_observations: usize,
    pub validation_occurrences: usize,
    pub validation_observations: usize,
    pub minimum_value_length: usize,
    pub maximum_value_length: usize,
}

#[derive(Debug, Serialize)]
pub struct TlvCandidate {
    pub config: TlvConfig,
    pub discovery_elements: usize,
    pub distinct_discovery_lengths: usize,
    pub validation_matches: usize,
    pub validation_elements: usize,
    pub validation_counterexamples: Vec<FramingCounterexample>,
    pub distinct_discovery_types: usize,
    pub recurring_discovery_types: usize,
    pub validation_elements_with_seen_types: usize,
    pub novel_validation_types: usize,
    pub type_profile_count: usize,
    pub type_profiles_truncated: bool,
    pub type_profiles: Vec<TlvTypeProfile>,
}

#[derive(Debug, Serialize)]
pub struct TlvInference {
    pub revision: u64,
    pub method: &'static str,
    pub discovery_trial_id: String,
    pub validation_trial_id: String,
    pub discovery_count: usize,
    pub validation_count: usize,
    pub candidate_count: usize,
    pub reported_candidate_limit: usize,
    pub candidates: Vec<TlvCandidate>,
}

#[derive(Default)]
struct ProfileCounts {
    discovery_occurrences: usize,
    discovery_observations: usize,
    validation_occurrences: usize,
    validation_observations: usize,
    minimum_value_length: Option<usize>,
    maximum_value_length: usize,
}

pub fn infer_tlv(
    state: &State,
    discovery_trial_id: &str,
    validation_trial_id: &str,
) -> Result<TlvInference, String> {
    let framing =
        infer_length_prefix_for_offsets(state, discovery_trial_id, validation_trial_id, &[1, 2])?;
    let discovery = trial_observations(state, discovery_trial_id)?;
    let validation = trial_observations(state, validation_trial_id)?;
    let mut candidates = Vec::new();
    for candidate in framing.candidates {
        let config = TlvConfig::from_framing(candidate.config);
        let mut profiles: BTreeMap<String, ProfileCounts> = BTreeMap::new();
        for (observations, discovery_set) in [(&discovery, true), (&validation, false)] {
            for observation in observations {
                let probe = probe_tlv(state, &observation.id, config)?;
                if probe.status != FramingStatus::Complete || probe.element_count < 2 {
                    continue;
                }
                let mut seen = BTreeSet::new();
                for element in probe.elements {
                    let key = element.type_hex;
                    let profile = profiles.entry(key.clone()).or_default();
                    if discovery_set {
                        profile.discovery_occurrences += 1;
                    } else {
                        profile.validation_occurrences += 1;
                    }
                    profile.minimum_value_length = Some(
                        profile
                            .minimum_value_length
                            .map_or(element.value_length, |minimum| {
                                minimum.min(element.value_length)
                            }),
                    );
                    profile.maximum_value_length =
                        profile.maximum_value_length.max(element.value_length);
                    seen.insert(key);
                }
                for key in seen {
                    let profile = profiles.get_mut(&key).expect("seen type has a profile");
                    if discovery_set {
                        profile.discovery_observations += 1;
                    } else {
                        profile.validation_observations += 1;
                    }
                }
            }
        }
        let distinct_discovery_types = profiles
            .values()
            .filter(|profile| profile.discovery_occurrences > 0)
            .count();
        let recurring_discovery_types = profiles
            .values()
            .filter(|profile| profile.discovery_observations >= 2)
            .count();
        let validation_elements_with_seen_types = profiles
            .values()
            .filter(|profile| profile.discovery_occurrences > 0)
            .map(|profile| profile.validation_occurrences)
            .sum();
        let novel_validation_types = profiles
            .values()
            .filter(|profile| {
                profile.discovery_occurrences == 0 && profile.validation_occurrences > 0
            })
            .count();
        let mut type_profiles: Vec<_> = profiles
            .into_iter()
            .map(|(type_hex, profile)| TlvTypeProfile {
                type_hex,
                discovery_occurrences: profile.discovery_occurrences,
                discovery_observations: profile.discovery_observations,
                validation_occurrences: profile.validation_occurrences,
                validation_observations: profile.validation_observations,
                minimum_value_length: profile.minimum_value_length.unwrap_or(0),
                maximum_value_length: profile.maximum_value_length,
            })
            .collect();
        type_profiles.sort_by(|a, b| {
            b.discovery_occurrences
                .cmp(&a.discovery_occurrences)
                .then_with(|| b.validation_occurrences.cmp(&a.validation_occurrences))
                .then_with(|| a.type_hex.cmp(&b.type_hex))
        });
        let type_profile_count = type_profiles.len();
        type_profiles.truncate(MAX_REPORTED_TYPE_PROFILES);
        candidates.push(TlvCandidate {
            config,
            discovery_elements: candidate.discovery_records,
            distinct_discovery_lengths: candidate.distinct_discovery_lengths,
            validation_matches: candidate.validation_matches,
            validation_elements: candidate.validation_records,
            validation_counterexamples: candidate.validation_counterexamples,
            distinct_discovery_types,
            recurring_discovery_types,
            validation_elements_with_seen_types,
            novel_validation_types,
            type_profile_count,
            type_profiles_truncated: type_profile_count > MAX_REPORTED_TYPE_PROFILES,
            type_profiles,
        });
    }
    Ok(TlvInference {
        revision: framing.revision,
        method: "typed_length_value_exact_fit_v1",
        discovery_trial_id: discovery_trial_id.into(),
        validation_trial_id: validation_trial_id.into(),
        discovery_count: framing.discovery_count,
        validation_count: framing.validation_count,
        candidate_count: framing.candidate_count,
        reported_candidate_limit: framing.reported_candidate_limit,
        candidates,
    })
}

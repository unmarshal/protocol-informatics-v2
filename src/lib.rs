//! Evidence-oriented analysis of unknown byte-oriented message formats.
//!
//! The first slice accepts already extracted messages. Capture decoding, message
//! clustering, field hypotheses, and active experiments belong in later layers.

mod alignment;
mod input;
pub mod pcap;
mod profile;
pub mod query;
pub mod report;
pub mod workflow;

pub use alignment::{AlignError, AlignedPair, CpuAligner, PairwiseAligner};
pub use input::{InputError, parse_hex_samples};
pub use profile::{Analysis, ColumnStats, MultipleAlignment, analyze, analyze_best};

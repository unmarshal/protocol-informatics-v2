//! Evidence-oriented analysis of unknown byte-oriented message formats.
//!
//! Capture decoding, experiment records, conservative grouping, and
//! intervention-tested numeric and checksum candidates build on the byte
//! alignment core.

mod alignment;
pub mod capture;
pub mod checksum;
pub mod clustering;
pub mod inference;
mod input;
pub mod pcap;
mod profile;
pub mod query;
pub mod report;
pub mod workflow;

pub use alignment::{AlignError, AlignedPair, CpuAligner, PairwiseAligner};
pub use input::{InputError, parse_hex_samples};
pub use profile::{Analysis, ColumnStats, MultipleAlignment, analyze, analyze_best};

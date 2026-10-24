use crate::{AlignError, PairwiseAligner};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipleAlignment {
    /// Rows retain the same order as the input samples; gaps are `None`.
    pub rows: Vec<Vec<Option<u8>>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ColumnStats {
    pub consensus: Option<u8>,
    pub support: usize,
    pub distinct: usize,
    pub entropy_bits: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Analysis {
    pub reference_index: usize,
    pub alignment: MultipleAlignment,
    pub columns: Vec<ColumnStats>,
}

#[derive(Debug)]
struct ReferenceProjection {
    insertions: Vec<Vec<u8>>,
    bases: Vec<Option<u8>>,
}

/// Star alignment against the longest sample, followed by an evidence profile.
pub fn analyze(
    samples: &[Vec<u8>],
    backend: &impl PairwiseAligner,
) -> Result<Analysis, AlignError> {
    let reference_index = samples
        .iter()
        .enumerate()
        .filter(|(_, sample)| !sample.is_empty())
        .max_by_key(|(_, sample)| sample.len())
        .map(|(index, _)| index)
        .ok_or(AlignError::EmptyInput)?;
    if samples.iter().any(Vec::is_empty) {
        return Err(AlignError::EmptyInput);
    }
    let reference = &samples[reference_index];
    let mut projections = Vec::with_capacity(samples.len());
    for sample in samples {
        let pair = backend.align(reference, sample)?;
        if pair.left.len() != pair.right.len() {
            return Err(AlignError::Backend(
                "backend returned unequal row lengths".into(),
            ));
        }
        let mut projection = ReferenceProjection {
            insertions: vec![Vec::new(); reference.len() + 1],
            bases: vec![None; reference.len()],
        };
        let mut position = 0;
        for (left, right) in pair.left.into_iter().zip(pair.right) {
            match (left, right) {
                (Some(byte), sample_byte) => {
                    if reference.get(position) != Some(&byte) {
                        return Err(AlignError::Backend(
                            "backend altered reference byte order".into(),
                        ));
                    }
                    projection.bases[position] = sample_byte;
                    position += 1;
                }
                (None, Some(byte)) => projection.insertions[position].push(byte),
                (None, None) => {
                    return Err(AlignError::Backend(
                        "backend returned a gap-only column".into(),
                    ));
                }
            }
        }
        if position != reference.len() {
            return Err(AlignError::Backend(
                "backend omitted reference bytes".into(),
            ));
        }
        projections.push(projection);
    }

    let insertion_widths: Vec<usize> = (0..=reference.len())
        .map(|slot| {
            projections
                .iter()
                .map(|item| item.insertions[slot].len())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut rows = Vec::with_capacity(samples.len());
    for projection in projections {
        let mut row = Vec::with_capacity(reference.len() + insertion_widths.iter().sum::<usize>());
        for (slot, width) in insertion_widths.iter().copied().enumerate() {
            row.extend(projection.insertions[slot].iter().copied().map(Some));
            row.extend(std::iter::repeat_n(
                None,
                width - projection.insertions[slot].len(),
            ));
            if slot < reference.len() {
                row.push(projection.bases[slot]);
            }
        }
        rows.push(row);
    }
    let aligned_width = rows[0].len();
    let columns = (0..aligned_width)
        .map(|index| profile_column(rows.iter().map(|row| row[index])))
        .collect();
    Ok(Analysis {
        reference_index,
        alignment: MultipleAlignment { rows },
        columns,
    })
}

fn profile_column(values: impl Iterator<Item = Option<u8>>) -> ColumnStats {
    let mut counts = [0_usize; 256];
    let mut support = 0;
    for value in values.flatten() {
        counts[value as usize] += 1;
        support += 1;
    }
    let distinct = counts.iter().filter(|&&count| count > 0).count();
    let consensus = counts
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .max_by_key(|(byte, count)| (**count, std::cmp::Reverse(*byte)))
        .map(|(byte, _)| byte as u8);
    let entropy_bits = if distinct <= 1 {
        0.0
    } else {
        counts
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / support as f64;
                -p * p.log2()
            })
            .sum()
    };
    ColumnStats {
        consensus,
        support,
        distinct,
        entropy_bits,
    }
}

impl Analysis {
    /// A stable, dependency-free JSON representation for scripts and agents.
    pub fn to_json(&self) -> String {
        let mut output = format!(
            "{{\"reference_index\":{},\"sample_count\":{},\"aligned_width\":{},\"columns\":[",
            self.reference_index,
            self.alignment.rows.len(),
            self.columns.len()
        );
        for (index, column) in self.columns.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            let consensus = column
                .consensus
                .map_or_else(|| "null".into(), |byte| byte.to_string());
            output.push_str(&format!(
                "{{\"index\":{index},\"consensus\":{consensus},\"support\":{},\"distinct\":{},\"entropy_bits\":{:.6}}}",
                column.support, column.distinct, column.entropy_bits
            ));
        }
        output.push_str("],\"aligned_samples\":[");
        for (index, row) in self.alignment.rows.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push('[');
            for (position, byte) in row.iter().enumerate() {
                if position > 0 {
                    output.push(',');
                }
                match byte {
                    Some(byte) => output.push_str(&byte.to_string()),
                    None => output.push_str("null"),
                }
            }
            output.push(']');
        }
        output.push_str("]}");
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CpuAligner;

    #[test]
    fn keeps_fixed_header_and_trailer_aligned_around_variable_payloads() {
        let samples = vec![b"\xaa\x03ABC\xff".to_vec(), b"\xaa\x01D\xff".to_vec()];
        let analysis = analyze(&samples, &CpuAligner).unwrap();
        assert_eq!(
            analysis.alignment.rows[0].len(),
            analysis.alignment.rows[1].len()
        );
        assert_eq!(analysis.columns[0].consensus, Some(0xaa));
        assert_eq!(analysis.columns.last().unwrap().consensus, Some(0xff));
        assert_eq!(analysis.columns.last().unwrap().support, 2);
        assert!(analysis.columns.iter().any(|column| column.support == 1));
        for (row, original) in analysis.alignment.rows.iter().zip(&samples) {
            assert_eq!(row.iter().flatten().copied().collect::<Vec<_>>(), *original);
        }
    }

    #[test]
    fn consensus_ties_are_deterministic() {
        let analysis = analyze(&[vec![2], vec![1]], &CpuAligner).unwrap();
        assert_eq!(analysis.columns[0].consensus, Some(1));
        assert_eq!(analysis.columns[0].entropy_bits, 1.0);
    }
}

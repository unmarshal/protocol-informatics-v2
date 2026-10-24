use std::fmt;

/// A replaceable pairwise alignment backend. Implementations must preserve byte order.
pub trait PairwiseAligner {
    fn align(&self, left: &[u8], right: &[u8]) -> Result<AlignedPair, AlignError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlignedPair {
    pub left: Vec<Option<u8>>,
    pub right: Vec<Option<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlignError {
    EmptyInput,
    TooLarge,
    Backend(String),
}

impl fmt::Display for AlignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "at least one nonempty sample is required"),
            Self::TooLarge => write!(f, "alignment exceeds the CPU matrix limit"),
            Self::Backend(message) => write!(f, "alignment backend: {message}"),
        }
    }
}

impl std::error::Error for AlignError {}

/// Deterministic global Needleman-Wunsch alignment with a linear gap penalty.
/// This is a baseline for correctness and future accelerator comparisons.
#[derive(Debug, Default, Clone, Copy)]
pub struct CpuAligner;

impl PairwiseAligner for CpuAligner {
    fn align(&self, left: &[u8], right: &[u8]) -> Result<AlignedPair, AlignError> {
        const MAX_CELLS: usize = 25_000_000;
        let width = right.len().checked_add(1).ok_or(AlignError::TooLarge)?;
        let height = left.len().checked_add(1).ok_or(AlignError::TooLarge)?;
        let cells = width.checked_mul(height).ok_or(AlignError::TooLarge)?;
        if cells > MAX_CELLS {
            return Err(AlignError::TooLarge);
        }
        let mut score = vec![0_i32; cells];
        for i in 1..height {
            score[i * width] = -(i as i32) * 2;
        }
        for (j, cell) in score.iter_mut().take(width).enumerate().skip(1) {
            *cell = -(j as i32) * 2;
        }
        for i in 1..height {
            for j in 1..width {
                let diagonal = score[(i - 1) * width + j - 1]
                    + if left[i - 1] == right[j - 1] { 2 } else { -1 };
                let delete = score[(i - 1) * width + j] - 2;
                let insert = score[i * width + j - 1] - 2;
                score[i * width + j] = diagonal.max(delete).max(insert);
            }
        }

        let (mut i, mut j) = (left.len(), right.len());
        let mut aligned_left = Vec::with_capacity(i.max(j));
        let mut aligned_right = Vec::with_capacity(i.max(j));
        while i > 0 || j > 0 {
            let current = score[i * width + j];
            if i > 0 && j > 0 {
                let diagonal = score[(i - 1) * width + j - 1]
                    + if left[i - 1] == right[j - 1] { 2 } else { -1 };
                if current == diagonal {
                    aligned_left.push(Some(left[i - 1]));
                    aligned_right.push(Some(right[j - 1]));
                    i -= 1;
                    j -= 1;
                    continue;
                }
            }
            if i > 0 && current == score[(i - 1) * width + j] - 2 {
                aligned_left.push(Some(left[i - 1]));
                aligned_right.push(None);
                i -= 1;
            } else {
                aligned_left.push(None);
                aligned_right.push(Some(right[j - 1]));
                j -= 1;
            }
        }
        aligned_left.reverse();
        aligned_right.reverse();
        Ok(AlignedPair {
            left: aligned_left,
            right: aligned_right,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_a_variable_length_payload_between_stable_markers() {
        let pair = CpuAligner.align(b"AxyzZ", b"AxZ").unwrap();
        assert_eq!(
            pair.left,
            b"AxyzZ".iter().copied().map(Some).collect::<Vec<_>>()
        );
        assert_eq!(
            pair.right,
            vec![Some(b'A'), Some(b'x'), None, None, Some(b'Z')]
        );
    }

    #[test]
    fn rejects_quadratic_work_above_the_cpu_limit() {
        let bytes = vec![0; 5_000];
        assert_eq!(CpuAligner.align(&bytes, &bytes), Err(AlignError::TooLarge));
    }
}

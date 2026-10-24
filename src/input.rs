use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    NoSamples,
    InvalidHex { line: usize },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSamples => write!(f, "input contains no samples"),
            Self::InvalidHex { line } => {
                write!(f, "line {line} is not a nonempty even-length hex sequence")
            }
        }
    }
}

impl std::error::Error for InputError {}

/// Accept one message per line. Whitespace and colons between hex digits are ignored.
pub fn parse_hex_samples(input: &str) -> Result<Vec<Vec<u8>>, InputError> {
    let mut samples = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let digits: String = line
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != ':')
            .collect();
        if digits.is_empty() || !digits.len().is_multiple_of(2) {
            return Err(InputError::InvalidHex { line: index + 1 });
        }
        let mut bytes = Vec::with_capacity(digits.len() / 2);
        for pair in digits.as_bytes().chunks_exact(2) {
            let text = std::str::from_utf8(pair)
                .map_err(|_| InputError::InvalidHex { line: index + 1 })?;
            let byte = u8::from_str_radix(text, 16)
                .map_err(|_| InputError::InvalidHex { line: index + 1 })?;
            bytes.push(byte);
        }
        samples.push(bytes);
    }
    if samples.is_empty() {
        return Err(InputError::NoSamples);
    }
    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_capture_export_conventions_and_reports_bad_line() {
        assert_eq!(
            parse_hex_samples("# request\n41:42 43\n\n44 45\n").unwrap(),
            vec![b"ABC".to_vec(), b"DE".to_vec()]
        );
        assert_eq!(
            parse_hex_samples("41\n4g"),
            Err(InputError::InvalidHex { line: 2 })
        );
    }
}

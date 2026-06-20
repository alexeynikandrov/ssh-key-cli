use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyRecord {
    pub algorithm: String,
    pub key_data: String,
    pub comment: Option<String>,
    pub original: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyError {
    EmptyInput,
    InvalidFormat,
    UnsupportedAlgorithm,
    ReadFailed(String),
}

pub fn parse_public_key(input: &str) -> Result<PublicKeyRecord, PublicKeyError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(PublicKeyError::EmptyInput);
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(PublicKeyError::InvalidFormat);
    }

    let algorithm = parts[0];
    if !is_supported_algorithm(algorithm) {
        return Err(PublicKeyError::UnsupportedAlgorithm);
    }

    let key_data = parts[1];
    if key_data.is_empty() {
        return Err(PublicKeyError::InvalidFormat);
    }

    let comment = if parts.len() > 2 {
        Some(parts[2..].join(" "))
    } else {
        None
    };

    Ok(PublicKeyRecord {
        algorithm: algorithm.to_owned(),
        key_data: key_data.to_owned(),
        comment,
        original: trimmed.to_owned(),
    })
}

pub fn normalize_public_key(input: &str) -> Result<String, PublicKeyError> {
    let record = parse_public_key(input)?;
    let mut normalized = format!("{} {}", record.algorithm, record.key_data);
    if let Some(comment) = record.comment {
        normalized.push(' ');
        normalized.push_str(comment.trim());
    }
    Ok(normalized)
}

pub fn read_local_public_key(path: &str) -> Result<String, PublicKeyError> {
    let content = fs::read_to_string(Path::new(path))
        .map_err(|_| PublicKeyError::ReadFailed(path.to_owned()))?;
    normalize_public_key(&content)
}

fn is_supported_algorithm(value: &str) -> bool {
    matches!(
        value,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
    )
}

#[cfg(test)]
mod tests {
    use super::{PublicKeyError, normalize_public_key, parse_public_key, read_local_public_key};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_valid_public_key() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1 node-a";
        let parsed = parse_public_key(key).expect("key should parse");

        assert_eq!(parsed.algorithm, "ssh-ed25519");
        assert_eq!(parsed.key_data, "AAAAC3NzaC1lZDI1NTE5AAAAIB1");
        assert_eq!(parsed.comment.as_deref(), Some("node-a"));
    }

    #[test]
    fn rejects_empty_input() {
        let parsed = parse_public_key("   ");
        assert_eq!(parsed, Err(PublicKeyError::EmptyInput));
    }

    #[test]
    fn rejects_invalid_format() {
        let parsed = parse_public_key("ssh-ed25519");
        assert_eq!(parsed, Err(PublicKeyError::InvalidFormat));
    }

    #[test]
    fn rejects_unsupported_algorithm() {
        let parsed = parse_public_key("ssh-dss AAAAC3Nza comment");
        assert_eq!(parsed, Err(PublicKeyError::UnsupportedAlgorithm));
    }

    #[test]
    fn normalizes_whitespace() {
        let normalized = normalize_public_key("  ssh-ed25519   AAAAC3Nza    node-a  ")
            .expect("normalization should work");
        assert_eq!(normalized, "ssh-ed25519 AAAAC3Nza node-a");
    }

    #[test]
    fn reads_and_normalizes_local_key_file() {
        let path = temp_file_path("public-key");
        fs::write(&path, "  ssh-ed25519   AAAAC3Nza    node-a  \n")
            .expect("temp key should be written");

        let normalized =
            read_local_public_key(path.to_string_lossy().as_ref()).expect("key should be loaded");
        assert_eq!(normalized, "ssh-ed25519 AAAAC3Nza node-a");

        fs::remove_file(path).expect("temp key should be removed");
    }

    #[test]
    fn fails_when_local_key_file_is_missing() {
        let path = temp_file_path("missing");
        let loaded = read_local_public_key(path.to_string_lossy().as_ref());
        assert_eq!(
            loaded,
            Err(PublicKeyError::ReadFailed(
                path.to_string_lossy().to_string()
            ))
        );
    }

    fn temp_file_path(prefix: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("ssh-key-sync-{prefix}-{timestamp}.tmp"))
    }
}

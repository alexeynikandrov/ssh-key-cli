use crate::ssh_keys::normalize_public_key;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MANAGED_BEGIN: &str = "# ssh-key-sync begin";
const MANAGED_END: &str = "# ssh-key-sync end";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizedKeysError {
    MissingManagedEnd,
    InvalidPublicKey,
    ReadFailed(String),
    WriteFailed(String),
    SyncFailed(String),
    RenameFailed(String),
    SetPermissionsFailed(String),
}

pub fn upsert_managed_block(
    existing_content: &str,
    managed_keys: &[String],
) -> Result<String, AuthorizedKeysError> {
    let normalized_keys = normalize_and_dedup(managed_keys)?;
    let lines: Vec<&str> = existing_content.lines().collect();

    let begin_index = lines.iter().position(|line| line.trim() == MANAGED_BEGIN);
    let end_index = lines.iter().position(|line| line.trim() == MANAGED_END);

    if begin_index.is_some() && end_index.is_none() {
        return Err(AuthorizedKeysError::MissingManagedEnd);
    }

    let mut output_lines: Vec<String> = Vec::new();
    match (begin_index, end_index) {
        (Some(begin), Some(end)) => {
            for line in &lines[..begin] {
                output_lines.push((*line).to_owned());
            }
            append_managed_block(&mut output_lines, &normalized_keys);
            for line in &lines[end + 1..] {
                output_lines.push((*line).to_owned());
            }
        }
        _ => {
            for line in lines {
                output_lines.push(line.to_owned());
            }
            if !output_lines.is_empty() && !output_lines.last().is_some_and(|line| line.is_empty())
            {
                output_lines.push(String::new());
            }
            append_managed_block(&mut output_lines, &normalized_keys);
        }
    }

    Ok(output_lines.join("\n"))
}

pub fn apply_managed_block_to_file(
    authorized_keys_path: &str,
    managed_keys: &[String],
) -> Result<String, AuthorizedKeysError> {
    let path = Path::new(authorized_keys_path);
    ensure_ssh_directory_permissions(path)?;

    let existing = read_existing_authorized_keys(path)?;
    let updated = upsert_managed_block(&existing, managed_keys)?;
    atomic_write(path, &updated)?;
    set_authorized_keys_permissions(path)?;

    Ok(updated)
}

fn append_managed_block(output_lines: &mut Vec<String>, keys: &[String]) {
    output_lines.push(MANAGED_BEGIN.to_owned());
    for key in keys {
        output_lines.push(key.to_owned());
    }
    output_lines.push(MANAGED_END.to_owned());
}

fn normalize_and_dedup(managed_keys: &[String]) -> Result<Vec<String>, AuthorizedKeysError> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();

    for key in managed_keys {
        let normalized =
            normalize_public_key(key).map_err(|_| AuthorizedKeysError::InvalidPublicKey)?;
        if seen.insert(normalized.clone()) {
            output.push(normalized);
        }
    }

    Ok(output)
}

fn read_existing_authorized_keys(path: &Path) -> Result<String, AuthorizedKeysError> {
    if !path.exists() {
        return Ok(String::new());
    }
    fs::read_to_string(path)
        .map_err(|_| AuthorizedKeysError::ReadFailed(path.display().to_string()))
}

fn atomic_write(path: &Path, content: &str) -> Result<(), AuthorizedKeysError> {
    let tmp_path = temp_path_near(path);
    let mut tmp_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|_| AuthorizedKeysError::WriteFailed(tmp_path.display().to_string()))?;
    tmp_file
        .write_all(content.as_bytes())
        .map_err(|_| AuthorizedKeysError::WriteFailed(tmp_path.display().to_string()))?;
    tmp_file
        .sync_all()
        .map_err(|_| AuthorizedKeysError::SyncFailed(tmp_path.display().to_string()))?;

    fs::rename(&tmp_path, path)
        .map_err(|_| AuthorizedKeysError::RenameFailed(path.display().to_string()))?;

    sync_parent_directory(path)?;
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<(), AuthorizedKeysError> {
    let parent = path
        .parent()
        .ok_or_else(|| AuthorizedKeysError::SyncFailed(path.display().to_string()))?;
    let dir = File::open(parent)
        .map_err(|_| AuthorizedKeysError::SyncFailed(parent.display().to_string()))?;
    dir.sync_all()
        .map_err(|_| AuthorizedKeysError::SyncFailed(parent.display().to_string()))
}

fn temp_path_near(path: &Path) -> PathBuf {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "authorized_keys".to_owned());
    path.with_file_name(format!("{filename}.tmp"))
}

fn ensure_ssh_directory_permissions(path: &Path) -> Result<(), AuthorizedKeysError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent)
        .map_err(|_| AuthorizedKeysError::WriteFailed(parent.display().to_string()))?;
    set_ssh_dir_permissions(parent)
}

#[cfg(unix)]
fn set_ssh_dir_permissions(path: &Path) -> Result<(), AuthorizedKeysError> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, permissions)
        .map_err(|_| AuthorizedKeysError::SetPermissionsFailed(path.display().to_string()))
}

#[cfg(not(unix))]
fn set_ssh_dir_permissions(_path: &Path) -> Result<(), AuthorizedKeysError> {
    Ok(())
}

fn set_authorized_keys_permissions(path: &Path) -> Result<(), AuthorizedKeysError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .map_err(|_| AuthorizedKeysError::SetPermissionsFailed(path.display().to_string()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorizedKeysError, apply_managed_block_to_file, upsert_managed_block};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn appends_new_managed_block_when_absent() {
        let input = "ssh-ed25519 AAAA user@host";
        let managed = vec![
            "ssh-ed25519 BBBB node-b".to_owned(),
            "ssh-ed25519 CCCC node-c".to_owned(),
        ];

        let updated = upsert_managed_block(input, &managed).expect("upsert should succeed");

        assert!(updated.contains("ssh-ed25519 AAAA user@host"));
        assert!(updated.contains("# ssh-key-sync begin"));
        assert!(updated.contains("ssh-ed25519 BBBB node-b"));
        assert!(updated.contains("ssh-ed25519 CCCC node-c"));
        assert!(updated.contains("# ssh-key-sync end"));
    }

    #[test]
    fn replaces_existing_managed_block_only() {
        let input = "\
ssh-ed25519 AAAA user@host
# ssh-key-sync begin
ssh-ed25519 OLD old
# ssh-key-sync end
ssh-ed25519 DDDD manual";
        let managed = vec!["ssh-ed25519 BBBB node-b".to_owned()];

        let updated = upsert_managed_block(input, &managed).expect("upsert should succeed");

        assert!(updated.contains("ssh-ed25519 AAAA user@host"));
        assert!(updated.contains("ssh-ed25519 DDDD manual"));
        assert!(updated.contains("ssh-ed25519 BBBB node-b"));
        assert!(!updated.contains("ssh-ed25519 OLD old"));
    }

    #[test]
    fn rejects_invalid_managed_key() {
        let input = "";
        let managed = vec!["invalid".to_owned()];

        let updated = upsert_managed_block(input, &managed);
        assert_eq!(updated, Err(AuthorizedKeysError::InvalidPublicKey));
    }

    #[test]
    fn rejects_missing_block_end() {
        let input = "\
ssh-ed25519 AAAA user@host
# ssh-key-sync begin
ssh-ed25519 OLD old";
        let managed = vec!["ssh-ed25519 BBBB node-b".to_owned()];

        let updated = upsert_managed_block(input, &managed);
        assert_eq!(updated, Err(AuthorizedKeysError::MissingManagedEnd));
    }

    #[test]
    fn applies_managed_block_to_new_file() {
        let base = temp_test_dir("apply-new");
        let ssh_dir = base.join(".ssh");
        let file = ssh_dir.join("authorized_keys");
        let managed = vec!["ssh-ed25519 BBBB node-b".to_owned()];

        let updated = apply_managed_block_to_file(file.to_string_lossy().as_ref(), &managed)
            .expect("apply should work");

        let disk = fs::read_to_string(&file).expect("file should exist");
        assert_eq!(updated, disk);
        assert!(disk.contains("# ssh-key-sync begin"));
        assert!(disk.contains("ssh-ed25519 BBBB node-b"));
        assert!(disk.contains("# ssh-key-sync end"));

        fs::remove_dir_all(base).expect("temp dir should be removed");
    }

    #[test]
    fn keeps_manual_lines_while_updating_managed_block_on_disk() {
        let base = temp_test_dir("apply-existing");
        let ssh_dir = base.join(".ssh");
        fs::create_dir_all(&ssh_dir).expect("ssh dir should be created");
        let file = ssh_dir.join("authorized_keys");
        fs::write(
            &file,
            "ssh-ed25519 AAAA user@host\n# ssh-key-sync begin\nssh-ed25519 OLD old\n# ssh-key-sync end\n",
        )
        .expect("seed file should be written");
        let managed = vec!["ssh-ed25519 BBBB node-b".to_owned()];

        let updated = apply_managed_block_to_file(file.to_string_lossy().as_ref(), &managed)
            .expect("apply should work");
        assert!(updated.contains("ssh-ed25519 AAAA user@host"));
        assert!(updated.contains("ssh-ed25519 BBBB node-b"));
        assert!(!updated.contains("ssh-ed25519 OLD old"));

        fs::remove_dir_all(base).expect("temp dir should be removed");
    }

    #[test]
    fn fails_when_managed_key_is_invalid_before_write() {
        let base = temp_test_dir("invalid-before-write");
        let file = base.join(".ssh").join("authorized_keys");
        let managed = vec!["invalid".to_owned()];

        let result = apply_managed_block_to_file(file.to_string_lossy().as_ref(), &managed);
        assert_eq!(result, Err(AuthorizedKeysError::InvalidPublicKey));
        assert!(!file.exists());

        fs::remove_dir_all(base).expect("temp dir should be removed");
    }

    fn temp_test_dir(prefix: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ssh-key-sync-{prefix}-{timestamp}"));
        fs::create_dir_all(&path).expect("temp test dir should be created");
        path
    }
}

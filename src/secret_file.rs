use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use zeroize::Zeroizing;

pub(crate) const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_KEYRING_KEYS: usize = 64;

pub(crate) fn read_secret_file(path: impl AsRef<Path>) -> io::Result<Zeroizing<Vec<u8>>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_SECRET_FILE_BYTES {
        return Err(invalid_secret_file());
    }

    let capacity = usize::try_from(metadata.len())
        .unwrap_or(MAX_SECRET_FILE_BYTES as usize)
        .min(MAX_SECRET_FILE_BYTES as usize);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(invalid_secret_file());
    }
    Ok(bytes)
}

pub(crate) const fn valid_keyring_key_count(count: usize) -> bool {
    count > 0 && count <= MAX_KEYRING_KEYS
}

fn invalid_secret_file() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "secret must be a regular file no larger than 64 KiB",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_reader_enforces_the_opened_file_boundary() {
        let path =
            std::env::temp_dir().join(format!("camellia-bounded-secret-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, vec![7_u8; MAX_SECRET_FILE_BYTES as usize])
            .expect("write boundary secret");
        assert_eq!(
            read_secret_file(&path).expect("read boundary secret").len(),
            MAX_SECRET_FILE_BYTES as usize
        );

        std::fs::write(&path, vec![7_u8; MAX_SECRET_FILE_BYTES as usize + 1])
            .expect("write oversized secret");
        assert_eq!(
            read_secret_file(&path)
                .expect_err("oversized secret must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::remove_file(path).expect("remove bounded secret fixture");
    }

    #[test]
    fn keyring_count_has_explicit_rotation_bounds() {
        assert!(!valid_keyring_key_count(0));
        assert!(valid_keyring_key_count(MAX_KEYRING_KEYS));
        assert!(!valid_keyring_key_count(MAX_KEYRING_KEYS + 1));
    }
}

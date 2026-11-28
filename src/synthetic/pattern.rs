use anyhow::{Result, ensure};

pub fn suggest(password: &str, unknown: usize) -> Result<(String, u64)> {
    ensure!(
        unknown <= password.len(),
        "Unknown suffix exceeds the password length"
    );
    let (prefix, suffix) = password.split_at(password.len() - unknown);
    let upper_hex = password
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b));
    let lower_hex = password
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let mut mask = prefix.replace('?', "??");
    let mut count = 1_u64;
    for byte in suffix.bytes() {
        let (token, size) = if upper_hex {
            ("?H", 16)
        } else if lower_hex {
            ("?h", 16)
        } else if byte.is_ascii_digit() {
            ("?d", 10)
        } else if byte.is_ascii_lowercase() {
            ("?l", 26)
        } else if byte.is_ascii_uppercase() {
            ("?u", 26)
        } else {
            ("?s", 33)
        };
        mask.push_str(token);
        count = count
            .checked_mul(size)
            .ok_or_else(|| anyhow::anyhow!("Suggested mask exceeds 64-bit candidate indexing"))?;
    }
    Ok((mask, count))
}

use crate::frame::{Group, KeyFrame};
use crate::{Config, Export, Names, Report, count};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn extract(
    groups: BTreeMap<Group, Vec<KeyFrame>>,
    names: &Names,
    config: &Config,
    report: &mut Report,
) -> Vec<String> {
    let window = i128::from(config.timeout_ms) * 1_000_000;
    // Key excludes the pair suffix so retries can upgrade an M1/M2 to M2/M3.
    let mut unique = BTreeMap::<String, (u8, Export)>::new();
    for (group, mut frames) in groups {
        frames.sort_by_key(|k| (k.time_ns, k.index));
        for m2 in frames.iter().filter(|k| k.message == 2) {
            let ssid = if let Some(name) = &config.ssid {
                name
            } else {
                match names.get(&(group.stream, group.ap)) {
                    Some(values) if values.len() == 1 => values.first().expect("one SSID"),
                    Some(_) => {
                        count(&mut report.skipped_m2, "ambiguous_ssid");
                        continue;
                    }
                    None => {
                        count(&mut report.skipped_m2, "missing_ssid");
                        continue;
                    }
                }
            };
            let start = frames.partition_point(|k| k.time_ns < m2.time_ns - window);
            let end = frames.partition_point(|k| k.time_ns <= m2.time_ns + window);
            // Two selections sharing replay/version and the pairing window cannot
            // be assigned to an unlabelled AP nonce confidently. Fail closed.
            if frames[start..end].iter().any(|k| {
                k.message == 2
                    && k.replay == m2.replay
                    && k.descriptor_type == m2.descriptor_type
                    && k.descriptor_version == m2.descriptor_version
                    && k.profile != m2.profile
            }) {
                count(&mut report.skipped_m2, "ambiguous_security_profile");
                continue;
            }
            let candidates: Vec<_> = frames[start..end]
                .iter()
                .filter(|k| {
                    k.descriptor_type == m2.descriptor_type
                        && k.descriptor_version == m2.descriptor_version
                        && ((k.message == 1 && k.replay == m2.replay && k.time_ns <= m2.time_ns)
                            || (k.message == 3
                                && Some(k.replay) == m2.replay.checked_add(1)
                                && k.time_ns >= m2.time_ns))
                })
                .collect();
            let nonces: BTreeSet<_> = candidates.iter().map(|k| k.nonce).collect();
            if nonces.is_empty() {
                count(&mut report.skipped_m2, "no_matching_m1_or_m3");
                continue;
            }
            if nonces.len() != 1 {
                count(&mut report.skipped_m2, "ambiguous_anonce");
                continue;
            }
            let peer = candidates
                .iter()
                .find(|k| k.message == 3)
                .or_else(|| candidates.iter().rev().find(|k| k.message == 1))
                .expect("nonempty candidates");
            let pair = if peer.message == 3 { 2u8 } else { 0u8 };
            let mut eapol = m2.eapol.clone();
            eapol[81..97].fill(0);
            let base = format!(
                "WPA*02*{}*{}*{}*{}*{}*{}",
                hex::encode(m2.mic),
                hex::encode(group.ap),
                hex::encode(group.station),
                hex::encode(ssid),
                hex::encode(peer.nonce),
                hex::encode(eapol)
            );
            let export = Export {
                ap: hex::encode(group.ap),
                station: hex::encode(group.station),
                ssid_hex: hex::encode(ssid),
                stream: group.stream,
                m2_packet: m2.index,
                peer_packet: peer.index,
                message_pair: format!("{pair:02x}"),
                security_profile: m2.profile.expect("accepted M2 has a selected profile"),
            };
            match unique.entry(base) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert((pair, export));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    report.duplicate_exports += 1;
                    if pair > entry.get().0 {
                        entry.insert((pair, export));
                    }
                }
            }
        }
    }
    let mut lines = Vec::with_capacity(unique.len());
    for (base, (pair, export)) in unique {
        lines.push(format!("{base}*{pair:02x}"));
        report.exports.push(export);
    }
    lines
}

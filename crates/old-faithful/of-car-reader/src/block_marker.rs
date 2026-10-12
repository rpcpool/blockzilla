//! Alpenglow block markers, as archived in [`SlotMeta::block_markers`](crate::node::SlotMeta).
//!
//! Each archived marker is one Agave `VersionedBlockMarker` without the leading
//! zero entry count. Wire layout (little-endian):
//!
//! ```text
//! u16 version (1) | u8 variant | u16 payload len | payload
//! ```
//!
//! Footer, header and update-parent payloads start with their own `u8` version (1);
//! the genesis certificate has none. A marker whose version or variant this reader
//! does not know parses as [`BlockMarker::Unknown`] and keeps its raw bytes.

use core::fmt;

pub const MARKER_VERSION_V1: u16 = 1;
const ENVELOPE_LEN: usize = 2 + 1 + 2;
const PAYLOAD_VERSION_V1: u8 = 1;
const MAX_GENESIS_BITMAP_LEN: u64 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerVariant {
    Footer = 0,
    Header = 1,
    UpdateParent = 2,
    GenesisCertificate = 3,
}

impl MarkerVariant {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Footer,
            1 => Self::Header,
            2 => Self::UpdateParent,
            3 => Self::GenesisCertificate,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockMarker<'a> {
    Footer(BlockFooter<'a>),
    Header(ParentRef),
    /// Switches the block to a new parent (fast leader handover).
    UpdateParent(ParentRef),
    GenesisCertificate(GenesisCertificate<'a>),
    Unknown(UnknownMarker<'a>),
}

impl BlockMarker<'_> {
    pub fn variant(&self) -> Option<MarkerVariant> {
        match self {
            Self::Footer(_) => Some(MarkerVariant::Footer),
            Self::Header(_) => Some(MarkerVariant::Header),
            Self::UpdateParent(_) => Some(MarkerVariant::UpdateParent),
            Self::GenesisCertificate(_) => Some(MarkerVariant::GenesisCertificate),
            Self::Unknown(_) => None,
        }
    }
}

/// Parent of a block, from its header or update-parent marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentRef {
    pub parent_slot: u64,
    pub parent_block_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockFooter<'a> {
    pub bank_hash: [u8; 32],
    pub block_producer_time_nanos: u64,
    pub block_user_agent: &'a [u8],
    /// Undecoded `Option<BlockFinalizationCert>`, `Option<SkipRewardCertificate>` and
    /// `Option<NotarRewardCertificate>`. Their signer bitmaps index the epoch's BLS rank map.
    pub certificates: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisCertificate<'a> {
    pub slot: u64,
    pub block_id: [u8; 32],
    pub bls_signature: &'a [u8; 192],
    pub bitmap: &'a [u8],
}

/// A marker with a version or variant this reader does not know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownMarker<'a> {
    pub version: u16,
    pub variant: u8,
    /// Inner payload version, when the marker version is known but the payload's is not.
    pub payload_version: Option<u8>,
    pub raw: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockMarkerError {
    Truncated {
        needed: usize,
        have: usize,
    },
    TrailingBytes {
        declared: usize,
        have: usize,
    },
    InvalidPayload {
        variant: MarkerVariant,
        reason: &'static str,
    },
    Layout(String),
}

impl fmt::Display for BlockMarkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, have } => {
                write!(
                    f,
                    "block marker truncated: needs {needed} bytes, have {have}"
                )
            }
            Self::TrailingBytes { declared, have } => {
                write!(f, "block marker declares {declared} bytes, have {have}")
            }
            Self::InvalidPayload { variant, reason } => {
                write!(f, "invalid {variant:?} marker: {reason}")
            }
            Self::Layout(reason) => write!(f, "invalid block marker layout: {reason}"),
        }
    }
}

impl std::error::Error for BlockMarkerError {}

/// Parses one archived marker. `raw` must hold exactly one marker.
pub fn parse(raw: &[u8]) -> Result<BlockMarker<'_>, BlockMarkerError> {
    if raw.len() < ENVELOPE_LEN {
        return Err(BlockMarkerError::Truncated {
            needed: ENVELOPE_LEN,
            have: raw.len(),
        });
    }
    let version = u16::from_le_bytes([raw[0], raw[1]]);
    let variant_byte = raw[2];
    let unknown = |payload_version| {
        BlockMarker::Unknown(UnknownMarker {
            version,
            variant: variant_byte,
            payload_version,
            raw,
        })
    };
    if version != MARKER_VERSION_V1 {
        return Ok(unknown(None));
    }

    let declared = ENVELOPE_LEN + usize::from(u16::from_le_bytes([raw[3], raw[4]]));
    if raw.len() != declared {
        return Err(if raw.len() < declared {
            BlockMarkerError::Truncated {
                needed: declared,
                have: raw.len(),
            }
        } else {
            BlockMarkerError::TrailingBytes {
                declared,
                have: raw.len(),
            }
        });
    }
    let Some(variant) = MarkerVariant::from_u8(variant_byte) else {
        return Ok(unknown(None));
    };
    let payload = &raw[ENVELOPE_LEN..];

    if variant == MarkerVariant::GenesisCertificate {
        return parse_genesis_certificate(payload).map(BlockMarker::GenesisCertificate);
    }
    let Some((&payload_version, body)) = payload.split_first() else {
        return Err(invalid(variant, "empty payload"));
    };
    if payload_version != PAYLOAD_VERSION_V1 {
        return Ok(unknown(Some(payload_version)));
    }
    match variant {
        MarkerVariant::Footer => parse_footer(body).map(BlockMarker::Footer),
        MarkerVariant::Header => parse_parent_ref(variant, body).map(BlockMarker::Header),
        MarkerVariant::UpdateParent => {
            parse_parent_ref(variant, body).map(BlockMarker::UpdateParent)
        }
        MarkerVariant::GenesisCertificate => unreachable!("handled above"),
    }
}

/// Checks a block's markers against the order Agave enforces:
/// header, optional genesis certificate, optional update-parent, footer last.
pub fn validate_layout(markers: &[BlockMarker<'_>]) -> Result<(), BlockMarkerError> {
    let mut counts = [0usize; 4];
    for (i, marker) in markers.iter().enumerate() {
        let Some(variant) = marker.variant() else {
            continue;
        };
        counts[variant as usize] += 1;
        match variant {
            MarkerVariant::Header if i != 0 => {
                return Err(layout("header is not the first marker"));
            }
            MarkerVariant::GenesisCertificate
                if i != 1 || markers[0].variant() != Some(MarkerVariant::Header) =>
            {
                return Err(layout(
                    "genesis certificate is not directly after the header",
                ));
            }
            MarkerVariant::Footer if i + 1 != markers.len() => {
                return Err(layout("footer is not the last marker"));
            }
            _ => {}
        }
    }
    for (variant, want_exactly_one) in [
        (MarkerVariant::Header, true),
        (MarkerVariant::Footer, true),
        (MarkerVariant::UpdateParent, false),
        (MarkerVariant::GenesisCertificate, false),
    ] {
        let count = counts[variant as usize];
        if (want_exactly_one && count != 1) || count > 1 {
            return Err(layout(&format!("{count} {variant:?} markers")));
        }
    }
    Ok(())
}

fn parse_footer(body: &[u8]) -> Result<BlockFooter<'_>, BlockMarkerError> {
    const FIXED: usize = 32 + 8 + 1;
    if body.len() < FIXED {
        return Err(invalid(
            MarkerVariant::Footer,
            "shorter than bank hash, time and user agent length",
        ));
    }
    let user_agent_end = FIXED + usize::from(body[40]);
    if body.len() < user_agent_end {
        return Err(invalid(
            MarkerVariant::Footer,
            "user agent runs past the payload",
        ));
    }
    Ok(BlockFooter {
        bank_hash: body[0..32].try_into().expect("checked length"),
        block_producer_time_nanos: u64::from_le_bytes(
            body[32..40].try_into().expect("checked length"),
        ),
        block_user_agent: &body[FIXED..user_agent_end],
        certificates: &body[user_agent_end..],
    })
}

fn parse_parent_ref(variant: MarkerVariant, body: &[u8]) -> Result<ParentRef, BlockMarkerError> {
    if body.len() != 8 + 32 {
        return Err(invalid(
            variant,
            "expected a 40-byte parent slot and block id",
        ));
    }
    Ok(ParentRef {
        parent_slot: u64::from_le_bytes(body[0..8].try_into().expect("checked length")),
        parent_block_id: body[8..40].try_into().expect("checked length"),
    })
}

fn parse_genesis_certificate(payload: &[u8]) -> Result<GenesisCertificate<'_>, BlockMarkerError> {
    const FIXED: usize = 8 + 32 + 192 + 8;
    let variant = MarkerVariant::GenesisCertificate;
    if payload.len() < FIXED {
        return Err(invalid(
            variant,
            "shorter than slot, block id, signature and bitmap length",
        ));
    }
    let bitmap_len = u64::from_le_bytes(payload[232..FIXED].try_into().expect("checked length"));
    if bitmap_len > MAX_GENESIS_BITMAP_LEN {
        return Err(invalid(variant, "bitmap longer than 512 bytes"));
    }
    if (payload.len() - FIXED) as u64 != bitmap_len {
        return Err(invalid(variant, "bitmap length does not match the payload"));
    }
    Ok(GenesisCertificate {
        slot: u64::from_le_bytes(payload[0..8].try_into().expect("checked length")),
        block_id: payload[8..40].try_into().expect("checked length"),
        bls_signature: payload[40..232].try_into().expect("checked length"),
        bitmap: &payload[FIXED..],
    })
}

fn invalid(variant: MarkerVariant, reason: &'static str) -> BlockMarkerError {
    BlockMarkerError::InvalidPayload { variant, reason }
}

fn layout(reason: &str) -> BlockMarkerError {
    BlockMarkerError::Layout(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(variant: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = MARKER_VERSION_V1.to_le_bytes().to_vec();
        out.push(variant);
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn parent_payload(slot: u64, id: u8) -> Vec<u8> {
        let mut p = vec![PAYLOAD_VERSION_V1];
        p.extend_from_slice(&slot.to_le_bytes());
        p.extend_from_slice(&[id; 32]);
        p
    }

    // Same footer as yellowstone-faithful's blockmarker Test_blockFooterUi.
    fn footer_payload(user_agent: &str, certificates: &[u8]) -> Vec<u8> {
        let mut p = vec![PAYLOAD_VERSION_V1];
        p.extend_from_slice(&[0; 32]);
        p.extend_from_slice(&1_791_392_218_636_594_070u64.to_le_bytes());
        p.push(user_agent.len() as u8);
        p.extend_from_slice(user_agent.as_bytes());
        p.extend_from_slice(certificates);
        p
    }

    fn genesis_payload(bitmap_len: usize) -> Vec<u8> {
        let mut p = 7u64.to_le_bytes().to_vec();
        p.extend_from_slice(&[3; 32]);
        p.extend_from_slice(&[9; 192]);
        p.extend_from_slice(&(bitmap_len as u64).to_le_bytes());
        p.extend(std::iter::repeat_n(0xff, bitmap_len));
        p
    }

    fn parse_all(raw: &[Vec<u8>]) -> Vec<BlockMarker<'_>> {
        raw.iter().map(|m| parse(m).unwrap()).collect()
    }

    #[test]
    fn parses_footer_like_faithful() {
        let user_agent = "agave/4.4.0-beta.0 (src:98535e50; feat:6e955f07, client:Agave)";
        let raw = marker(0, &footer_payload(user_agent, &[0, 0, 0]));
        let BlockMarker::Footer(footer) = parse(&raw).unwrap() else {
            panic!("expected footer");
        };
        assert_eq!(footer.bank_hash, [0; 32]);
        assert_eq!(footer.block_producer_time_nanos, 1_791_392_218_636_594_070);
        assert_eq!(footer.block_user_agent, user_agent.as_bytes());
        assert_eq!(footer.certificates, &[0, 0, 0]);
    }

    #[test]
    fn parses_header_update_parent_and_genesis_certificate() {
        let raw = [
            marker(1, &parent_payload(41, 1)),
            marker(3, &genesis_payload(4)),
            marker(2, &parent_payload(40, 2)),
            marker(0, &footer_payload("", &[])),
        ];
        let parsed = parse_all(&raw);
        assert_eq!(
            parsed[0],
            BlockMarker::Header(ParentRef {
                parent_slot: 41,
                parent_block_id: [1; 32]
            })
        );
        let BlockMarker::GenesisCertificate(cert) = parsed[1] else {
            panic!("expected genesis certificate");
        };
        assert_eq!(
            (cert.slot, cert.block_id, cert.bitmap),
            (7, [3; 32], &[0xff; 4][..])
        );
        assert_eq!(cert.bls_signature, &[9; 192]);
        assert_eq!(
            parsed[2],
            BlockMarker::UpdateParent(ParentRef {
                parent_slot: 40,
                parent_block_id: [2; 32]
            })
        );
        validate_layout(&parsed).unwrap();
    }

    #[test]
    fn keeps_unknown_versions_and_variants_raw() {
        let mut future_version = marker(0, &footer_payload("", &[]));
        future_version[0] = 2;
        let mut future_payload = footer_payload("", &[]);
        future_payload[0] = 2;
        for (raw, payload_version) in [
            (future_version, None),
            (marker(9, &[1, 2, 3]), None),
            (marker(0, &future_payload), Some(2)),
        ] {
            let BlockMarker::Unknown(unknown) = parse(&raw).unwrap() else {
                panic!("expected unknown marker");
            };
            assert_eq!(unknown.payload_version, payload_version);
            assert_eq!(unknown.raw, &raw[..]);
        }
    }

    #[test]
    fn rejects_malformed_markers() {
        let footer = marker(0, &footer_payload("ua", &[]));
        assert!(matches!(
            parse(&footer[..4]),
            Err(BlockMarkerError::Truncated { .. })
        ));
        assert!(matches!(
            parse(&footer[..footer.len() - 1]),
            Err(BlockMarkerError::Truncated { .. })
        ));
        let mut trailing = footer.clone();
        trailing.push(0);
        assert!(matches!(
            parse(&trailing),
            Err(BlockMarkerError::TrailingBytes { .. })
        ));

        let mut short_user_agent = footer_payload("ua", &[]);
        short_user_agent[41] = 200;
        assert!(parse(&marker(0, &short_user_agent)).is_err());
        assert!(parse(&marker(1, &parent_payload(1, 1)[..40])).is_err());
        assert!(parse(&marker(3, &genesis_payload(513))).is_err());
        let mut wrong_bitmap_len = genesis_payload(4);
        wrong_bitmap_len.pop();
        assert!(parse(&marker(3, &wrong_bitmap_len)).is_err());
    }

    #[test]
    fn validates_marker_order_and_counts() {
        let header = marker(1, &parent_payload(1, 1));
        let footer = marker(0, &footer_payload("", &[]));
        let update = marker(2, &parent_payload(1, 1));
        let genesis = marker(3, &genesis_payload(0));
        let rejected: [&[&Vec<u8>]; 7] = [
            &[&footer],
            &[&header],
            &[&footer, &header],
            &[&header, &footer, &update],
            &[&header, &update, &update, &footer],
            &[&header, &update, &genesis, &footer],
            &[&header, &header, &footer],
        ];
        for layout in rejected {
            let raw: Vec<Vec<u8>> = layout.iter().map(|m| (*m).clone()).collect();
            assert!(validate_layout(&parse_all(&raw)).is_err(), "{layout:?}");
        }
        let accepted = [header.clone(), genesis, update, footer];
        validate_layout(&parse_all(&accepted)).unwrap();
    }
}

use core::marker::PhantomData;
use minicbor::data::Type;
use minicbor::decode::Error as CborError;
use minicbor::{Decode, Decoder, Encode};
use serde::{Deserialize, Serialize};

use crate::block_marker::{self, BlockFooter, BlockMarker, BlockMarkerError};

pub type Result<T> = core::result::Result<T, NodeDecodeError>;
pub type CarCid = [u8; 36];

#[inline]
pub fn car_cid_from_bytes(bytes: &[u8]) -> Option<CarCid> {
    let mut cid = [0u8; 36];
    (bytes.len() == cid.len()).then(|| {
        cid.copy_from_slice(bytes);
        cid
    })
}

#[derive(Debug)]
pub enum NodeDecodeError {
    Cbor(CborError),
    UnknownKind(u64),
}

impl core::fmt::Display for NodeDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NodeDecodeError::Cbor(e) => write!(f, "cbor decode error: {e}"),
            NodeDecodeError::UnknownKind(k) => write!(f, "unknown kind id {k}"),
        }
    }
}

impl std::error::Error for NodeDecodeError {}

impl From<CborError> for NodeDecodeError {
    #[inline]
    fn from(e: CborError) -> Self {
        NodeDecodeError::Cbor(e)
    }
}

/// Borrowed view over an encoded CBOR array, allowing cheap `len()` + iterator decoding.
#[derive(Debug, Clone)]
pub struct CborArrayView<'b, T> {
    pub slice: &'b [u8],
    pub(crate) _t: PhantomData<T>,
}

impl<'b, C, T> Decode<'b, C> for CborArrayView<'b, T> {
    #[inline]
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> core::result::Result<Self, CborError> {
        let start = d.position();
        // Reject unsupported shapes before the borrowed iterator can treat them as empty.
        d.array()?
            .ok_or_else(|| CborError::message("indefinite array not supported"))?;
        d.set_position(start);
        d.skip()?;
        let end = d.position();
        let input = d.input();

        Ok(Self {
            slice: &input[start..end],
            _t: PhantomData,
        })
    }
}

impl<'b, T> CborArrayView<'b, T>
where
    T: Decode<'b, ()>,
{
    #[inline]
    pub fn len(&self) -> usize {
        let mut d = Decoder::new(self.slice);
        // `array()` returns Option<u64> for indefinite arrays.
        d.array().ok().flatten().unwrap_or(0) as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = core::result::Result<T, CborError>> + 'b {
        let mut d = Decoder::new(self.slice);
        let n = d.array().ok().flatten().unwrap_or(0);
        (0..n).map(move |_| d.decode_with(&mut ()))
    }

    #[inline]
    pub fn decode_at(&self, idx: usize) -> core::result::Result<T, minicbor::decode::Error> {
        let mut d = minicbor::Decoder::new(self.slice);
        let n = d.array().ok().flatten().unwrap_or(0) as usize;
        if idx >= n {
            return Err(minicbor::decode::Error::message("index out of bounds"));
        }
        for _ in 0..idx {
            d.skip()?;
        }
        d.decode_with(&mut ())
    }
}

#[derive(Debug)]
pub struct DataFrame<'a> {
    pub kind: u64,
    pub hash: Option<u64>,
    pub hash_was_negative: bool,
    pub index: Option<u64>,
    pub total: Option<u64>,
    pub data: &'a [u8],
    pub next: Option<CborArrayView<'a, CborCidRef<'a>>>,
}

impl<'b, C> Decode<'b, C> for DataFrame<'b> {
    #[inline]
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> core::result::Result<Self, CborError> {
        let len = d
            .array()?
            .ok_or_else(|| CborError::message("indefinite dataframe array not supported"))?;
        if len < 5 {
            return Err(CborError::message("dataframe array too short"));
        }

        let kind = d.u64()?;
        let (hash, hash_was_negative) = decode_optional_hash_u64(d)?;
        let index = decode_optional_u64(d)?;
        let total = decode_optional_u64(d)?;
        let data = d.bytes()?;
        let next = if len > 5 { d.decode()? } else { None };
        for _ in 6..len {
            d.skip()?;
        }

        Ok(Self {
            kind,
            hash,
            hash_was_negative,
            index,
            total,
            data,
            next,
        })
    }
}

#[inline]
fn decode_optional_u64(d: &mut Decoder<'_>) -> core::result::Result<Option<u64>, CborError> {
    if d.datatype()? == Type::Null {
        d.null()?;
        return Ok(None);
    }
    Ok(Some(d.u64()?))
}

#[inline]
fn decode_optional_hash_u64(
    d: &mut Decoder<'_>,
) -> core::result::Result<(Option<u64>, bool), CborError> {
    match d.datatype()? {
        Type::Null => {
            d.null()?;
            Ok((None, false))
        }
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => Ok((Some(d.u64()?), false)),
        Type::I8 | Type::I16 | Type::I32 | Type::I64 => Ok((Some(d.i64()? as u64), true)),
        other => Err(CborError::type_mismatch(other)),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedDataFrame {
    pub hash: Option<u64>,
    pub index: Option<u64>,
    pub total: Option<u64>,
    pub data: Vec<u8>,
}

impl<'a> From<&DataFrame<'a>> for OwnedDataFrame {
    #[inline]
    fn from(value: &DataFrame<'a>) -> Self {
        Self {
            hash: value.hash,
            index: value.index,
            total: value.total,
            data: value.data.to_vec(),
        }
    }
}

/// Block metadata. Old Faithful writes the shortest tuple, so pre-Alpenglow blocks
/// have three elements and Alpenglow blocks add `block_markers` and `block_id`.
#[derive(Debug, Decode, Encode, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cbor(array)]
pub struct SlotMeta {
    #[n(0)]
    pub parent_slot: Option<u64>,
    #[n(1)]
    pub blocktime: Option<i64>,
    #[n(2)]
    pub block_height: Option<u64>,
    /// Raw Alpenglow block markers in block order; parse with [`crate::block_marker`].
    #[cbor(n(3), with = "byte_strings", has_nil)]
    pub block_markers: Option<Vec<Vec<u8>>>,
    /// Alpenglow block id (double merkle root) that certificates vote on.
    #[cbor(n(4), with = "minicbor::bytes")]
    pub block_id: Option<[u8; 32]>,
}

impl SlotMeta {
    pub fn parsed_block_markers(
        &self,
    ) -> impl Iterator<Item = core::result::Result<BlockMarker<'_>, BlockMarkerError>> {
        self.block_markers
            .iter()
            .flatten()
            .map(|raw| block_marker::parse(raw))
    }

    /// The block's footer, or `None` for a block without one (before Alpenglow).
    pub fn block_footer(&self) -> core::result::Result<Option<BlockFooter<'_>>, BlockMarkerError> {
        for marker in self.parsed_block_markers() {
            if let BlockMarker::Footer(footer) = marker? {
                return Ok(Some(footer));
            }
        }
        Ok(None)
    }
}

/// CBOR `[bytes]` or null for `Option<Vec<Vec<u8>>>`.
mod byte_strings {
    use minicbor::data::Type;
    use minicbor::{Decoder, Encoder};

    pub fn encode<Ctx, W: minicbor::encode::Write>(
        value: &Option<Vec<Vec<u8>>>,
        e: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match value {
            None => {
                e.null()?;
            }
            Some(items) => {
                e.array(items.len() as u64)?;
                for item in items {
                    e.bytes(item)?;
                }
            }
        }
        Ok(())
    }

    pub fn decode<Ctx>(
        d: &mut Decoder<'_>,
        _ctx: &mut Ctx,
    ) -> Result<Option<Vec<Vec<u8>>>, minicbor::decode::Error> {
        if d.datatype()? == Type::Null {
            d.null()?;
            return Ok(None);
        }
        let len = d
            .array()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite block_markers array"))?;
        let mut items = Vec::with_capacity(len.min(8) as usize);
        for _ in 0..len {
            items.push(d.bytes()?.to_vec());
        }
        Ok(Some(items))
    }

    pub fn nil() -> Option<Option<Vec<Vec<u8>>>> {
        Some(None)
    }

    pub fn is_nil(value: &Option<Vec<Vec<u8>>>) -> bool {
        value.is_none()
    }
}

#[derive(Debug, Decode, Encode, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cbor(array)]
pub struct Shredding {
    #[n(0)]
    pub entry_end_idx: i64,
    #[n(1)]
    pub shred_end_idx: i64,
}

#[derive(Debug, Decode)]
#[cbor(array)]
pub struct TransactionNode<'a> {
    #[n(0)]
    pub kind: u64,
    #[n(1)]
    #[cbor(borrow = "'a + 'bytes")]
    pub data: DataFrame<'a>,
    #[n(2)]
    pub metadata: DataFrame<'a>,
    #[n(3)]
    pub slot: u64,
    #[n(4)]
    pub index: Option<u64>,
}

#[derive(Debug, Decode)]
#[cbor(array)]
pub struct EntryNode<'a> {
    #[n(0)]
    pub kind: u64,
    #[n(1)]
    pub num_hashes: u64,
    #[n(2)]
    #[cbor(decode_with = "minicbor::bytes::decode")]
    pub hash: &'a [u8],
    #[n(3)]
    #[cbor(borrow = "'a + 'bytes")]
    pub transactions: CborArrayView<'a, CborCidRef<'a>>,
}

#[derive(Debug, Decode, Clone)]
#[cbor(array)]
pub struct BlockNode<'a> {
    #[n(0)]
    pub kind: u64,
    #[n(1)]
    pub slot: u64,
    #[n(2)]
    #[cbor(borrow = "'a + 'bytes")]
    pub shredding: CborArrayView<'a, Shredding>,
    #[n(3)]
    #[cbor(borrow = "'a + 'bytes")]
    pub entries: CborArrayView<'a, CborCidRef<'a>>,
    #[n(4)]
    pub meta: SlotMeta,
    #[n(5)]
    pub rewards: Option<CborCidRef<'a>>,
}

#[derive(Debug, Decode)]
#[cbor(array)]
pub struct SubsetNode<'a> {
    #[n(0)]
    pub kind: u64,
    #[n(1)]
    pub first: u64,
    #[n(2)]
    pub last: u64,
    #[n(3)]
    #[cbor(borrow = "'a + 'bytes")]
    pub blocks: CborArrayView<'a, CborCidRef<'a>>,
}

#[derive(Debug, Decode)]
#[cbor(array)]
pub struct EpochNode<'a> {
    #[n(0)]
    pub kind: u64,
    #[n(1)]
    pub epoch: u64,
    #[n(2)]
    #[cbor(borrow = "'a + 'bytes")]
    pub subsets: CborArrayView<'a, CborCidRef<'a>>,
}

#[derive(Debug, Decode)]
#[cbor(array)]
pub struct RewardsNode<'a> {
    #[n(0)]
    pub kind: u64,
    #[n(1)]
    pub slot: u64,
    #[n(2)]
    #[cbor(borrow = "'a + 'bytes")]
    pub data: DataFrame<'a>,
}

#[derive(Debug)]
pub enum Node<'a> {
    Transaction(TransactionNode<'a>),
    Entry(EntryNode<'a>),
    Block(BlockNode<'a>),
    Subset(SubsetNode<'a>),
    Epoch(EpochNode<'a>),
    Rewards(RewardsNode<'a>),
    DataFrame(DataFrame<'a>),
}

#[inline]
pub fn decode_node(data: &[u8]) -> Result<Node<'_>> {
    let kind = peek_node_type(data)?;
    decode_node_with_kind(data, kind)
}

#[inline]
pub(crate) fn decode_node_with_kind(data: &[u8], kind: u64) -> Result<Node<'_>> {
    let mut d = Decoder::new(data);

    Ok(match kind {
        0 => Node::Transaction(d.decode()?),
        1 => Node::Entry(d.decode()?),
        2 => Node::Block(d.decode()?),
        3 => Node::Subset(d.decode()?),
        4 => Node::Epoch(d.decode()?),
        5 => Node::Rewards(d.decode()?),
        6 => Node::DataFrame(d.decode()?),
        _ => return Err(NodeDecodeError::UnknownKind(kind)),
    })
}

#[inline]
pub fn peek_node_type(data: &[u8]) -> Result<u64> {
    let mut peek = Decoder::new(data);
    let _ = peek.array()?;
    Ok(peek.u64()?)
}

#[derive(Debug, Clone, Copy)]
pub struct CborCidRef<'a> {
    pub bytes: &'a [u8],
    pub tagged: bool,
}

impl<'a> CborCidRef<'a> {
    #[inline]
    pub fn hash_bytes(&self) -> &'a [u8] {
        &self.bytes[1..]
    }

    #[inline]
    pub fn normalized_bytes(&self) -> &'a [u8] {
        normalize_cid_ref_bytes(self.bytes)
    }

    #[inline]
    pub fn car_cid_bytes(&self) -> Option<&'a [u8]> {
        let bytes = self.normalized_bytes();
        (bytes.len() == 36).then_some(bytes)
    }

    #[inline]
    pub fn car_cid(&self) -> Option<CarCid> {
        car_cid_from_bytes(self.car_cid_bytes()?)
    }

    #[inline]
    pub fn inline_raw_bytes(&self) -> Option<&'a [u8]> {
        parse_inline_raw_identity_cid(self.normalized_bytes())
    }
}

impl<'b, C> Decode<'b, C> for CborCidRef<'b> {
    #[inline]
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> core::result::Result<Self, CborError> {
        let tagged = d.datatype()? == Type::Tag;
        if tagged {
            let _ = d.tag()?;
        }
        let bytes = d.bytes()?;
        if bytes.len() <= 1 {
            return Err(CborError::message("invalid CID bytes"));
        }
        Ok(Self { bytes, tagged })
    }
}

#[inline]
fn normalize_cid_ref_bytes(bytes: &[u8]) -> &[u8] {
    match bytes {
        [0, rest @ ..] => rest,
        bytes => bytes,
    }
}

fn parse_inline_raw_identity_cid(bytes: &[u8]) -> Option<&[u8]> {
    let (version, version_len) = parse_uvarint(bytes)?;
    if version != 1 {
        return None;
    }
    let (codec, codec_len) = parse_uvarint(&bytes[version_len..])?;
    if codec != 0x55 {
        return None;
    }
    let (multihash_code, mh_code_len) = parse_uvarint(&bytes[version_len + codec_len..])?;
    if multihash_code != 0 {
        return None;
    }
    let digest_len_start = version_len + codec_len + mh_code_len;
    let (digest_len, digest_len_len) = parse_uvarint(&bytes[digest_len_start..])?;
    let digest_start = digest_len_start + digest_len_len;
    let digest_end = digest_start.checked_add(digest_len as usize)?;
    let digest = bytes.get(digest_start..digest_end)?;
    (digest.len() == digest_len as usize).then_some(digest)
}

fn parse_uvarint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for (index, byte) in bytes.iter().take(10).copied().enumerate() {
        if byte < 0x80 {
            if index == 9 && byte > 1 {
                return None;
            }
            value |= (byte as u64) << shift;
            return Some((value, index + 1));
        }

        value |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
    }

    None
}

pub struct CborArrayIter<'b, T> {
    d: Decoder<'b>,
    rem: u64,
    _t: PhantomData<T>,
}

impl<'b, T> CborArrayIter<'b, T>
where
    T: Decode<'b, ()>,
{
    #[inline]
    pub fn new(slice: &'b [u8]) -> core::result::Result<Self, CborError> {
        let mut d = Decoder::new(slice);

        let n = d.array().ok().flatten().unwrap_or(0);

        Ok(Self {
            d,
            rem: n,
            _t: PhantomData,
        })
    }

    #[inline]
    pub fn next_item(&mut self) -> Option<core::result::Result<T, CborError>> {
        if self.rem == 0 {
            return None;
        }
        self.rem -= 1;
        Some(self.d.decode_with(&mut ()))
    }
}

impl<'b, T> CborArrayView<'b, T>
where
    T: Decode<'b, ()>,
{
    #[inline]
    pub fn iter_stateful(&self) -> core::result::Result<CborArrayIter<'b, T>, CborError> {
        CborArrayIter::new(self.slice)
    }
}

/// Returns true if `payload` looks like a CBOR array whose 1st element (kind) is small uint 2.
#[inline]
pub fn is_block_node(payload: &[u8]) -> bool {
    payload.len() >= 2
        && payload[0] >= 0x80
        && payload[0] < 0xA0 // CBOR array (major type 4)
        && payload[1] == 0x02
}

#[inline]
pub fn is_entry_node(payload: &[u8]) -> bool {
    payload.len() >= 2 && payload[0] >= 0x84 && payload[0] < 0xA0 && payload[1] == 0x01
}

#[inline]
pub fn is_transaction_node(payload: &[u8]) -> bool {
    payload.len() >= 2 && payload[0] >= 0x80 && payload[0] < 0xA0 && payload[1] == 0x00
}

/// Fast Block metadata decoder that skips all unnecessary fields
#[inline]
pub fn decode_block_metadata(data: &[u8]) -> Result<(u64, SlotMeta)> {
    let mut d = Decoder::new(data);

    // Verify it's an array
    let array_len = d.array()?.ok_or_else(|| {
        NodeDecodeError::Cbor(CborError::message("indefinite array not supported"))
    })?;

    if array_len < 5 {
        return Err(NodeDecodeError::Cbor(CborError::message(
            "block array too short",
        )));
    }

    // [0] kind - verify it's 2 (Block)
    let kind = d.u64()?;
    if kind != 2 {
        return Err(NodeDecodeError::UnknownKind(kind));
    }

    // [1] slot - decode this
    let slot = d.u64()?;

    // [2] shredding - skip
    d.skip()?;

    // [3] entries - skip
    d.skip()?;

    // [4] meta - decode this
    let meta: SlotMeta = d.decode()?;

    // Don't need to read [5] rewards

    Ok((slot, meta))
}

/// Fast Entry hash decoder that skips all unnecessary fields
#[inline]
pub fn decode_entry_hash(data: &[u8]) -> Result<&[u8]> {
    let mut d = Decoder::new(data);

    // Verify it's an array
    let array_len = d.array()?.ok_or_else(|| {
        NodeDecodeError::Cbor(CborError::message("indefinite array not supported"))
    })?;

    if array_len < 3 {
        return Err(NodeDecodeError::Cbor(CborError::message(
            "entry array too short",
        )));
    }

    // [0] kind - verify it's 1 (Entry)
    let kind = d.u64()?;
    if kind != 1 {
        return Err(NodeDecodeError::UnknownKind(kind));
    }

    // [1] num_hashes - skip
    d.skip()?;

    // [2] hash - decode this as bytes
    let hash = d.bytes()?;

    // Don't need to read [3] transactions

    Ok(hash)
}

#[inline]
pub fn decode_entry_poh(data: &[u8]) -> crate::node::Result<(u64, &[u8])> {
    use minicbor::{Decoder, decode::Error as CborError};

    let mut d = Decoder::new(data);

    let array_len = d.array()?.ok_or_else(|| {
        crate::node::NodeDecodeError::Cbor(CborError::message("indefinite array not supported"))
    })?;

    if array_len < 3 {
        return Err(crate::node::NodeDecodeError::Cbor(CborError::message(
            "entry array too short",
        )));
    }

    let kind = d.u64()?;
    if kind != 1 {
        return Err(crate::node::NodeDecodeError::UnknownKind(kind));
    }

    // [1] num_hashes
    let num_hashes = d.u64()?;

    // [2] hash bytes
    let hash = d.bytes()?;

    Ok((num_hashes, hash))
}

#[inline]
pub fn decode_entry_summary(data: &[u8]) -> crate::node::Result<(u64, &[u8], usize)> {
    use minicbor::{Decoder, decode::Error as CborError};

    let mut d = Decoder::new(data);

    let array_len = d.array()?.ok_or_else(|| {
        crate::node::NodeDecodeError::Cbor(CborError::message("indefinite array not supported"))
    })?;

    if array_len < 4 {
        return Err(crate::node::NodeDecodeError::Cbor(CborError::message(
            "entry array too short",
        )));
    }

    let kind = d.u64()?;
    if kind != 1 {
        return Err(crate::node::NodeDecodeError::UnknownKind(kind));
    }

    let num_hashes = d.u64()?;
    let hash = d.bytes()?;

    let tx_count = d.array()?.ok_or_else(|| {
        crate::node::NodeDecodeError::Cbor(CborError::message("indefinite array not supported"))
    })? as usize;

    Ok((num_hashes, hash, tx_count))
}

#[cfg(test)]
mod tests {
    use super::{DataFrame, Node, SlotMeta, decode_block_metadata, decode_node};
    use crate::block_marker::{self, BlockMarker, ParentRef};
    use minicbor::{Decode, Decoder, Encoder};

    // SlotMeta CBOR of real CAR blocks (radiance v0.0.31-rc.3): testnet slots 448940256
    // and 448940257 (Alpenglow, header + footer markers) and mainnet slot 453168000.
    const TESTNET_448940256: &str = "851a1ac248df1a6ac3e8911a17df899482582e010001290001df48c21a00000000bac494bc36eb254155a7697313529be54f481a939789d3b45eef1f59b92528c75902390100003402017194310ec1e664fb8cbcdbc8a0f248ab38feff9fed499588df1535f900a4f0eb2f484a1cb2b4db180001df48c21a00000000bac494bc36eb254155a7697313529be54f481a939789d3b45eef1f59b92528c7ace9e16141d85ac968a6ea594c7f37c02e7977d75e40e902fe20889110b51db390ae7df00cc85662c9ec811b472a6d09152b17e45720cea29165618e3f4bbfa3f2284ba7a0213eaff3b4823435c4390ba0f84a2f06edb28f7799618f6c746afd3e0000d601fdff7befbfdf7a4af7feef65895ddbffb9db86cfefffe93faec6f5c59fbbf7867d8bf7edf776ffbfe3fedf7fdffddffffb6f9ff7ddeb3fc30faf200001d848c21a00000000a89381940a6a07978e3d4be5dadaa61866fd560bd1e9945a06c644f469d0bea076352b813618d9a90d6fbf044b31259812174f0c3a3dada90c264657bb090c3cda403d2d120a845fb447232302399584913ec48eceb2bebef9d2366b0d0b4d5d0e005500000000000000000000001001d848c21a00000000e7b4bc491a3a4c428d7a77d180cdf6df7b0e4a949dfd47865590d9cda65a0868a2f2d6c8e5ddd0b72616480866add2acce4b2eb4e5fa1fd16dbee4d9a178d4e4bf1ee27005116e9e1a7db9ae371595080b883ae5744adcd61ed19ab15f2b1c22a57e9c08efaea6620733805c338eacabd2d654c69cc1370808d8aeedca09fc3f3e00d601fffffbefffdffeffffffefffcfdfffffffffffffffffffffffdffff5ffffffffffffffffffffffffffffffffffffdffffffffffffffbfff3bfef37582090bab6dca987c34e352e0206672cabee5ef1ce559d1799337e8498774c85fe4d";
    const TESTNET_448940257: &str = "851a1ac248e01a6ac3e8921a17df899582582e010001290001e048c21a0000000090bab6dca987c34e352e0206672cabee5ef1ce559d1799337e8498774c85fe4d590238010000330201046c6a473d2af0392ebc458af98f48c2410840a2a284c5380ff47a5b5b8c58ed73a2b125b2b4db180001e048c21a0000000090bab6dca987c34e352e0206672cabee5ef1ce559d1799337e8498774c85fe4d93e7bd265bbab21ffa0d3af71d7213194df275cbdafa4c98a6dcbe3e8b854d2c25053b01f1d25d79f209489882eee7df11456be62b32ac7adff9ccee5f884def2d5a40fa1a2e63164a5f8b6610f16475c4608773711d968cec80c6eaf426d5ce3d0000cf01f7ef7be59fde7a8a7bffbf19d16aff737fdb70fdfd7f9a8fa6d9bffabefb5b58bfea7effdbf65fcff2ffd47ffdbf7fbb5efbdecbcddddb8019540001d948c21a00000000a40e14ee8ec965306a5487cafdac9e4ad5ccc5459ea4c0f84440234a27acff54b54bda9eb7796270ede8c5810146ed18088166ee3d754af04546adc58fe8312ee953fbc41fa6c31d3fdff39ad91d498a2e3f6646b97d0deac342f6a4994f4c560e005500000000000000000000001001d948c21a00000000df797ebc81eeed1f272210f279f1ad8fdafcc6e5a047d21d742a607da159790e97655a8e9a8605766d21f7da3b7db1dda8ab94582c5c1381a51c65b1303b431161ee89849eec7bfbfce479d366b3aea2127f8059d433bdee6f4449ffe857eb43d466294bfc5bfa5f6c434409d1f4fc0d21a3fddfd41e894d4026530aba775e2f3e00d601fffffbefffdffeffffffefffcfdfffffffffffffffffffffffdffff5ffffffffffffffffffffffffffffffffffffdffffffffffffffbfff3bfef3758200af1e9000b056d583cee7f5b24eee940cd5a2532dfd34143d7e605c06beb1c0b";
    const MAINNET_453168000: &str = "831a1b02cb7f1a6ac1e9ff1a19b3b028";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn decode_meta(cbor: &[u8]) -> SlotMeta {
        Decoder::new(cbor).decode().unwrap()
    }

    fn encode_meta(meta: &SlotMeta) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.encode(meta).unwrap();
        e.into_writer()
    }

    fn block_node(meta_cbor: &[u8]) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u64(2)
            .unwrap()
            .u64(448_940_256)
            .unwrap();
        e.array(0).unwrap().array(0).unwrap();
        let mut out = e.into_writer();
        out.extend_from_slice(meta_cbor);
        out.push(0xf6); // rewards: null
        out
    }

    #[test]
    fn real_alpenglow_slot_meta_decodes_and_reencodes_byte_identical() {
        let cbor = unhex(TESTNET_448940256);
        let meta = decode_meta(&cbor);
        assert_eq!(meta.parent_slot, Some(448_940_255));
        assert_eq!(meta.blocktime, Some(1_791_223_953));
        assert_eq!(meta.block_height, Some(400_525_716));
        assert_eq!(meta.block_markers.as_ref().map(Vec::len), Some(2));
        assert_eq!(meta.block_id.unwrap()[..4], [0x90, 0xba, 0xb6, 0xdc]);
        assert_eq!(encode_meta(&meta), cbor);

        let markers: Vec<BlockMarker<'_>> = meta
            .parsed_block_markers()
            .collect::<Result<_, _>>()
            .unwrap();
        block_marker::validate_layout(&markers).unwrap();
        let BlockMarker::Header(header) = markers[0] else {
            panic!("expected header first");
        };
        assert_eq!(header.parent_slot, 448_940_255);
        let footer = meta.block_footer().unwrap().unwrap();
        assert_eq!(footer.block_producer_time_nanos, 1_791_223_953_881_712_687);
        assert_eq!(
            footer.block_producer_time_nanos / 1_000_000_000,
            1_791_223_953
        );
        assert_eq!(footer.bank_hash[..4], [0x71, 0x94, 0x31, 0x0e]);
        assert!(footer.block_user_agent.is_empty());
        assert_eq!(footer.certificates.len(), 522);
    }

    #[test]
    fn real_alpenglow_headers_chain_to_the_parent_block_id() {
        let first = decode_meta(&unhex(TESTNET_448940256));
        let second = decode_meta(&unhex(TESTNET_448940257));
        let Some(Ok(BlockMarker::Header(ParentRef {
            parent_slot,
            parent_block_id,
        }))) = second.parsed_block_markers().next()
        else {
            panic!("expected header first");
        };
        assert_eq!(parent_slot, 448_940_256);
        assert_eq!(Some(parent_block_id), first.block_id);
    }

    #[test]
    fn pre_alpenglow_slot_meta_stays_a_three_element_tuple() {
        let cbor = unhex(MAINNET_453168000);
        let meta = decode_meta(&cbor);
        assert_eq!(meta.block_markers, None);
        assert_eq!(meta.block_id, None);
        assert_eq!(meta.block_footer().unwrap(), None);
        assert_eq!(encode_meta(&meta), cbor);
    }

    #[test]
    fn slot_meta_writes_null_gaps_and_omits_trailing_absent_fields() {
        let meta = SlotMeta {
            parent_slot: Some(1),
            blocktime: Some(2),
            block_height: None,
            block_markers: Some(vec![vec![1, 0, 1, 0, 0]]),
            block_id: None,
        };
        // [1, 2, null, [h'0100010000']]
        assert_eq!(encode_meta(&meta), unhex("840102f681450100010000"));
        assert_eq!(decode_meta(&encode_meta(&meta)), meta);
    }

    #[test]
    fn slot_meta_rejects_a_block_id_that_is_not_32_bytes() {
        // [1, 2, 3, null, h'00']
        assert!(
            Decoder::new(&unhex("85010203f64100"))
                .decode::<SlotMeta>()
                .is_err()
        );
    }

    #[test]
    fn block_node_decoders_read_alpenglow_slot_meta() {
        let cbor = unhex(TESTNET_448940256);
        let payload = block_node(&cbor);
        let (slot, meta) = decode_block_metadata(&payload).unwrap();
        assert_eq!(slot, 448_940_256);
        assert_eq!(meta, decode_meta(&cbor));
        let Node::Block(block) = decode_node(&payload).unwrap() else {
            panic!("expected block");
        };
        assert_eq!(block.meta, meta);
        assert!(block.rewards.is_none());
    }

    #[test]
    fn dataframe_rejects_unsupported_next_array_shapes() {
        let mut link = vec![0xd8, 42, 0x58, 37, 0, 1, 0x71, 0x12, 0x20];
        link.extend_from_slice(&[0x11; 32]);
        for indefinite in [false, true] {
            let mut frame = vec![0x86, 6, 0xf6, 0xf6, 0xf6, 0x40, 0x9f];
            if indefinite {
                frame.extend_from_slice(&link);
                frame.push(0xff);
            } else {
                *frame.last_mut().unwrap() = 0x40; // Wrong type: byte string.
            }
            assert!(DataFrame::decode(&mut Decoder::new(&frame), &mut ()).is_err());
        }
        let mut valid = vec![0x86, 6, 0xf6, 0xf6, 0xf6, 0x40, 0x81];
        valid.extend_from_slice(&link);
        let frame = DataFrame::decode(&mut Decoder::new(&valid), &mut ()).unwrap();
        assert_eq!(frame.next.unwrap().iter().count(), 1);
    }

    #[test]
    fn dataframe_hash_accepts_signed_cbor_i64() {
        let signed_hash = -5_787_489_622_768_765_176i64;
        let mut e = Encoder::new(Vec::new());
        e.array(5).expect("array");
        e.u64(6).expect("kind");
        e.i64(signed_hash).expect("signed hash");
        e.null().expect("index");
        e.null().expect("total");
        e.bytes(&[1, 2, 3]).expect("data");
        let payload = e.into_writer();

        let Node::DataFrame(frame) = decode_node(&payload).expect("decode dataframe") else {
            panic!("expected dataframe");
        };

        assert_eq!(frame.hash, Some(signed_hash as u64));
        assert!(frame.hash_was_negative);
        assert_eq!(frame.index, None);
        assert_eq!(frame.total, None);
        assert_eq!(frame.data, &[1, 2, 3]);
    }

    #[test]
    fn dataframe_hash_keeps_unsigned_cbor_marker() {
        let mut e = Encoder::new(Vec::new());
        e.array(5).expect("array");
        e.u64(6).expect("kind");
        e.u64(42).expect("unsigned hash");
        e.null().expect("index");
        e.null().expect("total");
        e.bytes(&[]).expect("data");
        let payload = e.into_writer();

        let mut d = Decoder::new(&payload);
        let frame = DataFrame::decode(&mut d, &mut ()).expect("decode dataframe");

        assert_eq!(frame.hash, Some(42));
        assert!(!frame.hash_was_negative);
    }
}

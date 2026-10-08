use anyhow::{Result, anyhow};
use of_car_reader::compact_index::{
    BUCKET_HEADER_SIZE, CompactIndexHeader, CompactIndexMeta, bst_lookup, bucket_hash,
    decode_offset_and_size, truncate_entry_hash,
};
use of_car_reader::node::{Node, decode_node};
use of_car_reader::slot_ranges::{EpochSchedule, SLOTS_PER_EPOCH, SlotRange};
use std::collections::HashMap;
#[cfg(any(not(target_arch = "wasm32"), test))]
use std::future::{Ready, ready};

pub const DEFAULT_MAX_BUCKET_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct BuildSlotRangesConfig {
    pub max_bucket_payload_bytes: usize,
    pub allow_node_read_fallback: bool,
    pub epoch_schedule: EpochSchedule,
}

impl Default for BuildSlotRangesConfig {
    fn default() -> Self {
        Self {
            max_bucket_payload_bytes: DEFAULT_MAX_BUCKET_PAYLOAD_BYTES,
            allow_node_read_fallback: false,
            epoch_schedule: EpochSchedule::MAINNET,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BuildSlotRangesStats {
    pub present_slots: u32,
    pub slot_bucket_payload_bytes_read: u64,
    pub cid_bucket_payload_bytes_read: u64,
    pub max_slot_bucket_payload_bytes: usize,
    pub max_cid_bucket_payload_bytes: usize,
    pub slot_node_read_fallbacks: u64,
    pub cid_node_read_fallbacks: u64,
    pub slot_index_false_positives: u32,
}

#[derive(Clone, Debug)]
pub struct BuildSlotRangesOutput {
    pub ranges: Vec<SlotRange>,
    pub stats: BuildSlotRangesStats,
}

pub trait RangeReader {
    type ReadFuture<'a>: Future<Output = Result<()>> + 'a
    where
        Self: 'a;

    fn read_exact_at<'a>(&'a mut self, offset: u64, out: &'a mut [u8]) -> Self::ReadFuture<'a>;
}

#[cfg(not(target_arch = "wasm32"))]
pub struct LocalFileRangeReader {
    file: std::fs::File,
}

#[cfg(not(target_arch = "wasm32"))]
impl LocalFileRangeReader {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        use anyhow::Context;

        let path = path.as_ref();
        let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        Ok(Self { file })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl RangeReader for LocalFileRangeReader {
    type ReadFuture<'a>
        = Ready<Result<()>>
    where
        Self: 'a;

    fn read_exact_at<'a>(&'a mut self, offset: u64, out: &'a mut [u8]) -> Self::ReadFuture<'a> {
        use anyhow::Context;
        use std::os::unix::fs::FileExt;

        ready(
            self.file
                .read_exact_at(out, offset)
                .with_context(|| format!("read {} bytes at offset {offset}", out.len())),
        )
    }
}

pub struct AsyncCompactIndex<R> {
    source: String,
    meta: CompactIndexMeta,
    reader: R,
}

impl<R: RangeReader> AsyncCompactIndex<R> {
    pub async fn open(mut reader: R, source: impl Into<String>) -> Result<Self> {
        let source = source.into();
        let mut fixed = vec![0u8; of_car_reader::compact_index::COMPACT_INDEX_FIXED_HEADER_SIZE];
        reader.read_exact_at(0, &mut fixed).await?;

        let header = CompactIndexMeta::parse_header_prefix(&fixed, &source)?;
        let bucket_headers_len = bucket_headers_len(header)?;
        let mut bucket_headers = vec![0u8; bucket_headers_len];
        reader
            .read_exact_at(header.total_header_size, &mut bucket_headers)
            .await?;
        let meta = CompactIndexMeta::parse_bucket_headers(header, &bucket_headers, &source)?;

        Ok(Self {
            source,
            meta,
            reader,
        })
    }

    #[inline]
    pub fn value_size(&self) -> usize {
        self.meta.value_size()
    }

    #[inline]
    pub fn num_buckets(&self) -> u32 {
        self.meta.num_buckets()
    }

    #[inline]
    pub fn version(&self) -> u8 {
        self.meta.version()
    }

    #[inline]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[inline]
    pub fn meta(&self) -> &CompactIndexMeta {
        &self.meta
    }

    pub async fn read_bucket_payload_into(&mut self, bucket: u32, buf: &mut [u8]) -> Result<()> {
        let header = self.meta.bucket_header(bucket)?;
        self.reader.read_exact_at(header.data_offset, buf).await
    }

    pub async fn lookup_into_node_reads(&mut self, key: &[u8], out: &mut [u8]) -> Result<bool> {
        if out.len() != self.value_size() {
            return Err(anyhow!(
                "lookup output length {} does not match index value size {}",
                out.len(),
                self.value_size()
            ));
        }

        let bucket = bucket_hash(key, self.num_buckets());
        let header = self.meta.bucket_header(bucket)?;
        let hash_len = header.hash_len as usize;
        let stride = hash_len
            .checked_add(self.value_size())
            .ok_or_else(|| anyhow!("compact index stride overflow"))?;
        let entries = header.num_entries as usize;

        if entries == 0 {
            return Ok(false);
        }

        let target = truncate_entry_hash(header.hash_domain, key, hash_len);
        let mut index = 0usize;
        let mut node = vec![0u8; stride];

        while index < entries {
            let offset = header
                .data_offset
                .checked_add((index * stride) as u64)
                .ok_or_else(|| anyhow!("compact index node offset overflow"))?;
            self.reader.read_exact_at(offset, &mut node).await?;

            let hash = read_hash(&node[..hash_len]);
            if hash == target {
                out.copy_from_slice(&node[hash_len..hash_len + self.value_size()]);
                return Ok(true);
            }

            index = (index << 1) | 1;
            if hash < target {
                index += 1;
            }
        }

        Ok(false)
    }
}

/// `car` is only read for the few blocks that more than one slot resolves to.
pub async fn build_slot_ranges_from_indexes<S, C, K>(
    epoch: u64,
    car_header_size: u64,
    slot_index: &mut AsyncCompactIndex<S>,
    cid_index: &mut AsyncCompactIndex<C>,
    car: &mut K,
    config: BuildSlotRangesConfig,
) -> Result<BuildSlotRangesOutput>
where
    S: RangeReader,
    C: RangeReader,
    K: RangeReader,
{
    if slot_index.version() != 1 || cid_index.version() != 1 {
        return Err(anyhow!(
            "unsupported compact index version slot={} cid={}",
            slot_index.version(),
            cid_index.version()
        ));
    }
    if cid_index.value_size() != 9 {
        return Err(anyhow!(
            "unsupported cid index value_size={} (expected 9)",
            cid_index.value_size()
        ));
    }

    let epoch_start_slot = config
        .epoch_schedule
        .first_slot(epoch)
        .ok_or_else(|| anyhow!("epoch {epoch} is a warmup epoch or overflows"))?;
    let bitset_len = (SLOTS_PER_EPOCH as usize).div_ceil(8);
    let mut stats = BuildSlotRangesStats::default();

    let mut slot_groups = Vec::with_capacity(SLOTS_PER_EPOCH as usize);
    for i in 0..SLOTS_PER_EPOCH {
        let slot = epoch_start_slot + i;
        let bucket = bucket_hash(&slot.to_le_bytes(), slot_index.num_buckets());
        slot_groups.push((bucket, i as u32));
    }
    slot_groups.sort_unstable_by_key(|(bucket, slot)| (*bucket, *slot));

    let cid_value_size = slot_index.value_size();
    let mut slot_has_cid = vec![0u8; bitset_len];
    let mut slot_cids = vec![0u8; (SLOTS_PER_EPOCH as usize) * cid_value_size];
    let mut bucket_buf = Vec::new();

    let mut group_start = 0usize;
    while group_start < slot_groups.len() {
        let bucket = slot_groups[group_start].0;
        let mut group_end = group_start + 1;
        while group_end < slot_groups.len() && slot_groups[group_end].0 == bucket {
            group_end += 1;
        }

        let header = slot_index.meta().bucket_header(bucket)?;
        let hash_len = header.hash_len as usize;
        let payload_len =
            bucket_payload_len(hash_len, slot_index.value_size(), header.num_entries)?;
        stats.max_slot_bucket_payload_bytes = stats.max_slot_bucket_payload_bytes.max(payload_len);

        if payload_len > config.max_bucket_payload_bytes {
            if !config.allow_node_read_fallback {
                return Err(anyhow!(
                    "{} bucket {bucket} payload is {} bytes, over configured cap {}",
                    slot_index.source(),
                    payload_len,
                    config.max_bucket_payload_bytes
                ));
            }

            for &(_, i) in &slot_groups[group_start..group_end] {
                let slot = epoch_start_slot + i as u64;
                let key = slot.to_le_bytes();
                let out = &mut slot_cids
                    [(i as usize) * cid_value_size..(i as usize + 1) * cid_value_size];
                if slot_index.lookup_into_node_reads(&key, out).await? {
                    set_bit(&mut slot_has_cid, i as usize);
                }
                stats.slot_node_read_fallbacks += 1;
            }
        } else {
            bucket_buf.clear();
            bucket_buf.resize(payload_len, 0);
            slot_index
                .read_bucket_payload_into(bucket, &mut bucket_buf)
                .await?;
            stats.slot_bucket_payload_bytes_read += payload_len as u64;

            for &(_, i) in &slot_groups[group_start..group_end] {
                let slot = epoch_start_slot + i as u64;
                let key = slot.to_le_bytes();
                let target = truncate_entry_hash(header.hash_domain, &key, hash_len);
                if let Some(value) = bst_lookup(
                    &bucket_buf,
                    header.num_entries,
                    hash_len,
                    cid_value_size,
                    target,
                ) {
                    let out = &mut slot_cids
                        [(i as usize) * cid_value_size..(i as usize + 1) * cid_value_size];
                    out.copy_from_slice(value);
                    set_bit(&mut slot_has_cid, i as usize);
                }
            }
        }

        group_start = group_end;
    }
    drop(slot_groups);

    let mut cid_groups = Vec::new();
    for i in 0..SLOTS_PER_EPOCH as usize {
        if !get_bit(&slot_has_cid, i) {
            continue;
        }
        stats.present_slots += 1;
        let cid = &slot_cids[i * cid_value_size..(i + 1) * cid_value_size];
        let bucket = bucket_hash(cid, cid_index.num_buckets());
        cid_groups.push((bucket, i as u32));
    }
    cid_groups.sort_unstable_by_key(|(bucket, slot)| (*bucket, *slot));

    let mut slot_has_end = vec![0u8; bitset_len];
    let mut slot_offset_abs = vec![0u64; SLOTS_PER_EPOCH as usize];
    let mut slot_end_excl_abs = vec![0u64; SLOTS_PER_EPOCH as usize];

    let mut group_start = 0usize;
    while group_start < cid_groups.len() {
        let bucket = cid_groups[group_start].0;
        let mut group_end = group_start + 1;
        while group_end < cid_groups.len() && cid_groups[group_end].0 == bucket {
            group_end += 1;
        }

        let header = cid_index.meta().bucket_header(bucket)?;
        let hash_len = header.hash_len as usize;
        let payload_len = bucket_payload_len(hash_len, cid_index.value_size(), header.num_entries)?;
        stats.max_cid_bucket_payload_bytes = stats.max_cid_bucket_payload_bytes.max(payload_len);

        if payload_len > config.max_bucket_payload_bytes {
            if !config.allow_node_read_fallback {
                return Err(anyhow!(
                    "{} bucket {bucket} payload is {} bytes, over configured cap {}",
                    cid_index.source(),
                    payload_len,
                    config.max_bucket_payload_bytes
                ));
            }

            let mut out = vec![0u8; cid_index.value_size()];
            for &(_, i) in &cid_groups[group_start..group_end] {
                let cid =
                    &slot_cids[(i as usize) * cid_value_size..(i as usize + 1) * cid_value_size];
                if cid_index.lookup_into_node_reads(cid, &mut out).await? && out.len() == 9 {
                    let (offset, size) = decode_offset_and_size(&out)?;
                    slot_offset_abs[i as usize] = offset;
                    slot_end_excl_abs[i as usize] = offset
                        .checked_add(size as u64)
                        .ok_or_else(|| anyhow!("overflow end_excl_abs"))?;
                    set_bit(&mut slot_has_end, i as usize);
                }
                stats.cid_node_read_fallbacks += 1;
            }
        } else {
            bucket_buf.clear();
            bucket_buf.resize(payload_len, 0);
            cid_index
                .read_bucket_payload_into(bucket, &mut bucket_buf)
                .await?;
            stats.cid_bucket_payload_bytes_read += payload_len as u64;

            for &(_, i) in &cid_groups[group_start..group_end] {
                let cid =
                    &slot_cids[(i as usize) * cid_value_size..(i as usize + 1) * cid_value_size];
                let target = truncate_entry_hash(header.hash_domain, cid, hash_len);

                if let Some(value) = bst_lookup(
                    &bucket_buf,
                    header.num_entries,
                    hash_len,
                    cid_index.value_size(),
                    target,
                ) && value.len() == 9
                {
                    let (offset, size) = decode_offset_and_size(value)?;
                    slot_offset_abs[i as usize] = offset;
                    slot_end_excl_abs[i as usize] = offset
                        .checked_add(size as u64)
                        .ok_or_else(|| anyhow!("overflow end_excl_abs"))?;
                    set_bit(&mut slot_has_end, i as usize);
                }
            }
        }

        group_start = group_end;
    }

    // The slot index stores short key hashes, so a slot without a block can match another
    // slot's entry and resolve to that block. Keep only the slot each shared block belongs to.
    let mut slots_by_end: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, &end) in slot_end_excl_abs.iter().enumerate() {
        if get_bit(&slot_has_end, i) {
            slots_by_end.entry(end).or_default().push(i);
        }
    }
    for slots in slots_by_end.into_values().filter(|slots| slots.len() > 1) {
        let i = slots[0];
        let cid = &slot_cids[i * cid_value_size..(i + 1) * cid_value_size];
        let block_slot =
            read_block_slot(car, slot_offset_abs[i], slot_end_excl_abs[i], cid).await?;
        let owner = block_slot
            .checked_sub(epoch_start_slot)
            .and_then(|idx| usize::try_from(idx).ok())
            .filter(|idx| slots.contains(idx))
            .ok_or_else(|| {
                anyhow!(
                    "block at CAR offset {} is slot {block_slot}, but the slot index maps slots {:?} to it",
                    slot_offset_abs[i],
                    slots.iter().map(|&s| epoch_start_slot + s as u64).collect::<Vec<_>>()
                )
            })?;
        for &s in slots.iter().filter(|&&s| s != owner) {
            clear_bit(&mut slot_has_end, s);
            stats.slot_index_false_positives += 1;
            stats.present_slots -= 1;
        }
    }

    let mut ranges = vec![SlotRange::EMPTY; SLOTS_PER_EPOCH as usize];
    let mut prev_end_excl_abs: Option<u64> = None;
    for i in 0..SLOTS_PER_EPOCH as usize {
        if !get_bit(&slot_has_end, i) {
            continue;
        }

        let cur_end_excl_abs = slot_end_excl_abs[i];
        let start_abs = prev_end_excl_abs.unwrap_or(car_header_size);

        // Blocks are written in slot order, so an end at or before the previous one is a bad lookup.
        if cur_end_excl_abs <= start_abs {
            return Err(anyhow!(
                "slot {} ends at CAR offset {cur_end_excl_abs}, not after the previous block's end {start_abs}",
                epoch_start_slot + i as u64
            ));
        }
        let len64 = cur_end_excl_abs - start_abs;
        if len64 <= u32::MAX as u64 {
            ranges[i] = SlotRange {
                offset: start_abs,
                len: len64 as u32,
            };
        }

        prev_end_excl_abs = Some(cur_end_excl_abs);
    }

    Ok(BuildSlotRangesOutput { ranges, stats })
}

pub fn decode_car_header_total_size(prefix: &[u8], source: &str) -> Result<u64> {
    if prefix.len() < 10 {
        return Err(anyhow!(
            "car header prefix from {source} is too short ({} bytes), need at least 10",
            prefix.len()
        ));
    }

    let (header_len, varint_len) = decode_uvarint64(&prefix[..10])
        .ok_or_else(|| anyhow!("could not decode car header length from {source}"))?;

    (varint_len as u64)
        .checked_add(header_len)
        .ok_or_else(|| anyhow!("car header size overflow for {source}"))
}

#[inline]
fn bucket_payload_len(hash_len: usize, value_size: usize, entries: u32) -> Result<usize> {
    hash_len
        .checked_add(value_size)
        .and_then(|stride| stride.checked_mul(entries as usize))
        .ok_or_else(|| anyhow!("bucket payload size overflow"))
}

fn bucket_headers_len(header: CompactIndexHeader) -> Result<usize> {
    (header.num_buckets as usize)
        .checked_mul(BUCKET_HEADER_SIZE)
        .ok_or_else(|| anyhow!("bucket headers size overflow"))
}

#[inline(always)]
fn set_bit(bitset: &mut [u8], index: usize) {
    bitset[index / 8] |= 1 << (index % 8);
}

#[inline(always)]
fn clear_bit(bitset: &mut [u8], index: usize) {
    bitset[index / 8] &= !(1 << (index % 8));
}

#[inline(always)]
fn get_bit(bitset: &[u8], index: usize) -> bool {
    (bitset[index / 8] & (1 << (index % 8))) != 0
}

#[inline]
fn read_hash(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= (*byte as u64) << (index * 8);
    }
    value
}

/// Reads the slot of the block node stored in the CAR section `[offset, end)`.
async fn read_block_slot<K: RangeReader>(
    car: &mut K,
    offset: u64,
    end: u64,
    cid: &[u8],
) -> Result<u64> {
    let len = usize::try_from(end - offset).map_err(|_| anyhow!("CAR section too large"))?;
    let mut section = vec![0u8; len];
    car.read_exact_at(offset, &mut section).await?;
    let (_, varint_len) = decode_uvarint64(&section)
        .ok_or_else(|| anyhow!("bad CAR section length at offset {offset}"))?;
    let payload = section[varint_len..].strip_prefix(cid).ok_or_else(|| {
        anyhow!("CAR section at offset {offset} does not start with the indexed CID")
    })?;
    match decode_node(payload) {
        Ok(Node::Block(block)) => Ok(block.slot),
        Ok(_) => Err(anyhow!(
            "CAR section at offset {offset} is not a block node"
        )),
        Err(err) => Err(anyhow!("decode block node at offset {offset}: {err}")),
    }
}

#[inline]
fn decode_uvarint64(buf: &[u8]) -> Option<(u64, usize)> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;

    for (i, &b) in buf.iter().take(10).enumerate() {
        if b < 0x80 {
            if i == 9 && b > 1 {
                return None;
            }
            x |= (b as u64) << s;
            return Some((x, i + 1));
        } else {
            x |= ((b & 0x7f) as u64) << s;
            s += 7;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MemoryRangeReader {
        bytes: Vec<u8>,
        max_read: Rc<RefCell<usize>>,
    }

    impl RangeReader for MemoryRangeReader {
        type ReadFuture<'a>
            = Ready<Result<()>>
        where
            Self: 'a;

        fn read_exact_at<'a>(&'a mut self, offset: u64, out: &'a mut [u8]) -> Self::ReadFuture<'a> {
            let previous = *self.max_read.borrow();
            *self.max_read.borrow_mut() = previous.max(out.len());
            let start = offset as usize;
            let end = start + out.len();
            if end > self.bytes.len() {
                return ready(Err(anyhow!("test range out of bounds")));
            }
            out.copy_from_slice(&self.bytes[start..end]);
            ready(Ok(()))
        }
    }

    #[test]
    fn decodes_car_header_size() {
        assert_eq!(
            decode_car_header_total_size(&[4, 0, 0, 0, 0, 0, 0, 0, 0, 0], "x").unwrap(),
            5
        );
    }

    #[test]
    fn async_compact_index_reads_bounded_bucket() {
        let max_read = Rc::new(RefCell::new(0usize));
        let bytes = tiny_compact_index(b"slot-key", &[1, 2, 3]);
        let reader = MemoryRangeReader {
            bytes,
            max_read: Rc::clone(&max_read),
        };
        let mut index =
            futures::executor::block_on(AsyncCompactIndex::open(reader, "mem")).unwrap();
        let mut out = [0u8; 3];
        assert!(
            futures::executor::block_on(index.lookup_into_node_reads(b"slot-key", &mut out))
                .unwrap()
        );
        assert_eq!(out, [1, 2, 3]);
        assert_eq!(
            *max_read.borrow(),
            of_car_reader::compact_index::COMPACT_INDEX_FIXED_HEADER_SIZE
        );
    }

    #[test]
    fn slot_index_false_positives_keep_the_block_on_its_own_slot() {
        // 1-byte slot hashes, so hundreds of block-less slots match one of the two blocks.
        let slot_hash_len = 1;
        let first_slot = EpochSchedule::MAINNET.first_slot(1).unwrap();
        let slot_hash = |slot: u64| truncate_entry_hash(11, &slot.to_le_bytes(), slot_hash_len);
        let block1 = first_slot + 1000;
        let block2 = (first_slot + 2000..)
            .find(|&slot| slot_hash(slot) != slot_hash(block1))
            .unwrap();
        // The case that used to blank out real blocks: a block-less slot before block1 resolves to block2.
        let early = (first_slot..block1)
            .find(|&slot| slot_hash(slot) == slot_hash(block2))
            .unwrap();
        let (cid1, cid2) = (vec![1u8; 36], vec![2u8; 36]);

        let header_size = 10u64;
        let mut car = vec![0u8; header_size as usize];
        let mut offsets_and_sizes = Vec::new();
        for (slot, cid) in [(block1, &cid1), (block2, &cid2)] {
            // Some entry bytes before the block node, as in a real CAR.
            car.extend_from_slice(&[0xee; 50]);
            let offset = car.len() as u64;
            car.extend_from_slice(&car_section(cid, &block_node(slot)));
            let size = car.len() as u64 - offset;
            let mut value = offset.to_le_bytes()[..6].to_vec();
            value.extend_from_slice(&(size as u32).to_le_bytes()[..3]);
            offsets_and_sizes.push((offset, size, value));
        }

        let memory = |bytes| MemoryRangeReader {
            bytes,
            max_read: Rc::new(RefCell::new(0)),
        };
        let slot_index_bytes = compact_index(
            slot_hash_len as u8,
            &[
                (block1.to_le_bytes().to_vec(), cid1.clone()),
                (block2.to_le_bytes().to_vec(), cid2.clone()),
            ],
        );
        let cid_index_bytes = compact_index(
            8,
            &[
                (cid1, offsets_and_sizes[0].2.clone()),
                (cid2, offsets_and_sizes[1].2.clone()),
            ],
        );
        let mut slot_index =
            futures::executor::block_on(AsyncCompactIndex::open(memory(slot_index_bytes), "slot"))
                .unwrap();
        let mut cid_index =
            futures::executor::block_on(AsyncCompactIndex::open(memory(cid_index_bytes), "cid"))
                .unwrap();

        let output = futures::executor::block_on(build_slot_ranges_from_indexes(
            1,
            header_size,
            &mut slot_index,
            &mut cid_index,
            &mut memory(car),
            BuildSlotRangesConfig::default(),
        ))
        .unwrap();

        let ranged: Vec<_> = output
            .ranges
            .iter()
            .enumerate()
            .filter(|(_, range)| !range.is_empty())
            .map(|(i, range)| (first_slot + i as u64, *range))
            .collect();
        let end1 = offsets_and_sizes[0].0 + offsets_and_sizes[0].1;
        let end2 = offsets_and_sizes[1].0 + offsets_and_sizes[1].1;
        assert_eq!(
            ranged,
            vec![
                (
                    block1,
                    SlotRange {
                        offset: header_size,
                        len: (end1 - header_size) as u32
                    }
                ),
                (
                    block2,
                    SlotRange {
                        offset: end1,
                        len: (end2 - end1) as u32
                    }
                ),
            ]
        );
        assert!(early < block1);
        assert!(output.stats.slot_index_false_positives > 100);
        assert_eq!(output.stats.present_slots, 2);
    }

    // Block node with a legacy SlotMeta [parent_slot, blocktime, block_height] and no rewards.
    fn block_node(slot: u64) -> Vec<u8> {
        let mut out = vec![0x86, 0x02, 0x1b];
        out.extend_from_slice(&slot.to_be_bytes());
        out.extend_from_slice(&[0x80, 0x80, 0x83, 0x1b]);
        out.extend_from_slice(&(slot - 1).to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0xf6]);
        out
    }

    fn car_section(cid: &[u8], payload: &[u8]) -> Vec<u8> {
        let len = cid.len() + payload.len();
        assert!(len < 0x80, "test sections use a one-byte length");
        let mut out = vec![len as u8];
        out.extend_from_slice(cid);
        out.extend_from_slice(payload);
        out
    }

    // Single-bucket compact index with its entries in the Eytzinger order bst_lookup walks.
    fn compact_index(hash_len: u8, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let hash_domain = 11u32;
        let mut hashed: Vec<_> = entries
            .iter()
            .map(|(key, value)| {
                (
                    truncate_entry_hash(hash_domain, key, hash_len as usize),
                    value,
                )
            })
            .collect();
        hashed.sort_by_key(|(hash, _)| *hash);
        let mut order = vec![0usize; hashed.len()];
        fn eytzinger(order: &mut [usize], next: &mut usize, k: usize) {
            if k <= order.len() {
                eytzinger(order, next, 2 * k);
                order[k - 1] = *next;
                *next += 1;
                eytzinger(order, next, 2 * k + 1);
            }
        }
        eytzinger(&mut order, &mut 0, 1);

        let fixed_len = of_car_reader::compact_index::COMPACT_INDEX_FIXED_HEADER_SIZE;
        let mut out = Vec::new();
        out.extend_from_slice(of_car_reader::compact_index::COMPACT_INDEX_MAGIC);
        out.extend_from_slice(&13u32.to_le_bytes());
        out.extend_from_slice(&(hashed[0].1.len() as u64).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.push(1);

        let mut bucket_header = [0u8; BUCKET_HEADER_SIZE];
        bucket_header[0..4].copy_from_slice(&hash_domain.to_le_bytes());
        bucket_header[4..8].copy_from_slice(&(hashed.len() as u32).to_le_bytes());
        bucket_header[8] = hash_len;
        bucket_header[10..16]
            .copy_from_slice(&((fixed_len + BUCKET_HEADER_SIZE) as u64).to_le_bytes()[..6]);
        out.extend_from_slice(&bucket_header);
        for &i in &order {
            let (hash, value) = hashed[i];
            out.extend_from_slice(&hash.to_le_bytes()[..hash_len as usize]);
            out.extend_from_slice(value);
        }
        out
    }

    fn tiny_compact_index(key: &[u8], value: &[u8]) -> Vec<u8> {
        let hash_domain = 11u32;
        let hash_len = 8u8;
        let header_len = 13u32;
        let bucket_count = 1u32;
        let fixed_len = of_car_reader::compact_index::COMPACT_INDEX_FIXED_HEADER_SIZE;
        let data_offset = fixed_len + BUCKET_HEADER_SIZE;
        let target = truncate_entry_hash(hash_domain, key, hash_len as usize);

        let mut out = Vec::new();
        out.extend_from_slice(of_car_reader::compact_index::COMPACT_INDEX_MAGIC);
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&(value.len() as u64).to_le_bytes());
        out.extend_from_slice(&bucket_count.to_le_bytes());
        out.push(1);

        let mut bucket_header = [0u8; BUCKET_HEADER_SIZE];
        bucket_header[0..4].copy_from_slice(&hash_domain.to_le_bytes());
        bucket_header[4..8].copy_from_slice(&1u32.to_le_bytes());
        bucket_header[8] = hash_len;
        bucket_header[10..16].copy_from_slice(&(data_offset as u64).to_le_bytes()[..6]);
        out.extend_from_slice(&bucket_header);
        out.extend_from_slice(&target.to_le_bytes());
        out.extend_from_slice(value);
        out
    }
}

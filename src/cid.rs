use bytes::{Buf, BufMut};
use bytes_varint::{VarIntSupport, VarIntSupportMut};
use sha2::{Digest, Sha256};
use std::{
    fmt::{self, Debug, Display, Write},
    fs::File,
    io, mem,
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};
use thiserror::Error;

use crate::{Hash, BLOCK_SIZE};

#[derive(Error, Debug)]
pub enum CidDecodeError {
    #[error("unsupported version: {version}")]
    UnsupportedVersion { version: u8 },

    #[error("invalid size")]
    InvalidSize,

    #[error("invalid encoding")]
    InvalidEncoding,

    #[error("invalid hash")]
    InvalidHash,
}

#[derive(Hash, PartialEq, Eq)]
struct Inner {
    version: u8,
    size: u64,
    hash: Hash,
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Cid(Arc<Inner>);
impl Cid {
    pub const VERSION_RAW: u8 = b'A';

    pub const MAX_SIZE_IN_BYTES: usize = 1 + 9 + mem::size_of::<Hash>();

    pub fn builder(version: u8) -> CidBuilder {
        CidBuilder {
            version,
            size: 0,
            head: 0,
            hasher: Sha256::new(),
            leaves: Vec::new(),
        }
    }

    pub fn new(version: u8, size: u64, hash: Hash) -> Self {
        Self(Arc::new(Inner {
            version,
            size,
            hash,
        }))
    }

    pub fn from_reader(version: u8, mut reader: impl io::Read) -> io::Result<Self> {
        let mut builder = Self::builder(version);
        let mut buf = [0; BLOCK_SIZE];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            builder.update(&buf[..n]);
        }
        Ok(builder.finalize())
    }

    pub fn from_file(version: u8, file: &mut File) -> io::Result<(Self, SystemTime)> {
        let modified = file.metadata()?.modified()?;
        let cid = Self::from_reader(version, &mut *file)?;
        let new_modified = file.metadata()?.modified()?;
        if modified != new_modified {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file modified while reading",
            ));
        }
        Ok((cid, modified))
    }

    pub fn from_data(version: u8, data: impl AsRef<[u8]>) -> Cid {
        let mut builder = Self::builder(version);
        builder.update(data);
        builder.finalize()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CidDecodeError> {
        let (version, bytes) = bytes.split_at(1);
        Self::from_version_and_buf(version[0], bytes)
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.0.version);
        buf.put_u64_varint(self.0.size);
        buf.put_slice(&self.0.hash);
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, CidDecodeError> {
        let version = buf.get_u8();
        Self::from_version_and_buf(version, buf)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::MAX_SIZE_IN_BYTES);
        self.encode(&mut buf);
        buf
    }

    fn from_version_and_buf(version: u8, mut buf: impl Buf) -> Result<Self, CidDecodeError> {
        if version != Self::VERSION_RAW {
            return Err(CidDecodeError::UnsupportedVersion { version });
        }
        let size = buf
            .get_u64_varint()
            .map_err(|_| CidDecodeError::InvalidSize)?;
        if buf.remaining() != mem::size_of::<Hash>() {
            return Err(CidDecodeError::InvalidHash);
        }
        let mut hash = Hash::default();
        buf.copy_to_slice(&mut hash);
        Ok(Self(Arc::new(Inner {
            version,
            size,
            hash,
        })))
    }

    pub fn version(&self) -> u8 {
        self.0.version
    }

    pub fn size(&self) -> u64 {
        self.0.size
    }

    pub fn hash(&self) -> &Hash {
        &self.0.hash
    }

    pub fn num_blocks(&self) -> u64 {
        self.0.size.div_ceil(BLOCK_SIZE as u64)
    }

    pub fn is_raw(&self) -> bool {
        self.0.version == Self::VERSION_RAW
    }
}

pub struct CidBuilder {
    version: u8,
    size: u64,
    head: usize,
    hasher: Sha256,
    leaves: Vec<Hash>,
}
impl CidBuilder {
    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let mut data = data.as_ref();
        self.size += data.len() as u64;
        while !data.is_empty() {
            let n = std::cmp::min(data.len(), BLOCK_SIZE - self.head);
            let (left, right) = data.split_at(n);
            self.hasher.update(left);
            data = right;
            self.head += n;
            if self.head == BLOCK_SIZE {
                self.head = 0;
                let hasher = mem::replace(&mut self.hasher, Sha256::new());
                self.leaves.push(hasher.finalize().into());
            }
        }
    }

    pub fn finalize(mut self) -> Cid {
        if self.head != 0 {
            self.leaves.push(self.hasher.finalize().into());
        }
        let hash = get_root(&self.leaves);
        Cid::new(self.version, self.size, hash)
    }
}

fn get_root(leaves: &[Hash]) -> Hash {
    let size = leaves.len().next_power_of_two();
    let mut hashes = Vec::with_capacity(size * 2 - 1);
    hashes.resize_with(size - 1, Hash::default);
    hashes.extend_from_slice(leaves);
    hashes.resize_with(size * 2 - 1, Hash::default);
    for i in (0..size - 1).rev() {
        let mut hasher = Sha256::new();
        hasher.update(&hashes[i * 2 + 1]);
        hasher.update(&hashes[i * 2 + 2]);
        hashes[i] = hasher.finalize().into();
    }
    hashes[0]
}

impl Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_char(self.0.version as char)?;
        let mut buf = Vec::with_capacity(Self::MAX_SIZE_IN_BYTES - 1);
        buf.put_u64_varint(self.0.size);
        buf.extend(&self.0.hash);
        f.write_str(&bs58::encode(&buf).into_string())
    }
}
impl Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Cid")
            .field("version", &self.0.version)
            .field("size", &self.0.size)
            .field("hash", &hex::encode(&self.0.hash))
            .finish()
    }
}

impl FromStr for Cid {
    type Err = CidDecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (version, s) = s.split_at(1);
        let version = version.as_bytes()[0];
        let buf = bs58::decode(s)
            .into_vec()
            .map_err(|_| CidDecodeError::InvalidEncoding)?;
        Self::from_version_and_buf(version, buf.as_slice())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cid_builder() {
        let mut cid = Cid::builder(Cid::VERSION_RAW);
        cid.update(b"hello");
        cid.update(b"world");
        let cid1 = cid.finalize();
        let cid2 = Cid::from_data(Cid::VERSION_RAW, b"helloworld");
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn cid_display() {
        let cid = Cid::new(Cid::VERSION_RAW, 10, [1; 32]);
        let s = cid.to_string();
        let cid2 = Cid::from_str(&s).unwrap();
        assert_eq!(cid, cid2);
    }
}

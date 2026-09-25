use std::io::{self, Cursor, Read, Write};

use flate2::read::ZlibDecoder;
use xz2::{read::XzDecoder, stream::Stream};

use super::{invalid, unsupported};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Codec {
    Auto,
    Zlib,
    Lzma,
    Xz,
    Other(u16),
}

impl Codec {
    pub fn new(id: Option<u16>) -> Self {
        match id {
            None => Self::Auto,
            Some(1) => Self::Zlib,
            Some(2) => Self::Lzma,
            Some(4) => Self::Xz,
            Some(id) => Self::Other(id),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "undetermined",
            Self::Zlib => "zlib",
            Self::Lzma => "lzma",
            Self::Xz => "xz",
            Self::Other(3) => "lzo",
            Self::Other(5) => "lz4",
            Self::Other(6) => "zstd",
            Self::Other(_) => "unknown",
        }
    }

    pub fn decode(&mut self, input: &[u8], limit: usize) -> io::Result<Vec<u8>> {
        match self {
            Self::Other(id) => Err(unsupported(format!("SquashFS compression {id}"))),
            Self::Zlib => bounded_read(ZlibDecoder::new(input), limit),
            Self::Xz => {
                let stream = Stream::new_stream_decoder(64 * 1024 * 1024, 0)?;
                bounded_read(XzDecoder::new_stream(input, stream), limit)
            }
            Self::Lzma => decode_lzma(input, limit),
            Self::Auto => {
                let (codec, decoded) = if input.starts_with(b"7zip")
                    || input.first().is_some_and(|v| *v == 0x5d || *v == 0x6d)
                {
                    (Self::Lzma, decode_lzma(input, limit)?)
                } else {
                    match bounded_read(ZlibDecoder::new(input), limit) {
                        Ok(data) => (Self::Zlib, data),
                        Err(_) => (Self::Lzma, decode_lzma(input, limit)?),
                    }
                };
                *self = codec;
                Ok(decoded)
            }
        }
    }
}

fn bounded_read(reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut result)?;
    if result.len() > limit {
        return Err(invalid("SquashFS block exceeds decompression limit"));
    }
    Ok(result)
}

fn decode_lzma(input: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    if input.starts_with(b"7zip") {
        let mut header = [0u8; 13];
        header[0] = 0x5d;
        header[1..5].copy_from_slice(&(1_048_576u32).to_le_bytes());
        header[5..].fill(0xff);
        return lzma_reader(&header, &input[4..], limit);
    }
    if input.len() < 5 || input[0] >= 225 {
        return Err(invalid("invalid SquashFS LZMA properties"));
    }
    if input.len() >= 13 {
        let length = u64::from_le_bytes(input[5..13].try_into().unwrap());
        if length <= limit as u64 || length == u64::MAX {
            if let Ok(decoded) = lzma_reader(&input[..13], &input[13..], limit) {
                return Ok(decoded);
            }
        }
    }
    let mut header = [0xff; 13];
    header[..5].copy_from_slice(&input[..5]);
    lzma_reader(&header, &input[5..], limit)
}

fn lzma_reader(header: &[u8], payload: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    let properties = header[0];
    let lc = properties % 9;
    let lp = (properties / 9) % 5;
    let input = Cursor::new(header).chain(Cursor::new(payload));
    if lc + lp <= 4 {
        let stream = Stream::new_lzma_decoder(64 * 1024 * 1024)?;
        bounded_read(XzDecoder::new_stream(input, stream), limit)
    } else {
        let mut output = LimitedBuffer {
            bytes: Vec::new(),
            limit,
        };
        let mut input = io::BufReader::new(input);
        let options = lzma_rs::decompress::Options {
            memlimit: Some(16 * 1024 * 1024),
            ..Default::default()
        };
        lzma_rs::lzma_decompress_with_options(&mut input, &mut output, &options)
            .map_err(|error| invalid(format!("invalid SquashFS LZMA block: {error}")))?;
        Ok(output.bytes)
    }
}

struct LimitedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for LimitedBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(invalid("SquashFS block exceeds decompression limit"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

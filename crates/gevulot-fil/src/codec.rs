use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CodecError {
    #[error("Serialize/deserialize error: {0}")]
    Serde(
        #[from]
        #[backtrace]
        bincode::Error,
    ),
    #[error("Compression/decompression error: {0}")]
    Compression(io::Error),
}

type Result<T> = std::result::Result<T, CodecError>;

/// `encode` function serializes a value using bincode writes the compressed data into a byte vector
pub fn encode<T>(value: &T) -> Result<Vec<u8>>
where T: serde::Serialize + ?Sized {
    let mut buf = vec![];
    encode_into(&mut buf, value)?;
    Ok(buf)
}

/// `encode_into` serializes a value using bincode and writes the compressed data to a
/// writer using the zstd compression algorithm.
pub fn encode_into<W, T>(writer: W, value: &T) -> Result<()>
where
    W: std::io::Write,
    T: serde::Serialize + ?Sized,
{
    let zstd_encoder = zstd::Encoder::new(writer, 0)
        .map_err(CodecError::Compression)?
        .auto_finish();
    bincode::serialize_into(zstd_encoder, value).map_err(Into::into)
}

/// `decode` decodes a byte slice into a deserialized value of a type that
/// implements `DeserializeOwned`.
pub fn decode<T>(input: &[u8]) -> Result<T>
where T: serde::de::DeserializeOwned + ?Sized {
    decode_from(input)
}

/// `decode_from` reads from a reader, decodes the data using Zstandard and deserializes it
/// using Bincode.
pub fn decode_from<R, T>(reader: R) -> Result<T>
where
    R: std::io::Read,
    T: serde::de::DeserializeOwned + ?Sized,
{
    let zstd_decoder = zstd::Decoder::new(reader).map_err(CodecError::Compression)?;
    bincode::deserialize_from(zstd_decoder).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde::Serialize;

    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestData {
        x: u8,
        y: u64,
        z: String,
    }

    #[test]
    fn test_basic() {
        let expect = TestData {
            x: 1,
            y: 2,
            z: String::from("test"),
        };
        let b = encode(&expect).unwrap();
        let actual = decode(&b).unwrap();
        assert_eq!(expect, actual);
    }
}

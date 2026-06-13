use base64::Engine;

use crate::cli::Encoding;

pub fn encode_armored(data: &[u8], encoding: Encoding) -> Vec<u8> {
    match encoding {
        Encoding::Raw => data.to_vec(),
        Encoding::Base64 => base64::engine::general_purpose::STANDARD
            .encode(data)
            .into_bytes(),
        Encoding::Hex => hex::encode(data).into_bytes(),
    }
}

pub fn decode_if_armored(
    data: Vec<u8>,
    encoding: Encoding,
    context: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match encoding {
        Encoding::Raw => Ok(data),
        Encoding::Base64 => {
            let s = std::str::from_utf8(&data)
                .map_err(|_| format!("{context} is not valid UTF-8 (required for base64)"))?;
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .map_err(|e| format!("{context} is not valid base64: {e}").into())
        }
        Encoding::Hex => {
            let s = std::str::from_utf8(&data)
                .map_err(|_| format!("{context} is not valid UTF-8 (required for hex)"))?;
            hex::decode(s.trim()).map_err(|e| format!("{context} is not valid hex: {e}").into())
        }
    }
}

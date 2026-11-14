//! Strict DER (X.690) validation
//!
//! The [`parse_der`](crate::der::parse_der) function is intentionally lenient: it accepts BER
//! encodings that are not canonical DER (non-minimal length fields, redundant leading octets in
//! integers, unordered `SET`/`SET OF` components, trailing bytes after the object, ...).
//!
//! This module provides a strict validation entry point, for contexts (like X.509 certificates)
//! where the input must be canonical DER. It checks, recursively:
//!
//! - length fields use the shortest form (short form when length < 128, no leading zero octets
//!   in the long form), and indefinite lengths are rejected;
//! - `INTEGER` contents have no redundant leading `0x00` or `0xff` octets;
//! - primitive universal types are not encoded as constructed (and constructed types are not
//!   encoded as primitive);
//! - `SET` and `SET OF` components are sorted in lexicographic order of their encodings;
//! - no extra bytes follow the end of the object.
//!
//! Errors are reported as a [`DerStrictError`], which carries both the category of the
//! violation and the offset (from the start of input) where it was detected.
//!
//! Note: this module only adds validation on top of the existing parser. The lenient BER/DER
//! parsing functions are unchanged.
//!
//! # Example
//!
//! ```rust
//! use der_parser::der::{parse_der_strict, DerStrictErrorKind};
//!
//! // valid DER
//! let bytes = &[0x02, 0x01, 0x05];
//! assert!(parse_der_strict(bytes).is_ok());
//!
//! // non-minimal length: rejected by the strict parser
//! let bytes = &[0x02, 0x81, 0x01, 0x05];
//! let err = parse_der_strict(bytes).unwrap_err();
//! assert_eq!(err.kind, DerStrictErrorKind::NonMinimalLength);
//! ```

use crate::ber::MAX_RECURSION;
use crate::der::{parse_der, DerObject};
use core::fmt;

/// Category of a strict DER validation failure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerStrictErrorKind {
    /// Length uses the long form where the short form is required, or the long form is not
    /// minimally encoded (leading zero octets) (X.690 10.1)
    NonMinimalLength,
    /// Indefinite length is used; DER requires the definite form (X.690 10.1)
    IndefiniteLength,
    /// `INTEGER` contents have redundant leading `0x00` or `0xff` octets (X.690 8.3.2)
    IntegerLeadingBytes,
    /// A primitive type is encoded as constructed, or a constructed type as primitive
    ConstructedEncoding,
    /// `SET`/`SET OF` components are not sorted in lexicographic order of their encodings
    /// (X.690 11.6)
    UnorderedSet,
    /// Extra bytes follow the end of the object
    TrailingBytes,
    /// Tag uses the high-tag-number form where the short form is required, or is not minimally
    /// encoded (X.690 8.1.2.4)
    NonMinimalTag,
    /// Tag encoding is malformed
    InvalidTag,
    /// Length field is malformed (too many length octets)
    InvalidLength,
    /// Object contents violate a DER constraint (e.g. `BOOLEAN` value, `BIT STRING` padding)
    InvalidContent,
    /// Input ends before the object is complete
    Truncated,
    /// Maximum recursion depth exceeded
    RecursionLimit,
}

impl fmt::Display for DerStrictErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DerStrictErrorKind::NonMinimalLength => "length is not minimally encoded",
            DerStrictErrorKind::IndefiniteLength => "indefinite length is not allowed in DER",
            DerStrictErrorKind::IntegerLeadingBytes => {
                "integer has redundant leading 0x00/0xff octets"
            }
            DerStrictErrorKind::ConstructedEncoding => {
                "invalid constructed/primitive encoding for type"
            }
            DerStrictErrorKind::UnorderedSet => "SET/SET OF components are not sorted",
            DerStrictErrorKind::TrailingBytes => "trailing bytes after object",
            DerStrictErrorKind::NonMinimalTag => "tag is not minimally encoded",
            DerStrictErrorKind::InvalidTag => "invalid tag encoding",
            DerStrictErrorKind::InvalidLength => "invalid length encoding",
            DerStrictErrorKind::InvalidContent => "object contents violate a DER constraint",
            DerStrictErrorKind::Truncated => "input is truncated",
            DerStrictErrorKind::RecursionLimit => "maximum recursion depth exceeded",
        };
        f.write_str(s)
    }
}

/// Error returned by the strict DER validation functions
///
/// Contains the category of the violation and the offset (from the start of the input)
/// where it was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerStrictError {
    /// Category of the validation failure
    pub kind: DerStrictErrorKind,
    /// Offset (in bytes, from start of input) where the violation was detected
    pub offset: usize,
}

impl DerStrictError {
    #[inline]
    const fn new(kind: DerStrictErrorKind, offset: usize) -> Self {
        DerStrictError { kind, offset }
    }
}

impl fmt::Display for DerStrictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "strict DER validation failed at offset {}: {}",
            self.offset, self.kind
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DerStrictError {}

/// Validate that the input is canonical DER (X.690), recursively
///
/// This function checks the strict DER constraints (see [module documentation](self))
/// on the entire input: the full input must contain exactly one DER object, with no
/// trailing bytes.
///
/// On error, the returned [`DerStrictError`] indicates the category of the violation and
/// the offset where it was detected.
///
/// To also get the parsed object, use [`parse_der_strict`].
pub fn validate_der_strict(i: &[u8]) -> Result<(), DerStrictError> {
    let consumed = validate_tlv(i, 0, MAX_RECURSION)?;
    if consumed != i.len() {
        return Err(DerStrictError::new(
            DerStrictErrorKind::TrailingBytes,
            consumed,
        ));
    }
    Ok(())
}

/// Parse an object, requiring the input to be canonical DER (X.690)
///
/// Unlike [`parse_der`], this function rejects encodings that are valid BER but not
/// canonical DER (see [module documentation](self) for the list of checked constraints),
/// and requires the entire input to be consumed.
///
/// On error, the returned [`DerStrictError`] indicates the category of the violation and
/// the offset where it was detected.
///
/// ### Example
///
/// ```rust
/// use der_parser::der::{parse_der_strict, Tag};
///
/// let bytes = &[0x02, 0x03, 0x01, 0x00, 0x01];
/// let obj = parse_der_strict(bytes).expect("strict validation failed");
/// assert_eq!(obj.header.tag(), Tag::Integer);
/// ```
pub fn parse_der_strict(i: &[u8]) -> Result<DerObject<'_>, DerStrictError> {
    validate_der_strict(i)?;
    // input has been validated as canonical DER, so parsing cannot fail
    let (_, obj) =
        parse_der(i).map_err(|_| DerStrictError::new(DerStrictErrorKind::InvalidContent, 0))?;
    Ok(obj)
}

/// Validate one TLV object at the start of `buf` (whose absolute offset in the original
/// input is `base`), and return the number of bytes it occupies.
fn validate_tlv(buf: &[u8], base: usize, depth: usize) -> Result<usize, DerStrictError> {
    if depth == 0 {
        return Err(DerStrictError::new(
            DerStrictErrorKind::RecursionLimit,
            base,
        ));
    }
    // --- identifier octets (X.690 8.1.2) ---
    let b0 = *buf
        .first()
        .ok_or(DerStrictError::new(DerStrictErrorKind::Truncated, base))?;
    let class = b0 >> 6;
    let constructed = b0 & 0x20 != 0;
    let mut tag = u64::from(b0 & 0x1f);
    let mut pos = 1;
    if tag == 0x1f {
        // high-tag-number form
        tag = 0;
        let mut first = true;
        loop {
            let b = *buf.get(pos).ok_or(DerStrictError::new(
                DerStrictErrorKind::Truncated,
                base + pos,
            ))?;
            pos += 1;
            if first {
                // X.690 8.1.2.4.2: bits 7 to 1 of the first subsequent octet shall not all be zero
                if b & 0x7f == 0 {
                    return Err(DerStrictError::new(
                        DerStrictErrorKind::NonMinimalTag,
                        base + pos - 1,
                    ));
                }
                first = false;
            }
            tag = tag
                .checked_mul(128)
                .and_then(|t| t.checked_add(u64::from(b & 0x7f)))
                .ok_or(DerStrictError::new(DerStrictErrorKind::InvalidTag, base))?;
            if b & 0x80 == 0 {
                break;
            }
        }
        // tag numbers < 31 must use the short form (X.690 8.1.2.4)
        if tag < 31 {
            return Err(DerStrictError::new(DerStrictErrorKind::NonMinimalTag, base));
        }
    }
    // --- length octets (X.690 8.1.3, 10.1) ---
    let len_offset = pos;
    let len_byte = *buf.get(pos).ok_or(DerStrictError::new(
        DerStrictErrorKind::Truncated,
        base + pos,
    ))?;
    pos += 1;
    let length: usize;
    if len_byte == 0x80 {
        // indefinite form is not allowed in DER (X.690 10.1)
        return Err(DerStrictError::new(
            DerStrictErrorKind::IndefiniteLength,
            base + len_offset,
        ));
    } else if len_byte & 0x80 == 0 {
        length = usize::from(len_byte);
    } else {
        let num_len_octets = usize::from(len_byte & 0x7f);
        // keep in sync with the parser limit (MAX_OBJECT_SIZE is 2^32 - 1)
        if num_len_octets > 4 {
            return Err(DerStrictError::new(
                DerStrictErrorKind::InvalidLength,
                base + len_offset,
            ));
        }
        if buf.len() - pos < num_len_octets {
            return Err(DerStrictError::new(
                DerStrictErrorKind::Truncated,
                base + pos,
            ));
        }
        // the first length octet shall not be zero (minimal long form)
        if buf[pos] == 0 {
            return Err(DerStrictError::new(
                DerStrictErrorKind::NonMinimalLength,
                base + len_offset,
            ));
        }
        let mut l: usize = 0;
        for &b in &buf[pos..pos + num_len_octets] {
            l = (l << 8) | usize::from(b);
        }
        // lengths < 128 must use the short form (X.690 10.1)
        if l < 128 {
            return Err(DerStrictError::new(
                DerStrictErrorKind::NonMinimalLength,
                base + len_offset,
            ));
        }
        length = l;
        pos += num_len_octets;
    }
    // --- contents octets ---
    let content_offset = pos;
    let end = content_offset
        .checked_add(length)
        .ok_or(DerStrictError::new(
            DerStrictErrorKind::InvalidLength,
            base + len_offset,
        ))?;
    if buf.len() < end {
        return Err(DerStrictError::new(
            DerStrictErrorKind::Truncated,
            base + content_offset,
        ));
    }
    let content = &buf[content_offset..end];
    // --- constraints on universal types ---
    const UNIVERSAL: u8 = 0;
    if class == UNIVERSAL {
        match tag {
            // SEQUENCE, SET and EXTERNAL are always constructed
            8 | 16 | 17 => {
                if !constructed {
                    return Err(DerStrictError::new(
                        DerStrictErrorKind::ConstructedEncoding,
                        base,
                    ));
                }
            }
            // all other universal types are primitive in DER
            _ => {
                if constructed {
                    return Err(DerStrictError::new(
                        DerStrictErrorKind::ConstructedEncoding,
                        base,
                    ));
                }
            }
        }
        match tag {
            // BOOLEAN (X.690 8.2)
            1 => {
                if length != 1 || (content[0] != 0 && content[0] != 0xff) {
                    return Err(DerStrictError::new(
                        DerStrictErrorKind::InvalidContent,
                        base + content_offset,
                    ));
                }
            }
            // INTEGER (X.690 8.3.2): no redundant leading 0x00 or 0xff octets
            2 => match content {
                [] => {
                    return Err(DerStrictError::new(
                        DerStrictErrorKind::InvalidContent,
                        base + content_offset,
                    ))
                }
                [0x00, b, ..] if *b < 0x80 => {
                    return Err(DerStrictError::new(
                        DerStrictErrorKind::IntegerLeadingBytes,
                        base + content_offset,
                    ))
                }
                [0xff, b, ..] if *b >= 0x80 => {
                    return Err(DerStrictError::new(
                        DerStrictErrorKind::IntegerLeadingBytes,
                        base + content_offset,
                    ))
                }
                _ => (),
            },
            // BIT STRING (X.690 8.6)
            3 => {
                if length == 0 {
                    return Err(DerStrictError::new(
                        DerStrictErrorKind::InvalidContent,
                        base + content_offset,
                    ));
                }
                let unused = content[0];
                if unused > 7 || (length == 1 && unused != 0) {
                    return Err(DerStrictError::new(
                        DerStrictErrorKind::InvalidContent,
                        base + content_offset,
                    ));
                }
                if length > 1 && unused > 0 {
                    let mask = (1u8 << unused) - 1;
                    if content[length - 1] & mask != 0 {
                        return Err(DerStrictError::new(
                            DerStrictErrorKind::InvalidContent,
                            base + content_offset,
                        ));
                    }
                }
            }
            // NULL (X.690 8.8)
            5 if length != 0 => {
                return Err(DerStrictError::new(
                    DerStrictErrorKind::InvalidContent,
                    base + content_offset,
                ));
            }
            _ => (),
        }
    }
    // --- recurse into constructed contents ---
    if constructed {
        let is_set = class == UNIVERSAL && tag == 17;
        let mut child_offset = content_offset;
        let mut previous: Option<&[u8]> = None;
        while child_offset < end {
            let consumed = validate_tlv(&buf[child_offset..end], base + child_offset, depth - 1)?;
            if is_set {
                // X.690 11.6: components are sorted in lexicographic order of their encodings
                let current = &buf[child_offset..child_offset + consumed];
                if let Some(prev) = previous {
                    if prev > current {
                        return Err(DerStrictError::new(
                            DerStrictErrorKind::UnorderedSet,
                            base + child_offset,
                        ));
                    }
                }
                previous = Some(current);
            }
            child_offset += consumed;
        }
    }
    Ok(end)
}

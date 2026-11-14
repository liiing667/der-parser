// test_case seem to generate this warning - ignore it
#![allow(clippy::unused_unit)]

use asn1_rs::ASN1DateTime;
use asn1_rs::ASN1TimeZone;
use asn1_rs::Any;
use der_parser::ber::*;
use der_parser::der::*;
use der_parser::error::*;
use der_parser::oid::*;
use der_parser::*;
use hex_literal::hex;
use nom::branch::alt;
use nom::combinator::map;
use nom::error::ErrorKind;
use nom::sequence::tuple;
use nom::Err;
use pretty_assertions::assert_eq;
use std::borrow::Cow;
use test_case::test_case;

#[test]
fn test_der_bool() {
    let empty = &b""[..];
    let b_true = DerObject::from_obj(BerObjectContent::Boolean(true));
    let b_false = DerObject::from_obj(BerObjectContent::Boolean(false));
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0x00]), Ok((empty, b_false)));
    assert_eq!(parse_der_bool(&[0x01, 0x01, 0xff]), Ok((empty, b_true)));
    assert_eq!(
        parse_der_bool(&[0x01, 0x01, 0x7f]),
        Err(Err::Error(BerError::DerConstraintFailed(
            DerConstraint::InvalidBoolean
        )))
    );
}

#[test]
fn test_der_int() {
    let empty = &b""[..];
    let bytes = hex!("02 03 01 00 01");
    let expected = DerObject::from_obj(BerObjectContent::Integer(b"\x01\x00\x01"));
    assert_eq!(parse_der_integer(&bytes), Ok((empty, expected)));
    let res = parse_der_u64(&bytes);
    assert_eq!(res.expect("integer").1, 0x10001);
    // wrong tag
    let bytes = hex!("04 03 41 41 41");
    let res = parse_der_integer(&bytes);
    assert!(res.is_err());
    let res = parse_der_u64(&bytes);
    assert!(res.is_err());
    // very long integer
    let bytes = hex!("02 0b 40 41 02 03 04 05 06 07 08 09 0a");
    let res = parse_der_integer(&bytes);
    assert!(res.is_ok());
    let res = parse_der_u64(&bytes);
    assert!(res.is_err());
}

#[test]
fn test_der_bitstring_primitive() {
    let empty = &b""[..];
    //
    // correct DER encoding
    //
    let bytes = &[0x03, 0x04, 0x06, 0x6e, 0x5d, 0xc0];
    let expected = DerObject::from_obj(BerObjectContent::BitString(
        6,
        BitStringObject { data: &bytes[3..] },
    ));
    assert_eq!(parse_der_bitstring(bytes), Ok((empty, expected)));
    //
    // correct encoding, but wrong padding bits (not all set to 0)
    //
    let bytes = &[0x03, 0x04, 0x06, 0x6e, 0x5d, 0xe0];
    assert_eq!(
        parse_der_bitstring(bytes),
        Err(Err::Error(BerError::DerConstraintFailed(
            DerConstraint::UnusedBitsNotZero
        )))
    );
    // // XXX test disabled: the parser is laxist here, since *many* implementations do
    // // XXX not respect this constraint!
    // // long form of length (invalid, < 127)
    // //
    // let bytes = &[0x03, 0x81, 0x04, 0x06, 0x6e, 0x5d, 0xc0];
    // assert_eq!(
    //     parse_der_bitstring(bytes),
    //     Err(Err::Error(BerError::DerConstraintFailed))
    // );
}

#[test]
fn test_der_bitstring_constructed() {
    let bytes = &hex!("23 81 0c 03 03 00 0a 3b 03 05 04 5f 29 1c d0");
    assert_eq!(
        parse_der_bitstring(bytes),
        Err(Err::Error(BerError::DerConstraintFailed(
            DerConstraint::Constructed
        )))
    );
}

#[test]
fn test_der_indefinite_length() {
    let bytes = &hex!("23 80 03 03 00 0a 3b 03 05 04 5f 29 1c d0 00 00");
    assert_eq!(
        parse_der_bitstring(bytes),
        Err(Err::Error(BerError::DerConstraintFailed(
            DerConstraint::IndefiniteLength
        )))
    );
}

#[test]
fn test_der_octetstring_primitive() {
    let empty = &b""[..];
    let bytes = [0x04, 0x05, 0x41, 0x41, 0x41, 0x41, 0x41];
    let expected = DerObject::from_obj(BerObjectContent::OctetString(b"AAAAA"));
    assert_eq!(parse_der_octetstring(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_null() {
    let empty = &b""[..];
    let expected = DerObject::from_obj(BerObjectContent::Null);
    assert_eq!(parse_der_null(&[0x05, 0x00]), Ok((empty, expected)));
}

#[test]
fn test_der_oid() {
    let empty = &b""[..];
    let bytes = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05,
    ];
    let expected = DerObject::from_obj(BerObjectContent::OID(
        Oid::from(&[1, 2, 840, 113_549, 1, 1, 5]).unwrap(),
    ));
    assert_eq!(parse_der_oid(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_enum() {
    let empty = &b""[..];
    let expected = DerObject::from_obj(BerObjectContent::Enum(2));
    assert_eq!(parse_der_enum(&[0x0a, 0x01, 0x02]), Ok((empty, expected)));
}

#[test]
fn test_der_utf8string() {
    let empty = &b""[..];
    let bytes = [
        0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65, 0x2d, 0x53, 0x74, 0x61, 0x74, 0x65,
    ];
    let expected = DerObject::from_obj(BerObjectContent::UTF8String("Some-State"));
    assert_eq!(parse_der_utf8string(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_relativeoid() {
    let empty = &b""[..];
    let bytes = [0x0d, 0x04, 0xc2, 0x7b, 0x03, 0x02];
    let expected = DerObject::from_obj(BerObjectContent::RelativeOID(
        Oid::from_relative(&[8571, 3, 2]).unwrap(),
    ));
    assert_eq!(parse_der_relative_oid(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_seq() {
    let empty = &b""[..];
    let bytes = [0x30, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01];
    let expected = DerObject::from_seq(vec![DerObject::from_int_slice(b"\x01\x00\x01")]);
    assert_eq!(parse_der_sequence(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_set() {
    let empty = &b""[..];
    let bytes = [0x31, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01];
    let expected = DerObject::from_set(vec![DerObject::from_int_slice(b"\x01\x00\x01")]);
    assert_eq!(parse_der_set(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_seq_defined() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x0a, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected = DerObject::from_seq(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]);
    fn parser(i: &[u8]) -> DerResult<'_> {
        parse_der_sequence_defined(
            // the nom `tuple` combinator returns a tuple, so we have to map it
            // to a list
            map(tuple((parse_der_integer, parse_der_integer)), |(a, b)| {
                vec![a, b]
            }),
        )(i)
    }
    assert_eq!(parser(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_set_defined() {
    let empty = &b""[..];
    let bytes = [
        0x31, 0x0a, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected = DerObject::from_set(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]);
    fn parser(i: &[u8]) -> DerResult<'_> {
        parse_der_set_defined(
            // the nom `tuple` combinator returns a tuple, so we have to map it
            // to a list
            map(tuple((parse_der_integer, parse_der_integer)), |(a, b)| {
                vec![a, b]
            }),
        )(i)
    }
    assert_eq!(parser(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_seq_of() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x0a, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected = DerObject::from_seq(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]);
    fn parser(i: &[u8]) -> DerResult<'_> {
        parse_der_sequence_of(parse_der_integer)(i)
    }
    assert_eq!(parser(&bytes), Ok((empty, expected.clone())));
    //
    fn parser2(i: &[u8]) -> BerResult<'_> {
        parse_ber_sequence_of(parse_der_integer)(i)
    }
    assert_eq!(parser2(&bytes), Ok((empty, expected)));
}

// extra bytes are simply ignored
#[test]
fn test_der_seq_of_incomplete() {
    let bytes = [0x30, 0x07, 0x02, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00];
    fn parser(i: &[u8]) -> DerResult<'_> {
        parse_der_sequence_of(parse_der_integer)(i)
    }
    assert_eq!(
        parser(&bytes),
        Err(Err::Failure(BerError::unexpected_tag(Some(Tag(2)), Tag(0))))
    );
    //
    fn parser2(i: &[u8]) -> BerResult<'_, Vec<BerObject<'_>>> {
        parse_ber_sequence_of_v(parse_der_integer)(i)
    }
    // eprintln!("trailing data");
    assert_eq!(
        parser2(&bytes),
        Err(Err::Failure(BerError::unexpected_tag(Some(Tag(2)), Tag(0))))
    );
    let h = &hex!("30 06 02 03 01 00 01 02");
    // eprintln!("remaining 02 at end (incomplete)");
    assert_eq!(
        parser2(h),
        Err(Err::Error(BerError::NomError(ErrorKind::Eof)))
    );
}

#[test]
fn test_der_set_of() {
    let empty = &b""[..];
    let bytes = [
        0x31, 0x0a, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00,
    ];
    let expected = DerObject::from_set(vec![
        DerObject::from_int_slice(b"\x01\x00\x01"),
        DerObject::from_int_slice(b"\x01\x00\x00"),
    ]);
    fn parser(i: &[u8]) -> DerResult<'_> {
        parse_der_set_of(parse_der_integer)(i)
    }
    assert_eq!(parser(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_utctime() {
    let bytes = hex!("17 0b 39 32 30 35 32 31 32 33 34 32 5A FF");
    let expected = DerObject::from_obj(BerObjectContent::UTCTime(ASN1DateTime::new(
        92,
        5,
        21,
        23,
        42,
        0,
        None,
        ASN1TimeZone::Z,
    )));
    assert_eq!(parse_der_utctime(&bytes), Ok((&[0xff][..], expected)));
    // missing 'Z'
    let bytes = hex!("17 0a 39 32 30 35 32 31 32 33 34 32");
    let e = parse_der_utctime(&bytes).expect_err("expected error");
    assert_eq!(
        e,
        Err::Error(BerError::DerConstraintFailed(
            DerConstraint::MissingTimeZone
        ))
    );
}

#[test]
fn test_der_generalizedtime() {
    let empty = &b""[..];
    let bytes = hex!("18 0D 31 39 39 32 30 35 32 31 32 33 34 32 5A");
    let expected = DerObject::from_obj(BerObjectContent::GeneralizedTime(ASN1DateTime::new(
        1992,
        5,
        21,
        23,
        42,
        0,
        None,
        ASN1TimeZone::Z,
    )));
    assert_eq!(parse_der_generalizedtime(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_generalstring() {
    let empty = &b""[..];
    let bytes = [0x1b, 0x04, 0x63, 0x69, 0x66, 0x73];
    let expected = DerObject::from_obj(BerObjectContent::GeneralString("cifs"));
    assert_eq!(parse_der_generalstring(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_contextspecific() {
    let bytes = [0xa0, 0x03, 0x02, 0x01, 0x02];
    let empty = &b""[..];
    let header = Header::new(Class::ContextSpecific, true, Tag(0), 3.into())
        .with_raw_tag(Some(Cow::Borrowed(&[0xa0])));
    let any = Any::new(header.clone(), &bytes[2..]);
    let expected = DerObject {
        header,
        content: BerObjectContent::Unknown(any),
    };
    assert_eq!(parse_der(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_explicit_optional() {
    let empty = &b""[..];
    let bytes = [0xa0, 0x03, 0x02, 0x01, 0x02];
    let header = Header::new(Class::ContextSpecific, true, Tag(0), 3.into())
        .with_raw_tag(Some(Cow::Borrowed(&[0xa0])));
    let expected = DerObject {
        header: header.clone(),
        content: BerObjectContent::Optional(Some(Box::new(BerObject::from_header_and_content(
            header,
            BerObjectContent::Tagged(
                Class::ContextSpecific,
                Tag(0),
                Box::new(DerObject::from_int_slice(b"\x02")),
            ),
        )))),
    };
    assert_eq!(
        parse_der_explicit_optional(&bytes, Tag(0), parse_der_integer),
        Ok((empty, expected))
    );
    let expected2 = DerObject::from_obj(BerObjectContent::Optional(None));
    assert_eq!(
        parse_der_explicit_optional(&bytes, Tag(1), parse_der_integer),
        Ok((&bytes[..], expected2))
    );
}

#[test]
fn test_der_implicit() {
    let empty = &b""[..];
    let bytes = [0x81, 0x04, 0x70, 0x61, 0x73, 0x73];
    let expected = DerObject {
        header: Header::new(Class::ContextSpecific, false, Tag(1), 4.into())
            .with_raw_tag(Some(Cow::Borrowed(&[0x81]))),
        content: BerObjectContent::IA5String("pass"),
    };
    fn der_read_ia5string_content<'a>(
        i: &'a [u8],
        hdr: &Header,
        depth: usize,
    ) -> BerResult<'a, BerObjectContent<'a>> {
        ber_read_element_content_as(i, Tag::Ia5String, hdr.length(), hdr.is_constructed(), depth)
    }
    assert_eq!(
        parse_der_implicit(&bytes, Tag(1), der_read_ia5string_content),
        Ok((empty, expected))
    );
    assert_eq!(
        parse_der_implicit(&bytes, Tag(2), der_read_ia5string_content),
        Err(Err::Error(BerError::unexpected_tag(Some(Tag(2)), Tag(1))))
    );
}

#[test]
fn test_der_implicit_long_tag() {
    let empty = &b""[..];
    let bytes = [0x5f, 0x52, 0x04, 0x70, 0x61, 0x73, 0x73];
    let expected = DerObject {
        header: Header::new(Class::Application, false, Tag(0x52), 4.into())
            .with_raw_tag(Some(Cow::Borrowed(&[0x5f, 0x52]))),
        content: BerObjectContent::IA5String("pass"),
    };
    fn der_read_ia5string_content<'a>(
        i: &'a [u8],
        hdr: &Header,
        depth: usize,
    ) -> BerResult<'a, BerObjectContent<'a>> {
        ber_read_element_content_as(i, Tag::Ia5String, hdr.length(), hdr.is_constructed(), depth)
    }
    assert_eq!(
        parse_der_implicit(&bytes, Tag(0x52), der_read_ia5string_content),
        Ok((empty, expected))
    );
    assert_eq!(
        parse_der_implicit(&bytes, Tag(2), der_read_ia5string_content),
        Err(Err::Error(BerError::unexpected_tag(
            Some(Tag(2)),
            Tag(0x52)
        )))
    );
}

#[test]
fn test_der_optional() {
    let empty = &b""[..];
    let bytes1 = [
        0x30, 0x0a, 0x0a, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let bytes2 = [0x30, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01];
    let expected1 = DerObject::from_seq(vec![
        DerObject::from_obj(BerObjectContent::Optional(Some(Box::new(
            DerObject::from_obj(BerObjectContent::Enum(1)),
        )))),
        DerObject::from_int_slice(b"\x01\x00\x01"),
    ]);
    let expected2 = DerObject::from_seq(vec![
        DerObject::from_obj(BerObjectContent::Optional(None)),
        DerObject::from_int_slice(b"\x01\x00\x01"),
    ]);
    fn parse_optional_enum(i: &[u8]) -> DerResult<'_> {
        parse_ber_optional(parse_der_enum)(i)
    }
    fn parser(i: &[u8]) -> DerResult<'_> {
        parse_der_sequence_defined(
            // the nom `tuple` combinator returns a tuple, so we have to map it
            // to a list
            map(tuple((parse_optional_enum, parse_der_integer)), |(a, b)| {
                vec![a, b]
            }),
        )(i)
    }
    assert_eq!(parser(&bytes1), Ok((empty, expected1)));
    assert_eq!(parser(&bytes2), Ok((empty, expected2)));
}

#[test]
fn test_der_seq_dn() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x46, 0x52,
        0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65,
        0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
        0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64,
    ];
    let expected = DerObject::from_seq(vec![
        DerObject::from_set(vec![DerObject::from_seq(vec![
            DerObject::from_obj(BerObjectContent::OID(Oid::from(&[2, 5, 4, 6]).unwrap())), // countryName
            DerObject::from_obj(BerObjectContent::PrintableString("FR")),
        ])]),
        DerObject::from_set(vec![DerObject::from_seq(vec![
            DerObject::from_obj(BerObjectContent::OID(Oid::from(&[2, 5, 4, 8]).unwrap())), // stateOrProvinceName
            DerObject::from_obj(BerObjectContent::UTF8String("Some-State")),
        ])]),
        DerObject::from_set(vec![DerObject::from_seq(vec![
            DerObject::from_obj(BerObjectContent::OID(Oid::from(&[2, 5, 4, 10]).unwrap())), // organizationName
            DerObject::from_obj(BerObjectContent::UTF8String("Internet Widgits Pty Ltd")),
        ])]),
    ]);
    assert_eq!(parse_der(&bytes), Ok((empty, expected)));
}

#[test]
fn test_der_seq_dn_defined() {
    let empty = &b""[..];
    let bytes = [
        0x30, 0x45, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x46, 0x52,
        0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x53, 0x6f, 0x6d, 0x65,
        0x2d, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x18, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x57, 0x69, 0x64, 0x67,
        0x69, 0x74, 0x73, 0x20, 0x50, 0x74, 0x79, 0x20, 0x4c, 0x74, 0x64,
    ];
    let expected = DerObject::from_seq(vec![
        DerObject::from_set(vec![DerObject::from_seq(vec![
            DerObject::from_obj(BerObjectContent::OID(Oid::from(&[2, 5, 4, 6]).unwrap())), // countryName
            DerObject::from_obj(BerObjectContent::PrintableString("FR")),
        ])]),
        DerObject::from_set(vec![DerObject::from_seq(vec![
            DerObject::from_obj(BerObjectContent::OID(Oid::from(&[2, 5, 4, 8]).unwrap())), // stateOrProvinceName
            DerObject::from_obj(BerObjectContent::UTF8String("Some-State")),
        ])]),
        DerObject::from_set(vec![DerObject::from_seq(vec![
            DerObject::from_obj(BerObjectContent::OID(Oid::from(&[2, 5, 4, 10]).unwrap())), // organizationName
            DerObject::from_obj(BerObjectContent::UTF8String("Internet Widgits Pty Ltd")),
        ])]),
    ]);
    #[inline]
    fn parse_directory_string(i: &[u8]) -> DerResult<'_> {
        alt((
            parse_der_utf8string,
            parse_der_printablestring,
            parse_der_ia5string,
        ))(i)
    }
    #[inline]
    fn parse_attr_type_and_value(i: &[u8]) -> DerResult<'_> {
        parse_der_sequence_defined(
            // the nom `tuple` combinator returns a tuple, so we have to map it
            // to a list
            map(tuple((parse_der_oid, parse_directory_string)), |(a, b)| {
                vec![a, b]
            }),
        )(i)
    }
    #[inline]
    fn parse_rdn(i: &[u8]) -> DerResult<'_> {
        parse_der_set_of(parse_attr_type_and_value)(i)
    }
    #[inline]
    fn parse_name(i: &[u8]) -> DerResult<'_> {
        parse_der_sequence_of(parse_rdn)(i)
    }
    assert_eq!(parse_name(&bytes), Ok((empty, expected)));
}

#[test_case(&hex!("02 01 01"), Ok(1) ; "u32-1")]
#[test_case(&hex!("02 01 ff"), Err(BerError::IntegerNegative) ; "negative integer")]
#[test_case(&hex!("02 02 00 ff"), Ok(255) ; "u32-255")]
#[test_case(&hex!("02 02 01 23"), Ok(0x123) ; "u32-0x123")]
#[test_case(&hex!("02 04 01 23 45 67"), Ok(0x0123_4567) ; "u32-long-ok")]
// XXX DER encoding is invalid (not minimal) in following test:
// #[test_case(&hex!("02 04 ff ff ff ff"), Err(BerError::IntegerNegative) ; "u32-long2-neg")]
#[test_case(&hex!("02 06 00 00 01 23 45 67"), Err(BerError::DerConstraintFailed(DerConstraint::IntegerLeadingZeroes)) ; "u32-long-leading-zeros")]
#[test_case(&hex!("02 05 01 23 45 67 01"), Err(BerError::IntegerTooLarge) ; "u32 too large")]
#[test_case(&hex!("02 09 01 23 45 67 01 23 45 67 ab"), Err(BerError::IntegerTooLarge) ; "u32 too large 2")]
#[test_case(&hex!("03 03 01 00 01"), Err(BerError::unexpected_tag(Some(Tag(2)), Tag(3))) ; "invalid tag")]
fn tc_der_u32(i: &[u8], out: Result<u32, BerError>) {
    let res = parse_der_u32(i);
    match out {
        Ok(expected) => {
            pretty_assertions::assert_eq!(res, Ok((&b""[..], expected)));
        }
        Err(e) => {
            pretty_assertions::assert_eq!(res, Err(Err::Error(e)));
        }
    }
}

#[test_case(&hex!("02 01 01"), Ok(1) ; "i32-1")]
#[test_case(&hex!("02 01 ff"), Ok(-1) ; "i32-neg1")]
#[test_case(&hex!("02 01 80"), Ok(-128) ; "i32-neg128")]
#[test_case(&hex!("02 02 ff 7f"), Ok(-129) ; "i32-neg129")]
#[test_case(&hex!("02 02 00 ff"), Ok(255) ; "i32-255")]
#[test_case(&hex!("02 02 ff f0"), Err(BerError::DerConstraintFailed(DerConstraint::IntegerLeadingFF)) ; "i32-neg-leading-ff")]
fn tc_der_i32(i: &[u8], out: Result<i32, BerError>) {
    let res = parse_der_i32(i);
    match out {
        Ok(expected) => {
            pretty_assertions::assert_eq!(res, Ok((&b""[..], expected)));
        }
        Err(e) => {
            pretty_assertions::assert_eq!(res, Err(Err::Error(e)));
        }
    }
}

#[test_case(&hex!("02 01 01"), Ok(1) ; "u64-1")]
#[test_case(&hex!("02 02 00 ff"), Ok(255) ; "u64-255")]
#[test_case(&hex!("02 02 01 23"), Ok(0x123) ; "u64-0x123")]
#[test_case(&hex!("02 08 01 23 45 67 01 23 45 67"), Ok(0x0123_4567_0123_4567) ; "u64-long-ok")]
#[test_case(&hex!("02 09 00 ff ff ff ff ff ff ff ff"), Ok(0xffff_ffff_ffff_ffff) ; "u64-long2-ok")]
#[test_case(&hex!("02 09 01 23 45 67 01 23 45 67 ab"), Err(BerError::IntegerTooLarge) ; "u64 too large")]
#[test_case(&hex!("03 03 01 00 01"), Err(BerError::unexpected_tag(Some(Tag(2)), Tag(3))) ; "invalid tag")]
fn tc_der_u64(i: &[u8], out: Result<u64, BerError>) {
    let res = parse_der_u64(i);
    match out {
        Ok(expected) => {
            pretty_assertions::assert_eq!(res, Ok((&b""[..], expected)));
        }
        Err(e) => {
            pretty_assertions::assert_eq!(res, Err(Err::Error(e)));
        }
    }
}

#[test_case(&hex!("02 01 01"), Ok(&[1]) ; "slice 1")]
#[test_case(&hex!("02 01 ff"), Ok(&[255]) ; "slice 2")]
#[test_case(&hex!("02 09 01 23 45 67 01 23 45 67 ab"), Ok(&hex!("01 23 45 67 01 23 45 67 ab")) ; "slice 3")]
#[test_case(&hex!("22 80 02 01 01 00 00"), Err(BerError::DerConstraintFailed(DerConstraint::IndefiniteLength)) ; "constructed slice")]
#[test_case(&hex!("03 03 01 00 01"), Err(BerError::unexpected_tag(Some(Tag(2)), Tag(3))) ; "invalid tag")]
fn tc_der_slice(i: &[u8], out: Result<&[u8], BerError>) {
    let res = parse_der_slice(i, 2);
    match out {
        Ok(expected) => {
            pretty_assertions::assert_eq!(res, Ok((&b""[..], expected)));
        }
        Err(e) => {
            pretty_assertions::assert_eq!(res, Err(Err::Error(e)));
        }
    }
}

// ----- strict DER validation -----

fn strict_err(i: &[u8]) -> DerStrictError {
    parse_der_strict(i).expect_err("strict validation should fail")
}

#[test]
fn test_der_strict_valid() {
    // primitive objects
    assert!(parse_der_strict(&hex!("02 03 01 00 01")).is_ok());
    assert!(parse_der_strict(&hex!("01 01 ff")).is_ok());
    assert!(parse_der_strict(&hex!("05 00")).is_ok());
    assert!(parse_der_strict(&hex!("02 01 80")).is_ok()); // -128, minimal
    assert!(parse_der_strict(&hex!("02 02 00 80")).is_ok()); // 128, leading 0x00 required
    assert!(parse_der_strict(&hex!("02 02 ff 7f")).is_ok()); // -129, leading 0xff required
                                                             // minimal long-form length (128 bytes)
    let mut v = vec![0x04, 0x81, 0x80];
    v.extend_from_slice(&[0x41; 128]);
    assert!(parse_der_strict(&v).is_ok());
    // recursive containers: SEQUENCE { INTEGER, SET { INTEGER, INTEGER } }
    let bytes = hex!("30 0b 02 01 01 31 06 02 01 01 02 01 02");
    let obj = parse_der_strict(&bytes).expect("strict validation failed");
    assert_eq!(obj.header.tag(), Tag::Sequence);
    // explicit tagged object (constructed context-specific)
    assert!(parse_der_strict(&hex!("a0 03 02 01 05")).is_ok());
    // SET sorted by tag: BOOLEAN < INTEGER in lexicographic order of encodings
    assert!(parse_der_strict(&hex!("31 06 01 01 ff 02 01 01")).is_ok());
    // validate_der_strict agrees
    assert!(validate_der_strict(&bytes).is_ok());
}

#[test]
fn test_der_strict_non_minimal_length() {
    // long form used for length < 128
    let err = strict_err(&hex!("02 81 01 2a"));
    assert_eq!(err.kind, DerStrictErrorKind::NonMinimalLength);
    assert_eq!(err.offset, 1);
    // long form with leading zero length octet
    let mut v = vec![0x04, 0x82, 0x00, 0x80];
    v.extend_from_slice(&[0x41; 128]);
    let err = strict_err(&v);
    assert_eq!(err.kind, DerStrictErrorKind::NonMinimalLength);
    assert_eq!(err.offset, 1);
    // nested: SEQUENCE { INTEGER with non-minimal length }
    let err = strict_err(&hex!("30 04 02 81 01 2a"));
    assert_eq!(err.kind, DerStrictErrorKind::NonMinimalLength);
    assert_eq!(err.offset, 3);
    // indefinite length
    let err = strict_err(&hex!("24 80 04 01 41 00 00"));
    assert_eq!(err.kind, DerStrictErrorKind::IndefiniteLength);
    assert_eq!(err.offset, 1);
    // the lenient parser still accepts these
    assert!(parse_der(&hex!("02 81 01 2a")).is_ok());
}

#[test]
fn test_der_strict_integer_leading_bytes() {
    // redundant leading 0x00
    let err = strict_err(&hex!("02 02 00 7f"));
    assert_eq!(err.kind, DerStrictErrorKind::IntegerLeadingBytes);
    assert_eq!(err.offset, 2);
    // redundant leading 0xff
    let err = strict_err(&hex!("02 02 ff 80"));
    assert_eq!(err.kind, DerStrictErrorKind::IntegerLeadingBytes);
    assert_eq!(err.offset, 2);
    // nested inside a SEQUENCE
    let err = strict_err(&hex!("30 07 02 01 01 02 02 00 7f"));
    assert_eq!(err.kind, DerStrictErrorKind::IntegerLeadingBytes);
    assert_eq!(err.offset, 7);
    // empty INTEGER
    let err = strict_err(&hex!("02 00"));
    assert_eq!(err.kind, DerStrictErrorKind::InvalidContent);
    // the lenient parser accepts the redundant 0xff form
    assert!(parse_der(&hex!("02 02 ff 80")).is_ok());
}

#[test]
fn test_der_strict_constructed_encoding() {
    // constructed OCTET STRING (primitive type)
    let err = strict_err(&hex!("24 03 04 01 41"));
    assert_eq!(err.kind, DerStrictErrorKind::ConstructedEncoding);
    assert_eq!(err.offset, 0);
    // primitive SEQUENCE (constructed type)
    let err = strict_err(&hex!("10 00"));
    assert_eq!(err.kind, DerStrictErrorKind::ConstructedEncoding);
    assert_eq!(err.offset, 0);
    // primitive SET
    let err = strict_err(&hex!("11 00"));
    assert_eq!(err.kind, DerStrictErrorKind::ConstructedEncoding);
    // constructed BIT STRING
    let err = strict_err(&hex!("23 03 03 01 00"));
    assert_eq!(err.kind, DerStrictErrorKind::ConstructedEncoding);
}

#[test]
fn test_der_strict_unordered_set() {
    // SET { 2, 1 }: not sorted
    let err = strict_err(&hex!("31 06 02 01 02 02 01 01"));
    assert_eq!(err.kind, DerStrictErrorKind::UnorderedSet);
    assert_eq!(err.offset, 5);
    // SET sorted by tag: INTEGER before BOOLEAN is wrong order
    let err = strict_err(&hex!("31 06 02 01 01 01 01 ff"));
    assert_eq!(err.kind, DerStrictErrorKind::UnorderedSet);
    assert_eq!(err.offset, 5);
    // unordered SET nested in a SEQUENCE
    let err = strict_err(&hex!("30 08 31 06 02 01 02 02 01 01"));
    assert_eq!(err.kind, DerStrictErrorKind::UnorderedSet);
    assert_eq!(err.offset, 7);
    // SET OF (same tag): unordered INTEGERs
    let err = strict_err(&hex!("31 09 02 01 03 02 01 02 02 01 01"));
    assert_eq!(err.kind, DerStrictErrorKind::UnorderedSet);
    assert_eq!(err.offset, 5);
    // the lenient parser accepts unordered sets
    assert!(parse_der(&hex!("31 06 02 01 02 02 01 01")).is_ok());
}

#[test]
fn test_der_strict_trailing_bytes() {
    let err = strict_err(&hex!("02 01 01 00"));
    assert_eq!(err.kind, DerStrictErrorKind::TrailingBytes);
    assert_eq!(err.offset, 3);
    // the lenient parser accepts and returns the remainder
    let (rem, _) = parse_der(&hex!("02 01 01 00")).expect("parsing failed");
    assert_eq!(rem, &[0x00]);
}

#[test]
fn test_der_strict_other_errors() {
    // truncated input
    let err = strict_err(&hex!("02 02 01"));
    assert_eq!(err.kind, DerStrictErrorKind::Truncated);
    let err = strict_err(&[]);
    assert_eq!(err.kind, DerStrictErrorKind::Truncated);
    // invalid BOOLEAN value
    let err = strict_err(&hex!("01 01 7f"));
    assert_eq!(err.kind, DerStrictErrorKind::InvalidContent);
    // recursion limit
    let mut v = vec![0x05, 0x00];
    for _ in 0..60 {
        let len = v.len();
        let mut w = vec![0x30, len as u8];
        w.append(&mut v);
        v = w;
    }
    let err = strict_err(&v);
    assert_eq!(err.kind, DerStrictErrorKind::RecursionLimit);
    // error display shows category and offset
    let err = strict_err(&hex!("02 01 01 00"));
    let s = format!("{}", err);
    assert!(s.contains("trailing bytes"));
    assert!(s.contains('3'));
}

//! Pure, bounded validation for the pinned shared executable host-adapter manifest v1.
//!
//! Schema/profile authority: `.github` revision
//! `47b927c73564204ec77bf197eb1b1ea10550e5fb`; executable manifest schema SHA-256
//! `9d9e66b0ee578097ceeeba34d5219b60169cbb9d4aa51ac7ff1ef2139e626cd1`;
//! host contract/profile SHA-256
//! `2353172147bc041e4d6022134854c98cc2dca9d4ac21d3b85b0e1209de586417`.
//!
//! This module validates declarative bytes only. A validated manifest does not
//! assert publisher trust, host presence, effective capability, or executability.

use num_bigint::BigInt;
use num_traits::ToPrimitive;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_HOST_ADAPTER_MANIFEST_BYTES: usize = 1_048_576;
pub const MAX_HOST_ADAPTER_MANIFEST_DEPTH: usize = 32;
pub const MAX_HOST_ADAPTER_MANIFEST_NODES: usize = 16_384;
pub const MAX_CONFIGURATION_SCHEMA_BYTES: usize = 65_536;
pub const MAX_CONFIGURATION_SCHEMA_DEPTH: usize = 16;
pub const MAX_CONFIGURATION_SCHEMA_NODES: usize = 4_096;
pub const MAX_NUMERIC_TOKEN_BYTES: usize = 4_096;
pub const MAX_NUMERIC_EXPONENT_DIGITS: usize = 128;
const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";
pub const HOST_ADAPTER_MANIFEST_SCHEMA_SHA256: &str =
    "9d9e66b0ee578097ceeeba34d5219b60169cbb9d4aa51ac7ff1ef2139e626cd1";
pub const HOST_ADAPTER_PROFILE_SHA256: &str =
    "2353172147bc041e4d6022134854c98cc2dca9d4ac21d3b85b0e1209de586417";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostManifestRejection {
    #[error("host adapter manifest exceeds the local byte limit")]
    InputTooLarge,
    #[error("host adapter manifest exceeds the local nesting limit")]
    ExcessiveNesting,
    #[error("host adapter manifest exceeds the local node limit")]
    NodeLimit,
    #[error("host adapter configuration schema exceeds the local byte limit")]
    ConfigurationSchemaTooLarge,
    #[error("host adapter configuration schema exceeds the local nesting limit")]
    ConfigurationSchemaExcessiveNesting,
    #[error("host adapter configuration schema exceeds the local node limit")]
    ConfigurationSchemaNodeLimit,
    #[error("host adapter manifest contains an overlong numeric token")]
    NumericTokenSizeLimit,
    #[error("host adapter manifest numeric exponent has too many digits")]
    NumericExponentDigitLimit,
    #[error("host adapter manifest contains duplicate object keys")]
    DuplicateKey,
    #[error("host adapter manifest is not valid JSON")]
    InvalidJson,
    #[error("host adapter manifest violates the pinned contract")]
    ContractViolation,
}

impl HostManifestRejection {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::InputTooLarge => "manifest_byte_capacity_exceeded",
            Self::ExcessiveNesting => "manifest_depth_capacity_exceeded",
            Self::NodeLimit => "manifest_node_capacity_exceeded",
            Self::ConfigurationSchemaTooLarge => "configuration_schema_byte_capacity_exceeded",
            Self::ConfigurationSchemaExcessiveNesting => {
                "configuration_schema_depth_capacity_exceeded"
            }
            Self::ConfigurationSchemaNodeLimit => "configuration_schema_node_capacity_exceeded",
            Self::NumericTokenSizeLimit => "numeric_token_capacity_exceeded",
            Self::NumericExponentDigitLimit => "numeric_exponent_capacity_exceeded",
            Self::DuplicateKey => "manifest_duplicate_key",
            Self::InvalidJson => "manifest_invalid_json",
            Self::ContractViolation => "manifest_contract_violation",
        }
    }

    pub fn is_local_capacity(self) -> bool {
        !matches!(
            self,
            Self::DuplicateKey | Self::InvalidJson | Self::ContractViolation
        )
    }
}

/// A fully validated declarative host adapter manifest.
///
/// Fields and construction remain private so callers cannot manufacture a
/// validated descriptor. `as_manifest_bytes` is the exact source authority for
/// copying and digesting; `as_raw_json` is lossless JSON for passive inspection.
pub struct HostAdapterManifest {
    id: String,
    source: Vec<u8>,
    raw_json: Box<RawValue>,
}

impl fmt::Debug for HostAdapterManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostAdapterManifest")
            .field("id", &self.id)
            .field("source_bytes", &self.source.len())
            .finish_non_exhaustive()
    }
}

impl HostAdapterManifest {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn as_manifest_bytes(&self) -> &[u8] {
        &self.source
    }

    pub fn as_raw_json(&self) -> &RawValue {
        &self.raw_json
    }
}

impl Serialize for HostAdapterManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.raw_json.serialize(serializer)
    }
}

pub fn decode_host_adapter_manifest(
    bytes: &[u8],
) -> Result<HostAdapterManifest, HostManifestRejection> {
    if bytes.len() > MAX_HOST_ADAPTER_MANIFEST_BYTES {
        return Err(HostManifestRejection::InputTooLarge);
    }
    precheck_full_json(bytes)?;

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw_json = Box::<RawValue>::deserialize(&mut deserializer).map_err(map_parse_error)?;
    deserializer
        .end()
        .map_err(|_| HostManifestRejection::InvalidJson)?;
    let mut budget = ParseBudget::default();
    let root = parse_node(&raw_json, &mut budget, 1, None)?;
    let id = validate_manifest(&root)?;
    Ok(HostAdapterManifest {
        id,
        source: bytes.to_vec(),
        raw_json,
    })
}

#[derive(Default)]
struct ParseBudget {
    full_nodes: usize,
    schema_nodes: usize,
}

#[derive(Debug)]
enum JsonKind {
    Object(BTreeMap<String, Node>),
    Array(Vec<Node>),
    String(String),
    Number(ExactDecimal),
    Bool(bool),
    Null,
}

#[derive(Debug)]
struct Node {
    kind: JsonKind,
}

fn precheck_full_json(bytes: &[u8]) -> Result<(), HostManifestRejection> {
    let (mut depth, mut nodes, mut in_string, mut escaped, mut previous) =
        (0usize, 0usize, false, false, None);
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                let mut next = index + 1;
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if bytes.get(next) != Some(&b':') {
                    nodes += 1;
                }
            }
            previous = Some(byte);
            if nodes > MAX_HOST_ADAPTER_MANIFEST_NODES {
                return Err(HostManifestRejection::NodeLimit);
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                nodes += 1;
                if depth > MAX_HOST_ADAPTER_MANIFEST_DEPTH {
                    return Err(HostManifestRejection::ExcessiveNesting);
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            b'-' | b'0'..=b'9' | b't' | b'f' | b'n'
                if previous.is_none_or(|value| matches!(value, b':' | b',' | b'[')) =>
            {
                nodes += 1;
            }
            _ => {}
        }
        if !byte.is_ascii_whitespace() {
            previous = Some(byte);
        }
        if nodes > MAX_HOST_ADAPTER_MANIFEST_NODES {
            return Err(HostManifestRejection::NodeLimit);
        }
        index += 1;
    }
    Ok(())
}

struct RawObject<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for RawObject<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = RawObject<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object with unique decoded keys")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Vec::new();
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom("fornax_duplicate_object_key"));
                    }
                    let value = map.next_value::<&'de RawValue>()?;
                    values.push((key, value));
                }
                Ok(RawObject(values))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

fn parse_node(
    raw: &RawValue,
    budget: &mut ParseBudget,
    depth: usize,
    schema_depth: Option<usize>,
) -> Result<Node, HostManifestRejection> {
    let text = raw.get();
    let first = text
        .as_bytes()
        .first()
        .copied()
        .ok_or(HostManifestRejection::InvalidJson)?;
    let is_container = matches!(first, b'{' | b'[');
    if is_container && depth > MAX_HOST_ADAPTER_MANIFEST_DEPTH {
        return Err(HostManifestRejection::ExcessiveNesting);
    }
    budget.full_nodes += 1;
    if budget.full_nodes > MAX_HOST_ADAPTER_MANIFEST_NODES {
        return Err(HostManifestRejection::NodeLimit);
    }
    if let Some(schema_depth) = schema_depth {
        if is_container && schema_depth > MAX_CONFIGURATION_SCHEMA_DEPTH {
            return Err(HostManifestRejection::ConfigurationSchemaExcessiveNesting);
        }
        budget.schema_nodes += 1;
        if budget.schema_nodes > MAX_CONFIGURATION_SCHEMA_NODES {
            return Err(HostManifestRejection::ConfigurationSchemaNodeLimit);
        }
        if schema_depth == 1 && raw.get().len() > MAX_CONFIGURATION_SCHEMA_BYTES {
            return Err(HostManifestRejection::ConfigurationSchemaTooLarge);
        }
    }

    let kind = match first {
        b'{' => {
            let mut deserializer = serde_json::Deserializer::from_str(text);
            let values = RawObject::deserialize(&mut deserializer).map_err(map_parse_error)?;
            deserializer
                .end()
                .map_err(|_| HostManifestRejection::InvalidJson)?;
            let mut object = BTreeMap::new();
            for (key, value) in values.0 {
                let child_schema_depth =
                    if depth == 1 && schema_depth.is_none() && key == "configuration_schema" {
                        Some(1)
                    } else {
                        schema_depth.map(|current| current + 1)
                    };
                let child = parse_node(value, budget, depth + 1, child_schema_depth)?;
                object.insert(key, child);
            }
            JsonKind::Object(object)
        }
        b'[' => {
            let mut deserializer = serde_json::Deserializer::from_str(text);
            let values =
                Vec::<&RawValue>::deserialize(&mut deserializer).map_err(map_parse_error)?;
            deserializer
                .end()
                .map_err(|_| HostManifestRejection::InvalidJson)?;
            let mut array = Vec::with_capacity(values.len());
            for value in values {
                let child = parse_node(value, budget, depth + 1, schema_depth.map(|d| d + 1))?;
                array.push(child);
            }
            JsonKind::Array(array)
        }
        b'"' => JsonKind::String(
            serde_json::from_str(text).map_err(|_| HostManifestRejection::InvalidJson)?,
        ),
        b't' | b'f' => JsonKind::Bool(
            serde_json::from_str(text).map_err(|_| HostManifestRejection::InvalidJson)?,
        ),
        b'n' => {
            serde_json::from_str::<()>(text).map_err(|_| HostManifestRejection::InvalidJson)?;
            JsonKind::Null
        }
        b'-' | b'0'..=b'9' => JsonKind::Number(ExactDecimal::parse(text)?),
        _ => return Err(HostManifestRejection::InvalidJson),
    };
    Ok(Node { kind })
}

fn map_parse_error(error: serde_json::Error) -> HostManifestRejection {
    if error.to_string().contains("fornax_duplicate_object_key") {
        HostManifestRejection::DuplicateKey
    } else {
        HostManifestRejection::InvalidJson
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactDecimal {
    sign: i8,
    digits: String,
    exponent: BigInt,
}

impl ExactDecimal {
    fn parse(token: &str) -> Result<Self, HostManifestRejection> {
        if token.len() > MAX_NUMERIC_TOKEN_BYTES {
            return Err(HostManifestRejection::NumericTokenSizeLimit);
        }
        let bytes = token.as_bytes();
        let e_pos = bytes.iter().position(|b| *b == b'e' || *b == b'E');
        let (mantissa, exponent_text) = match e_pos {
            Some(index) => (&token[..index], Some(&token[index + 1..])),
            None => (token, None),
        };
        let explicit_exponent = if let Some(text) = exponent_text {
            let digits = text.trim_start_matches(['+', '-']);
            if digits.is_empty() || digits.len() > MAX_NUMERIC_EXPONENT_DIGITS {
                return Err(HostManifestRejection::NumericExponentDigitLimit);
            }
            let magnitude = BigInt::parse_bytes(digits.as_bytes(), 10)
                .ok_or(HostManifestRejection::InvalidJson)?;
            if text.starts_with('-') {
                -magnitude
            } else {
                magnitude
            }
        } else {
            BigInt::from(0)
        };
        let negative = mantissa.starts_with('-');
        let unsigned = mantissa.strip_prefix('-').unwrap_or(mantissa);
        let dot = unsigned.find('.');
        let fractional_len = dot.map_or(0, |i| unsigned.len() - i - 1);
        let mut digits = unsigned.chars().filter(|ch| *ch != '.').collect::<String>();
        let first_nonzero = digits.find(|ch| ch != '0').unwrap_or(digits.len());
        digits.drain(..first_nonzero);
        if digits.is_empty() {
            return Ok(Self {
                sign: 0,
                digits: "0".to_owned(),
                exponent: BigInt::from(0),
            });
        }
        let trailing_zeros = digits.bytes().rev().take_while(|b| *b == b'0').count();
        if trailing_zeros > 0 {
            digits.truncate(digits.len() - trailing_zeros);
        }
        let exponent =
            explicit_exponent - BigInt::from(fractional_len) + BigInt::from(trailing_zeros);
        Ok(Self {
            sign: if negative { -1 } else { 1 },
            digits,
            exponent,
        })
    }

    fn cmp(&self, other: &Self) -> Ordering {
        match self.sign.cmp(&other.sign) {
            Ordering::Equal if self.sign == 0 => Ordering::Equal,
            Ordering::Equal => {
                let magnitude = self.cmp_magnitude(other);
                if self.sign < 0 {
                    magnitude.reverse()
                } else {
                    magnitude
                }
            }
            different => different,
        }
    }

    fn cmp_magnitude(&self, other: &Self) -> Ordering {
        let left_order = &self.exponent + BigInt::from(self.digits.len());
        let right_order = &other.exponent + BigInt::from(other.digits.len());
        match left_order.cmp(&right_order) {
            Ordering::Equal => {
                let width = self.digits.len().max(other.digits.len());
                for i in 0..width {
                    let left = self.digits.as_bytes().get(i).copied().unwrap_or(b'0');
                    let right = other.digits.as_bytes().get(i).copied().unwrap_or(b'0');
                    match left.cmp(&right) {
                        Ordering::Equal => {}
                        ordering => return ordering,
                    }
                }
                Ordering::Equal
            }
            ordering => ordering,
        }
    }

    fn is_integral(&self) -> bool {
        if self.sign == 0 || self.exponent >= BigInt::from(0) {
            return true;
        }
        false
    }

    fn bounded_i64(&self) -> Option<i64> {
        if !self.is_integral() {
            return None;
        }
        let min = Self::parse("-9223372036854775808").ok()?;
        let max = Self::parse("9223372036854775807").ok()?;
        if self.cmp(&min) == Ordering::Less || self.cmp(&max) == Ordering::Greater {
            return None;
        }
        let integer = self.to_bounded_integer_string(20)?;
        integer.parse().ok()
    }

    fn to_bounded_integer_string(&self, max_digits: usize) -> Option<String> {
        if self.sign == 0 {
            return Some("0".to_owned());
        }
        let exponent = self.exponent.to_i64()?;
        if exponent < 0 {
            let scale = usize::try_from(-exponent).ok()?;
            if scale > self.digits.len() {
                return None;
            }
            let split = self.digits.len() - scale;
            if self.digits[split..].bytes().any(|b| b != b'0') {
                return None;
            }
            let mut integer = self.digits[..split].to_owned();
            if integer.is_empty() {
                integer.push('0');
            }
            if self.sign < 0 {
                integer.insert(0, '-');
            }
            return Some(integer);
        }
        let exponent = usize::try_from(exponent).ok()?;
        if self.digits.len().saturating_add(exponent) > max_digits {
            return None;
        }
        let mut integer = self.digits.clone();
        integer.extend(std::iter::repeat_n('0', exponent));
        if self.sign < 0 {
            integer.insert(0, '-');
        }
        Some(integer)
    }
}

#[derive(Debug, Clone)]
enum DigitSegment {
    Text(String),
    Repeat(u8, BigInt),
}

#[derive(Debug, Clone)]
struct VirtualMagnitude {
    segments: Vec<DigitSegment>,
    length: BigInt,
}

impl VirtualMagnitude {
    fn from_digits(digits: &str, zeroes: BigInt) -> Self {
        let mut segments = Vec::new();
        let trimmed = digits.trim_start_matches('0');
        if !trimmed.is_empty() {
            segments.push(DigitSegment::Text(trimmed.to_owned()));
        }
        if zeroes > BigInt::from(0) {
            segments.push(DigitSegment::Repeat(b'0', zeroes));
        }
        let mut value = Self {
            segments,
            length: BigInt::from(0),
        };
        value.relength();
        value
    }

    fn relength(&mut self) {
        self.length = self.segments.iter().fold(BigInt::from(0), |sum, segment| {
            sum + match segment {
                DigitSegment::Text(s) => BigInt::from(s.len()),
                DigitSegment::Repeat(_, n) => n.clone(),
            }
        });
    }

    fn increment(&self) -> Self {
        let mut segments = self.segments.clone();
        if segments.is_empty() {
            return Self::from_digits("1", BigInt::from(0));
        }
        if let Some(DigitSegment::Repeat(byte, count)) = segments.last_mut() {
            if *byte == b'0' && *count > BigInt::from(0) {
                *count -= 1;
                if *count == BigInt::from(0) {
                    segments.pop();
                }
                segments.push(DigitSegment::Text("1".to_owned()));
                let mut result = Self {
                    segments,
                    length: BigInt::from(0),
                };
                result.relength();
                return result;
            }
        }
        if let Some(DigitSegment::Text(digits)) = segments.last_mut() {
            increment_digits(digits);
        }
        let mut result = Self {
            segments,
            length: BigInt::from(0),
        };
        result.relength();
        result
    }

    fn decrement(&self) -> Self {
        let mut segments = self.segments.clone();
        if let Some(DigitSegment::Repeat(byte, count)) = segments.last_mut() {
            if *byte == b'0' && *count > BigInt::from(0) {
                let count = count.clone();
                segments.pop();
                if let Some(DigitSegment::Text(prefix)) = segments.last_mut() {
                    decrement_digits(prefix);
                }
                segments.push(DigitSegment::Repeat(b'9', count));
                let mut result = Self {
                    segments,
                    length: BigInt::from(0),
                };
                result.strip_leading_zero_segments();
                result.relength();
                return result;
            }
        }
        if let Some(DigitSegment::Text(digits)) = segments.last_mut() {
            decrement_digits(digits);
        }
        let mut result = Self {
            segments,
            length: BigInt::from(0),
        };
        result.strip_leading_zero_segments();
        result.relength();
        result
    }

    fn strip_leading_zero_segments(&mut self) {
        while let Some(DigitSegment::Text(text)) = self.segments.first_mut() {
            let trimmed = text.trim_start_matches('0').to_owned();
            if trimmed.is_empty() {
                self.segments.remove(0);
            } else {
                *text = trimmed;
                break;
            }
        }
    }

    fn cmp(&self, other: &Self) -> Ordering {
        match self.length.cmp(&other.length) {
            Ordering::Equal => compare_segments(&self.segments, &other.segments),
            ordering => ordering,
        }
    }
}

fn increment_digits(digits: &mut String) {
    let mut bytes = digits.as_bytes().to_vec();
    for byte in bytes.iter_mut().rev() {
        if *byte < b'9' {
            *byte += 1;
            digits.clear();
            digits.push_str(std::str::from_utf8(&bytes).expect("decimal digits"));
            return;
        }
        *byte = b'0';
    }
    bytes.insert(0, b'1');
    digits.clear();
    digits.push_str(std::str::from_utf8(&bytes).expect("decimal digits"));
}

fn decrement_digits(digits: &mut String) {
    let mut bytes = digits.as_bytes().to_vec();
    for byte in bytes.iter_mut().rev() {
        if *byte > b'0' {
            *byte -= 1;
            break;
        }
        *byte = b'9';
    }
    let trimmed = bytes.iter().position(|b| *b != b'0').unwrap_or(bytes.len());
    digits.clear();
    digits.push_str(std::str::from_utf8(&bytes[trimmed..]).expect("decimal digits"));
}

fn compare_segments(left: &[DigitSegment], right: &[DigitSegment]) -> Ordering {
    let (mut li, mut ri, mut lo, mut ro) = (0usize, 0usize, BigInt::from(0), BigInt::from(0));
    while li < left.len() && ri < right.len() {
        let (lb, llen) = segment_chunk(&left[li], &lo);
        let (rb, rlen) = segment_chunk(&right[ri], &ro);
        match compare_chunks((lb, &left[li], &lo, &llen), (rb, &right[ri], &ro, &rlen)) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
        let consumed = llen.min(rlen);
        lo += &consumed;
        ro += &consumed;
        if lo >= segment_len(&left[li]) {
            li += 1;
            lo = BigInt::from(0);
        }
        if ro >= segment_len(&right[ri]) {
            ri += 1;
            ro = BigInt::from(0);
        }
    }
    Ordering::Equal
}

fn segment_len(segment: &DigitSegment) -> BigInt {
    match segment {
        DigitSegment::Text(s) => BigInt::from(s.len()),
        DigitSegment::Repeat(_, n) => n.clone(),
    }
}

fn segment_chunk(segment: &DigitSegment, offset: &BigInt) -> (u8, BigInt) {
    match segment {
        DigitSegment::Text(s) => {
            let index = offset.to_usize().unwrap_or(s.len());
            (s.as_bytes()[index], BigInt::from(s.len() - index))
        }
        DigitSegment::Repeat(byte, length) => (*byte, length - offset),
    }
}

fn compare_chunks(
    left: (u8, &DigitSegment, &BigInt, &BigInt),
    right: (u8, &DigitSegment, &BigInt, &BigInt),
) -> Ordering {
    let (lbyte, lseg, loffset, llen) = left;
    let (rbyte, rseg, roffset, rlen) = right;
    let count = llen.min(rlen);
    match (lseg, rseg) {
        (DigitSegment::Repeat(_, _), DigitSegment::Repeat(_, _)) => lbyte.cmp(&rbyte),
        _ => {
            let count = count.to_usize().unwrap_or(usize::MAX);
            for offset in 0..count {
                let l = digit_at(lseg, loffset, offset);
                let r = digit_at(rseg, roffset, offset);
                match l.cmp(&r) {
                    Ordering::Equal => {}
                    order => return order,
                }
            }
            Ordering::Equal
        }
    }
}

fn digit_at(segment: &DigitSegment, offset: &BigInt, within: usize) -> u8 {
    match segment {
        DigitSegment::Text(s) => s.as_bytes()[offset.to_usize().unwrap_or(s.len()) + within],
        DigitSegment::Repeat(byte, _) => *byte,
    }
}

#[derive(Debug, Clone)]
struct ExactInteger {
    sign: i8,
    magnitude: VirtualMagnitude,
}

impl ExactInteger {
    fn zero() -> Self {
        Self {
            sign: 0,
            magnitude: VirtualMagnitude::from_digits("", BigInt::from(0)),
        }
    }

    fn from_decimal_rounded(value: &ExactDecimal, rounding: IntegerRounding) -> Self {
        if value.sign == 0 {
            return Self::zero();
        }
        if value.exponent >= BigInt::from(0) {
            return Self {
                sign: value.sign,
                magnitude: VirtualMagnitude::from_digits(&value.digits, value.exponent.clone()),
            };
        }
        let scale = -&value.exponent;
        if scale >= BigInt::from(value.digits.len()) {
            let nonzero_fraction = true;
            return match (value.sign, rounding) {
                (1, IntegerRounding::Floor) | (-1, IntegerRounding::Ceil) => Self::zero(),
                (1, IntegerRounding::Ceil) | (-1, IntegerRounding::Floor) if nonzero_fraction => {
                    Self {
                        sign: value.sign,
                        magnitude: VirtualMagnitude::from_digits("1", BigInt::from(0)),
                    }
                }
                _ => Self::zero(),
            };
        }
        let scale_usize = scale.to_usize().unwrap_or(value.digits.len());
        let split = value.digits.len() - scale_usize;
        let integer_digits = &value.digits[..split];
        let fraction_nonzero = value.digits[split..].bytes().any(|byte| byte != b'0');
        let mut magnitude = VirtualMagnitude::from_digits(integer_digits, BigInt::from(0));
        let increment = fraction_nonzero
            && matches!(
                (value.sign, rounding),
                (1, IntegerRounding::Ceil) | (-1, IntegerRounding::Floor)
            );
        if increment {
            magnitude = magnitude.increment();
        }
        let sign = if magnitude.length == BigInt::from(0) {
            0
        } else {
            value.sign
        };
        Self { sign, magnitude }
    }

    fn cmp(&self, other: &Self) -> Ordering {
        match self.sign.cmp(&other.sign) {
            Ordering::Equal if self.sign == 0 => Ordering::Equal,
            Ordering::Equal => {
                let order = self.magnitude.cmp(&other.magnitude);
                if self.sign < 0 {
                    order.reverse()
                } else {
                    order
                }
            }
            order => order,
        }
    }

    fn add_one(&mut self) {
        match self.sign {
            -1 => {
                self.magnitude = self.magnitude.decrement();
                if self.magnitude.length == BigInt::from(0) {
                    self.sign = 0;
                }
            }
            0 => {
                self.sign = 1;
                self.magnitude = VirtualMagnitude::from_digits("1", BigInt::from(0));
            }
            _ => self.magnitude = self.magnitude.increment(),
        }
    }

    fn subtract_one(&mut self) {
        match self.sign {
            -1 => self.magnitude = self.magnitude.increment(),
            0 => {
                self.sign = -1;
                self.magnitude = VirtualMagnitude::from_digits("1", BigInt::from(0));
            }
            _ => {
                self.magnitude = self.magnitude.decrement();
                if self.magnitude.length == BigInt::from(0) {
                    self.sign = 0;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum IntegerRounding {
    Floor,
    Ceil,
}

fn validate_manifest(root: &Node) -> Result<String, HostManifestRejection> {
    let object = expect_object(root)?;
    check_closed(
        object,
        &[
            "manifest_kind",
            "manifest_version",
            "adapter_id",
            "adapter_version",
            "protocol_versions",
            "contract_version_range",
            "roles",
            "capabilities",
            "host_version_constraints",
            "configuration_schema",
            "launch",
            "runtime_files",
            "input_limits",
            "needs",
        ],
    )?;
    expect_string_field(object, "manifest_kind", "host-adapter")?;
    expect_small_integer(object.get("manifest_version"), 1, 1)?;
    let id = expect_pattern_string(object.get("adapter_id"), |s| valid_identifier(s, 64, false))?;
    nonempty_string(object.get("adapter_version"))?;
    let protocols = expect_array_field(object, "protocol_versions")?;
    if protocols.is_empty() || protocols.len() > 32 {
        return contract();
    }
    let mut protocol_set = BTreeSet::new();
    for value in protocols {
        let version = expect_small_integer(Some(value), 1, i32::MAX as i64)?;
        if !protocol_set.insert(version) {
            return contract();
        }
    }
    validate_contract_range(object.get("contract_version_range"))?;
    validate_string_enum_array(
        object.get("roles"),
        &[
            "LifecycleSource",
            "ToolBoundarySource",
            "PolicyControlSink",
            "UsageEvidenceSource",
            "IdentitySource",
            "OperatorSurface",
            "ConfigDriver",
        ],
        true,
    )?;
    validate_pattern_array(object.get("capabilities"), valid_capability)?;
    validate_host_constraints(object.get("host_version_constraints"))?;
    validate_schema(object.get("configuration_schema"))?;
    validate_launch(object.get("launch"))?;
    validate_runtime_files(object.get("runtime_files"))?;
    validate_input_limits(object.get("input_limits"))?;
    validate_needs(object.get("needs"))?;
    Ok(id.to_owned())
}

fn validate_contract_range(value: Option<&Node>) -> Result<(), HostManifestRejection> {
    let range = expect_object(value.ok_or(HostManifestRejection::ContractViolation)?)?;
    check_closed(range, &["minimum", "maximum"])?;
    let min = expect_small_integer(range.get("minimum"), 1, i32::MAX as i64)?;
    let max = expect_small_integer(range.get("maximum"), 1, i32::MAX as i64)?;
    if min > max {
        return contract();
    }
    Ok(())
}

fn validate_host_constraints(value: Option<&Node>) -> Result<(), HostManifestRejection> {
    let values = expect_array(value.ok_or(HostManifestRejection::ContractViolation)?)?;
    if values.is_empty() {
        return contract();
    }
    let mut providers = BTreeSet::new();
    for value in values {
        let entry = expect_object(value)?;
        check_closed(entry, &["provider", "minimum", "maximum"])?;
        let provider =
            expect_pattern_string(entry.get("provider"), |s| valid_identifier(s, 32, false))?;
        if !providers.insert(provider) {
            return contract();
        }
        let minimum = parse_optional_version(entry.get("minimum"))?;
        let maximum = parse_optional_version(entry.get("maximum"))?;
        if matches!((&minimum, &maximum), (Some(min), Some(max)) if min.cmp_precedence(max) == Ordering::Greater)
        {
            return contract();
        }
    }
    Ok(())
}

// The shared SemVer grammar has no machine-integer limit on core components.
// Borrow lexical components to keep comparison proportional to bounded input.
struct HostVersion<'a> {
    core: [&'a str; 3],
    prerelease: Option<&'a str>,
}

impl<'a> HostVersion<'a> {
    fn parse(version: &'a str) -> Result<Self, HostManifestRejection> {
        let (precedence, build) = match version.split_once('+') {
            Some((precedence, build)) => (precedence, Some(build)),
            None => (version, None),
        };
        if build.is_some_and(|text| !valid_version_identifiers(text, false)) {
            return contract();
        }
        let (core, prerelease) = match precedence.split_once('-') {
            Some((core, prerelease)) => (core, Some(prerelease)),
            None => (precedence, None),
        };
        if prerelease.is_some_and(|text| !valid_version_identifiers(text, true)) {
            return contract();
        }
        let mut components = core.split('.');
        let core = [
            components
                .next()
                .ok_or(HostManifestRejection::ContractViolation)?,
            components
                .next()
                .ok_or(HostManifestRejection::ContractViolation)?,
            components
                .next()
                .ok_or(HostManifestRejection::ContractViolation)?,
        ];
        if components.next().is_some() || core.iter().any(|text| !valid_version_number(text)) {
            return contract();
        }
        Ok(Self { core, prerelease })
    }

    fn cmp_precedence(&self, other: &Self) -> Ordering {
        for index in 0..3 {
            let order = compare_version_number(self.core[index], other.core[index]);
            if order != Ordering::Equal {
                return order;
            }
        }
        let (left, right) = match (self.prerelease, other.prerelease) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Greater,
            (Some(_), None) => return Ordering::Less,
            (Some(left), Some(right)) => (left, right),
        };
        let mut left = left.split('.');
        let mut right = right.split('.');
        loop {
            let (left, right) = match (left.next(), right.next()) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some(left), Some(right)) => (left, right),
            };
            let order = match (version_digits(left), version_digits(right)) {
                (true, true) => compare_version_number(left, right),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => left.cmp(right),
            };
            if order != Ordering::Equal {
                return order;
            }
        }
    }
}

fn version_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_version_number(text: &str) -> bool {
    version_digits(text) && (text.len() == 1 || !text.starts_with('0'))
}

fn valid_version_identifiers(text: &str, prerelease: bool) -> bool {
    text.split('.').all(|identifier| {
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && (!prerelease || !version_digits(identifier) || valid_version_number(identifier))
    })
}

fn compare_version_number(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn parse_optional_version(
    value: Option<&Node>,
) -> Result<Option<HostVersion<'_>>, HostManifestRejection> {
    match value.map(|node| &node.kind) {
        Some(JsonKind::Null) => Ok(None),
        Some(JsonKind::String(version)) => HostVersion::parse(version).map(Some),
        _ => contract(),
    }
}

fn validate_launch(value: Option<&Node>) -> Result<(), HostManifestRejection> {
    let launch = expect_object(value.ok_or(HostManifestRejection::ContractViolation)?)?;
    check_closed(launch, &["executable", "argv"])?;
    let executable = expect_path(launch.get("executable"))?;
    let argv = expect_array_field(launch, "argv")?;
    for arg in argv {
        expect_string_no_line_breaks(Some(arg))?;
    }
    if executable.is_empty() {
        return contract();
    }
    Ok(())
}

fn validate_runtime_files(value: Option<&Node>) -> Result<(), HostManifestRejection> {
    for item in expect_array(value.ok_or(HostManifestRejection::ContractViolation)?)? {
        let entry = expect_object(item)?;
        check_closed(entry, &["path", "kind", "digest"])?;
        expect_path(entry.get("path"))?;
        match string(entry.get("kind"))? {
            "dependency" | "entrypoint" => {}
            _ => return contract(),
        }
        let digest = string(entry.get("digest"))?;
        if digest.len() != 71
            || !digest.starts_with("sha256:")
            || !digest[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return contract();
        }
    }
    Ok(())
}

fn validate_input_limits(value: Option<&Node>) -> Result<(), HostManifestRejection> {
    let limits = expect_object(value.ok_or(HostManifestRejection::ContractViolation)?)?;
    check_closed(limits, &["max_bytes"])?;
    expect_small_integer(limits.get("max_bytes"), 1, 1_048_576)?;
    Ok(())
}

fn validate_needs(value: Option<&Node>) -> Result<(), HostManifestRejection> {
    let needs = expect_object(value.ok_or(HostManifestRejection::ContractViolation)?)?;
    check_closed(needs, &["environment", "read_paths", "write_paths"])?;
    for item in expect_array_field(needs, "environment")? {
        expect_pattern_string(Some(item), valid_environment_name)?;
    }
    for field in ["read_paths", "write_paths"] {
        for item in expect_array_field(needs, field)? {
            string(Some(item))?;
        }
    }
    Ok(())
}

fn validate_string_enum_array(
    value: Option<&Node>,
    allowed: &[&str],
    empty_allowed: bool,
) -> Result<(), HostManifestRejection> {
    let values = expect_array(value.ok_or(HostManifestRejection::ContractViolation)?)?;
    if !empty_allowed && values.is_empty() {
        return contract();
    }
    let mut unique = BTreeSet::new();
    for item in values {
        let value = string(Some(item))?;
        if !allowed.contains(&value) || !unique.insert(value) {
            return contract();
        }
    }
    Ok(())
}

fn validate_pattern_array(
    value: Option<&Node>,
    valid: impl Fn(&str) -> bool,
) -> Result<(), HostManifestRejection> {
    let values = expect_array(value.ok_or(HostManifestRejection::ContractViolation)?)?;
    let mut unique = BTreeSet::new();
    for item in values {
        let value = string(Some(item))?;
        if !valid(value) || !unique.insert(value) {
            return contract();
        }
    }
    Ok(())
}

fn validate_schema(value: Option<&Node>) -> Result<(), HostManifestRejection> {
    let schema = value.ok_or(HostManifestRejection::ContractViolation)?;
    let object = expect_object(schema)?;
    if let Some(dialect) = object.get("$schema") {
        if string(Some(dialect))? != DRAFT_2020_12 {
            return contract();
        }
    }
    if string(object.get("type"))? != "object" {
        return contract();
    }
    validate_schema_node(schema, true)
}

fn validate_schema_node(schema: &Node, root: bool) -> Result<(), HostManifestRejection> {
    let object = expect_object(schema)?;
    const ALLOWED: &[&str] = &[
        "$schema",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
        "const",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "minProperties",
        "maxProperties",
        "title",
        "description",
    ];
    for key in object.keys() {
        if !ALLOWED.contains(&key.as_str()) || (key == "$schema" && !root) {
            return contract();
        }
    }
    let kind = string(object.get("type"))?;
    if !matches!(
        kind,
        "object" | "array" | "string" | "integer" | "number" | "boolean" | "null"
    ) {
        return contract();
    }
    if let Some(title) = object.get("title") {
        bounded_annotation(title)?;
    }
    if let Some(description) = object.get("description") {
        bounded_annotation(description)?;
    }

    if let Some(properties) = object.get("properties") {
        if kind != "object" {
            return contract();
        }
        for child in expect_object(properties)?.values() {
            validate_schema_node(child, false)?;
        }
    }
    if let Some(required) = object.get("required") {
        if kind != "object" {
            return contract();
        }
        let values = expect_array(required)?;
        let mut unique = BTreeSet::new();
        for item in values {
            if !unique.insert(string(Some(item))?) {
                return contract();
            }
        }
    }
    if kind == "object" {
        match &object
            .get("additionalProperties")
            .ok_or(HostManifestRejection::ContractViolation)?
            .kind
        {
            JsonKind::Bool(_) => {}
            JsonKind::Object(_) => {
                validate_schema_node(object.get("additionalProperties").expect("present"), false)?
            }
            _ => return contract(),
        }
    } else if object.contains_key("additionalProperties") {
        return contract();
    }

    if let Some(items) = object.get("items") {
        if kind != "array" {
            return contract();
        }
        validate_schema_node(items, false)?;
    }
    if kind != "array" && object.contains_key("items") {
        return contract();
    }

    if let Some(enumeration) = object.get("enum") {
        let values = expect_array(enumeration)?;
        if values.is_empty() || values.len() > 64 {
            return contract();
        }
        for (index, value) in values.iter().enumerate() {
            if !is_scalar(value)
                || values[..index]
                    .iter()
                    .any(|previous| scalar_equal(previous, value))
            {
                return contract();
            }
        }
    }
    if let Some(constant) = object.get("const") {
        if !is_scalar(constant) {
            return contract();
        }
    }

    let numeric_keys = ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"];
    if numeric_keys.iter().any(|key| object.contains_key(*key)) {
        if !matches!(kind, "integer" | "number") {
            return contract();
        }
        validate_numeric_interval(object, kind == "integer")?;
    }
    validate_cardinality_keywords(object, kind)?;
    Ok(())
}

fn validate_numeric_interval(
    object: &BTreeMap<String, Node>,
    integer: bool,
) -> Result<(), HostManifestRejection> {
    let lower_inclusive = number(object.get("minimum"))?;
    let lower_exclusive = number(object.get("exclusiveMinimum"))?;
    let upper_inclusive = number(object.get("maximum"))?;
    let upper_exclusive = number(object.get("exclusiveMaximum"))?;
    let lower = stricter_lower(lower_inclusive, lower_exclusive);
    let upper = stricter_upper(upper_inclusive, upper_exclusive);
    let (Some((lower, lower_strict)), Some((upper, upper_strict))) = (lower, upper) else {
        return Ok(());
    };
    match lower.cmp(upper) {
        Ordering::Greater => contract(),
        Ordering::Equal if lower_strict || upper_strict => contract(),
        Ordering::Equal if integer => {
            if !lower.is_integral() {
                contract()
            } else {
                Ok(())
            }
        }
        Ordering::Equal => Ok(()),
        Ordering::Less if !integer => Ok(()),
        Ordering::Less => {
            let mut least = ExactInteger::from_decimal_rounded(
                lower,
                if lower_strict {
                    IntegerRounding::Floor
                } else {
                    IntegerRounding::Ceil
                },
            );
            let mut greatest = ExactInteger::from_decimal_rounded(
                upper,
                if upper_strict {
                    IntegerRounding::Ceil
                } else {
                    IntegerRounding::Floor
                },
            );
            if lower_strict {
                least.add_one();
            }
            if upper_strict {
                greatest.subtract_one();
            }
            if least.cmp(&greatest) == Ordering::Greater {
                contract()
            } else {
                Ok(())
            }
        }
    }
}

fn stricter_lower<'a>(
    inclusive: Option<&'a ExactDecimal>,
    exclusive: Option<&'a ExactDecimal>,
) -> Option<(&'a ExactDecimal, bool)> {
    match (inclusive, exclusive) {
        (Some(i), Some(e)) => {
            if i.cmp(e) == Ordering::Greater {
                Some((i, false))
            } else {
                Some((e, true))
            }
        }
        (Some(i), None) => Some((i, false)),
        (None, Some(e)) => Some((e, true)),
        _ => None,
    }
}

fn stricter_upper<'a>(
    inclusive: Option<&'a ExactDecimal>,
    exclusive: Option<&'a ExactDecimal>,
) -> Option<(&'a ExactDecimal, bool)> {
    match (inclusive, exclusive) {
        (Some(i), Some(e)) => {
            if i.cmp(e) == Ordering::Less {
                Some((i, false))
            } else {
                Some((e, true))
            }
        }
        (Some(i), None) => Some((i, false)),
        (None, Some(e)) => Some((e, true)),
        _ => None,
    }
}

fn number(value: Option<&Node>) -> Result<Option<&ExactDecimal>, HostManifestRejection> {
    match value.map(|node| &node.kind) {
        None => Ok(None),
        Some(JsonKind::Number(value)) => Ok(Some(value)),
        _ => contract(),
    }
}

fn validate_cardinality_keywords(
    object: &BTreeMap<String, Node>,
    kind: &str,
) -> Result<(), HostManifestRejection> {
    for key in ["minLength", "maxLength"] {
        if object.contains_key(key) && kind != "string" {
            return contract();
        }
    }
    for key in ["minItems", "maxItems"] {
        if object.contains_key(key) && kind != "array" {
            return contract();
        }
    }
    for key in ["minProperties", "maxProperties"] {
        if object.contains_key(key) && kind != "object" {
            return contract();
        }
    }
    for key in [
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "minProperties",
        "maxProperties",
    ] {
        if let Some(value) = object.get(key) {
            let number = expect_number(value)?;
            if number.sign < 0 || !number.is_integral() {
                return contract();
            }
        }
    }
    for (minimum, maximum) in [
        ("minLength", "maxLength"),
        ("minItems", "maxItems"),
        ("minProperties", "maxProperties"),
    ] {
        if let (Some(min), Some(max)) = (object.get(minimum), object.get(maximum)) {
            let min = expect_number(min)?;
            let max = expect_number(max)?;
            if min.cmp(max) == Ordering::Greater {
                return contract();
            }
        }
    }
    Ok(())
}

fn bounded_annotation(node: &Node) -> Result<(), HostManifestRejection> {
    if string(Some(node))?.chars().count() > 1024 {
        return contract();
    }
    Ok(())
}

fn is_scalar(node: &Node) -> bool {
    !matches!(node.kind, JsonKind::Object(_) | JsonKind::Array(_))
}

fn scalar_equal(left: &Node, right: &Node) -> bool {
    match (&left.kind, &right.kind) {
        (JsonKind::Null, JsonKind::Null) => true,
        (JsonKind::Bool(a), JsonKind::Bool(b)) => a == b,
        (JsonKind::String(a), JsonKind::String(b)) => a == b,
        (JsonKind::Number(a), JsonKind::Number(b)) => a.cmp(b) == Ordering::Equal,
        _ => false,
    }
}

fn valid_identifier(value: &str, max: usize, digit_leading: bool) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max
        && (bytes[0].is_ascii_lowercase() || (digit_leading && bytes[0].is_ascii_digit()))
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

fn valid_capability(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
}

fn valid_environment_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && (bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

fn expect_path(value: Option<&Node>) -> Result<&str, HostManifestRejection> {
    let path = string(value)?;
    if path.starts_with('/') && !path.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n')) {
        Ok(path)
    } else {
        contract()
    }
}

fn expect_string_no_line_breaks(value: Option<&Node>) -> Result<&str, HostManifestRejection> {
    let text = string(value)?;
    if !text.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n')) {
        Ok(text)
    } else {
        contract()
    }
}

fn nonempty_string(value: Option<&Node>) -> Result<&str, HostManifestRejection> {
    let text = string(value)?;
    if text.is_empty() {
        contract()
    } else {
        Ok(text)
    }
}

fn expect_pattern_string(
    value: Option<&Node>,
    valid: impl Fn(&str) -> bool,
) -> Result<&str, HostManifestRejection> {
    let text = string(value)?;
    if valid(text) {
        Ok(text)
    } else {
        contract()
    }
}

fn expect_string_field(
    object: &BTreeMap<String, Node>,
    key: &str,
    expected: &str,
) -> Result<(), HostManifestRejection> {
    if string(object.get(key))? == expected {
        Ok(())
    } else {
        contract()
    }
}

fn expect_small_integer(
    value: Option<&Node>,
    min: i64,
    max: i64,
) -> Result<i64, HostManifestRejection> {
    let number = expect_number(value.ok_or(HostManifestRejection::ContractViolation)?)?;
    let min_dec = ExactDecimal::parse(&min.to_string())?;
    let max_dec = ExactDecimal::parse(&max.to_string())?;
    if !number.is_integral()
        || number.cmp(&min_dec) == Ordering::Less
        || number.cmp(&max_dec) == Ordering::Greater
    {
        return contract();
    }
    number
        .bounded_i64()
        .ok_or(HostManifestRejection::ContractViolation)
}

fn expect_array_field<'a>(
    object: &'a BTreeMap<String, Node>,
    key: &str,
) -> Result<&'a [Node], HostManifestRejection> {
    expect_array(
        object
            .get(key)
            .ok_or(HostManifestRejection::ContractViolation)?,
    )
}

fn expect_array(node: &Node) -> Result<&[Node], HostManifestRejection> {
    match &node.kind {
        JsonKind::Array(values) => Ok(values),
        _ => contract(),
    }
}

fn expect_object(node: &Node) -> Result<&BTreeMap<String, Node>, HostManifestRejection> {
    match &node.kind {
        JsonKind::Object(values) => Ok(values),
        _ => contract(),
    }
}

fn expect_number(node: &Node) -> Result<&ExactDecimal, HostManifestRejection> {
    match &node.kind {
        JsonKind::Number(value) => Ok(value),
        _ => contract(),
    }
}

fn string(node: Option<&Node>) -> Result<&str, HostManifestRejection> {
    match node.map(|node| &node.kind) {
        Some(JsonKind::String(value)) => Ok(value),
        _ => contract(),
    }
}

fn check_closed(
    object: &BTreeMap<String, Node>,
    allowed: &[&str],
) -> Result<(), HostManifestRejection> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        contract()
    } else {
        Ok(())
    }
}

fn contract<T>() -> Result<T, HostManifestRejection> {
    Err(HostManifestRejection::ContractViolation)
}

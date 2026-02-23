use std::collections::BTreeMap;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Client, Method};
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;
use url::Url;

const DEFAULT_BASE_URL: &str = "https://api.stripe.com/";

const PATH_PARAM_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

#[derive(Debug, Error)]
pub enum StripeError {
    #[error("missing required path parameter: {0}")]
    MissingPathParameter(String),

    #[error("invalid path template: {0}")]
    InvalidPathTemplate(String),

    #[error("form body must be a JSON object")]
    InvalidFormBodyRoot,

    #[error("API key must not be empty")]
    MissingApiKey,

    #[error("invalid base URL `{base_url}`: {source}")]
    InvalidBaseUrl {
        base_url: String,
        #[source]
        source: url::ParseError,
    },

    #[error(transparent)]
    Request(#[from] reqwest::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
}

#[derive(Debug, Clone)]
enum WireBody {
    Json(Value),
    Form(Vec<(String, String)>),
    Raw {
        content_type: String,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
struct RawApiResponse {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StripeClient {
    http: Client,
    api_key: String,
    base_url: Url,
}

impl StripeClient {
    pub fn new(api_key: impl Into<String>) -> Result<Self, StripeError> {
        Self::builder(api_key).build()
    }

    pub fn builder(api_key: impl Into<String>) -> StripeClientBuilder {
        StripeClientBuilder {
            api_key: api_key.into(),
            base_url: Url::parse(DEFAULT_BASE_URL).expect("default base URL must be valid"),
            http_client: None,
        }
    }

    fn prepare_json_like_body(
        &self,
        value: Value,
        content_type: Option<&str>,
    ) -> Result<WireBody, StripeError> {
        match content_type {
            Some(content_type)
                if content_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") =>
            {
                let fields = flatten_form_fields(&value)?;
                Ok(WireBody::Form(fields))
            }
            Some(content_type) if content_type.eq_ignore_ascii_case("application/json") => {
                Ok(WireBody::Json(value))
            }
            Some(content_type) => Ok(WireBody::Raw {
                content_type: content_type.to_string(),
                bytes: serde_json::to_vec(&value)?,
            }),
            None => Ok(WireBody::Json(value)),
        }
    }

    fn decode_json_body<T: DeserializeOwned>(&self, payload: &[u8]) -> Result<T, StripeError> {
        if payload.is_empty() {
            Ok(serde_json::from_str("null")?)
        } else {
            Ok(serde_json::from_slice(payload)?)
        }
    }

    async fn execute(
        &self,
        method: Method,
        path_template: &str,
        path_params: BTreeMap<String, String>,
        query_params: Vec<(String, String)>,
        headers: Vec<(String, String)>,
        body: Option<WireBody>,
    ) -> Result<RawApiResponse, StripeError> {
        let rendered_path = render_path(path_template, &path_params)?;
        let mut url = self.base_url.join(rendered_path.trim_start_matches('/'))?;

        if !query_params.is_empty() {
            let mut query = url.query_pairs_mut();
            for (key, value) in &query_params {
                query.append_pair(key, value);
            }
        }

        let mut builder = self.http.request(method, url).bearer_auth(&self.api_key);

        for (key, value) in &headers {
            builder = builder.header(key, value);
        }

        builder = match body {
            Some(WireBody::Json(value)) => builder.json(&value),
            Some(WireBody::Form(fields)) => builder.form(&fields),
            Some(WireBody::Raw {
                content_type,
                bytes,
            }) => builder
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(bytes),
            None => builder,
        };

        let response = builder.send().await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.bytes().await?.to_vec();

        Ok(RawApiResponse {
            status,
            headers,
            body,
        })
    }
}

#[derive(Debug)]
pub struct StripeClientBuilder {
    api_key: String,
    base_url: Url,
    http_client: Option<Client>,
}

impl StripeClientBuilder {
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, StripeError> {
        let value = base_url.as_ref();
        self.base_url = Url::parse(value).map_err(|source| StripeError::InvalidBaseUrl {
            base_url: value.to_string(),
            source,
        })?;
        Ok(self)
    }

    pub fn http_client(mut self, http_client: Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub fn build(self) -> Result<StripeClient, StripeError> {
        if self.api_key.trim().is_empty() {
            return Err(StripeError::MissingApiKey);
        }

        Ok(StripeClient {
            http: self.http_client.unwrap_or_default(),
            api_key: self.api_key,
            base_url: self.base_url,
        })
    }
}

fn flatten_form_fields(value: &Value) -> Result<Vec<(String, String)>, StripeError> {
    let Value::Object(map) = value else {
        return Err(StripeError::InvalidFormBodyRoot);
    };

    let mut fields = Vec::new();
    for (key, item) in map {
        flatten_form_value(key, item, &mut fields);
    }
    Ok(fields)
}

fn flatten_form_value(prefix: &str, value: &Value, fields: &mut Vec<(String, String)>) {
    match value {
        Value::Null => {}
        Value::Bool(boolean) => fields.push((
            prefix.to_string(),
            if *boolean { "true" } else { "false" }.to_string(),
        )),
        Value::Number(number) => fields.push((prefix.to_string(), number.to_string())),
        Value::String(string) => fields.push((prefix.to_string(), string.to_string())),
        Value::Array(array) => {
            for (index, item) in array.iter().enumerate() {
                let next = format!("{prefix}[{index}]");
                flatten_form_value(&next, item, fields);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let next = format!("{prefix}[{key}]");
                flatten_form_value(&next, item, fields);
            }
        }
    }
}

fn render_path(template: &str, params: &BTreeMap<String, String>) -> Result<String, StripeError> {
    let mut rendered = String::with_capacity(template.len());
    let mut cursor = 0;

    while let Some(start_rel) = template[cursor..].find('{') {
        let start = cursor + start_rel;
        rendered.push_str(&template[cursor..start]);

        let Some(end_rel) = template[start + 1..].find('}') else {
            return Err(StripeError::InvalidPathTemplate(template.to_string()));
        };
        let end = start + 1 + end_rel;

        let name = &template[start + 1..end];
        let value = params
            .get(name)
            .ok_or_else(|| StripeError::MissingPathParameter(name.to_string()))?;

        rendered.push_str(&utf8_percent_encode(value, PATH_PARAM_ENCODE_SET).to_string());
        cursor = end + 1;
    }

    rendered.push_str(&template[cursor..]);
    Ok(rendered)
}

#[allow(clippy::all, dead_code, unused_imports, unused_mut, unused_variables)]
mod generated {
    use super::*;
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

pub use generated::*;

pub mod webhook {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use hmac::{Hmac, Mac};
    use serde::de::DeserializeOwned;
    use sha2::Sha256;
    use thiserror::Error;

    use crate::Event;

    type HmacSha256 = Hmac<Sha256>;

    pub const DEFAULT_TOLERANCE: Duration = Duration::from_secs(300);

    #[derive(Debug, Error)]
    pub enum StripeWebhookError {
        #[error("webhook endpoint secret must not be empty")]
        MissingEndpointSecret,

        #[error("Stripe-Signature header must not be empty")]
        MissingSignatureHeader,

        #[error("Stripe-Signature header has an invalid component: `{0}`")]
        InvalidHeaderComponent(String),

        #[error("Stripe-Signature header is missing `t=` timestamp")]
        MissingTimestamp,

        #[error("Stripe-Signature timestamp is invalid")]
        InvalidTimestamp,

        #[error("Stripe-Signature header is missing `v1=` signatures")]
        MissingV1Signature,

        #[error("Stripe-Signature `v1` contains invalid hex")]
        InvalidV1Signature,

        #[error("webhook signature does not match")]
        SignatureMismatch,

        #[error("webhook timestamp is outside the tolerance window")]
        TimestampOutsideTolerance,

        #[error(transparent)]
        Json(#[from] serde_json::Error),

        #[error(transparent)]
        Time(#[from] std::time::SystemTimeError),
    }

    #[derive(Debug)]
    struct ParsedSignatureHeader {
        timestamp: i64,
        v1_signatures: Vec<Vec<u8>>,
    }

    pub fn verify_signature(
        payload: &[u8],
        signature_header: &str,
        endpoint_secret: &str,
    ) -> Result<(), StripeWebhookError> {
        verify_signature_with_tolerance(
            payload,
            signature_header,
            endpoint_secret,
            DEFAULT_TOLERANCE,
        )
    }

    pub fn verify_signature_with_tolerance(
        payload: &[u8],
        signature_header: &str,
        endpoint_secret: &str,
        tolerance: Duration,
    ) -> Result<(), StripeWebhookError> {
        verify_signature_inner(
            payload,
            signature_header,
            endpoint_secret,
            tolerance,
            SystemTime::now(),
        )
    }

    pub fn construct_event(
        payload: &[u8],
        signature_header: &str,
        endpoint_secret: &str,
    ) -> Result<Event, StripeWebhookError> {
        construct_event_as(payload, signature_header, endpoint_secret)
    }

    pub fn construct_event_with_tolerance(
        payload: &[u8],
        signature_header: &str,
        endpoint_secret: &str,
        tolerance: Duration,
    ) -> Result<Event, StripeWebhookError> {
        construct_event_as_with_tolerance(payload, signature_header, endpoint_secret, tolerance)
    }

    pub fn construct_event_as<T: DeserializeOwned>(
        payload: &[u8],
        signature_header: &str,
        endpoint_secret: &str,
    ) -> Result<T, StripeWebhookError> {
        construct_event_as_with_tolerance(
            payload,
            signature_header,
            endpoint_secret,
            DEFAULT_TOLERANCE,
        )
    }

    pub fn construct_event_as_with_tolerance<T: DeserializeOwned>(
        payload: &[u8],
        signature_header: &str,
        endpoint_secret: &str,
        tolerance: Duration,
    ) -> Result<T, StripeWebhookError> {
        verify_signature_with_tolerance(payload, signature_header, endpoint_secret, tolerance)?;
        Ok(serde_json::from_slice(payload)?)
    }

    fn verify_signature_inner(
        payload: &[u8],
        signature_header: &str,
        endpoint_secret: &str,
        tolerance: Duration,
        now: SystemTime,
    ) -> Result<(), StripeWebhookError> {
        if endpoint_secret.trim().is_empty() {
            return Err(StripeWebhookError::MissingEndpointSecret);
        }
        if signature_header.trim().is_empty() {
            return Err(StripeWebhookError::MissingSignatureHeader);
        }

        let parsed = parse_signature_header(signature_header)?;
        let now_seconds = unix_seconds(now)?;
        let tolerance_seconds = i64::try_from(tolerance.as_secs()).unwrap_or(i64::MAX);
        let earliest = now_seconds.saturating_sub(tolerance_seconds);
        let latest = now_seconds.saturating_add(tolerance_seconds);
        if parsed.timestamp < earliest || parsed.timestamp > latest {
            return Err(StripeWebhookError::TimestampOutsideTolerance);
        }

        let expected_signature = sign_payload(endpoint_secret, parsed.timestamp, payload);
        if parsed
            .v1_signatures
            .iter()
            .any(|candidate| constant_time_eq(candidate, &expected_signature))
        {
            Ok(())
        } else {
            Err(StripeWebhookError::SignatureMismatch)
        }
    }

    fn parse_signature_header(
        signature_header: &str,
    ) -> Result<ParsedSignatureHeader, StripeWebhookError> {
        let mut timestamp = None;
        let mut v1_signatures = Vec::new();

        for raw_component in signature_header.split(',') {
            let component = raw_component.trim();
            if component.is_empty() {
                continue;
            }

            let Some((key, value)) = component.split_once('=') else {
                return Err(StripeWebhookError::InvalidHeaderComponent(
                    component.to_string(),
                ));
            };
            let key = key.trim();
            let value = value.trim();

            match key {
                "t" => {
                    let parsed = value
                        .parse::<i64>()
                        .map_err(|_| StripeWebhookError::InvalidTimestamp)?;
                    timestamp = Some(parsed);
                }
                "v1" => v1_signatures.push(decode_hex(value)?),
                _ => {}
            }
        }

        let timestamp = timestamp.ok_or(StripeWebhookError::MissingTimestamp)?;
        if v1_signatures.is_empty() {
            return Err(StripeWebhookError::MissingV1Signature);
        }

        Ok(ParsedSignatureHeader {
            timestamp,
            v1_signatures,
        })
    }

    fn sign_payload(endpoint_secret: &str, timestamp: i64, payload: &[u8]) -> Vec<u8> {
        let mut signed_payload = timestamp.to_string().into_bytes();
        signed_payload.push(b'.');
        signed_payload.extend_from_slice(payload);

        let mut mac = HmacSha256::new_from_slice(endpoint_secret.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(&signed_payload);
        mac.finalize().into_bytes().to_vec()
    }

    fn decode_hex(value: &str) -> Result<Vec<u8>, StripeWebhookError> {
        if value.len() % 2 != 0 {
            return Err(StripeWebhookError::InvalidV1Signature);
        }

        let bytes = value.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut index = 0usize;
        while index < bytes.len() {
            let hi = hex_nibble(bytes[index]).ok_or(StripeWebhookError::InvalidV1Signature)?;
            let lo = hex_nibble(bytes[index + 1]).ok_or(StripeWebhookError::InvalidV1Signature)?;
            out.push((hi << 4) | lo);
            index += 2;
        }
        Ok(out)
    }

    fn hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }

        let mut diff = 0u8;
        for (a, b) in left.iter().zip(right.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    fn unix_seconds(now: SystemTime) -> Result<i64, StripeWebhookError> {
        let seconds = now.duration_since(UNIX_EPOCH)?.as_secs();
        Ok(i64::try_from(seconds).unwrap_or(i64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::{GENERATED_OPERATION_COUNT, render_path, webhook};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn generated_operations_cover_openapi_endpoints() {
        assert_eq!(GENERATED_OPERATION_COUNT, 617);
    }

    #[test]
    fn render_path_substitutes_and_encodes_values() {
        let mut params = BTreeMap::new();
        params.insert("customer".to_string(), "cus 123/abc".to_string());

        let rendered = render_path("/v1/customers/{customer}", &params).unwrap();
        assert_eq!(rendered, "/v1/customers/cus%20123%2Fabc");
    }

    #[test]
    fn webhook_helpers_verify_and_construct_event() {
        let payload = br#"{
  "id":"evt_test_123",
  "object":"event",
  "api_version":"2026-01-28.clover",
  "created":1700000000,
  "data":{"object":{"id":"ch_123","object":"charge"}},
  "livemode":false,
  "pending_webhooks":1,
  "request":{"id":"req_123","idempotency_key":"idem_123"},
  "type":"charge.succeeded"
}"#;
        let secret = "whsec_test_secret";
        let now = unix_time_now();
        let signature = make_test_signature_header(payload, secret, now);

        webhook::verify_signature(payload, &signature, secret).unwrap();
        let event = webhook::construct_event(payload, &signature, secret).unwrap();
        assert_eq!(event.id, "evt_test_123");
        assert_eq!(event.param_type, "charge.succeeded");
    }

    #[test]
    fn webhook_helpers_reject_invalid_signature() {
        let payload = br#"{"id":"evt_test_123"}"#;
        let now = unix_time_now();
        let signature = make_test_signature_header(payload, "whsec_actual", now);

        let error = webhook::verify_signature(payload, &signature, "whsec_wrong").unwrap_err();
        assert!(matches!(
            error,
            webhook::StripeWebhookError::SignatureMismatch
        ));
    }

    #[test]
    fn webhook_helpers_reject_old_timestamps() {
        let payload = br#"{"id":"evt_test_123"}"#;
        let secret = "whsec_test_secret";
        let old_timestamp = unix_time_now() - 3600;
        let signature = make_test_signature_header(payload, secret, old_timestamp);

        let error = webhook::construct_event_with_tolerance(
            payload,
            &signature,
            secret,
            Duration::from_secs(300),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            webhook::StripeWebhookError::TimestampOutsideTolerance
        ));
    }

    #[test]
    fn webhook_helpers_construct_typed_event() {
        let payload = br#"{"id":"evt_test_456"}"#;
        let secret = "whsec_test_secret";
        let signature = make_test_signature_header(payload, secret, unix_time_now());

        #[derive(Debug, serde::Deserialize)]
        struct MinimalEvent {
            id: String,
        }

        let event: MinimalEvent = webhook::construct_event_as(payload, &signature, secret).unwrap();
        assert_eq!(event.id, "evt_test_456");
    }

    fn unix_time_now() -> i64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after unix epoch")
            .as_secs();
        i64::try_from(now).expect("unix time must fit in i64")
    }

    fn make_test_signature_header(payload: &[u8], secret: &str, timestamp: i64) -> String {
        let mut signed_payload = timestamp.to_string().into_bytes();
        signed_payload.push(b'.');
        signed_payload.extend_from_slice(payload);

        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
        mac.update(&signed_payload);
        let signature = mac.finalize().into_bytes();

        let mut hex_signature = String::with_capacity(signature.len() * 2);
        for byte in signature {
            use std::fmt::Write;
            write!(&mut hex_signature, "{byte:02x}").unwrap();
        }

        format!("t={timestamp},v1={hex_signature}")
    }
}

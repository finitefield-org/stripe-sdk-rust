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

#[cfg(test)]
mod tests {
    use super::{GENERATED_OPERATION_COUNT, render_path};
    use std::collections::BTreeMap;

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
}

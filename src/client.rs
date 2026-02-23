use std::collections::BTreeMap;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::{Client, Method, RequestBuilder, Response};
use serde_json::Value;
use url::Url;

use crate::error::StripeError;
use crate::operations::{Operation, find_operation};
use crate::request::{CallRequest, RequestBody};

const DEFAULT_BASE_URL: &str = "https://api.stripe.com/";

// Encode path parameters safely while preserving common URL-safe characters.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthStrategy {
    #[default]
    Bearer,
    Basic,
}

pub struct StripeClient {
    http: Client,
    api_key: String,
    base_url: Url,
    auth_strategy: AuthStrategy,
}

impl std::fmt::Debug for StripeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StripeClient")
            .field("http", &self.http)
            .field("api_key", &"<redacted>")
            .field("base_url", &self.base_url)
            .field("auth_strategy", &self.auth_strategy)
            .finish()
    }
}

impl StripeClient {
    pub fn new(api_key: impl Into<String>) -> Result<Self, StripeError> {
        Self::builder(api_key).build()
    }

    pub fn builder(api_key: impl Into<String>) -> StripeClientBuilder {
        StripeClientBuilder {
            api_key: api_key.into(),
            base_url: Url::parse(DEFAULT_BASE_URL).expect("default base URL must be valid"),
            auth_strategy: AuthStrategy::default(),
            http_client: None,
        }
    }

    pub fn operation(&self, operation_id: &str) -> Result<&'static Operation, StripeError> {
        find_operation(operation_id)
            .ok_or_else(|| StripeError::UnknownOperation(operation_id.to_string()))
    }

    pub async fn call(
        &self,
        operation_id: &str,
        request: CallRequest,
    ) -> Result<Response, StripeError> {
        let operation = self.operation(operation_id)?;
        let method = Method::from_bytes(operation.method.as_bytes())
            .map_err(|_| StripeError::InvalidHttpMethod(operation.method.to_string()))?;

        self.send(
            method,
            operation.path,
            operation.request_content_type,
            request,
        )
        .await
    }

    pub async fn request(
        &self,
        method: Method,
        path: &str,
        request: CallRequest,
    ) -> Result<Response, StripeError> {
        self.send(method, path, None, request).await
    }

    async fn send(
        &self,
        method: Method,
        path_template: &str,
        default_content_type: Option<&str>,
        request: CallRequest,
    ) -> Result<Response, StripeError> {
        let path = render_path(path_template, &request.path_params)?;
        let mut url = self.base_url.join(path.trim_start_matches('/'))?;

        if !request.query_params.is_empty() {
            let mut query = url.query_pairs_mut();
            for (key, value) in &request.query_params {
                query.append_pair(key, value);
            }
        }

        let mut builder = self.http.request(method, url);
        builder = match self.auth_strategy {
            AuthStrategy::Bearer => builder.bearer_auth(&self.api_key),
            AuthStrategy::Basic => builder.basic_auth(&self.api_key, Some("")),
        };

        for (key, value) in &request.headers {
            builder = builder.header(key.as_str(), value.as_str());
        }

        builder = apply_body(builder, request.body, default_content_type)?;

        Ok(builder.send().await?)
    }
}

pub struct StripeClientBuilder {
    api_key: String,
    base_url: Url,
    auth_strategy: AuthStrategy,
    http_client: Option<Client>,
}

impl StripeClientBuilder {
    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Result<Self, StripeError> {
        let value = base_url.as_ref();
        let parsed = Url::parse(value).map_err(|source| StripeError::InvalidBaseUrl {
            base_url: value.to_string(),
            source,
        })?;

        self.base_url = parsed;
        Ok(self)
    }

    pub fn auth_strategy(mut self, auth_strategy: AuthStrategy) -> Self {
        self.auth_strategy = auth_strategy;
        self
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
            auth_strategy: self.auth_strategy,
        })
    }
}

fn apply_body(
    builder: RequestBuilder,
    body: Option<RequestBody>,
    default_content_type: Option<&str>,
) -> Result<RequestBuilder, StripeError> {
    let Some(body) = body else {
        return Ok(builder);
    };

    match body {
        RequestBody::Json(json) => Ok(builder.json(&json)),
        RequestBody::Form(form) => {
            let fields = flatten_form_fields(&form)?;
            Ok(builder.form(&fields))
        }
        RequestBody::Raw {
            content_type,
            bytes,
        } => Ok(builder
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(bytes)),
        RequestBody::Auto(value) => match default_content_type {
            Some(content_type)
                if content_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") =>
            {
                let fields = flatten_form_fields(&value)?;
                Ok(builder.form(&fields))
            }
            _ => Ok(builder.json(&value)),
        },
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

#[cfg(test)]
mod tests {
    use super::{flatten_form_fields, render_path};
    use std::collections::BTreeMap;

    use serde_json::json;

    #[test]
    fn render_path_substitutes_and_encodes_values() {
        let mut params = BTreeMap::new();
        params.insert("customer".to_string(), "cus 123/abc".to_string());

        let rendered = render_path("/v1/customers/{customer}", &params).unwrap();
        assert_eq!(rendered, "/v1/customers/cus%20123%2Fabc");
    }

    #[test]
    fn render_path_returns_error_for_missing_values() {
        let params = BTreeMap::new();
        let error = render_path("/v1/customers/{customer}", &params).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing required path parameter: customer")
        );
    }

    #[test]
    fn flatten_form_fields_handles_nested_values() {
        let value = json!({
            "name": "Acme",
            "metadata": {
                "env": "dev"
            },
            "items": [
                { "price": "price_123" },
                { "price": "price_456" }
            ]
        });

        let fields = flatten_form_fields(&value).unwrap();

        assert!(fields.contains(&("name".to_string(), "Acme".to_string())));
        assert!(fields.contains(&("metadata[env]".to_string(), "dev".to_string())));
        assert!(fields.contains(&("items[0][price]".to_string(), "price_123".to_string())));
        assert!(fields.contains(&("items[1][price]".to_string(), "price_456".to_string())));
    }
}

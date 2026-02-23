use std::collections::BTreeMap;

use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct CallRequest {
    pub path_params: BTreeMap<String, String>,
    pub query_params: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Option<RequestBody>,
}

impl CallRequest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn path_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.path_params.insert(key.into(), value.into());
        self
    }

    pub fn query_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_params.push((key.into(), value.into()));
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }

    pub fn auto_body(mut self, value: Value) -> Self {
        self.body = Some(RequestBody::Auto(value));
        self
    }

    pub fn json_body(mut self, value: Value) -> Self {
        self.body = Some(RequestBody::Json(value));
        self
    }

    pub fn form_body(mut self, value: Value) -> Self {
        self.body = Some(RequestBody::Form(value));
        self
    }

    pub fn raw_body(mut self, content_type: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        self.body = Some(RequestBody::Raw {
            content_type: content_type.into(),
            bytes: bytes.into(),
        });
        self
    }
}

#[derive(Debug, Clone)]
pub enum RequestBody {
    Auto(Value),
    Json(Value),
    Form(Value),
    Raw {
        content_type: String,
        bytes: Vec<u8>,
    },
}

use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamLocation {
    Path,
    Query,
    Header,
}

#[derive(Debug, Clone)]
struct ParamSpec {
    api_name: String,
    field_name: String,
    location: ParamLocation,
    rust_type: String,
    optional: bool,
    is_vec: bool,
}

#[derive(Debug, Clone)]
struct BodySpec {
    rust_type: String,
    content_type: Option<String>,
    optional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseDecodeKind {
    Json,
    Text,
    Bytes,
    Empty,
}

#[derive(Debug, Clone)]
struct ResponseSpec {
    response_struct: String,
    body_alias: String,
    body_rust_type: String,
    decode_kind: ResponseDecodeKind,
}

#[derive(Debug, Clone)]
struct OperationSpec {
    operation_id: String,
    method_name: String,
    http_method: String,
    path: String,
    request_struct: String,
    params: Vec<ParamSpec>,
    body: Option<BodySpec>,
    response: ResponseSpec,
}

#[derive(Default, Debug)]
struct ModelRegistry {
    definitions: BTreeMap<String, String>,
    generated: HashSet<String>,
    in_progress: HashSet<String>,
    used_type_names: HashSet<String>,
    ref_type_names: HashMap<String, String>,
}

impl ModelRegistry {
    fn unique_type_name(&mut self, base: &str) -> String {
        let sanitized = sanitize_type_name(base);
        if self.used_type_names.insert(sanitized.clone()) {
            return sanitized;
        }

        let mut index = 2usize;
        loop {
            let candidate = format!("{sanitized}{index}");
            if self.used_type_names.insert(candidate.clone()) {
                return candidate;
            }
            index += 1;
        }
    }
}

#[derive(Debug, Clone)]
struct ResponseSelection {
    content_type: Option<String>,
    schema: Option<Value>,
}

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let spec_path = manifest_dir.join("spec/openapi.spec3.json");
    let build_script_path = manifest_dir.join("build.rs");

    println!("cargo:rerun-if-changed={}", build_script_path.display());
    println!("cargo:rerun-if-changed={}", spec_path.display());

    let raw = fs::read_to_string(&spec_path).expect("failed to read spec/openapi.spec3.json");
    let root: Value = serde_json::from_str(&raw).expect("failed to parse openapi spec");

    let (operations, models) = collect_operations(&root);
    let generated = render_generated_code(&operations, &models);

    let out_path =
        PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR")).join("generated.rs");
    fs::write(out_path, generated).expect("failed to write generated code");
}

fn collect_operations(root: &Value) -> (Vec<OperationSpec>, ModelRegistry) {
    let mut operations = Vec::new();
    let mut models = ModelRegistry::default();

    let paths = root
        .get("paths")
        .and_then(Value::as_object)
        .expect("spec.paths must be an object");

    for (path, path_item_value) in paths {
        let Some(path_item) = path_item_value.as_object() else {
            continue;
        };

        let path_parameters = parse_parameters(root, path_item.get("parameters"));

        for (method, operation_value) in path_item {
            if !is_http_method(method) {
                continue;
            }

            let Some(operation) = operation_value.as_object() else {
                continue;
            };
            let Some(operation_id) = operation
                .get("operationId")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };

            let method_name = sanitize_method_name(&to_snake_case(&operation_id));
            let request_struct = format!("{}Request", sanitize_type_name(&operation_id));

            let operation_parameters = parse_parameters(root, operation.get("parameters"));
            let merged_parameters = merge_parameters(path_parameters.clone(), operation_parameters);

            let params = build_param_specs(root, &merged_parameters);
            let body = build_body_spec(root, operation.get("requestBody"));
            let response = build_response_spec(root, operation, &operation_id, &mut models);

            operations.push(OperationSpec {
                operation_id,
                method_name,
                http_method: method.to_ascii_uppercase(),
                path: path.to_string(),
                request_struct,
                params,
                body,
                response,
            });
        }
    }

    operations.sort_by(|a, b| a.operation_id.cmp(&b.operation_id));
    (operations, models)
}

fn render_generated_code(operations: &[OperationSpec], models: &ModelRegistry) -> String {
    let mut out = String::new();
    out.push_str("// This file is @generated by build.rs from spec/openapi.spec3.json.\n\n");
    out.push_str("pub const GENERATED_OPERATION_COUNT: usize = ");
    out.push_str(&operations.len().to_string());
    out.push_str(";\n\n");

    for definition in models.definitions.values() {
        out.push_str(definition);
        out.push('\n');
    }

    for operation in operations {
        render_request_struct(&mut out, operation);
        out.push('\n');
        render_response_struct(&mut out, operation);
        out.push('\n');
    }

    out.push_str("impl StripeClient {\n");
    for operation in operations {
        render_method(&mut out, operation);
    }
    out.push_str("}\n");

    out
}

fn render_request_struct(out: &mut String, operation: &OperationSpec) {
    out.push_str("#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\n");
    out.push_str(&format!("pub struct {} {{\n", operation.request_struct));

    for param in &operation.params {
        let ty = if param.optional {
            format!("Option<{}>", param.rust_type)
        } else {
            param.rust_type.clone()
        };
        out.push_str(&format!("    pub {}: {},\n", param.field_name, ty));
    }

    out.push_str("    #[serde(default, skip_serializing_if = \"Vec::is_empty\")]\n");
    out.push_str("    pub extra_headers: Vec<(String, String)>,\n");

    if supports_idempotency_key(operation) {
        out.push_str("    #[serde(skip_serializing_if = \"Option::is_none\")]\n");
        out.push_str("    pub idempotency_key: Option<String>,\n");
    }

    if let Some(body) = &operation.body {
        let ty = if body.optional {
            format!("Option<{}>", body.rust_type)
        } else {
            body.rust_type.clone()
        };
        out.push_str(&format!("    pub body: {},\n", ty));
    }

    out.push_str("}\n\n");

    let required_fields = operation
        .params
        .iter()
        .filter(|param| !param.optional)
        .collect::<Vec<_>>();
    let body_required = operation.body.as_ref().is_some_and(|body| !body.optional);

    out.push_str(&format!("impl {} {{\n", operation.request_struct));

    let mut constructor_params = Vec::new();
    for param in &required_fields {
        constructor_params.push(format!("{}: {}", param.field_name, param.rust_type));
    }
    if body_required {
        let body_ty = &operation.body.as_ref().expect("checked above").rust_type;
        constructor_params.push(format!("body: {}", body_ty));
    }

    if constructor_params.is_empty() {
        out.push_str("    pub fn new() -> Self {\n");
        out.push_str("        Self {\n");
        for param in &operation.params {
            if param.optional {
                out.push_str(&format!("            {}: None,\n", param.field_name));
            } else {
                out.push_str(&format!(
                    "            {}: Default::default(),\n",
                    param.field_name
                ));
            }
        }
        out.push_str("            extra_headers: Vec::new(),\n");
        if supports_idempotency_key(operation) {
            out.push_str("            idempotency_key: None,\n");
        }
        if let Some(body) = &operation.body {
            if body.optional {
                out.push_str("            body: None,\n");
            } else {
                out.push_str("            body: Default::default(),\n");
            }
        }
        out.push_str("        }\n");
        out.push_str("    }\n");
    } else {
        out.push_str(&format!(
            "    pub fn new({}) -> Self {{\n",
            constructor_params.join(", ")
        ));
        out.push_str("        Self {\n");
        for param in &operation.params {
            if param.optional {
                out.push_str(&format!("            {}: None,\n", param.field_name));
            } else {
                out.push_str(&format!("            {},\n", param.field_name));
            }
        }
        out.push_str("            extra_headers: Vec::new(),\n");
        if supports_idempotency_key(operation) {
            out.push_str("            idempotency_key: None,\n");
        }
        if let Some(body) = &operation.body {
            if body.optional {
                out.push_str("            body: None,\n");
            } else {
                out.push_str("            body,\n");
            }
        }
        out.push_str("        }\n");
        out.push_str("    }\n");
    }

    for param in operation.params.iter().filter(|param| param.optional) {
        out.push_str(&format!(
            "    pub fn with_{}(mut self, value: {}) -> Self {{\n",
            param.field_name, param.rust_type
        ));
        out.push_str(&format!(
            "        self.{} = Some(value);\n",
            param.field_name
        ));
        out.push_str("        self\n");
        out.push_str("    }\n");
    }

    out.push_str(
        "    pub fn with_header(\n        mut self,\n        key: impl Into<String>,\n        value: impl Into<String>,\n    ) -> Self {\n",
    );
    out.push_str("        self.extra_headers.push((key.into(), value.into()));\n");
    out.push_str("        self\n");
    out.push_str("    }\n");

    out.push_str("    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {\n");
    out.push_str("        self.extra_headers.extend(headers);\n");
    out.push_str("        self\n");
    out.push_str("    }\n");

    if supports_idempotency_key(operation) {
        out.push_str("    pub fn with_idempotency_key(mut self, value: String) -> Self {\n");
        out.push_str("        self.idempotency_key = Some(value);\n");
        out.push_str("        self\n");
        out.push_str("    }\n");
    }

    if let Some(body) = &operation.body
        && body.optional
    {
        out.push_str(&format!(
            "    pub fn with_body(mut self, value: {}) -> Self {{\n",
            body.rust_type
        ));
        out.push_str("        self.body = Some(value);\n");
        out.push_str("        self\n");
        out.push_str("    }\n");
    }

    out.push_str("}\n");
}

fn render_response_struct(out: &mut String, operation: &OperationSpec) {
    out.push_str(&format!(
        "pub type {} = {};\n\n",
        operation.response.body_alias, operation.response.body_rust_type
    ));
    out.push_str("#[derive(Debug, Clone)]\n");
    out.push_str(&format!(
        "pub struct {} {{\n",
        operation.response.response_struct
    ));
    out.push_str("    pub status: u16,\n");
    out.push_str("    pub headers: reqwest::header::HeaderMap,\n");
    out.push_str(&format!(
        "    pub body: {},\n",
        operation.response.body_alias
    ));
    out.push_str("}\n");
}

fn render_method(out: &mut String, operation: &OperationSpec) {
    out.push_str(&format!(
        "    pub async fn {}(&self, request: {}) -> Result<{}, StripeError> {{\n",
        operation.method_name, operation.request_struct, operation.response.response_struct
    ));

    out.push_str("        let mut path_params = std::collections::BTreeMap::new();\n");
    out.push_str("        let mut query_params = Vec::new();\n");
    out.push_str("        let mut headers = Vec::new();\n");
    out.push_str("        headers.extend(request.extra_headers);\n");

    if supports_idempotency_key(operation) {
        out.push_str("        if let Some(value) = request.idempotency_key {\n");
        out.push_str("            headers.retain(|(key, _)| !key.eq_ignore_ascii_case(\"Idempotency-Key\"));\n");
        out.push_str("            headers.push((\"Idempotency-Key\".to_string(), value));\n");
        out.push_str("        }\n");
    }

    for param in &operation.params {
        match (param.location, param.optional, param.is_vec) {
            (ParamLocation::Path, _, _) => {
                if param.optional {
                    out.push_str(&format!(
                        "        if let Some(value) = request.{} {{\n",
                        param.field_name
                    ));
                    out.push_str(&format!(
                        "            path_params.insert({:?}.to_string(), value.to_string());\n",
                        param.api_name
                    ));
                    out.push_str("        }\n");
                } else {
                    out.push_str(&format!(
                        "        path_params.insert({:?}.to_string(), request.{}.to_string());\n",
                        param.api_name, param.field_name
                    ));
                }
            }
            (ParamLocation::Query, true, true) => {
                out.push_str(&format!(
                    "        if let Some(values) = request.{} {{\n",
                    param.field_name
                ));
                out.push_str("            for value in values {\n");
                out.push_str(&format!(
                    "                query_params.push(({:?}.to_string(), value.to_string()));\n",
                    param.api_name
                ));
                out.push_str("            }\n");
                out.push_str("        }\n");
            }
            (ParamLocation::Query, true, false) => {
                out.push_str(&format!(
                    "        if let Some(value) = request.{} {{\n",
                    param.field_name
                ));
                out.push_str(&format!(
                    "            query_params.push(({:?}.to_string(), value.to_string()));\n",
                    param.api_name
                ));
                out.push_str("        }\n");
            }
            (ParamLocation::Query, false, true) => {
                out.push_str(&format!(
                    "        for value in request.{} {{\n",
                    param.field_name
                ));
                out.push_str(&format!(
                    "            query_params.push(({:?}.to_string(), value.to_string()));\n",
                    param.api_name
                ));
                out.push_str("        }\n");
            }
            (ParamLocation::Query, false, false) => {
                out.push_str(&format!(
                    "        query_params.push(({:?}.to_string(), request.{}.to_string()));\n",
                    param.api_name, param.field_name
                ));
            }
            (ParamLocation::Header, true, true) => {
                out.push_str(&format!(
                    "        if let Some(values) = request.{} {{\n",
                    param.field_name
                ));
                out.push_str("            for value in values {\n");
                out.push_str(&format!(
                    "                headers.push(({:?}.to_string(), value.to_string()));\n",
                    param.api_name
                ));
                out.push_str("            }\n");
                out.push_str("        }\n");
            }
            (ParamLocation::Header, true, false) => {
                out.push_str(&format!(
                    "        if let Some(value) = request.{} {{\n",
                    param.field_name
                ));
                out.push_str(&format!(
                    "            headers.push(({:?}.to_string(), value.to_string()));\n",
                    param.api_name
                ));
                out.push_str("        }\n");
            }
            (ParamLocation::Header, false, true) => {
                out.push_str(&format!(
                    "        for value in request.{} {{\n",
                    param.field_name
                ));
                out.push_str(&format!(
                    "            headers.push(({:?}.to_string(), value.to_string()));\n",
                    param.api_name
                ));
                out.push_str("        }\n");
            }
            (ParamLocation::Header, false, false) => {
                out.push_str(&format!(
                    "        headers.push(({:?}.to_string(), request.{}.to_string()));\n",
                    param.api_name, param.field_name
                ));
            }
        }
    }

    if let Some(body) = &operation.body {
        match (body.optional, body.rust_type.as_str()) {
            (true, "Vec<u8>") => {
                out.push_str("        let body = match request.body {\n");
                out.push_str("            Some(bytes) => Some(WireBody::Raw {\n");
                out.push_str(&format!(
                    "                content_type: {:?}.to_string(),\n",
                    body.content_type
                        .as_deref()
                        .unwrap_or("application/octet-stream")
                ));
                out.push_str("                bytes,\n");
                out.push_str("            }),\n");
                out.push_str("            None => None,\n");
                out.push_str("        };\n");
            }
            (false, "Vec<u8>") => {
                out.push_str("        let body = Some(WireBody::Raw {\n");
                out.push_str(&format!(
                    "            content_type: {:?}.to_string(),\n",
                    body.content_type
                        .as_deref()
                        .unwrap_or("application/octet-stream")
                ));
                out.push_str("            bytes: request.body,\n");
                out.push_str("        });\n");
            }
            (true, _) => {
                out.push_str("        let body = match request.body {\n");
                out.push_str("            Some(value) => Some(self.prepare_json_like_body(value, ");
                write_content_type_expr(out, body.content_type.as_deref());
                out.push_str(")?),\n");
                out.push_str("            None => None,\n");
                out.push_str("        };\n");
            }
            (false, _) => {
                out.push_str("        let body = Some(self.prepare_json_like_body(request.body, ");
                write_content_type_expr(out, body.content_type.as_deref());
                out.push_str(")?);\n");
            }
        }
    } else {
        out.push_str("        let body = None;\n");
    }

    out.push_str("\n        let raw = self.execute(\n");
    out.push_str(&format!(
        "            reqwest::Method::{},\n",
        operation.http_method
    ));
    out.push_str(&format!("            {:?},\n", operation.path));
    out.push_str("            path_params,\n");
    out.push_str("            query_params,\n");
    out.push_str("            headers,\n");
    out.push_str("            body,\n");
    out.push_str("        )\n");
    out.push_str("        .await?;\n\n");

    match operation.response.decode_kind {
        ResponseDecodeKind::Json => {
            out.push_str(&format!(
                "        let body: {} = self.decode_json_body(&raw.body)?;\n",
                operation.response.body_alias
            ));
        }
        ResponseDecodeKind::Text => {
            out.push_str(&format!(
                "        let body: {} = String::from_utf8(raw.body).map_err(StripeError::Utf8)?;\n",
                operation.response.body_alias
            ));
        }
        ResponseDecodeKind::Bytes => {
            out.push_str(&format!(
                "        let body: {} = raw.body;\n",
                operation.response.body_alias
            ));
        }
        ResponseDecodeKind::Empty => {
            out.push_str(&format!(
                "        let body: {} = ();\n",
                operation.response.body_alias
            ));
        }
    }

    out.push_str(&format!(
        "        Ok({} {{ status: raw.status, headers: raw.headers, body }})\n",
        operation.response.response_struct
    ));
    out.push_str("    }\n\n");
}

fn supports_idempotency_key(operation: &OperationSpec) -> bool {
    operation.http_method == "POST"
}

fn write_content_type_expr(out: &mut String, content_type: Option<&str>) {
    match content_type {
        Some(value) => out.push_str(&format!("Some({value:?})")),
        None => out.push_str("None"),
    }
}

fn build_param_specs(root: &Value, parameters: &[Value]) -> Vec<ParamSpec> {
    let mut used = HashSet::new();
    let mut specs = Vec::new();

    for parameter in parameters {
        let Some(parameter_obj) = parameter.as_object() else {
            continue;
        };

        let Some(location) = parameter_obj.get("in").and_then(Value::as_str) else {
            continue;
        };

        let location = match location {
            "path" => ParamLocation::Path,
            "query" => ParamLocation::Query,
            "header" => ParamLocation::Header,
            _ => continue,
        };

        let Some(api_name) = parameter_obj.get("name").and_then(Value::as_str) else {
            continue;
        };

        let required = parameter_obj
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || matches!(location, ParamLocation::Path);

        let schema = parameter_obj
            .get("schema")
            .and_then(|schema| resolve_ref(root, schema))
            .unwrap_or(Value::Null);

        let (mut rust_type, is_vec) = infer_param_rust_type(root, &schema);
        if matches!(location, ParamLocation::Path) {
            rust_type = "String".to_string();
        }

        let field_name = unique_field_name(&sanitize_field_name(api_name), &mut used);

        specs.push(ParamSpec {
            api_name: api_name.to_string(),
            field_name,
            location,
            rust_type,
            optional: !required,
            is_vec,
        });
    }

    specs
}

fn build_body_spec(root: &Value, request_body: Option<&Value>) -> Option<BodySpec> {
    let request_body = request_body.and_then(|value| resolve_ref(root, value))?;
    let request_body = request_body.as_object()?;

    let required = request_body
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let content = request_body.get("content")?.as_object()?;

    let preferred = [
        "application/x-www-form-urlencoded",
        "application/json",
        "application/octet-stream",
        "multipart/form-data",
    ]
    .iter()
    .find_map(|key| content.get(*key).map(|value| ((*key).to_string(), value)));

    let (content_type, media) = match preferred {
        Some((content_type, media)) => (Some(content_type), media.clone()),
        None => {
            let (content_type, media) = content.iter().next()?;
            (Some(content_type.to_string()), media.clone())
        }
    };

    let media = media.as_object();
    let schema = media
        .and_then(|media| media.get("schema"))
        .and_then(|schema| resolve_ref(root, schema))
        .unwrap_or(Value::Null);

    let rust_type = match content_type.as_deref() {
        Some("application/octet-stream") => "Vec<u8>".to_string(),
        _ => {
            let (ty, _) = infer_param_rust_type(root, &schema);
            if ty == "serde_json::Value" {
                "serde_json::Value".to_string()
            } else {
                "serde_json::Value".to_string()
            }
        }
    };

    Some(BodySpec {
        rust_type,
        content_type,
        optional: !required,
    })
}

fn build_response_spec(
    root: &Value,
    operation: &Map<String, Value>,
    operation_id: &str,
    models: &mut ModelRegistry,
) -> ResponseSpec {
    let base_name = sanitize_type_name(operation_id);
    let response_struct = format!("{base_name}Response");
    let body_alias = format!("{base_name}ResponseBody");

    let Some(selection) = select_success_response(root, operation) else {
        return ResponseSpec {
            response_struct,
            body_alias,
            body_rust_type: "()".to_string(),
            decode_kind: ResponseDecodeKind::Empty,
        };
    };

    match selection.content_type.as_deref() {
        None => ResponseSpec {
            response_struct,
            body_alias,
            body_rust_type: "()".to_string(),
            decode_kind: ResponseDecodeKind::Empty,
        },
        Some(content_type) if is_json_content_type(content_type) => {
            let body_rust_type = match selection.schema {
                Some(schema) => {
                    infer_response_type(root, &schema, &format!("{body_alias}Model"), models)
                }
                None => "serde_json::Value".to_string(),
            };

            ResponseSpec {
                response_struct,
                body_alias,
                body_rust_type,
                decode_kind: ResponseDecodeKind::Json,
            }
        }
        Some(content_type) if content_type.starts_with("text/") => ResponseSpec {
            response_struct,
            body_alias,
            body_rust_type: "String".to_string(),
            decode_kind: ResponseDecodeKind::Text,
        },
        Some(content_type) if is_binary_content_type(content_type) => ResponseSpec {
            response_struct,
            body_alias,
            body_rust_type: "Vec<u8>".to_string(),
            decode_kind: ResponseDecodeKind::Bytes,
        },
        Some(_) => {
            let body_rust_type = match selection.schema {
                Some(schema) => {
                    infer_response_type(root, &schema, &format!("{body_alias}Model"), models)
                }
                None => "Vec<u8>".to_string(),
            };

            let decode_kind = if body_rust_type == "Vec<u8>" {
                ResponseDecodeKind::Bytes
            } else {
                ResponseDecodeKind::Json
            };

            ResponseSpec {
                response_struct,
                body_alias,
                body_rust_type,
                decode_kind,
            }
        }
    }
}

fn select_success_response(
    root: &Value,
    operation: &Map<String, Value>,
) -> Option<ResponseSelection> {
    let responses = operation.get("responses")?.as_object()?;

    let mut ordered = Vec::new();
    for (status, response) in responses {
        if let Some(priority) = success_status_priority(status) {
            ordered.push((priority, response));
        }
    }
    ordered.sort_by_key(|(priority, _)| *priority);

    for (_, response_value) in ordered {
        if let Some(selection) = response_selection_from_response_value(root, response_value) {
            return Some(selection);
        }
    }

    responses
        .get("default")
        .and_then(|response_value| response_selection_from_response_value(root, response_value))
}

fn success_status_priority(status: &str) -> Option<u16> {
    if status == "2XX" {
        return Some(250);
    }

    if status.len() == 3 && status.starts_with('2') && status.chars().all(|c| c.is_ascii_digit()) {
        return status.parse::<u16>().ok();
    }

    None
}

fn response_selection_from_response_value(
    root: &Value,
    response_value: &Value,
) -> Option<ResponseSelection> {
    let response = resolve_ref(root, response_value)?;
    let response_obj = response.as_object()?;

    let content = response_obj.get("content").and_then(Value::as_object);
    let Some(content) = content else {
        return Some(ResponseSelection {
            content_type: None,
            schema: None,
        });
    };

    if content.is_empty() {
        return Some(ResponseSelection {
            content_type: None,
            schema: None,
        });
    }

    let (content_type, media) = pick_preferred_media(content)?;
    let schema = media
        .as_object()
        .and_then(|media_obj| media_obj.get("schema"))
        .and_then(|schema| resolve_ref(root, schema));

    Some(ResponseSelection {
        content_type: Some(content_type.to_string()),
        schema,
    })
}

fn pick_preferred_media<'a>(content: &'a Map<String, Value>) -> Option<(&'a str, &'a Value)> {
    for preferred in ["application/json", "text/plain", "application/octet-stream"] {
        if let Some(media) = content.get(preferred) {
            return Some((preferred, media));
        }
    }

    if let Some((content_type, media)) = content
        .iter()
        .find(|(content_type, _)| is_json_content_type(content_type))
    {
        return Some((content_type.as_str(), media));
    }

    content
        .iter()
        .next()
        .map(|(content_type, media)| (content_type.as_str(), media))
}

fn is_json_content_type(content_type: &str) -> bool {
    content_type.starts_with("application/json") || content_type.ends_with("+json")
}

fn is_binary_content_type(content_type: &str) -> bool {
    content_type == "application/octet-stream"
        || content_type == "application/pdf"
        || content_type.starts_with("image/")
        || content_type.starts_with("audio/")
        || content_type.starts_with("video/")
}

fn infer_response_type(
    root: &Value,
    schema: &Value,
    suggested_name: &str,
    models: &mut ModelRegistry,
) -> String {
    if schema.is_null() {
        return "serde_json::Value".to_string();
    }

    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return infer_ref_type(root, reference, models);
    }

    if schema.get("oneOf").is_some()
        || schema.get("anyOf").is_some()
        || schema.get("allOf").is_some()
    {
        return "serde_json::Value".to_string();
    }

    let Some(schema_obj) = schema.as_object() else {
        return "serde_json::Value".to_string();
    };

    if schema_obj.get("type").and_then(Value::as_str) == Some("string")
        && schema_obj
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty())
    {
        let type_name = models.unique_type_name(suggested_name);
        ensure_named_type(root, schema, &type_name, models);
        return type_name;
    }

    match schema_obj.get("type").and_then(Value::as_str) {
        Some("string") => "String".to_string(),
        Some("boolean") => "bool".to_string(),
        Some("integer") => "i64".to_string(),
        Some("number") => "f64".to_string(),
        Some("array") => {
            let item_schema = schema_obj.get("items").unwrap_or(&Value::Null);
            let item_type =
                infer_response_type(root, item_schema, &format!("{suggested_name}Item"), models);
            format!("Vec<{item_type}>")
        }
        Some("object") => {
            let type_name = models.unique_type_name(suggested_name);
            ensure_named_type(root, schema, &type_name, models);
            type_name
        }
        _ => "serde_json::Value".to_string(),
    }
}

fn infer_ref_type(root: &Value, reference: &str, models: &mut ModelRegistry) -> String {
    let Some(pointer) = reference.strip_prefix('#') else {
        return "serde_json::Value".to_string();
    };

    if !pointer.starts_with("/components/schemas/") {
        return "serde_json::Value".to_string();
    }

    let type_name = if let Some(existing) = models.ref_type_names.get(reference) {
        existing.clone()
    } else {
        let base = pointer
            .rsplit('/')
            .next()
            .map(sanitize_type_name)
            .unwrap_or_else(|| "Schema".to_string());
        let unique = models.unique_type_name(&base);
        models
            .ref_type_names
            .insert(reference.to_string(), unique.clone());
        unique
    };

    if models.in_progress.contains(&type_name) {
        return format!("Box<{type_name}>");
    }

    if !models.generated.contains(&type_name)
        && let Some(target) = root.pointer(pointer)
    {
        ensure_named_type(root, target, &type_name, models);
    }

    type_name
}

fn ensure_named_type(root: &Value, schema: &Value, type_name: &str, models: &mut ModelRegistry) {
    if models.generated.contains(type_name) {
        return;
    }
    if !models.in_progress.insert(type_name.to_string()) {
        return;
    }

    let definition = render_named_type_definition(root, schema, type_name, models);
    models.definitions.insert(type_name.to_string(), definition);
    models.generated.insert(type_name.to_string());
    models.in_progress.remove(type_name);
}

fn render_named_type_definition(
    root: &Value,
    schema: &Value,
    type_name: &str,
    models: &mut ModelRegistry,
) -> String {
    if schema.is_null() {
        return format!("pub type {type_name} = serde_json::Value;\n");
    }

    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let target = infer_ref_type(root, reference, models);
        return format!("pub type {type_name} = {target};\n");
    }

    if schema.get("oneOf").is_some()
        || schema.get("anyOf").is_some()
        || schema.get("allOf").is_some()
    {
        return format!("pub type {type_name} = serde_json::Value;\n");
    }

    let Some(schema_obj) = schema.as_object() else {
        return format!("pub type {type_name} = serde_json::Value;\n");
    };

    if schema_obj.get("type").and_then(Value::as_str) == Some("string")
        && let Some(enum_values) = schema_obj.get("enum").and_then(Value::as_array)
        && !enum_values.is_empty()
    {
        return render_string_enum_definition(type_name, enum_values);
    }

    match schema_obj.get("type").and_then(Value::as_str) {
        Some("object") => render_object_definition(root, schema_obj, type_name, models),
        Some("array") => {
            let item_schema = schema_obj.get("items").unwrap_or(&Value::Null);
            let item_type =
                infer_response_type(root, item_schema, &format!("{type_name}Item"), models);
            format!("pub type {type_name} = Vec<{item_type}>;\n")
        }
        Some("string") => format!("pub type {type_name} = String;\n"),
        Some("boolean") => format!("pub type {type_name} = bool;\n"),
        Some("integer") => format!("pub type {type_name} = i64;\n"),
        Some("number") => format!("pub type {type_name} = f64;\n"),
        _ => format!("pub type {type_name} = serde_json::Value;\n"),
    }
}

fn render_object_definition(
    root: &Value,
    schema_obj: &Map<String, Value>,
    type_name: &str,
    models: &mut ModelRegistry,
) -> String {
    let properties = schema_obj.get("properties").and_then(Value::as_object);
    let additional = schema_obj.get("additionalProperties");

    let Some(properties) = properties else {
        return render_additional_or_value_alias(root, additional, type_name, models);
    };

    if properties.is_empty() {
        return render_additional_or_value_alias(root, additional, type_name, models);
    }

    let required = schema_obj
        .get("required")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();

    let mut definition = String::new();
    definition.push_str("#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\n");
    definition.push_str(&format!("pub struct {type_name} {{\n"));

    let mut used_fields = HashSet::new();
    let mut sorted_properties = properties.iter().collect::<Vec<_>>();
    sorted_properties.sort_by(|a, b| a.0.cmp(b.0));

    for (property_name, property_schema_value) in sorted_properties {
        let property_schema = resolve_ref(root, property_schema_value).unwrap_or(Value::Null);
        let mut field_type = infer_response_type(
            root,
            &property_schema,
            &format!("{type_name}{}", sanitize_type_name(property_name)),
            models,
        );

        let nullable = property_schema
            .get("nullable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let required_field = required.contains(property_name);
        let optional = !required_field || nullable;
        if optional {
            field_type = wrap_option(field_type);
        }

        let field_name = unique_field_name(&sanitize_field_name(property_name), &mut used_fields);

        if field_name != *property_name {
            definition.push_str(&format!("    #[serde(rename = {:?})]\n", property_name));
        }
        if optional {
            definition.push_str("    #[serde(skip_serializing_if = \"Option::is_none\")]\n");
        }
        definition.push_str(&format!("    pub {field_name}: {field_type},\n"));
    }

    if let Some(additional_value) = additional {
        let additional_type = if additional_value.as_bool() == Some(true) {
            Some("serde_json::Value".to_string())
        } else if additional_value.as_bool() == Some(false) {
            None
        } else {
            let schema = resolve_ref(root, additional_value).unwrap_or(Value::Null);
            Some(infer_response_type(
                root,
                &schema,
                &format!("{type_name}AdditionalProperty"),
                models,
            ))
        };

        if let Some(additional_type) = additional_type {
            definition.push_str("    #[serde(flatten)]\n");
            definition.push_str(&format!(
                "    pub additional_properties: std::collections::BTreeMap<String, {additional_type}>,\n"
            ));
        }
    }

    definition.push_str("}\n");
    definition
}

fn render_additional_or_value_alias(
    root: &Value,
    additional: Option<&Value>,
    type_name: &str,
    models: &mut ModelRegistry,
) -> String {
    let Some(additional) = additional else {
        return format!("pub type {type_name} = serde_json::Value;\n");
    };

    if additional.as_bool() == Some(false) {
        return format!("pub type {type_name} = serde_json::Value;\n");
    }

    let value_type = if additional.as_bool() == Some(true) {
        "serde_json::Value".to_string()
    } else {
        let schema = resolve_ref(root, additional).unwrap_or(Value::Null);
        infer_response_type(
            root,
            &schema,
            &format!("{type_name}AdditionalProperty"),
            models,
        )
    };

    format!("pub type {type_name} = std::collections::BTreeMap<String, {value_type}>;\n")
}

fn render_string_enum_definition(type_name: &str, values: &[Value]) -> String {
    let mut definition = String::new();
    definition.push_str("#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\n");
    definition.push_str(&format!("pub enum {type_name} {{\n"));

    let mut used_variants = HashSet::new();
    for value in values {
        let Some(raw) = value.as_str() else {
            continue;
        };

        let base_variant = sanitize_enum_variant_name(&to_pascal_identifier(raw));
        let mut variant = base_variant.clone();
        let mut suffix = 2usize;
        while !used_variants.insert(variant.clone()) {
            variant = format!("{base_variant}{suffix}");
            suffix += 1;
        }

        definition.push_str(&format!("    #[serde(rename = {:?})]\n", raw));
        definition.push_str(&format!("    {variant},\n"));
    }

    if used_variants.is_empty() {
        definition.push_str("    Value,\n");
    }

    definition.push_str("}\n");
    definition
}

fn to_pascal_identifier(input: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            if capitalize {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch.to_ascii_lowercase());
            }
            capitalize = false;
        } else {
            capitalize = true;
        }
    }

    if out.is_empty() {
        out = "Value".to_string();
    }
    if out
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit())
    {
        out.insert(0, 'V');
    }

    out
}

fn sanitize_enum_variant_name(name: &str) -> String {
    let mut value = if name.is_empty() {
        "Value".to_string()
    } else {
        name.to_string()
    };

    if is_rust_keyword(&value) {
        value.push_str("Value");
    }

    value
}

fn wrap_option(ty: String) -> String {
    if ty.starts_with("Option<") {
        ty
    } else {
        format!("Option<{ty}>")
    }
}

fn merge_parameters(path_parameters: Vec<Value>, operation_parameters: Vec<Value>) -> Vec<Value> {
    let mut merged: Vec<Value> = Vec::new();
    let mut index_by_key: HashMap<(String, String), usize> = HashMap::new();

    for parameter in path_parameters.into_iter().chain(operation_parameters) {
        let Some(obj) = parameter.as_object() else {
            continue;
        };
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(location) = obj.get("in").and_then(Value::as_str) else {
            continue;
        };

        let key = (location.to_string(), name.to_string());
        if let Some(index) = index_by_key.get(&key).copied() {
            merged[index] = parameter;
        } else {
            index_by_key.insert(key, merged.len());
            merged.push(parameter);
        }
    }

    merged
}

fn parse_parameters(root: &Value, value: Option<&Value>) -> Vec<Value> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    array
        .iter()
        .filter_map(|parameter| resolve_ref(root, parameter))
        .collect()
}

fn resolve_ref(root: &Value, value: &Value) -> Option<Value> {
    if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        let pointer = reference.strip_prefix('#')?;
        return root.pointer(pointer).cloned();
    }

    Some(value.clone())
}

fn infer_param_rust_type(root: &Value, schema: &Value) -> (String, bool) {
    if schema.is_null() {
        return ("serde_json::Value".to_string(), false);
    }

    if let Some(reference) = schema.get("$ref").and_then(Value::as_str)
        && let Some(pointer) = reference.strip_prefix('#')
        && let Some(target) = root.pointer(pointer)
    {
        return infer_param_rust_type(root, target);
    }

    if schema.get("oneOf").is_some()
        || schema.get("anyOf").is_some()
        || schema.get("allOf").is_some()
    {
        return ("serde_json::Value".to_string(), false);
    }

    let Some(schema_obj) = schema.as_object() else {
        return ("serde_json::Value".to_string(), false);
    };

    let Some(type_name) = schema_obj.get("type").and_then(Value::as_str) else {
        return ("serde_json::Value".to_string(), false);
    };

    match type_name {
        "string" => ("String".to_string(), false),
        "boolean" => ("bool".to_string(), false),
        "integer" => ("i64".to_string(), false),
        "number" => ("f64".to_string(), false),
        "array" => {
            let item_schema = schema_obj.get("items").unwrap_or(&Value::Null);
            let (item_type, _) = infer_param_rust_type(root, item_schema);
            (format!("Vec<{item_type}>"), true)
        }
        "object" => ("serde_json::Value".to_string(), false),
        _ => ("serde_json::Value".to_string(), false),
    }
}

fn sanitize_field_name(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }

    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        return "param".to_string();
    }

    let mut out = out;
    if out
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit())
    {
        out.insert_str(0, "p_");
    }

    if is_rust_keyword(&out) {
        out.insert_str(0, "param_");
    }

    out
}

fn unique_field_name(base: &str, used: &mut HashSet<String>) -> String {
    if used.insert(base.to_string()) {
        return base.to_string();
    }

    let mut index = 2usize;
    loop {
        let candidate = format!("{base}_{index}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        index += 1;
    }
}

fn sanitize_method_name(name: &str) -> String {
    let mut value = name.to_string();
    if value.is_empty() {
        value = "call_operation".to_string();
    }
    if value
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit())
    {
        value.insert_str(0, "op_");
    }
    if is_rust_keyword(&value) {
        value.insert_str(0, "op_");
    }
    value
}

fn sanitize_type_name(name: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;

    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if capitalize {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
            capitalize = false;
        } else {
            capitalize = true;
        }
    }

    if out.is_empty() {
        out = "Type".to_string();
    }

    if out
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit())
    {
        out.insert(0, 'T');
    }

    if is_rust_keyword(&out) {
        out.push_str("Type");
    }

    out
}

fn to_snake_case(name: &str) -> String {
    let mut out = String::new();
    let mut prev_is_lower_or_digit = false;

    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() {
                if prev_is_lower_or_digit && !out.ends_with('_') {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
                prev_is_lower_or_digit = false;
            } else {
                out.push(ch.to_ascii_lowercase());
                prev_is_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
            }
        } else if !out.ends_with('_') {
            out.push('_');
            prev_is_lower_or_digit = false;
        }
    }

    out.trim_matches('_').to_string()
}

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace"
    )
}

fn is_rust_keyword(value: &str) -> bool {
    matches!(
        value,
        "as" | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "Self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
    )
}

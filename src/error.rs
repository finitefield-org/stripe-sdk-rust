use thiserror::Error;

#[derive(Debug, Error)]
pub enum StripeError {
    #[error("unknown operation id: {0}")]
    UnknownOperation(String),

    #[error("invalid HTTP method in operation definition: {0}")]
    InvalidHttpMethod(String),

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
}

# stripe-sdk

This repository provides an SDK written in Rust to help you interact with the Stripe API.

Developed by [Finite Field, K.K.](https://finitefield.org)

Japanese: [translations/ja/README.md](translations/ja/README.md)

## Implementation Approach

- `build.rs` reads `spec/openapi.spec3.json` and automatically generates dedicated methods for each `operationId`.
- Requests are handled with operation-specific `*Request` types.
- Responses are returned as operation-specific `*Response` types, and `body` is also an operation-specific type (`*ResponseBody`).

## Usage

```rust
use serde_json::json;
use stripe_sdk::{
    GetCustomersRequest, PostCheckoutSessionsRequest, PostCustomersRequest, StripeClient,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = StripeClient::new("sk_test_xxx")?;

    let list = client
        .get_customers(GetCustomersRequest::new().with_limit(3))
        .await?;
    println!("list status = {}", list.status);

    let created = client
        .post_customers(
            PostCustomersRequest::new().with_body(json!({
                "name": "Acme Inc.",
                "email": "dev@example.com"
            })),
        )
        .await?;
    println!("create status = {}", created.status);

    let checkout = client
        .post_checkout_sessions(
            PostCheckoutSessionsRequest::new()
                .with_header("Idempotency-Key", "checkout_session_order_123")
                .with_body(json!({
                    "mode": "payment",
                    "success_url": "https://example.com/success",
                    "cancel_url": "https://example.com/cancel",
                    "line_items": [{
                        "price": "price_123",
                        "quantity": 1
                    }]
                })),
        )
        .await?;
    println!("checkout status = {}", checkout.status);

    Ok(())
}
```

## Webhook Helpers

```rust
use stripe_sdk::webhook;

fn handle_webhook(raw_body: &[u8], stripe_signature: &str) -> Result<(), webhook::StripeWebhookError> {
    let endpoint_secret = "whsec_xxx";

    let event = webhook::construct_event(raw_body, stripe_signature, endpoint_secret)?;
    println!("event type = {}", event.param_type);

    Ok(())
}
```

- Verify only: `webhook::verify_signature(...)`
- Parse to custom type: `webhook::construct_event_as::<T>(...)`

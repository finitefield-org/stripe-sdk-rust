# stripe-sdk

このレポジトリは、Stripe API を操作するのに役立つ Rust 製 SDK を提供します。

## 実装方針

- `spec/openapi.spec3.json` を `build.rs` が読み取り、全 `operationId` の定義をコンパイル時に自動生成します。
- `StripeClient::call("<operationId>", ...)` で、OpenAPI に沿った HTTP メソッド/パスを使って呼び出せます。
- v1 の `application/x-www-form-urlencoded` と v2 の `application/json` を `RequestBody::Auto` で自動選択します。

## 使い方

```rust
use serde_json::json;
use stripe_sdk::{CallRequest, StripeClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = StripeClient::new("sk_test_xxx")?;

    // GET /v1/customers
    let response = client
        .call("GetCustomers", CallRequest::new().query_param("limit", "3"))
        .await?;

    println!("status = {}", response.status());

    // POST /v1/customers
    let _created = client
        .call(
            "PostCustomers",
            CallRequest::new().auto_body(json!({
                "name": "Acme Inc.",
                "email": "dev@example.com"
            })),
        )
        .await?;

    Ok(())
}
```

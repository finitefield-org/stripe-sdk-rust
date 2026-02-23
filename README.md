# stripe-sdk

このレポジトリは、Stripe API を操作するのに役立つ Rust 製 SDK を提供します。

Developed by [Finite Field, K.K.](https://finitefield.org)

## 実装方針

- `spec/openapi.spec3.json` を `build.rs` が読み取り、各 `operationId` ごとの専用メソッドを自動生成します。
- リクエストは operation ごとの専用 `*Request` 型で扱います。
- レスポンスは operation ごとの専用 `*Response` 型で返し、`body` も operation ごとに専用型（`*ResponseBody`）になります。

## 使い方

```rust
use serde_json::json;
use stripe_sdk::{GetCustomersRequest, PostCustomersRequest, StripeClient};

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

    Ok(())
}
```

use axum::{body::Body, extract::MatchedPath, http::Request, middleware::Next, response::Response};

pub(crate) fn http_request_span<B>(level: tracing::Level, request: &Request<B>) -> tracing::Span {
    let route = http_route(request);
    macro_rules! make_span {
        ($level:expr) => {
            tracing::span!(
                $level,
                "request",
                method = %request.method(),
                route = %route,
                version = ?request.version(),
            )
        };
    }
    match level {
        tracing::Level::ERROR => make_span!(tracing::Level::ERROR),
        tracing::Level::WARN => make_span!(tracing::Level::WARN),
        tracing::Level::INFO => make_span!(tracing::Level::INFO),
        tracing::Level::DEBUG => make_span!(tracing::Level::DEBUG),
        tracing::Level::TRACE => make_span!(tracing::Level::TRACE),
    }
}

fn http_route<B>(request: &Request<B>) -> &str {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("<unmatched>")
}

pub(crate) async fn sanitize_request_id(mut request: Request<Body>, next: Next) -> Response {
    let valid = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .is_some_and(is_canonical_request_id);
    if !valid {
        request.headers_mut().remove("x-request-id");
    }
    next.run(request).await
}

fn is_canonical_request_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_canonical_uuid_request_ids_are_trusted() {
        assert!(is_canonical_request_id(
            "01234567-89ab-4def-8123-456789abcdef"
        ));
        for invalid in [
            "",
            "request-from-proxy",
            "0123456789ab4def8123456789abcdef",
            "01234567-89AB-4DEF-8123-456789ABCDEF",
            " 01234567-89ab-4def-8123-456789abcdef",
        ] {
            assert!(!is_canonical_request_id(invalid), "{invalid}");
        }
    }

    #[test]
    fn unmatched_trace_route_never_falls_back_to_sensitive_uri() {
        let request = Request::builder()
            .uri("/oauth/authorize?state=secret&code_challenge=private")
            .body(())
            .expect("request");
        let route = http_route(&request);
        assert_eq!(route, "<unmatched>");
        assert!(!route.contains("secret"));
        assert!(!route.contains("private"));
    }

    #[tokio::test]
    async fn trace_route_uses_template_instead_of_values_or_query() {
        async fn assert_safe_route(request: Request<Body>, next: Next) -> Response {
            let route = http_route(&request);
            assert_eq!(route, "/items/{item_id}");
            assert!(!route.contains("customer-secret"));
            assert!(!route.contains("oauth-state"));
            next.run(request).await
        }

        use axum::{Router, routing::get};
        use tower::ServiceExt;

        let app = Router::new()
            .route("/items/{item_id}", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(assert_safe_route));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/items/customer-secret?state=oauth-state")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert!(response.status().is_success());
    }
}

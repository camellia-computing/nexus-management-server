use axum::{body::Body, http::Request, middleware::Next, response::Response};

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
}

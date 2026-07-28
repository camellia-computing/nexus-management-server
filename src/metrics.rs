use std::{
    env,
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode, header},
    middleware::Next,
    response::IntoResponse,
    routing::get,
};
use tokio::sync::watch;

use crate::config::Environment;

const STATUS_CLASSES: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];
const BACKGROUND_OUTCOMES: [&str; 3] = ["success", "idle", "error"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeRole {
    Public,
    AdminWeb,
    AdminWorker,
}

impl RuntimeRole {
    const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::AdminWeb => "admin_web",
            Self::AdminWorker => "admin_worker",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundOutcome {
    Success,
    Idle,
    Error,
}

impl BackgroundOutcome {
    const fn index(self) -> usize {
        match self {
            Self::Success => 0,
            Self::Idle => 1,
            Self::Error => 2,
        }
    }
}

struct MetricsInner {
    role: RuntimeRole,
    started_at: Instant,
    http_in_flight: AtomicI64,
    http_requests: [AtomicU64; STATUS_CLASSES.len()],
    http_duration_micros: AtomicU64,
    readiness: [AtomicU64; 2],
    background_iterations: [AtomicU64; BACKGROUND_OUTCOMES.len()],
}

#[derive(Clone)]
pub struct RuntimeMetrics {
    inner: Arc<MetricsInner>,
}

impl RuntimeMetrics {
    pub fn new(role: RuntimeRole) -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                role,
                started_at: Instant::now(),
                http_in_flight: AtomicI64::new(0),
                http_requests: std::array::from_fn(|_| AtomicU64::new(0)),
                http_duration_micros: AtomicU64::new(0),
                readiness: std::array::from_fn(|_| AtomicU64::new(0)),
                background_iterations: std::array::from_fn(|_| AtomicU64::new(0)),
            }),
        }
    }

    pub fn record_readiness(&self, ready: bool) {
        self.inner.readiness[usize::from(!ready)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_background_iteration(&self, outcome: BackgroundOutcome) {
        self.inner.background_iterations[outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    fn track_request(&self) -> InFlightRequest {
        self.inner.http_in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightRequest {
            metrics: self.clone(),
            started_at: Instant::now(),
            finished: false,
        }
    }

    fn request_finished(&self, status_class: usize, elapsed: Duration) {
        self.inner.http_in_flight.fetch_sub(1, Ordering::Relaxed);
        self.inner.http_requests[status_class].fetch_add(1, Ordering::Relaxed);
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let _ = self.inner.http_duration_micros.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_add(micros)),
        );
    }

    pub fn render(&self) -> String {
        let role = self.inner.role.label();
        let mut output = String::with_capacity(2_048);
        writeln!(
            output,
            "# HELP camellia-nexus_process_uptime_seconds Process uptime in seconds."
        )
        .unwrap();
        writeln!(output, "# TYPE camellia-nexus_process_uptime_seconds gauge").unwrap();
        writeln!(
            output,
            "camellia-nexus_process_uptime_seconds{{role=\"{role}\"}} {}",
            self.inner.started_at.elapsed().as_secs()
        )
        .unwrap();
        writeln!(
            output,
            "# HELP camellia-nexus_http_requests_total Completed HTTP requests by status class."
        )
        .unwrap();
        writeln!(output, "# TYPE camellia-nexus_http_requests_total counter").unwrap();
        for (index, status_class) in STATUS_CLASSES.iter().enumerate() {
            writeln!(
                output,
                "camellia-nexus_http_requests_total{{role=\"{role}\",status_class=\"{status_class}\"}} {}",
                self.inner.http_requests[index].load(Ordering::Relaxed)
            )
            .unwrap();
        }
        writeln!(
            output,
            "# HELP camellia-nexus_http_in_flight_requests Current HTTP requests being processed."
        )
        .unwrap();
        writeln!(
            output,
            "# TYPE camellia-nexus_http_in_flight_requests gauge"
        )
        .unwrap();
        writeln!(
            output,
            "camellia-nexus_http_in_flight_requests{{role=\"{role}\"}} {}",
            self.inner.http_in_flight.load(Ordering::Relaxed)
        )
        .unwrap();
        writeln!(output, "# HELP camellia-nexus_http_request_duration_seconds_sum Total HTTP request duration in seconds.").unwrap();
        writeln!(
            output,
            "# TYPE camellia-nexus_http_request_duration_seconds_sum counter"
        )
        .unwrap();
        writeln!(
            output,
            "camellia-nexus_http_request_duration_seconds_sum{{role=\"{role}\"}} {:.6}",
            self.inner.http_duration_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
        )
        .unwrap();
        writeln!(
            output,
            "# HELP camellia-nexus_readiness_checks_total Readiness checks by outcome."
        )
        .unwrap();
        writeln!(
            output,
            "# TYPE camellia-nexus_readiness_checks_total counter"
        )
        .unwrap();
        for (index, outcome) in ["ready", "error"].iter().enumerate() {
            writeln!(
                output,
                "camellia-nexus_readiness_checks_total{{role=\"{role}\",outcome=\"{outcome}\"}} {}",
                self.inner.readiness[index].load(Ordering::Relaxed)
            )
            .unwrap();
        }
        writeln!(
            output,
            "# HELP camellia-nexus_background_iterations_total Background iterations by outcome."
        )
        .unwrap();
        writeln!(
            output,
            "# TYPE camellia-nexus_background_iterations_total counter"
        )
        .unwrap();
        for (index, outcome) in BACKGROUND_OUTCOMES.iter().enumerate() {
            writeln!(
                output,
                "camellia-nexus_background_iterations_total{{role=\"{role}\",outcome=\"{outcome}\"}} {}",
                self.inner.background_iterations[index].load(Ordering::Relaxed)
            )
            .unwrap();
        }
        output
    }
}

struct InFlightRequest {
    metrics: RuntimeMetrics,
    started_at: Instant,
    finished: bool,
}

impl InFlightRequest {
    fn finish(mut self, status: StatusCode) {
        self.metrics
            .request_finished(status_class(status), self.started_at.elapsed());
        self.finished = true;
    }
}

impl Drop for InFlightRequest {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics
                .request_finished(STATUS_CLASSES.len() - 1, self.started_at.elapsed());
        }
    }
}

pub struct MetricsServer {
    listener: tokio::net::TcpListener,
    metrics: RuntimeMetrics,
}

impl MetricsServer {
    pub async fn from_env(
        environment: Environment,
        role: RuntimeRole,
        metrics: RuntimeMetrics,
    ) -> Result<Option<Self>, String> {
        let Some(bind) = metrics_bind_from_env(environment)? else {
            return Ok(None);
        };
        let listener = tokio::net::TcpListener::bind(bind).await.map_err(|error| {
            format!("could not bind CAMELLIA_NEXUS_METRICS_BIND {bind}: {error}")
        })?;
        tracing::info!(bind = %bind, role = role.label(), "Camellia Nexus metrics listener started");
        Ok(Some(Self { listener, metrics }))
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> std::io::Result<()> {
        axum::serve(self.listener, metrics_router(self.metrics))
            .with_graceful_shutdown(async move {
                while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
            })
            .await
    }
}

pub async fn track_http_metrics(
    State(metrics): State<RuntimeMetrics>,
    request: Request,
    next: Next,
) -> Response<Body> {
    let in_flight = metrics.track_request();
    let response = next.run(request).await;
    in_flight.finish(response.status());
    response
}

fn metrics_router(metrics: RuntimeMetrics) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/metrics", get(metrics_response))
        .fallback(StatusCode::NOT_FOUND)
        .with_state(metrics)
}

async fn metrics_response(State(metrics): State<RuntimeMetrics>) -> impl IntoResponse {
    let mut response = metrics.render().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn metrics_bind_from_env(environment: Environment) -> Result<Option<SocketAddr>, String> {
    let value = env::var("CAMELLIA_NEXUS_METRICS_BIND")
        .ok()
        .filter(|value| !value.trim().is_empty());
    parse_metrics_bind(
        environment,
        value.as_deref(),
        env::var("CAMELLIA_NEXUS_METRICS_ALLOW_NON_LOOPBACK").as_deref() == Ok("true"),
    )
}

fn parse_metrics_bind(
    environment: Environment,
    value: Option<&str>,
    allow_non_loopback: bool,
) -> Result<Option<SocketAddr>, String> {
    let Some(value) = value else {
        return if environment == Environment::Production {
            Err("CAMELLIA_NEXUS_METRICS_BIND is required for production runtime roles".to_owned())
        } else {
            Ok(None)
        };
    };
    let bind: SocketAddr = value
        .parse()
        .map_err(|_| "CAMELLIA_NEXUS_METRICS_BIND must be a socket address".to_owned())?;
    if environment == Environment::Production && bind.port() == 0 {
        return Err(
            "CAMELLIA_NEXUS_METRICS_BIND must use an explicit non-zero port in production"
                .to_owned(),
        );
    }
    if environment == Environment::Production && !is_loopback(bind.ip()) && !allow_non_loopback {
        return Err(
            "non-loopback CAMELLIA_NEXUS_METRICS_BIND requires CAMELLIA_NEXUS_METRICS_ALLOW_NON_LOOPBACK=true"
                .to_owned(),
        );
    }
    Ok(Some(bind))
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

fn status_class(status: StatusCode) -> usize {
    match status.as_u16() / 100 {
        1 => 0,
        2 => 1,
        3 => 2,
        4 => 3,
        5 => 4,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::middleware;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[test]
    fn renders_bounded_prometheus_labels_and_counters() {
        let metrics = RuntimeMetrics::new(RuntimeRole::AdminWorker);
        metrics.record_readiness(true);
        metrics.record_readiness(false);
        metrics.record_background_iteration(BackgroundOutcome::Success);
        metrics.track_request().finish(StatusCode::CONFLICT);
        let rendered = metrics.render();
        assert!(rendered.contains("role=\"admin_worker\",status_class=\"4xx\"} 1"));
        assert!(rendered.contains("role=\"admin_worker\",outcome=\"ready\"} 1"));
        assert!(rendered.contains("role=\"admin_worker\",outcome=\"error\"} 1"));
        assert!(rendered.contains("role=\"admin_worker\",outcome=\"success\"} 1"));
        assert!(
            rendered.contains("camellia-nexus_http_in_flight_requests{role=\"admin_worker\"} 0")
        );
        assert!(!rendered.contains("account_id"));
        assert!(!rendered.contains("device_id"));
    }

    #[test]
    fn cancelled_requests_release_the_in_flight_gauge() {
        let metrics = RuntimeMetrics::new(RuntimeRole::Public);
        drop(metrics.track_request());
        let rendered = metrics.render();
        assert!(rendered.contains("role=\"public\",status_class=\"other\"} 1"));
        assert!(rendered.contains("camellia-nexus_http_in_flight_requests{role=\"public\"} 0"));
    }

    #[test]
    fn status_classes_are_finite() {
        assert_eq!(status_class(StatusCode::CONTINUE), 0);
        assert_eq!(status_class(StatusCode::NO_CONTENT), 1);
        assert_eq!(status_class(StatusCode::FOUND), 2);
        assert_eq!(status_class(StatusCode::BAD_REQUEST), 3);
        assert_eq!(status_class(StatusCode::INTERNAL_SERVER_ERROR), 4);
    }

    #[test]
    fn production_metrics_bind_is_explicit_and_private_by_default() {
        assert!(parse_metrics_bind(Environment::Production, None, false).is_err());
        assert!(parse_metrics_bind(Environment::Production, Some("0.0.0.0:9091"), false).is_err());
        assert_eq!(
            parse_metrics_bind(Environment::Production, Some("127.0.0.1:9091"), false).unwrap(),
            Some("127.0.0.1:9091".parse().unwrap())
        );
        assert_eq!(
            parse_metrics_bind(Environment::Production, Some("0.0.0.0:9091"), true).unwrap(),
            Some("0.0.0.0:9091".parse().unwrap())
        );
        assert_eq!(
            parse_metrics_bind(Environment::Development, None, false).unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn metrics_listener_is_no_store_and_http_middleware_counts_status_classes() {
        let metrics = RuntimeMetrics::new(RuntimeRole::Public);
        let application = Router::new()
            .route("/ok", get(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn_with_state(
                metrics.clone(),
                track_http_metrics,
            ));
        let response = application
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(metrics.render().contains("status_class=\"2xx\"} 1"));

        let response = metrics_router(metrics)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8(body.to_vec())
                .unwrap()
                .contains("camellia-nexus_http_requests_total")
        );
    }
}

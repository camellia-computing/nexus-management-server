use std::{process::ExitCode, sync::Arc};

use camellia_nexus_management_server::{
    AuthorizationPolicy, LicenseRepository, LicenseService, MemoryRepository, PostgresRepository,
    ServerConfig,
    billing::CommercialRepository,
    cli_help::{admin_help, root_help, runtime_help, serve_help, version},
    config::{Environment, LoggingConfig},
    limited_listener::{BoundedListener, connection_limit},
    metrics::{BackgroundOutcome, MetricsServer, RuntimeMetrics, RuntimeRole},
    router_with_metrics,
    runtime_task::{join_required_task, supervise_required_task},
    team::{PostgresTeamRepository, TeamRepository},
    webhooks::{
        PostgresWebhookRepository, WebhookDispatcherConfig, WebhookKeyring, WebhookTimeAuthority,
        run_webhook_dispatcher,
    },
    workspace::{WorkspaceKeyring, WorkspaceRepository},
};
use tracing_subscriber::{
    EnvFilter, fmt as tracing_fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

#[derive(Debug, PartialEq, Eq)]
enum CliAction {
    Serve,
    Migrate,
    Healthcheck(String),
    AdminWeb,
    AdminWorker,
    Admin(Vec<String>),
    RootHelp,
    ServeHelp,
    RuntimeHelp(String),
    AdminHelp(Vec<String>),
    Version,
}

impl CliAction {
    fn command_name(&self) -> &'static str {
        match self {
            Self::Serve => "serve",
            Self::Migrate => "migrate",
            Self::Healthcheck(_) => "healthcheck",
            Self::AdminWeb => "admin-web",
            Self::AdminWorker => "admin-worker",
            Self::Admin(_) | Self::AdminHelp(_) => "admin",
            Self::RootHelp | Self::ServeHelp | Self::RuntimeHelp(_) => "help",
            Self::Version => "version",
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let action = match parse_cli_args(&args) {
        Ok(action) => action,
        Err(error) => {
            eprintln!(
                "error: {error}\n\nRun `{}` --help for usage.\n使用 `{}` --help 查看用法。",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_NAME")
            );
            return ExitCode::from(2);
        }
    };
    match &action {
        CliAction::RootHelp => {
            println!("{}", root_help());
            return ExitCode::SUCCESS;
        }
        CliAction::ServeHelp => {
            println!("{}", serve_help());
            return ExitCode::SUCCESS;
        }
        CliAction::RuntimeHelp(command) => {
            return match runtime_help(command) {
                Ok(help) => {
                    println!("{help}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(2)
                }
            };
        }
        CliAction::AdminHelp(topic) => {
            return match admin_help(topic) {
                Ok(help) => {
                    println!("{help}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(2)
                }
            };
        }
        CliAction::Version => {
            println!("{}", version());
            return ExitCode::SUCCESS;
        }
        CliAction::Healthcheck(endpoint) => {
            return match run_healthcheck(endpoint).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("healthcheck failed: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        CliAction::Admin(args) => {
            match camellia_nexus_management_server::admin::print_help_if_requested(args) {
                Ok(true) => return ExitCode::SUCCESS,
                Ok(false) => {}
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        CliAction::Serve | CliAction::Migrate | CliAction::AdminWeb | CliAction::AdminWorker => {}
    }

    let environment = match Environment::from_env() {
        Ok(environment) => environment,
        Err(error) => {
            eprintln!("fatal configuration error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let logging = match LoggingConfig::from_env(environment) {
        Ok(logging) => logging,
        Err(error) => {
            eprintln!("fatal logging configuration error: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = init_logging(&logging) {
        eprintln!("fatal logging initialization error: {error}");
        return ExitCode::FAILURE;
    }

    let command = action.command_name();
    match run(action).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(
                error = %error,
                command,
                "Camellia Nexus command failed"
            );
            ExitCode::FAILURE
        }
    }
}

fn parse_cli_args(args: &[String]) -> Result<CliAction, String> {
    match args {
        [] => Ok(CliAction::Serve),
        [flag] if matches!(flag.as_str(), "-h" | "--help" | "help") => Ok(CliAction::RootHelp),
        [flag] if matches!(flag.as_str(), "-V" | "--version" | "version") => Ok(CliAction::Version),
        [command, help]
            if matches!(command.as_str(), "migrate" | "healthcheck" | "admin-web" | "admin-worker")
                && matches!(help.as_str(), "-h" | "--help" | "help") =>
        {
            Ok(CliAction::RuntimeHelp(command.clone()))
        }
        [help, command]
            if help == "help"
                && matches!(command.as_str(), "migrate" | "healthcheck" | "admin-web" | "admin-worker") =>
        {
            Ok(CliAction::RuntimeHelp(command.clone()))
        }
        [command] if command == "serve" => Ok(CliAction::Serve),
        [command] if command == "migrate" => Ok(CliAction::Migrate),
        [command, endpoint] if command == "healthcheck" => {
            validate_healthcheck_url(endpoint)?;
            Ok(CliAction::Healthcheck(endpoint.clone()))
        }
        [command] if command == "admin-web" => Ok(CliAction::AdminWeb),
        [command] if command == "admin-worker" => Ok(CliAction::AdminWorker),
        [command, help]
            if command == "serve" && matches!(help.as_str(), "-h" | "--help" | "help") =>
        {
            Ok(CliAction::ServeHelp)
        }
        [help, command] if help == "help" && command == "serve" => Ok(CliAction::ServeHelp),
        [help, command, topic @ ..] if help == "help" && command == "admin" => {
            Ok(CliAction::AdminHelp(topic.to_vec()))
        }
        [command, admin_args @ ..] if command == "admin" => {
            Ok(CliAction::Admin(admin_args.to_vec()))
        }
        [command, ..] if command == "serve" => Err(
            "the serve command accepts no positional arguments / serve 命令不接受位置参数"
                .to_owned(),
        ),
        [command, ..] if command == "healthcheck" => Err(
            "healthcheck requires exactly one local /healthz or /readyz URL / healthcheck 需要且仅需要一个本机 /healthz 或 /readyz URL"
                .to_owned(),
        ),
        [command, ..] if matches!(command.as_str(), "migrate" | "admin-web" | "admin-worker") => Err(
            format!("the {command} command accepts no positional arguments / {command} 命令不接受位置参数"),
        ),
        [command, ..] => Err(format!("unknown command: {command} / 未知命令：{command}")),
    }
}

fn validate_healthcheck_url(value: &str) -> Result<url::Url, String> {
    let endpoint = url::Url::parse(value)
        .map_err(|_| "healthcheck URL is invalid / healthcheck URL 无效".to_owned())?;
    let is_loopback = match endpoint.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    if endpoint.scheme() != "http"
        || endpoint.port().is_none()
        || endpoint.username() != ""
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !matches!(endpoint.path(), "/healthz" | "/readyz")
        || !is_loopback
    {
        return Err(
            "healthcheck must target an explicit local HTTP port and /healthz or /readyz / healthcheck 必须指向显式本机 HTTP 端口及 /healthz 或 /readyz"
                .to_owned(),
        );
    }
    Ok(endpoint)
}

async fn run_healthcheck(value: &str) -> Result<(), String> {
    let endpoint = validate_healthcheck_url(value)?;
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(2_500))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())?
        .get(endpoint)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("readiness endpoint returned {}", response.status()));
    }
    Ok(())
}

async fn run(action: CliAction) -> Result<(), Box<dyn std::error::Error>> {
    if let CliAction::Admin(args) = action {
        return camellia_nexus_management_server::admin::run(args).await;
    }
    if action == CliAction::AdminWeb {
        return camellia_nexus_management_server::admin_http::run_admin_web(
            camellia_nexus_management_server::admin_http::AdminHttpConfig::from_env()?,
        )
        .await;
    }
    if action == CliAction::AdminWorker {
        return camellia_nexus_management_server::admin_jobs::run_admin_worker().await;
    }
    if action == CliAction::Migrate {
        let environment = camellia_nexus_management_server::config::Environment::from_env()?;
        let database_url = std::env::var("DATABASE_URL")?;
        let repository =
            PostgresRepository::connect(&database_url, 1, std::time::Duration::from_secs(15))
                .await?;
        repository.migrate().await?;
        let grants_applied =
            camellia_nexus_management_server::database_roles::apply_runtime_database_grants(
                &repository,
                environment,
            )
            .await?;
        repository.readiness_check().await?;
        tracing::info!(
            grants_applied,
            "database migrations completed and schema is ready"
        );
        return Ok(());
    }

    let (config, signer) = ServerConfig::from_env()?;
    let (
        repository,
        commercial_repository,
        team_repository,
        workspace_repository,
        webhook_repository,
    ) = repository(&config).await?;
    let authorization = AuthorizationPolicy::new(
        config.oauth.client_id.clone(),
        config.oauth.redirect_uris.clone(),
        config
            .oauth
            .activation_codes
            .iter()
            .map(|entry| (entry.code.clone(), entry.account_id.clone())),
    )?;
    let mut service = LicenseService::with_authoritative_time_and_authorization(
        repository,
        signer,
        config.issuer.clone(),
        config.audience.clone(),
        config.time_max_forward_jump_seconds,
        config.client_version_policy.clone(),
        authorization,
    )
    .await?;
    if let Some(commercial_repository) = commercial_repository {
        service = service.with_commercial_repository(commercial_repository);
    }
    if let Some(team_repository) = team_repository {
        service = service.with_team_repository(team_repository);
    }
    if let Some(workspace_repository) = workspace_repository {
        service = service.with_workspace_repository(workspace_repository);
    }
    if let Some(webhook_repository) = &webhook_repository {
        service = service.with_webhook_repository(Arc::clone(webhook_repository));
    }
    let runtime_metrics = RuntimeMetrics::new(RuntimeRole::Public);
    match service.readiness_check().await {
        Ok(()) => runtime_metrics.record_readiness(true),
        Err(error) => {
            runtime_metrics.record_readiness(false);
            return Err(error.into());
        }
    }
    let metrics_server = MetricsServer::from_env(
        config.environment,
        RuntimeRole::Public,
        runtime_metrics.clone(),
    )
    .await?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(
        bind = %config.bind,
        issuer = %config.issuer,
        audience = %config.audience,
        minimum_client_version = %config.client_version_policy.minimum_version,
        recommended_client_version = %config.client_version_policy.recommended_version,
        client_version_enforce_after = config.client_version_policy.enforce_after,
        environment = ?config.environment,
        log_format = ?config.logging.format,
        log_level = config.logging.level.as_filter(),
        http_log_level = config.logging.http.level.as_filter(),
        "Camellia Nexus management server listening"
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let metrics_task = metrics_server.map(|server| {
        let task = tokio::spawn(server.serve(shutdown_rx.clone()));
        tokio::spawn(supervise_required_task(
            "public metrics listener",
            task,
            shutdown_tx.clone(),
            shutdown_rx.clone(),
        ))
    });
    let maintenance_service = service.clone();
    let maintenance_interval = config.maintenance_interval;
    let cleanup_batch_size = config.cleanup_batch_size;
    let maintenance_metrics = runtime_metrics.clone();
    let maintenance_shutdown = shutdown_rx.clone();
    let maintenance_task = tokio::spawn(async move {
        maintenance_loop(
            maintenance_service,
            maintenance_interval,
            cleanup_batch_size,
            maintenance_metrics,
            maintenance_shutdown,
        )
        .await;
        Ok::<(), std::io::Error>(())
    });
    let maintenance = tokio::spawn(supervise_required_task(
        "public maintenance",
        maintenance_task,
        shutdown_tx.clone(),
        shutdown_rx.clone(),
    ));
    let webhook_worker = webhook_repository.map(|repository| {
        let time_authority: Arc<dyn WebhookTimeAuthority> = Arc::new(service.clone());
        let dispatcher = tokio::spawn(run_webhook_dispatcher(
            repository,
            time_authority,
            Arc::new(WebhookDispatcherConfig::default()),
            shutdown_rx.clone(),
        ));
        let worker_shutdown = shutdown_tx.clone();
        let observed_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut result = match dispatcher.await {
                Ok(result) => result,
                Err(_) => Err(
                    camellia_nexus_management_server::webhooks::WebhookError::WorkerTaskPanicked,
                ),
            };
            if !*observed_shutdown.borrow() {
                if result.is_ok() {
                    result = Err(
                        camellia_nexus_management_server::webhooks::WebhookError::UnexpectedDispatcherExit,
                    );
                }
                match &result {
                    Ok(()) => {}
                    Err(error) => tracing::error!(
                        error_category = error.code(),
                        "workspace webhook dispatcher failed"
                    ),
                }
                let _ = worker_shutdown.send(true);
            }
            result
        })
    });
    let signal_tx = shutdown_tx.clone();
    let mut server_shutdown = shutdown_rx.clone();
    let serve_result = axum::serve(
        BoundedListener::new(listener, connection_limit(config.http.max_in_flight)),
        router_with_metrics(
            service.clone(),
            config.cors_allowed_origins,
            config.logging.http,
            config.http,
            runtime_metrics,
        ),
    )
    .with_graceful_shutdown(async move {
        tokio::select! {
            () = shutdown_signal() => {}
            changed = server_shutdown.changed() => {
                if changed.is_ok() && !*server_shutdown.borrow() {
                    return;
                }
            }
        }
        let _ = signal_tx.send(true);
    })
    .await;
    let _ = shutdown_tx.send(true);
    let maintenance_result = join_required_task("public maintenance supervisor", maintenance).await;
    let metrics_result = match metrics_task {
        Some(task) => join_required_task("public metrics supervisor", task).await,
        None => Ok(()),
    };
    let webhook_result = match webhook_worker {
        Some(worker) => match worker.await {
            Ok(result) => result,
            Err(_) => {
                Err(camellia_nexus_management_server::webhooks::WebhookError::WorkerTaskPanicked)
            }
        },
        None => Ok(()),
    };
    service.shutdown().await;
    serve_result?;
    maintenance_result?;
    metrics_result?;
    webhook_result?;
    Ok(())
}

async fn maintenance_loop(
    service: LicenseService,
    interval: std::time::Duration,
    batch_size: u32,
    metrics: RuntimeMetrics,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = timer.tick() => {
                let maintenance = async {
                    let mut failed = false;
                    match service.cleanup_expired(batch_size).await {
                        Ok(report) => tracing::info!(
                            challenges = report.challenges,
                            authorization_codes = report.authorization_codes,
                            refresh_sessions = report.refresh_sessions,
                            rate_limit_buckets = report.rate_limit_buckets,
                            "license repository maintenance completed"
                        ),
                        Err(error) => {
                            failed = true;
                            tracing::warn!(%error, "license repository maintenance failed");
                        }
                    }
                    match service.cleanup_webhooks(batch_size).await {
                        Ok(Some(report)) => tracing::info!(
                            expired_deliveries = report.expired_deliveries,
                            deleted_events = report.deleted_events,
                            deleted_operations = report.deleted_operations,
                            deleted_endpoints = report.deleted_endpoints,
                            "workspace webhook maintenance completed"
                        ),
                        Ok(None) => {}
                        Err(error) => {
                            failed = true;
                            tracing::warn!(%error, "workspace webhook maintenance failed");
                        }
                    }
                    metrics.record_background_iteration(if failed {
                        BackgroundOutcome::Error
                    } else {
                        BackgroundOutcome::Success
                    });
                };
                tokio::select! {
                    () = maintenance => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            },
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            },
            Err(error) => {
                tracing::warn!(%error, "SIGTERM handler is unavailable; waiting for Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown requested; draining in-flight license requests");
}

fn init_logging(config: &LoggingConfig) -> Result<(), Box<dyn std::error::Error>> {
    let filter = match config.filter.as_deref() {
        Some(filter) => EnvFilter::try_new(filter)?,
        None => EnvFilter::try_new(format!(
            "{},tower_http={},sqlx=warn,hyper=warn,h2=warn",
            config.level.as_filter(),
            config.http.level.as_filter()
        ))?,
    };

    match config.format {
        camellia_nexus_management_server::config::LogFormat::Json => tracing_subscriber::registry()
            .with(
                tracing_fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_target(true)
                    .with_current_span(false)
                    .with_span_list(false),
            )
            .with(filter)
            .try_init()?,
        camellia_nexus_management_server::config::LogFormat::Compact => {
            tracing_subscriber::registry()
                .with(tracing_fmt::layer().compact().with_target(false))
                .with(filter)
                .try_init()?
        }
    }
    Ok(())
}

async fn repository(
    config: &ServerConfig,
) -> Result<
    (
        Arc<dyn LicenseRepository>,
        Option<Arc<dyn CommercialRepository>>,
        Option<Arc<dyn TeamRepository>>,
        Option<Arc<WorkspaceRepository>>,
        Option<Arc<PostgresWebhookRepository>>,
    ),
    Box<dyn std::error::Error>,
> {
    match &config.storage {
        camellia_nexus_management_server::config::StorageConfig::Memory => {
            tracing::warn!("using in-memory repository; this mode is for local testing only");
            Ok((
                Arc::new(MemoryRepository::default()),
                None,
                None,
                None,
                None,
            ))
        }
        camellia_nexus_management_server::config::StorageConfig::Postgres { database_url } => {
            tracing::info!(
                max_connections = config.max_database_connections,
                migrate = config.migrate_database,
                "initializing postgres license repository"
            );
            let repository = PostgresRepository::connect(
                database_url,
                config.max_database_connections,
                config.database_acquire_timeout,
            )
            .await?;
            if config.migrate_database {
                tracing::info!("running postgres migrations");
                repository.migrate().await?;
            }
            let keyring = Arc::new(match &config.workspace_keyring_path {
                Some(path) => WorkspaceKeyring::load(path)?,
                None => {
                    tracing::warn!(
                        "using an ephemeral workspace keyring; persisted cloud configurations and Team operation responses will not survive a restart"
                    );
                    WorkspaceKeyring::ephemeral_for_development()
                }
            });
            let team_repository = Arc::new(PostgresTeamRepository::new(
                &repository,
                Arc::clone(&keyring),
            ));
            let workspace_repository =
                Arc::new(WorkspaceRepository::new(&repository, Arc::clone(&keyring)));
            let webhook_keyring = match &config.webhook_keyring_path {
                Some(path) => Arc::new(WebhookKeyring::load(path)?),
                None => {
                    tracing::warn!(
                        "using an ephemeral webhook keyring; existing webhook endpoint secrets cannot be decrypted after a restart"
                    );
                    Arc::new(WebhookKeyring::ephemeral_for_development())
                }
            };
            let webhook_repository = Arc::new(PostgresWebhookRepository::new(
                repository.clone(),
                webhook_keyring,
            ));
            let repository = Arc::new(repository);
            Ok((
                repository.clone(),
                Some(repository.clone()),
                Some(team_repository),
                Some(workspace_repository),
                Some(webhook_repository),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn runtime_failures_have_unambiguous_command_names() {
        assert_eq!(CliAction::Serve.command_name(), "serve");
        assert_eq!(CliAction::Migrate.command_name(), "migrate");
        assert_eq!(CliAction::AdminWeb.command_name(), "admin-web");
        assert_eq!(CliAction::AdminWorker.command_name(), "admin-worker");
        assert_eq!(CliAction::Admin(Vec::new()).command_name(), "admin");
    }

    #[test]
    fn parses_root_help_version_and_runtime_commands() {
        assert_eq!(parse_cli_args(&[]).unwrap(), CliAction::Serve);
        assert_eq!(parse_cli_args(&args(&["serve"])).unwrap(), CliAction::Serve);
        assert_eq!(
            parse_cli_args(&args(&["migrate"])).unwrap(),
            CliAction::Migrate
        );
        assert_eq!(
            parse_cli_args(&args(&["healthcheck", "http://127.0.0.1:8088/readyz"])).unwrap(),
            CliAction::Healthcheck("http://127.0.0.1:8088/readyz".to_owned())
        );
        assert_eq!(
            parse_cli_args(&args(&["--help"])).unwrap(),
            CliAction::RootHelp
        );
        assert_eq!(
            parse_cli_args(&args(&["serve", "--help"])).unwrap(),
            CliAction::ServeHelp
        );
        assert_eq!(
            parse_cli_args(&args(&["migrate", "--help"])).unwrap(),
            CliAction::RuntimeHelp("migrate".to_owned())
        );
        assert_eq!(
            parse_cli_args(&args(&["help", "healthcheck"])).unwrap(),
            CliAction::RuntimeHelp("healthcheck".to_owned())
        );
        assert_eq!(
            parse_cli_args(&args(&["admin-web", "help"])).unwrap(),
            CliAction::RuntimeHelp("admin-web".to_owned())
        );
        assert_eq!(
            parse_cli_args(&args(&["admin-worker", "-h"])).unwrap(),
            CliAction::RuntimeHelp("admin-worker".to_owned())
        );
        assert_eq!(
            parse_cli_args(&args(&["--version"])).unwrap(),
            CliAction::Version
        );
        assert_eq!(
            parse_cli_args(&args(&["admin", "code", "list"])).unwrap(),
            CliAction::Admin(args(&["code", "list"]))
        );
        assert_eq!(
            parse_cli_args(&args(&["help", "admin", "code", "issue"])).unwrap(),
            CliAction::AdminHelp(args(&["code", "issue"]))
        );
    }

    #[test]
    fn rejects_unknown_or_extra_serve_arguments() {
        assert!(parse_cli_args(&args(&["unknown"])).is_err());
        assert!(parse_cli_args(&args(&["serve", "unexpected"])).is_err());
        assert!(parse_cli_args(&args(&["healthcheck"])).is_err());
        assert!(parse_cli_args(&args(&["healthcheck", "https://example.com/readyz"])).is_err());
        assert!(parse_cli_args(&args(&["healthcheck", "http://localhost:8088/readyz"])).is_err());
        assert!(parse_cli_args(&args(&["healthcheck", "http://127.0.0.1:8088/status"])).is_err());
        assert!(parse_cli_args(&args(&["migrate", "unexpected"])).is_err());
        assert!(parse_cli_args(&args(&["admin-web", "unexpected"])).is_err());
        assert!(parse_cli_args(&args(&["admin-worker", "unexpected"])).is_err());
    }

    #[tokio::test]
    async fn healthcheck_requires_a_successful_local_endpoint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = axum::Router::new()
            .route(
                "/readyz",
                axum::routing::get(|| async { axum::http::StatusCode::NO_CONTENT }),
            )
            .route(
                "/healthz",
                axum::routing::get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        run_healthcheck(&format!("http://{address}/readyz"))
            .await
            .unwrap();
        assert!(
            run_healthcheck(&format!("http://{address}/healthz"))
                .await
                .is_err()
        );
        server.abort();
    }
}

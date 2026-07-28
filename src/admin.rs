use std::{collections::BTreeMap, env, error::Error, str::FromStr, sync::Arc};

use rust_decimal::Decimal;
use serde_json::{Value, json};

use crate::{
    admin_app::{
        ActivationCodeBatchRequest, ActivationCodeExpiry, AdminApplication, AdminPrincipal,
        MutationContext, NewLicense, apply_license_plan,
    },
    admin_auth::{AdminAuthService, AdminKeyring, normalize_username},
    admin_identity::AdminIdentityService,
    billing::{
        CommercialOffer, ManualPaymentMethod, NewInvoice, NewPaymentClaim, PaymentClaimStatus,
        PaymentReviewDecision,
    },
    cli_help::{admin_help, canonical_admin_help_topic, is_admin_group},
    config::{Environment, time_max_forward_jump_seconds_from_env},
    contracts::{DeviceState, Plan},
    domain::{AccountState, ActivationCodeStatus, LicenseStatus},
    error::ApiError,
    store::{LicenseRepository, PostgresRepository, TimeAuthorityStatus},
    time_format::{
        parse_absolute_time, parse_expiry_time, parse_optional_expiry_time,
        parse_relative_duration_seconds, with_human_times,
    },
};

type AdminResult<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Human,
    Raw,
}

pub async fn run(args: Vec<String>) -> AdminResult<()> {
    let (args, output) = parse_admin_options(args)?;
    if print_parsed_help_if_requested(&args)? {
        return Ok(());
    }
    let repository = admin_repository().await?;
    let application = AdminApplication::from_environment(repository.clone())?;
    match args[0].as_str() {
        "account" => account(&application, &args[1..], output).await,
        "license" => license(&application, &args[1..], output).await,
        "code" => code(&application, &args[1..], output).await,
        "device" => device(&application, &args[1..], output).await,
        "audit" => audit(&repository, &args[1..], output).await,
        "billing" => billing(&repository, &args[1..], output).await,
        "operator" => operator(&application, &args[1..], output).await,
        command => Err(format!("unknown admin command: {command}").into()),
    }
}

async fn operator(
    application: &AdminApplication,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    match args.first().map(String::as_str) {
        Some("bootstrap") => {
            let username = required(args, 1, "username")?;
            let flags = Flags::new(&args[2..], &["display-name", "actor", "reason"])?;
            let display_name = required_flag(&flags, "display-name", 128)?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let path = env::var("CAMELLIA_NEXUS_ADMIN_KEYRING_PATH").map_err(
                |_| "CAMELLIA_NEXUS_ADMIN_KEYRING_PATH is required for operator commands",
            )?;
            let keyring = Arc::new(AdminKeyring::load(path)?);
            keyring.readiness_check(application.repository()).await?;
            let service = AdminAuthService::new(application.clone(), keyring)?;
            let token = service
                .bootstrap_owner(username, &display_name, &actor, &reason)
                .await?;
            print_json(
                output,
                &json!({
                    "username": username.to_ascii_lowercase(),
                    "enrollmentToken": token,
                    "expiresInSeconds": 600,
                }),
            )?;
        }
        Some("recover-owner") => {
            let username = normalize_username(required(args, 1, "username")?)?;
            let flags = Flags::new(&args[2..], &["actor", "reason", "confirm"])?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let confirmation = required_flag(&flags, "confirm", 64)?;
            let path = env::var("CAMELLIA_NEXUS_ADMIN_KEYRING_PATH").map_err(
                |_| "CAMELLIA_NEXUS_ADMIN_KEYRING_PATH is required for operator commands",
            )?;
            let keyring = Arc::new(AdminKeyring::load(path)?);
            keyring.readiness_check(application.repository()).await?;
            let service = AdminIdentityService::new(application.clone(), keyring);
            let token = service
                .recover_owner_offline(&username, &actor, &reason, &confirmation)
                .await?;
            print_json(
                output,
                &json!({
                    "username": username,
                    "enrollmentToken": token,
                    "expiresInSeconds": 600,
                }),
            )?;
        }
        Some(command) => return Err(format!("unknown operator command: {command}").into()),
        None => return Err("operator command is required".into()),
    }
    Ok(())
}

async fn billing(
    repository: &PostgresRepository,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    match args.first().map(String::as_str) {
        Some("offer") => billing_offer(repository, &args[1..], output).await,
        Some("method") => billing_method(repository, &args[1..], output).await,
        Some("invoice") => billing_invoice(repository, &args[1..], output).await,
        Some("payment") => billing_payment(repository, &args[1..], output).await,
        Some(command) => Err(format!("unknown billing command: {command}").into()),
        None => Err("billing command is required".into()),
    }
}

async fn billing_offer(
    repository: &PostgresRepository,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    match args.first().map(String::as_str) {
        Some("list") => print_json(output, &repository.commercial_offers(false).await?)?,
        Some("create") => {
            let id = required(args, 1, "offer id")?;
            let flags = Flags::new(
                &args[2..],
                &[
                    "plan",
                    "duration-days",
                    "currency",
                    "amount",
                    "seat-amount",
                    "name-en",
                    "name-zh",
                    "actor",
                    "reason",
                ],
            )?;
            let now = authoritative_now(repository).await?;
            let offer = CommercialOffer {
                id: id.to_owned(),
                row_version: 1,
                plan: parse_commercial_plan(required_flag(&flags, "plan", 16)?.as_str())?,
                plan_revision: crate::plan_catalog::CURRENT_PLAN_REVISION,
                duration_days: parse_bounded_u32(
                    &required_flag(&flags, "duration-days", 8)?,
                    1,
                    3_660,
                    "duration days",
                )?,
                currency: required_flag(&flags, "currency", 16)?.to_ascii_uppercase(),
                base_amount: parse_amount(&required_flag(&flags, "amount", 64)?)?,
                seat_amount: flags.value("seat-amount").map(parse_amount).transpose()?,
                name_en: required_flag(&flags, "name-en", 256)?,
                name_zh: required_flag(&flags, "name-zh", 256)?,
                active: true,
                created_at: now,
                updated_at: now,
            };
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let offer = repository
                .create_commercial_offer(&offer, &actor, &reason, None)
                .await?;
            print_json(output, &offer)?;
        }
        Some(command) => return Err(format!("unknown billing offer command: {command}").into()),
        None => return Err("billing offer command is required".into()),
    }
    Ok(())
}

async fn billing_method(
    repository: &PostgresRepository,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    match args.first().map(String::as_str) {
        Some("list") => print_json(output, &repository.manual_payment_methods(false).await?)?,
        Some("create") => {
            let id = required(args, 1, "payment method id")?;
            let flags = Flags::new(
                &args[2..],
                &[
                    "name-en",
                    "name-zh",
                    "instructions-en",
                    "instructions-zh",
                    "asset",
                    "destination-hint",
                    "actor",
                    "reason",
                ],
            )?;
            let now = authoritative_now(repository).await?;
            let method = ManualPaymentMethod {
                id: id.to_owned(),
                row_version: 1,
                name_en: required_flag(&flags, "name-en", 256)?,
                name_zh: required_flag(&flags, "name-zh", 256)?,
                instructions_en: required_flag(&flags, "instructions-en", 4_000)?,
                instructions_zh: required_flag(&flags, "instructions-zh", 4_000)?,
                settlement_asset: required_flag(&flags, "asset", 16)?.to_ascii_uppercase(),
                destination_hint: required_flag(&flags, "destination-hint", 512)?,
                active: true,
                created_at: now,
                updated_at: now,
            };
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let method = repository
                .create_manual_payment_method(&method, &actor, &reason, None)
                .await?;
            print_json(output, &method)?;
        }
        Some(command) => return Err(format!("unknown billing method command: {command}").into()),
        None => return Err("billing method command is required".into()),
    }
    Ok(())
}

async fn billing_invoice(
    repository: &PostgresRepository,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    match args.first().map(String::as_str) {
        Some("list") => {
            let flags = Flags::new(&args[1..], &["account"])?;
            print_json(
                output,
                &repository.billing_invoices(flags.value("account")).await?,
            )?;
        }
        Some("create") => {
            let id = required(args, 1, "invoice id")?;
            let flags = Flags::new(
                &args[2..],
                &[
                    "account", "license", "offer", "seats", "due-at", "actor", "reason",
                ],
            )?;
            let now = authoritative_now(repository).await?;
            let account_id = required_flag(&flags, "account", 256)?;
            let license_id = required_flag(&flags, "license", 256)?;
            let offer_id = required_flag(&flags, "offer", 256)?;
            let seats = flags
                .value("seats")
                .map(|value| parse_bounded_u32(value, 3, 10_000, "seats"))
                .transpose()?
                .unwrap_or(0);
            let due_at = parse_expiry_time(&required_flag(&flags, "due-at", 128)?, now)?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let invoice = repository
                .create_billing_invoice(
                    NewInvoice {
                        id,
                        account_id: &account_id,
                        license_id: &license_id,
                        offer_id: &offer_id,
                        seats,
                        due_at,
                    },
                    &actor,
                    &reason,
                    now,
                    None,
                )
                .await?;
            print_json(output, &invoice)?;
        }
        Some(command) => return Err(format!("unknown billing invoice command: {command}").into()),
        None => return Err("billing invoice command is required".into()),
    }
    Ok(())
}

async fn billing_payment(
    repository: &PostgresRepository,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    match args.first().map(String::as_str) {
        Some("list") => {
            let flags = Flags::new(&args[1..], &["status"])?;
            let status = flags
                .value("status")
                .map(PaymentClaimStatus::from_str)
                .transpose()?;
            print_json(output, &repository.manual_payment_claims(status).await?)?;
        }
        Some("submit") => {
            let id = required(args, 1, "payment claim id")?;
            let flags = Flags::new(
                &args[2..],
                &[
                    "invoice",
                    "method",
                    "transaction",
                    "amount",
                    "asset",
                    "paid-at",
                    "payer",
                    "note",
                    "submitted-by",
                ],
            )?;
            let now = authoritative_now(repository).await?;
            let paid_at =
                crate::time_format::parse_absolute_time(&required_flag(&flags, "paid-at", 128)?)?;
            let claim = repository
                .submit_manual_payment_claim(
                    NewPaymentClaim {
                        id,
                        invoice_id: flags.value("invoice").ok_or("--invoice is required")?,
                        payment_method_id: flags.value("method").ok_or("--method is required")?,
                        external_transaction_id: flags
                            .value("transaction")
                            .ok_or("--transaction is required")?,
                        paid_amount: parse_amount(
                            flags.value("amount").ok_or("--amount is required")?,
                        )?,
                        paid_asset: flags.value("asset").ok_or("--asset is required")?,
                        paid_at,
                        payer_name: flags.value("payer"),
                        note: flags.value("note"),
                        submitted_by: flags
                            .value("submitted-by")
                            .ok_or("--submitted-by is required")?,
                    },
                    now,
                )
                .await?;
            print_json(output, &claim)?;
        }
        Some("approve" | "reject" | "request-information") => {
            let command = args[0].as_str();
            let claim_id = required(args, 1, "payment claim id")?;
            let allowed = if command == "approve" {
                &[
                    "row-version",
                    "actor",
                    "reason",
                    "operation-id",
                    "allow-amount-override",
                ][..]
            } else {
                &["row-version", "actor", "reason", "operation-id"][..]
            };
            let flags = Flags::new(&args[2..], allowed)?;
            let decision = match command {
                "approve" => PaymentReviewDecision::Approve,
                "reject" => PaymentReviewDecision::Reject,
                _ => PaymentReviewDecision::RequestInformation,
            };
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let operation_id = required_flag(&flags, "operation-id", 128)?;
            let expected_row_version =
                parse_positive_u64(&required_flag(&flags, "row-version", 20)?, "row version")?;
            let allow_amount_override = flags
                .value("allow-amount-override")
                .map(|value| parse_bool("--allow-amount-override", value))
                .transpose()?
                .unwrap_or(false);
            let now = authoritative_now(repository).await?;
            let claim = repository
                .review_manual_payment_claim(
                    claim_id,
                    expected_row_version,
                    decision,
                    &actor,
                    &reason,
                    &operation_id,
                    allow_amount_override,
                    now,
                )
                .await?;
            print_json(output, &claim)?;
        }
        Some(command) => return Err(format!("unknown billing payment command: {command}").into()),
        None => return Err("billing payment command is required".into()),
    }
    Ok(())
}

pub fn print_help_if_requested(args: &[String]) -> AdminResult<bool> {
    let (args, _) = parse_admin_options(args.to_vec())?;
    print_parsed_help_if_requested(&args)
}

fn print_parsed_help_if_requested(args: &[String]) -> AdminResult<bool> {
    let Some(topic) = requested_help_topic(args) else {
        return Ok(false);
    };
    println!("{}", admin_help(&topic)?);
    Ok(true)
}

fn requested_help_topic(args: &[String]) -> Option<Vec<String>> {
    if args.is_empty() {
        return Some(Vec::new());
    }
    if args[0] == "help" {
        return Some(args[1..].to_vec());
    }
    if args.len() == 1 && is_admin_group(&args[0]) {
        return Some(args.to_vec());
    }
    let help_index = args
        .iter()
        .position(|arg| matches!(arg.as_str(), "-h" | "--help" | "help"))?;
    Some(canonical_admin_help_topic(&args[..help_index]))
}

fn parse_admin_options(args: Vec<String>) -> AdminResult<(Vec<String>, OutputMode)> {
    let mut output = None;
    let mut command_args = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--human" => {
                set_output_mode(&mut output, OutputMode::Human)?;
                index += 1;
            }
            "--raw" => {
                set_output_mode(&mut output, OutputMode::Raw)?;
                index += 1;
            }
            "--output" => {
                let value = args
                    .get(index + 1)
                    .ok_or("--output requires human or raw")?;
                set_output_mode(&mut output, parse_output_mode(value)?)?;
                index += 2;
            }
            value if value.starts_with("--output=") => {
                let value = value
                    .split_once('=')
                    .map(|(_, value)| value)
                    .ok_or("--output requires human or raw")?;
                set_output_mode(&mut output, parse_output_mode(value)?)?;
                index += 1;
            }
            _ => {
                command_args.push(args[index].clone());
                index += 1;
            }
        }
    }
    Ok((command_args, output.unwrap_or(OutputMode::Human)))
}

fn set_output_mode(target: &mut Option<OutputMode>, next: OutputMode) -> AdminResult<()> {
    if let Some(existing) = target
        && *existing != next
    {
        return Err("choose only one output mode: human or raw".into());
    }
    *target = Some(next);
    Ok(())
}

fn parse_output_mode(value: &str) -> AdminResult<OutputMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "human" | "pretty" => Ok(OutputMode::Human),
        "raw" | "machine" => Ok(OutputMode::Raw),
        _ => Err("--output must be human or raw".into()),
    }
}

async fn admin_repository() -> AdminResult<PostgresRepository> {
    let database_url =
        env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required for admin commands")?;
    let max_connections = env::var("CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8);
    let environment = Environment::from_env()?;
    let migrate = env_bool(
        "CAMELLIA_NEXUS_DATABASE_MIGRATE",
        environment == Environment::Development,
    )?;
    let acquire_timeout = std::time::Duration::from_secs(
        std::env::var("CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(5),
    );
    let repository =
        PostgresRepository::connect(&database_url, max_connections, acquire_timeout).await?;
    if migrate {
        repository.migrate().await?;
    }
    repository.readiness_check().await?;
    Ok(repository)
}

async fn authoritative_now(repository: &PostgresRepository) -> AdminResult<i64> {
    let observation = repository
        .observe_time_authority(None, time_max_forward_jump_seconds_from_env()?)
        .await?;
    if observation.status == TimeAuthorityStatus::ForwardJump {
        Err(ApiError::TimeAuthorityUnavailable.into())
    } else {
        Ok(observation.trusted_unix)
    }
}

async fn account(
    application: &AdminApplication,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("account command is required".into());
    };
    match command {
        "list" => print_json(output, &application.repository().accounts().await?)?,
        "show" => {
            let id = required(args, 1, "account id")?;
            print_json(output, &application.repository().account(id).await?)?;
        }
        "create" => {
            let id = required(args, 1, "account id")?;
            let flags = Flags::new(&args[2..], &["actor", "reason", "note"])?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let context = mutation_context(actor, reason)?;
            let account = application
                .create_account(id, optional_bounded_flag(&flags, "note", 1_024)?, &context)
                .await?;
            print_json(output, &account)?;
        }
        "set-state" => {
            let id = required(args, 1, "account id")?;
            let state = parse_account_state(required(args, 2, "state")?)?;
            let flags = Flags::new(&args[3..], &["actor", "reason"])?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let context = mutation_context(actor, reason)?;
            let account = application
                .set_account_state(id, state, None, &context)
                .await?;
            print_json(output, &account)?;
        }
        "delete" => {
            return Err("accounts are durable audit entities; use account set-state suspended or denylisted --actor ... --reason ...".into());
        }
        _ => return Err(format!("unknown account command: {command}").into()),
    }
    Ok(())
}

async fn license(
    application: &AdminApplication,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("license command is required".into());
    };
    match command {
        "list" => {
            let flags = Flags::new(&args[1..], &["account"])?;
            print_json(
                output,
                &application
                    .repository()
                    .licenses(flags.value("account"))
                    .await?,
            )?;
        }
        "show" => print_json(
            output,
            &application
                .repository()
                .license(required(args, 1, "license id")?)
                .await?,
        )?,
        "create" => {
            let id = required(args, 1, "license id")?;
            let flags = Flags::new(
                &args[2..],
                &[
                    "account",
                    "actor",
                    "reason",
                    "plan",
                    "status",
                    "seats",
                    "expires-at",
                ],
            )?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let account_id = flags.value("account").ok_or("--account is required")?;
            let plan = parse_plan(flags.value("plan").ok_or("--plan is required")?)?;
            let now = application.trusted_now().await?;
            let context = mutation_context(actor, reason)?;
            let license = application
                .create_license(
                    NewLicense {
                        id: id.to_owned(),
                        account_id: account_id.to_owned(),
                        plan,
                        status: flags
                            .value("status")
                            .map(parse_license_status)
                            .transpose()?
                            .unwrap_or(LicenseStatus::Active),
                        expires_at: flags
                            .value("expires-at")
                            .map(|value| parse_optional_expiry_time(value, now))
                            .transpose()?
                            .flatten(),
                        purchased_seats: flags
                            .value("seats")
                            .map(parse_seats)
                            .transpose()?
                            .unwrap_or(0),
                    },
                    &context,
                )
                .await?;
            print_json(output, &license)?;
        }
        "set-plan" => {
            let id = required(args, 1, "license id")?;
            let plan = parse_plan(required(args, 2, "plan")?)?;
            let flags = Flags::new(&args[3..], &["actor", "reason", "seats"])?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let seats = flags
                .value("seats")
                .map(parse_optional_plan_seats)
                .transpose()?;
            let context = mutation_context(actor, reason)?;
            let license = application
                .mutate_license(
                    id,
                    None,
                    &context,
                    json!({"plan": plan, "purchasedSeats": seats}),
                    move |license| apply_license_plan(license, plan, seats),
                    "license_plan_set",
                )
                .await?;
            print_json(output, &license)?;
        }
        "set-seats" => {
            let id = required(args, 1, "license id")?;
            let flags = Flags::new(&args[3..], &["actor", "reason"])?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let seats = parse_seats(required(args, 2, "seats")?)?;
            let context = mutation_context(actor, reason)?;
            let license = application
                .mutate_license(
                    id,
                    None,
                    &context,
                    json!({"purchasedSeats": seats}),
                    move |license| apply_license_plan(license, Plan::Team, Some(seats)),
                    "license_seats_set",
                )
                .await?;
            print_json(output, &license)?;
        }
        "set-status" => {
            let id = required(args, 1, "license id")?;
            let flags = Flags::new(&args[3..], &["actor", "reason"])?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let status = parse_license_status(required(args, 2, "status")?)?;
            let context = mutation_context(actor, reason)?;
            let license = application
                .mutate_license(
                    id,
                    None,
                    &context,
                    json!({"status": status}),
                    move |license| {
                        if license.status != status {
                            license.status = status;
                            license.license_epoch = license.license_epoch.saturating_add(1);
                            license.row_version = license.row_version.saturating_add(1);
                        }
                        Ok(())
                    },
                    "license_status_set",
                )
                .await?;
            print_json(output, &license)?;
        }
        "set-expires-at" => {
            let id = required(args, 1, "license id")?;
            let flags = Flags::new(&args[3..], &["actor", "reason"])?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let value = required(args, 2, "time or none")?;
            let now = application.trusted_now().await?;
            let expires_at = parse_optional_expiry_time(value, now)?;
            let context = mutation_context(actor, reason)?;
            let license = application
                .mutate_license(
                    id,
                    None,
                    &context,
                    json!({"expiresAt": expires_at}),
                    move |license| {
                        if license.expires_at != expires_at {
                            license.expires_at = expires_at;
                            license.license_epoch = license.license_epoch.saturating_add(1);
                            license.row_version = license.row_version.saturating_add(1);
                        }
                        Ok(())
                    },
                    "license_expiry_set",
                )
                .await?;
            print_json(output, &license)?;
        }
        "delete" => {
            return Err("licenses are durable audit entities; use license set-status canceled --actor ... --reason ...".into());
        }
        _ => return Err(format!("unknown license command: {command}").into()),
    }
    Ok(())
}

async fn code(
    application: &AdminApplication,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("code command is required".into());
    };
    match command {
        "issue" => issue_codes(application, &args[1..], output).await?,
        "list" => {
            let flags = Flags::new(&args[1..], &["account", "status"])?;
            let status = flags
                .value("status")
                .map(parse_activation_status)
                .transpose()?;
            print_json(
                output,
                &application
                    .repository()
                    .activation_codes(flags.value("account"), status)
                    .await?,
            )?;
        }
        "show" => {
            let record = application
                .resolve_activation_code(required(args, 1, "code, hash or prefix")?)
                .await?;
            print_json(output, &record)?;
        }
        "revoke" | "restore" | "expire" => {
            let allowed = match command {
                "revoke" => &["actor", "reason"][..],
                "restore" => &["actor", "reason", "max-redemptions"][..],
                "expire" => &["actor", "reason", "expires-at"][..],
                _ => unreachable!(),
            };
            let flags = Flags::new(&args[2..], allowed)?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let now = application.trusted_now().await?;
            let expires_at = flags
                .value("expires-at")
                .map(|value| parse_expiry_time(value, now))
                .transpose()?;
            let max_redemptions = flags
                .value("max-redemptions")
                .map(parse_redemption_limit)
                .transpose()?;
            let context = mutation_context(actor, reason)?;
            let record = application
                .mutate_activation_code(
                    required(args, 1, "code, hash or prefix")?,
                    None,
                    &context,
                    command,
                    max_redemptions,
                    expires_at,
                )
                .await?;
            print_json(output, &record)?;
        }
        "delete" => {
            return Err(
                "activation codes are immutable audit records; use code revoke --actor ... --reason ..."
                    .into(),
            );
        }
        _ => return Err(format!("unknown code command: {command}").into()),
    }
    Ok(())
}

async fn issue_codes(
    application: &AdminApplication,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    let flags = Flags::new(
        args,
        &[
            "account",
            "license",
            "issued-by",
            "reason",
            "operation-id",
            "count",
            "max-redemptions",
            "channel",
            "expires-at",
            "ttl-days",
            "note",
        ],
    )?;
    let account_id = flags.value("account").ok_or("--account is required")?;
    let license_id = flags.value("license").ok_or("--license is required")?;
    let count = flags
        .value("count")
        .map(str::parse)
        .transpose()?
        .unwrap_or(1_u32);
    if !(1..=1_000).contains(&count) {
        return Err("--count must be between 1 and 1000".into());
    }
    let max_redemptions = flags
        .value("max-redemptions")
        .map(parse_redemption_limit)
        .transpose()?
        .unwrap_or(1);
    let issued_by = required_flag(&flags, "issued-by", 128)?;
    let reason = required_flag(&flags, "reason", 512)?;
    let operation_id = required_flag(&flags, "operation-id", 128)?;
    let channel = optional_bounded_flag(&flags, "channel", 128)?;
    let note = optional_bounded_flag(&flags, "note", 1_024)?;
    let expiry = activation_code_expiry_from_flags(&flags)?;
    let mut context = mutation_context(issued_by, reason)?;
    context.operation_id = Some(operation_id.clone());
    let issued = application
        .issue_activation_codes(
            ActivationCodeBatchRequest {
                account_id: account_id.to_owned(),
                license_id: license_id.to_owned(),
                count,
                max_redemptions,
                expiry,
                channel,
                note,
                operation_id,
            },
            &context,
        )
        .await?;
    print_json(output, &issued)?;
    Ok(())
}

async fn device(
    application: &AdminApplication,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("device command is required".into());
    };
    match command {
        "list" => {
            let flags = Flags::new(&args[1..], &["account"])?;
            print_json(
                output,
                &application
                    .repository()
                    .devices(flags.value("account"))
                    .await?,
            )?;
        }
        "show" => print_json(
            output,
            &application
                .repository()
                .device(required(args, 1, "device id")?)
                .await?,
        )?,
        "set-state" => {
            let id = required(args, 1, "device id")?;
            let state = parse_device_state(required(args, 2, "state")?)?;
            if state == DeviceState::Active {
                return Err(
                    "devices can become active only through the activation proof flow".into(),
                );
            }
            let flags = Flags::new(&args[3..], &["actor", "reason"])?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let context = mutation_context(actor, reason)?;
            let device = application
                .set_device_state(id, state, None, &context)
                .await?;
            print_json(output, &device)?;
        }
        "revoke" => {
            let id = required(args, 1, "device id")?;
            let flags = Flags::new(&args[2..], &["actor", "reason"])?;
            let actor = required_flag(&flags, "actor", 128)?;
            let reason = required_flag(&flags, "reason", 512)?;
            let context = mutation_context(actor, reason)?;
            let device = application
                .set_device_state(id, DeviceState::Revoked, None, &context)
                .await?;
            print_json(output, &device)?;
        }
        "restore" => {
            return Err("device restore bypasses proof-of-possession; use a new activation code and the normal activation flow".into());
        }
        "delete" => {
            return Err("devices are durable audit entities; use device set-state removed --actor ... --reason ...".into());
        }
        _ => return Err(format!("unknown device command: {command}").into()),
    }
    Ok(())
}

fn mutation_context(actor: String, reason: String) -> AdminResult<MutationContext> {
    Ok(MutationContext::new(AdminPrincipal::cli(actor)?, reason)?)
}

async fn audit(
    repository: &PostgresRepository,
    args: &[String],
    output: OutputMode,
) -> AdminResult<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("audit command is required".into());
    };
    match command {
        "list" => {
            let flags = Flags::new(&args[1..], &["account", "limit"])?;
            let limit = flags
                .value("limit")
                .map(str::parse)
                .transpose()?
                .unwrap_or(100_i64);
            if !(1..=500).contains(&limit) {
                return Err("--limit must be between 1 and 500".into());
            }
            print_json(
                output,
                &repository
                    .audit_events(flags.value("account"), limit)
                    .await?,
            )?;
        }
        _ => return Err(format!("unknown audit command: {command}").into()),
    }
    Ok(())
}

fn activation_code_expiry_from_flags(flags: &Flags<'_>) -> AdminResult<ActivationCodeExpiry> {
    if flags.value("expires-at").is_some() && flags.value("ttl-days").is_some() {
        return Err("choose only one of --expires-at or --ttl-days".into());
    }
    if let Some(expires_at) = flags.value("expires-at") {
        return match parse_relative_duration_seconds(expires_at)? {
            Some(seconds) => Ok(ActivationCodeExpiry::relative_seconds(seconds)?),
            None => Ok(ActivationCodeExpiry::fixed(Some(parse_absolute_time(
                expires_at,
            )?))),
        };
    }
    if let Some(days) = flags.value("ttl-days") {
        let days: i64 = days.parse()?;
        if !(1..=3_650).contains(&days) {
            return Err("--ttl-days must be between 1 and 3650".into());
        }
        return Ok(ActivationCodeExpiry::relative_seconds(
            days.checked_mul(24 * 60 * 60)
                .ok_or("--ttl-days exceeds the supported time range")?,
        )?);
    }
    Ok(ActivationCodeExpiry::relative_seconds(30 * 24 * 60 * 60)?)
}

fn required<'a>(args: &'a [String], index: usize, name: &str) -> AdminResult<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{name} is required").into())
}

fn required_flag(flags: &Flags<'_>, key: &str, max_len: usize) -> AdminResult<String> {
    optional_bounded_flag(flags, key, max_len)?.ok_or_else(|| format!("--{key} is required").into())
}

fn optional_bounded_flag(
    flags: &Flags<'_>,
    key: &str,
    max_len: usize,
) -> AdminResult<Option<String>> {
    let Some(value) = flags.value(key) else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max_len {
        return Err(format!("--{key} must contain 1 to {max_len} characters").into());
    }
    Ok(Some(value.to_owned()))
}

fn parse_redemption_limit(value: &str) -> AdminResult<u32> {
    let value = value.parse::<u32>()?;
    if !(1..=10_000).contains(&value) {
        return Err("--max-redemptions must be between 1 and 10000".into());
    }
    Ok(value)
}

fn parse_seats(value: &str) -> AdminResult<u32> {
    let value = value.parse::<u32>()?;
    if !(3..=10_000).contains(&value) {
        return Err("team seats must be between 3 and 10000".into());
    }
    Ok(value)
}

fn parse_optional_plan_seats(value: &str) -> AdminResult<u32> {
    parse_bounded_u32(
        value,
        0,
        crate::plan_catalog::TEAM_MAXIMUM_SEATS,
        "plan seats",
    )
}

fn parse_amount(value: &str) -> AdminResult<Decimal> {
    let amount = Decimal::from_str(value.trim())?;
    if amount.is_sign_negative() || amount.scale() > 8 {
        return Err("amount must be non-negative with at most 8 decimal places".into());
    }
    Ok(amount)
}

fn parse_bounded_u32(value: &str, minimum: u32, maximum: u32, label: &str) -> AdminResult<u32> {
    let value = value.parse::<u32>()?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{label} must be between {minimum} and {maximum}").into());
    }
    Ok(value)
}

fn parse_positive_u64(value: &str, label: &str) -> AdminResult<u64> {
    let value = value.parse::<u64>()?;
    if value == 0 {
        return Err(format!("{label} must be positive").into());
    }
    Ok(value)
}

fn parse_bool(key: &str, value: &str) -> AdminResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{key} must be true or false").into()),
    }
}

struct Flags<'a> {
    values: BTreeMap<&'a str, &'a str>,
}

impl<'a> Flags<'a> {
    fn new(args: &'a [String], allowed: &[&str]) -> AdminResult<Self> {
        let mut values = BTreeMap::new();
        let mut index = 0;
        while index < args.len() {
            let key = args[index]
                .strip_prefix("--")
                .filter(|key| !key.is_empty())
                .ok_or_else(|| format!("unexpected argument: {}", args[index]))?;
            if !allowed.contains(&key) {
                return Err(format!("unknown option: --{key}").into());
            }
            let value = args
                .get(index + 1)
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| format!("--{key} requires a value"))?;
            if values.insert(key, value.as_str()).is_some() {
                return Err(format!("--{key} may be specified only once").into());
            }
            index += 2;
        }
        Ok(Self { values })
    }

    fn value(&self, key: &str) -> Option<&'a str> {
        self.values.get(key).copied()
    }
}

fn parse_account_state(value: &str) -> AdminResult<AccountState> {
    match value {
        "active" => Ok(AccountState::Active),
        "suspended" => Ok(AccountState::Suspended),
        "denylisted" | "blacklisted" | "blocked" => Ok(AccountState::Denylisted),
        _ => Err("state must be active, suspended or denylisted".into()),
    }
}

fn parse_license_status(value: &str) -> AdminResult<LicenseStatus> {
    match value {
        "active" => Ok(LicenseStatus::Active),
        "past_due" | "past-due" => Ok(LicenseStatus::PastDue),
        "canceled" | "cancelled" => Ok(LicenseStatus::Canceled),
        _ => Err("status must be active, past_due or canceled".into()),
    }
}

fn parse_activation_status(value: &str) -> AdminResult<ActivationCodeStatus> {
    match value {
        "active" => Ok(ActivationCodeStatus::Active),
        "consumed" | "used" => Ok(ActivationCodeStatus::Consumed),
        "revoked" => Ok(ActivationCodeStatus::Revoked),
        _ => Err("status must be active, consumed or revoked".into()),
    }
}

fn parse_device_state(value: &str) -> AdminResult<DeviceState> {
    match value {
        "active" => Ok(DeviceState::Active),
        "removed" => Ok(DeviceState::Removed),
        "revoked" => Ok(DeviceState::Revoked),
        "suspicious" => Ok(DeviceState::Suspicious),
        _ => Err("state must be active, removed, revoked or suspicious".into()),
    }
}

fn parse_plan(value: &str) -> AdminResult<Plan> {
    match value {
        "free" => Ok(Plan::Free),
        "pro" => Ok(Plan::Pro),
        "team" => Ok(Plan::Team),
        _ => Err("plan must be free, pro or team".into()),
    }
}

fn parse_commercial_plan(value: &str) -> AdminResult<Plan> {
    match value {
        "pro" => Ok(Plan::Pro),
        "team" => Ok(Plan::Team),
        _ => Err("commercial offer plan must be pro or team".into()),
    }
}

fn env_bool(key: &str, default: bool) -> AdminResult<bool> {
    let Some(value) = env::var(key).ok() else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{key} must be true or false").into()),
    }
}

fn admin_json_value<T: serde::Serialize>(output: OutputMode, value: &T) -> AdminResult<Value> {
    match output {
        OutputMode::Human => with_human_times(value),
        OutputMode::Raw => Ok(serde_json::to_value(value)?),
    }
}

fn render_json<T: serde::Serialize>(output: OutputMode, value: &T) -> AdminResult<String> {
    Ok(serde_json::to_string_pretty(&admin_json_value(
        output, value,
    )?)?)
}

fn print_json<T: serde::Serialize>(output: OutputMode, value: &T) -> AdminResult<()> {
    println!("{}", render_json(output, value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commercial_offer_plans_exclude_non_commercial_free_tier() {
        assert_eq!(parse_commercial_plan("pro").unwrap(), Plan::Pro);
        assert_eq!(parse_commercial_plan("team").unwrap(), Plan::Team);
        assert_eq!(
            parse_commercial_plan("free").unwrap_err().to_string(),
            "commercial offer plan must be pro or team"
        );
    }

    #[test]
    fn parses_global_output_options_and_strips_them_from_command_args() {
        let (args, output) = parse_admin_options(vec![
            "--raw".into(),
            "license".into(),
            "show".into(),
            "lic_1".into(),
        ])
        .unwrap();
        assert_eq!(output, OutputMode::Raw);
        assert_eq!(args, ["license", "show", "lic_1"]);

        let (args, output) = parse_admin_options(vec![
            "code".into(),
            "list".into(),
            "--output=human".into(),
            "--status".into(),
            "active".into(),
        ])
        .unwrap();
        assert_eq!(output, OutputMode::Human);
        assert_eq!(args, ["code", "list", "--status", "active"]);
    }

    #[test]
    fn rejects_conflicting_output_options() {
        let error = parse_admin_options(vec!["--raw".into(), "--human".into()])
            .expect_err("conflicting options should fail");
        assert!(error.to_string().contains("choose only one output mode"));
    }

    #[test]
    fn resolves_root_group_and_operation_help_without_runtime_dependencies() {
        assert_eq!(requested_help_topic(&[]), Some(Vec::new()));
        assert_eq!(
            requested_help_topic(&["account".into()]),
            Some(vec!["account".into()])
        );
        assert_eq!(
            requested_help_topic(&["code".into(), "issue".into(), "--help".into()]),
            Some(vec!["code".into(), "issue".into()])
        );
        assert_eq!(
            requested_help_topic(&["help".into(), "license".into(), "upsert".into()]),
            Some(vec!["license".into(), "upsert".into()])
        );
        assert_eq!(
            requested_help_topic(&[
                "billing".into(),
                "payment".into(),
                "approve".into(),
                "claim_001".into(),
                "--help".into(),
            ]),
            Some(vec!["billing".into(), "payment".into(), "approve".into(),])
        );
        assert_eq!(requested_help_topic(&["audit".into(), "list".into()]), None);
    }

    #[test]
    fn admin_flags_reject_unknown_duplicate_and_missing_values() {
        let unknown = vec!["--typo".to_owned(), "value".to_owned()];
        assert!(Flags::new(&unknown, &["actor"]).is_err());

        let duplicate = vec![
            "--actor".to_owned(),
            "first".to_owned(),
            "--actor".to_owned(),
            "second".to_owned(),
        ];
        assert!(Flags::new(&duplicate, &["actor"]).is_err());

        let missing = vec!["--actor".to_owned()];
        assert!(Flags::new(&missing, &["actor"]).is_err());
    }

    #[test]
    fn row_versions_must_be_positive_integers() {
        assert_eq!(parse_positive_u64("42", "row version").unwrap(), 42);
        assert!(parse_positive_u64("0", "row version").is_err());
        assert!(parse_positive_u64("-1", "row version").is_err());
        assert!(parse_positive_u64("not-a-number", "row version").is_err());
    }

    #[test]
    fn activation_code_expiry_has_a_safe_default_and_rejects_ambiguous_inputs() {
        let empty = Vec::<String>::new();
        let flags = Flags::new(&empty, &["expires-at", "ttl-days"]).unwrap();
        assert_eq!(
            activation_code_expiry_from_flags(&flags).unwrap(),
            ActivationCodeExpiry::relative_seconds(30 * 24 * 60 * 60).unwrap()
        );

        let relative = vec!["--expires-at".to_owned(), "+12h".to_owned()];
        let flags = Flags::new(&relative, &["expires-at", "ttl-days"]).unwrap();
        assert_eq!(
            activation_code_expiry_from_flags(&flags).unwrap(),
            ActivationCodeExpiry::relative_seconds(12 * 60 * 60).unwrap()
        );

        let absolute = vec!["--expires-at".to_owned(), "2000000000".to_owned()];
        let flags = Flags::new(&absolute, &["expires-at", "ttl-days"]).unwrap();
        assert_eq!(
            activation_code_expiry_from_flags(&flags).unwrap(),
            ActivationCodeExpiry::fixed(Some(2_000_000_000))
        );

        let ambiguous = vec![
            "--expires-at".to_owned(),
            "2027-01-01".to_owned(),
            "--ttl-days".to_owned(),
            "30".to_owned(),
        ];
        let flags = Flags::new(&ambiguous, &["expires-at", "ttl-days"]).unwrap();
        assert!(activation_code_expiry_from_flags(&flags).is_err());
    }

    #[test]
    fn human_output_adds_iso_fields_and_raw_output_stays_exact() {
        let value = json!({
            "expiresAt": 1_798_761_600,
            "payload": {
                "created_at": 1_798_761_600,
                "last_redeemed_at": 1_798_761_600
            }
        });

        let human = admin_json_value(OutputMode::Human, &value).unwrap();
        assert_eq!(human["expiresAt"], 1_798_761_600);
        assert_eq!(human["expiresAtIso"], "2027-01-01T00:00:00Z");
        assert_eq!(human["payload"]["created_at_iso"], "2027-01-01T00:00:00Z");
        assert_eq!(
            human["payload"]["last_redeemed_at_iso"],
            "2027-01-01T00:00:00Z"
        );

        let raw = admin_json_value(OutputMode::Raw, &value).unwrap();
        assert_eq!(raw, value);
        assert!(raw.get("expiresAtIso").is_none());
    }
}

#!/usr/bin/env bash
set -euo pipefail

fixture=__FIXTURE_DIRECTORY__
expression=
while (($#)); do
  case $1 in
    --extract)
      expression=$2
      shift 2
      ;;
    *) shift ;;
  esac
done

case $expression in
  '["database"]["bootstrap_password"]') name=database-bootstrap-password ;;
  '["database"]["migrate_password"]') name=database-migrate-password ;;
  '["database"]["public_password"]') name=database-public-password ;;
  '["database"]["admin_web_password"]') name=database-admin-web-password ;;
  '["database"]["admin_worker_password"]') name=database-admin-worker-password ;;
  '["crypto"]["entitlement_private_pem"]') name=entitlement-es256-private.pem ;;
  '["crypto"]["workspace_keyring_json"]') name=workspace-keyring.json ;;
  '["crypto"]["webhook_keyring_json"]') name=webhook-keyring.json ;;
  '["crypto"]["admin_keyring_json"]') name=admin-keyring.json ;;
  '["proxy"]["admin_secret"]') name=admin-proxy-secret ;;
  *) echo "unexpected SOPS extraction: $expression" >&2; exit 1 ;;
esac
cat -- "$fixture/$name"

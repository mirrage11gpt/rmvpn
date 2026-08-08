#!/bin/sh
set -eu

apk add --no-cache postgresql17-client >/dev/null
restic snapshots >/dev/null 2>&1 || restic init

while true; do
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dump="/backup/risevpn-${stamp}.dump"
  pg_dump --format=custom --no-owner --no-privileges "$DATABASE_URL" > "$dump"
  restic backup "$dump" --tag postgres
  restic forget --keep-daily 30 --prune
  restore_dir="/backup/restore-test"
  rm -rf "$restore_dir"
  mkdir -p "$restore_dir"
  restic restore latest --tag postgres --target "$restore_dir"
  restored="$(find "$restore_dir" -name '*.dump' -type f | head -n1)"
  test -n "$restored"
  admin_url="${DATABASE_URL%/*}/postgres"
  test_url="${DATABASE_URL%/*}/risevpn_restore_test"
  dropdb --if-exists --force --maintenance-db "$admin_url" risevpn_restore_test
  createdb --maintenance-db "$admin_url" risevpn_restore_test
  pg_restore --exit-on-error --no-owner --no-privileges --dbname "$test_url" "$restored"
  psql "$test_url" -v ON_ERROR_STOP=1 -c 'SELECT count(*) FROM plans' >/dev/null
  dropdb --if-exists --force --maintenance-db "$admin_url" risevpn_restore_test
  rm -f "$dump"
  sleep 86400
done

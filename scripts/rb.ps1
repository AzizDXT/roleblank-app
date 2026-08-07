<#
    RoleBlank OS — developer command interface (Windows host).

    WHY THIS EXISTS
    ---------------
    The Windows host enforces an Application Control (WDAC) policy that refuses to
    execute freshly-compiled, unsigned binaries. Every Rust build script therefore
    fails on the host with `os error 4551`. All compilation, testing and tooling is
    consequently performed inside a Linux container (`rust:1-bookworm`, which ships
    the same rustc 1.97.1 as the host toolchain). This script is the thin, explicit
    wrapper around that fact — it hides no behaviour, and every command it runs is
    echoed before execution.

    Usage:  .\scripts\rb.ps1 <command> [args...]
    Run     .\scripts\rb.ps1 help    for the command list.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)] [string] $Command = 'help',
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)] [string[]] $Rest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Constants ---------------------------------------------------------------
$RepoRoot     = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BackendDir   = Join-Path $RepoRoot 'backend'
$DockerSrc    = ($BackendDir -replace '\\', '/')
$RepoSrc      = ($RepoRoot   -replace '\\', '/')

$RustImage    = 'rust:1-bookworm'
$PgImage      = 'postgres:18.4-alpine'
$Net          = 'roleblank_net'
$PgName       = 'roleblank-postgres'
$PgPort       = 5440
$VolTarget    = 'roleblank_target'
$VolRegistry  = 'roleblank_cargo_registry'
$VolPgData    = 'roleblank_pgdata'

# Superuser credentials exist only for the local development container. They are
# NOT used by the application: the app connects as the unprivileged runtime role.
$PgSuperPw    = 'dev_superuser_pw_local_only'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Fail($msg) { Write-Host "!!! $msg" -ForegroundColor Red }

function Invoke-Checked([string[]] $CmdLine) {
    Write-Host "    $ $($CmdLine -join ' ')" -ForegroundColor DarkGray
    & $CmdLine[0] @($CmdLine[1..($CmdLine.Length - 1)])
    if ($LASTEXITCODE -ne 0) { throw "command failed with exit code $LASTEXITCODE" }
}

# Runs an arbitrary shell command inside the Rust toolchain container, attached to
# the development network so it can reach PostgreSQL by container name.
function Invoke-InRust([string] $Shell, [switch] $Interactive) {
    $args = @(
        'run', '--rm', '--network', $Net,
        '-v', "${DockerSrc}:/work",
        '-v', "${RepoSrc}:/repo",
        '-v', "${VolTarget}:/work/target",
        '-v', "${VolRegistry}:/usr/local/cargo/registry",
        '-e', 'CARGO_TERM_COLOR=always',
        '-e', "DATABASE_URL=postgres://roleblank_migrator:dev_migrator_pw@${PgName}:5432/roleblank",
        '-e', "TEST_DATABASE_ADMIN_URL=postgres://postgres:${PgSuperPw}@${PgName}:5432/postgres",
        '-w', '/work', $RustImage, 'bash', '-c', $Shell
    )
    Write-Host "    $ docker run ... $RustImage bash -c `"$Shell`"" -ForegroundColor DarkGray
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "container command failed with exit code $LASTEXITCODE" }
}

function Ensure-Infra {
    if (-not (docker network ls --format '{{.Name}}' | Select-String -SimpleMatch $Net -Quiet)) {
        Invoke-Checked @('docker', 'network', 'create', $Net)
    }
    foreach ($v in @($VolTarget, $VolRegistry, $VolPgData)) {
        if (-not (docker volume ls --format '{{.Name}}' | Select-String -SimpleMatch $v -Quiet)) {
            Invoke-Checked @('docker', 'volume', 'create', $v)
        }
    }
}

function Db-Up {
    Ensure-Infra
    $running = docker ps --filter "name=^/${PgName}$" --format '{{.Names}}'
    if ($running) { Write-Step "postgres already running on 127.0.0.1:$PgPort"; return }
    docker rm -f $PgName 2>&1 | Out-Null
    Write-Step "starting $PgImage as '$PgName' (127.0.0.1:$PgPort)"
    # PostgreSQL 18 images expect the volume at /var/lib/postgresql (not /data).
    Invoke-Checked @(
        'docker', 'run', '-d', '--name', $PgName, '--network', $Net,
        '-e', "POSTGRES_PASSWORD=$PgSuperPw", '-e', 'POSTGRES_USER=postgres', '-e', 'POSTGRES_DB=postgres',
        '-e', 'POSTGRES_INITDB_ARGS=--data-checksums',
        '-v', "${VolPgData}:/var/lib/postgresql",
        '-p', "127.0.0.1:${PgPort}:5432",
        '--health-cmd', 'pg_isready -U postgres', '--health-interval', '3s', '--health-retries', '20',
        $PgImage,
        # The integration harness gives every test its own database and pool, and cargo
        # runs test binaries in parallel. PostgreSQL's default 100 connections is the
        # binding constraint, not the code: exceeding it surfaces as 503 in the middle
        # of unrelated assertions, which reads like a product defect and is not one.
        '-c', 'max_connections=400', '-c', 'shared_buffers=256MB'
    )
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 750
        if ((docker inspect -f '{{.State.Health.Status}}' $PgName 2>$null) -eq 'healthy') {
            Write-Step 'postgres healthy'; return
        }
    }
    throw 'postgres did not become healthy in time'
}

function Db-Down { docker rm -f $PgName 2>&1 | Out-Null; Write-Step 'postgres stopped' }

function Db-Reset {
    Db-Down
    docker volume rm $VolPgData 2>&1 | Out-Null
    Write-Step 'postgres data volume destroyed'
    Db-Up
}

# Provisions the two separate PostgreSQL identities required by the privilege
# separation design (see docs/backend/08-operations.md).
function Db-Provision {
    Db-Up
    Write-Step 'provisioning roles and database (idempotent)'
    $sqlPath = Join-Path $RepoRoot 'ops/sql/provision_dev.sql'
    if (-not (Test-Path $sqlPath)) { throw "missing $sqlPath" }
    Get-Content -Raw $sqlPath | docker exec -i $PgName psql -v ON_ERROR_STOP=1 -U postgres -d postgres
    if ($LASTEXITCODE -ne 0) { throw 'provisioning failed' }
    Write-Step 'roles provisioned'
}

switch ($Command.ToLowerInvariant()) {
    'help' {
        @'
RoleBlank OS developer commands

  db-up            start the development PostgreSQL 18 container
  db-down          stop it
  db-reset         destroy the data volume and start clean
  db-provision     create roleblank database + migrator/runtime roles (idempotent)
  psql             open psql as superuser against the dev database
  migrate          run pending migrations as the migrator role
  build            cargo build
  release          cargo build --release
  run              run the API (foreground, port 8090)
  test             cargo test  (unit + integration; requires db-provision)
  test-security    cargo test --test security_suite
  lint             cargo fmt --check && cargo clippy -D warnings
  fmt              cargo fmt
  audit            cargo audit (installs into the container on demand)
  deny             cargo deny check
  coverage         cargo llvm-cov
  load-test        run the load-test script against a running API
  verify-audit     run the audit hash-chain verification command
  backup-dev       logical backup of the dev database
  restore-dev      restore the most recent dev backup
  sh               interactive shell inside the Rust container
'@ | Write-Host
    }
    'db-up'        { Db-Up }
    'db-down'      { Db-Down }
    'db-reset'     { Db-Reset }
    'db-provision' { Db-Provision }
    'psql'         { docker exec -it $PgName psql -U postgres -d roleblank }
    'migrate'      { Db-Up; Invoke-InRust 'cargo run --bin roleblank-api -- migrate' }
    'build'        { Invoke-InRust 'cargo build' }
    'release'      { Invoke-InRust 'cargo build --release' }
    'run'          { Invoke-InRust 'cargo run --bin roleblank-api -- serve' }
    'test'         { Db-Up; Invoke-InRust ('cargo test ' + ($Rest -join ' ')) }
    'test-security'{ Db-Up; Invoke-InRust 'cargo test --test security_suite -- --nocapture' }
    'lint'         { Invoke-InRust 'cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings' }
    'fmt'          { Invoke-InRust 'cargo fmt --all' }
    'audit'        { Invoke-InRust 'cargo audit --version >/dev/null 2>&1 || cargo install cargo-audit --locked; cargo audit' }
    'deny'         { Invoke-InRust 'cargo deny --version >/dev/null 2>&1 || cargo install cargo-deny --locked; cargo deny --manifest-path /work/Cargo.toml --config /repo/deny.toml check' }
    'coverage'     { Db-Up; Invoke-InRust 'cargo llvm-cov --version >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked; rustup component add llvm-tools-preview; cargo llvm-cov --summary-only' }
    'verify-audit' { Invoke-InRust 'cargo run --bin roleblank-api -- verify-audit' }
    'sh'           { docker run --rm -it --network $Net -v "${DockerSrc}:/work" -v "${RepoSrc}:/repo" -v "${VolTarget}:/work/target" -v "${VolRegistry}:/usr/local/cargo/registry" -w /work $RustImage bash }
    default        { Write-Fail "unknown command '$Command'"; exit 2 }
}

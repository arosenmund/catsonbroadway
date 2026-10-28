# Cats On Broadway

Cats On Broadway is a single use web hosting tool that allows you to serve a single file, 

## TLS Certificate

The TLS certificate is controlled by the **cert_config.json** file. The default
file defines named profiles:

- `local-dev`: localhost and 127.0.0.1 for local testing.
- `public-site`: example public website shape using `www.example.test`.
- `api-service`: API service shape using `api.example.test`.
- `static-content`: static asset host shape using `static.example.test`.
- `internal-service`: internal service shape with localhost fallback SANs.

Select a profile with `--cert-profile <name>`. If no profile is selected, the
`default_profile` value from `cert_config.json` is used. A legacy flat JSON cert
config is still supported for custom configs.

Each profile can set an optional `issuer` object independently of the server's
subject fields. For example:

```json
"issuer": {
  "organization": "Local Development PKI",
  "organizational_unit": "Local Certificate Services",
  "country": "US",
  "province": "Example State",
  "locality": "Example City",
  "common_name": "Local Development Root CA"
}
```

These six fields describe the issuer's distinguished name. Omitted or empty
issuer fields do not inherit values from the server subject. An issuer object
must contain at least one nonempty name field. Omitting `issuer` or setting it
to `null` preserves the original self-signed server certificate behavior. The
same optional object is supported in legacy flat configs.

With `issuer` present, the server generates a local CA with its own key and uses
it to sign the server certificate. `cert.pem` contains the server certificate
first, followed by the CA certificate; `key.pem` contains only the server's
private key. The CA private key is discarded. Every normal startup regenerates
the certificates and keys and overwrites these two files, so the CA changes on
each run; `--dry-run` writes neither file.

All five included profiles use generic example issuers. These generated CAs
are not publicly trusted, and the application does not install trust in clients
or the operating system. Configuring an issuer name does not establish trust.

## Headers

Headers are configured by the **headers.json** file. The default file defines
named profiles:

- `dev-self-signed`: default profile for local/self-signed certificate use; no
  HSTS.
- `minimal-static`: small compatibility-oriented static-file header set.
- `general-website`: common browser-facing website headers without HSTS.
- `api-json`: conservative API-oriented response headers.
- `strict-security`: stricter browser security headers, including HSTS.

Select a profile with `--header-profile <name>`. If no profile is selected, the
`default_profile` value from `headers.json` is used. A legacy flat JSON map of
header names to values is still supported for custom configs.

## Logging

Runtime logs are written to the current directory by default:

- `gin.log`: Gin framework/recovery output
- `access.log`: request access log entries

Use `--log-dir <path>` to place logs in a dedicated directory. Use
`--no-access-log` to disable request access logging. Use `--json-logs` to write
access log entries as JSON lines with timestamp, client IP, user-agent, method,
path, status, latency, and any Gin handler errors.

## Interactive TUI

Use `--tui` to open an interactive terminal setup screen before the server
starts. The form is prefilled from the normal CLI defaults and any flags you
already provided, so scripted usage and interactive usage share the same
settings model.

The TUI lets you choose the site from a dropdown populated by `stage_options`
and the payload from a dropdown populated by files under `payload_options`.
Choose `(none)` to serve only the selected site. The TUI also lets you choose
the payload download policy, certificate profile, header profile, listener
addresses, download URL settings, and log options. Use the Validate button to
run preflight checks before binding ports, then Start to launch the HTTP/HTTPS
server.

After Start, the TUI stays open as a color-coded live dashboard. It shows active
HTTP/HTTPS addresses, the selected site, cert/header profiles, payload URL and
download commands, request counters, and recent requests. Dashboard keys:

- `p`: pick or hot-swap a payload from `payload_options`
- `r`: rotate the current payload URL
- `n`: disable payload serving
- `f`: cycle recent-request filters
- `c`: open a command-focused view
- `q`, Esc, or Ctrl+C: stop the servers and return to the shell

## Web Stages

The **stage_options** folders has websites that can be selected and used. Feel free to add to these using the same structure and format for the folders/files.  There is no tech support for your custom website not working, but you are encouraged to add your own.

## Release Builds

Release scripts require Go to be installed and available on `PATH`.
Status output is colored by default when the terminal supports it. Use
`--no-color` in either release script for plain logs.

Build all default release targets from PowerShell:

```powershell
.\scripts\release.ps1 --version dev --clean
```

Build all default release targets from Bash:

```bash
bash ./scripts/release.sh --version dev --clean
```

Artifacts are written to `dist/`. The default matrix builds Windows, Linux, and
macOS targets:

- Windows: x86, x64, arm64
- Linux: x86, x64, arm64
- macOS: x64, arm64

macOS 32-bit x86 is not a supported Go target. Use `--targets` to build a
smaller comma-separated/custom target list. Release builds inject version,
commit, build date, and target metadata into `--version`.

By default each target also gets a release archive:

- Windows targets: `.zip`
- Linux/macOS targets: `.tar.gz`

Archives include the binary, README, `cert_config.json`, `headers.json`,
`stage_options`, and `payload_options`. `SHA256SUMS.txt` is written beside the
artifacts. Use `--no-archives` to build only binaries.

## RUNNING CatsOnBroadway

To run cats on broadway you need to specific the file that you want to be able to download/server. AND all of the files that were discussed above. 

Payload paths expire after one successful download by default. Use
`--payload-max-downloads <n>` to allow more downloads per generated path, or
`--payload-max-downloads 0` to keep one persistent path.

Generated download commands use the first host from `cert_config.json` by
default. Use `--download-host <host>` and `--download-port <port>` to print a
specific reachable URL. Use `--output-name <file>` to override the output
filename; otherwise it defaults to the basename of `--serve`.

The server listens on `:80` and `:443` by default. Use `--http-addr <addr>` and
`--https-addr <addr>` for non-privileged ports, for example
`--http-addr :8080 --https-addr :8443`. If `--download-port` is not set, printed
download URLs use the port from `--https-addr`.

Use `--dry-run` to validate configuration and print a startup summary without
binding ports or writing generated certificate files. Use `--version` to print
build metadata and exit.

For an interactive setup flow, add `--tui`:

```powershell
go run . --tui --http-addr :8080 --https-addr :8443
```

> Linux running instructions.   (Modify stage with your desired website path, as well as file to serve.)

bash```
.\catsonbroadway-v2.elf --site ./stage_options/IC-STAGE-3 --serve ./test.txt --cert-profile local-dev --header-profile dev-self-signed --download-host 127.0.0.1 --http-addr :8080 --https-addr :8443 --cert-config ./cert_config.json --headers ./headers.json

```

> Windows running instructions.  (Modify stage with your desired website path, as well as file to serve.)

batch```
.\catsonbroadway-v2.exe --site .\stage_options\IC-STAGE-3\ --serve .\test.txt --cert-profile local-dev --header-profile dev-self-signed --download-host 127.0.0.1 --http-addr :8080 --https-addr :8443 --cert-config .\cert_config.json --headers .\headers.json
```


The server prints curl, wget, PowerShell, Windows PowerShell 5.1, Python stdlib,
and Python requests examples for the active payload URL. Certificate-check
bypass flags are included for generated self-signed certificates and generated
local CA certificates, since neither is trusted by clients automatically.

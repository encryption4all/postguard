# Grafana dashboard for cryptify usage

`cryptify-usage.json` is the reference dashboard behind
[postguard#305](https://github.com/encryption4all/postguard/issues/305): messages
sent per channel, and cryptify storage in use per environment.

It reads only metrics that `GET /metrics` already exports (see
`cryptify/src/metrics.rs`). No exporter change is needed to import it.

## Metrics it uses

| Metric | Type | Labels | Panel |
| --- | --- | --- | --- |
| `cryptify_uploads_total` | counter | `channel` | Messages sent per channel |
| `cryptify_upload_bytes_total` | counter | `channel` | Bytes uploaded per channel |
| `cryptify_uploads_by_app_total` | counter | `app` | Messages per client app |
| `cryptify_storage_bytes` | gauge | none | Storage in use |
| `cryptify_active_files` | gauge | none | Files on disk |
| `cryptify_expired_files_total` | counter | none | Uploads expired before finalize |

`channel` is `website`, `staging-website`, `outlook`, `thunderbird`, `api` or
`unknown`; `app` is `pg-js`, `pg-dotnet`, `pg4ol`, `pg4tb` or `unknown`. Both
label sets are seeded at 0 on startup, so a channel with no traffic still shows
as a zero line instead of vanishing from the legend.

The counters are per process. A cryptify restart resets them to 0, which is why
every panel goes through `increase()` rather than reading the raw counter.

## The `env` label is supplied by Alloy, not by cryptify

Nothing in the exporter knows which deployment it is running in. Splitting
staging from Procolix production is the collector's job, and the two
environments get there by different paths; Cockpit cannot reach into the
Procolix network, so neither one is a Prometheus job pulling over HTTPS.

- **prod** — the `storage.postguard.eu` deployment. Grafana Alloy runs on the
  Procolix host, installed from apt, and scrapes cryptify locally at
  `127.0.0.1:8002/metrics` every 60s as `job="cryptify"`, then `remote_write`s
  to Scaleway Cockpit. Because the scrape is loopback, Alloy needs no bearer
  token and no TLS. `env` is an Alloy `external_labels` entry, `prod`,
  alongside `cluster = "procolix-prod"` and `host`.
- **staging** — the `storage.staging.postguard.eu` deployment. cryptify runs
  in the Kapsule namespace `postguard-dev`, discovered by the
  `k8s.grafana.com/*` pod annotations. The `env` label is not attached on
  this side yet; tracked in
  [postguard-ops#70](https://github.com/privacybydesign/postguard-ops/issues/70).
  Do not treat staging as working in this dashboard until that lands.

Set the same token as `metrics_token` in each deployment's `conf/config.toml`
(or `ROCKET_METRICS_TOKEN` in its environment). With no token configured the
endpoint answers unauthenticated and logs a warning at startup. This is the
endpoint's own auth, owned separately by #372 — it is not part of either
collection path above, since both scrape `/metrics` locally rather than
presenting the token over the network.

One trap worth keeping in mind if credentials come up here: Cockpit push
tokens are not Grafana service-account tokens. The former pushes data in, the
latter queries it back out.

The two gauges carry no labels of their own, so a raw select distinguishes series
only by `instance` and `job`. The storage and file-count panels therefore go
through `max by (env)`: with one target per environment it changes nothing, and
if an environment ever gets a second target sharing the volume it reports the
volume once instead of twice. Switch those three panels to `sum by (env)` if the
targets get separate volumes.

## Importing

Grafana, Dashboards, New, Import, upload `cryptify-usage.json`, pick the
Prometheus data source. The datasource is a dashboard variable rather than a
baked-in UID, so the same file imports into any Grafana instance.

Storage panels are sampled from `data_dir` on a background task every
`metrics_scan_interval_secs` (60 by default), so they trail a burst of uploads
by up to one interval. The dashboard refreshes every 5 minutes and opens on a
30-day window, which suits monthly usage reporting; shorten both if you are
watching a deploy.

## Keeping it honest

`mod dashboard_tests` in `cryptify/src/metrics.rs` reads this JSON and checks it
against `Metrics::render()`: every metric the exporter emits appears on the
dashboard, every `cryptify_*` name the dashboard queries is one the exporter
actually emits, and every panel filters on `env=~"$env"`. Renaming a metric or
adding a panel that ignores the environment filter fails `cargo test`.

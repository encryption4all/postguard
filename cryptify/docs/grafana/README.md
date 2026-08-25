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

## The `env` label is supplied by Prometheus, not by cryptify

Nothing in the exporter knows which deployment it is running in. Splitting
staging from Procolix production is the scrape config's job: attach a static
`env` label per job, and the dashboard's `Environment` variable picks it up.

```yaml
scrape_configs:
  - job_name: cryptify
    metrics_path: /metrics
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/cryptify-metrics-token
    static_configs:
      - targets: ["cryptify.staging.postguard.eu"]
        labels:
          env: staging
      - targets: ["cryptify.postguard.eu"]
        labels:
          env: production
```

Set the same token as `metrics_token` in each deployment's `conf/config.toml`
(or `ROCKET_METRICS_TOKEN` in its environment). With no token configured the
endpoint answers unauthenticated and logs a warning at startup, so keep it
restricted to the Prometheus segment at the firewall as well.

Adjust the target hostnames to whatever the two deployments actually resolve to.
The dashboard does not care about the hostnames, only that `env` is present.

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

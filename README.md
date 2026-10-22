# InfraLens

InfraLens is a local Linux command-line tool that collects bounded system evidence
and writes a private, versioned JSON snapshot with coverage and assessment details.

The package requires Python 3.12 or newer. In this cloud environment, point uv's
cache to writable temporary storage, then install development dependencies with
the committed lock file from the repository root:

```sh
export UV_CACHE_DIR=/tmp/uv-infralens-cache
export UV_LINK_MODE=copy
uv sync --frozen --extra dev
```

Run a local scan with:

```sh
uv run infralens scan --local --output ./snapshot.json
```

The output file is created with mode `0600`; existing files require `--overwrite`.
Use `--fail-on-partial` to return status 3 after saving when any collector is partial,
unsupported, or otherwise incomplete. Snapshots may contain hostnames, addresses,
process names, mountpoints, and service names; review them before sharing. Systemd
support and RHEL/WSL compatibility require separate validation.

## Design and documentation

- [Portfolio architecture overview](docs/PORTFOLIO_OVERVIEW.md): components, evidence flow, MVP status and safe demo.
- [Technical architecture](docs/ARCHITECTURE.md) and [data contract](docs/DATA_CONTRACT.md): detailed internal design and snapshot semantics.
- [Testing strategy](docs/TEST_STRATEGY.md): validation scope and known environmental limitations.

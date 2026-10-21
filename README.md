# InfraLens

InfraLens is a command-line tool for collecting and reviewing evidence about a
Linux host. The project is in its planning and bootstrap stage; discovery is not
implemented yet.

The package requires Python 3.12 or newer. In this cloud environment, point uv's
cache to writable temporary storage, then install development dependencies with
the committed lock file from the repository root:

```sh
export UV_CACHE_DIR=/tmp/uv-infralens-cache
uv sync --frozen --extra dev
```

The initial CLI supports `--help` and `--version`. The planned `scan` command
currently reports that scanning is not implemented.

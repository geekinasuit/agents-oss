# agents-oss

Multi-language utilties, common-code, and other open-source assets used by GeekInASuit
agentic systems. These are things we find useful for others to consume, read, copy, etc.
They may only be useful to other geekinasuit projects, but they're here in case they are
more generally useful.

## Layout

- `agency/` — the agency framework (this repository's Bazel module is named `agency`).
- `commons/` — shared ingredient libraries, usable independently of the framework.
- `foo/` — a temporary probe package validating the module skeleton; removed when the
  first real package lands.

Status: early; APIs are unstable.

## Building

Bazel (version pinned in `.bazelversion`; [bazelisk](https://github.com/bazelbuild/bazelisk)
recommended):

```
bazel test //...
```

Consume from another Bazel module with `bazel_dep(name = "agency", ...)` plus an
`archive_override` on a release archive until the module is in a registry.

## License

Apache-2.0 unless otherwise marked — some individual projects or packages may be MIT
licensed, marked in the package. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). DCO sign-off, no CLA.

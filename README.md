# agents-oss

Multi-language utilties, common-code, and other open-source assets used by GeekInASuit
agentic systems. These are things we find useful for others to consume, read, copy, etc.
They may only be useful to other geekinasuit projects, but they're here in case they are
more generally useful.

## Layout

- `agency/` — the agency framework (this repository's Bazel module is named `agency`).
- `commons/` — shared ingredient libraries, usable independently of the framework.

Status: early; APIs are unstable.

## Building

Bazel (version pinned in `.bazelversion`; [bazelisk](https://github.com/bazelbuild/bazelisk)
recommended):

```
bazel test //...
```

The ACP pod adapter (`agency/pod/adapter`) pins an npm package by lockfile. Bootstrap it
after cloning by running, in `agency/pod/adapter`:

```
npm ci --ignore-scripts
```

(The in-directory form matches the canary's own remediation message and avoids npm's
out-of-tree `--prefix` handling, which has proven environment-sensitive.)

`npm ci` only — never plain `npm install`, which may rewrite the lock. The lockfile IS
the pin; upgrading it is a deliberate, reviewed act. `bazel test //...` does not need
the install (the batteries drive a wire-faithful fake agent); it is required to run the
real-adapter pod canary.

Consume from another Bazel module with `bazel_dep(name = "agency", ...)` plus an
`archive_override` on a release archive until the module is in a registry.

## License

Apache-2.0 unless otherwise marked — some individual projects or packages may be MIT
licensed, marked in the package. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). DCO sign-off, no CLA.

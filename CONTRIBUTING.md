# Contributing

Contributions are welcome.

## Developer Certificate of Origin

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO)
rather than a CLA. Every commit must carry a `Signed-off-by` line (`git commit -s` adds it),
certifying that you have the right to submit the work under this repository's license.

## Pull requests

- Keep changes focused; one concern per PR.
- CI (`bazel test //...`) must be green.
- Public API — exported types and functions — carries KDoc. Implementation comments only where
  the code doesn't explain itself.

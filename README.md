# sentinel-secrets

A command-line tool I'm building to scan a git repository, both its current
files and its full commit history, for secrets that shouldn't be there:
API keys, access tokens, private keys, and other high-entropy credentials
accidentally committed along the way. Detection is signature-based (known
key formats) combined with entropy analysis (catching high-randomness
strings that don't match a known format), with a baseline file to mark
confirmed false positives so they stop reappearing on every run.

This is a passive, read-only tool: it reads files and git history on disk
and reports what it finds. It never sends anything over the network, never
attempts to validate whether a found key is actually live, and never
modifies the repository it scans.

Still under construction. See the [open issues](https://github.com/ZukoG/sentinel-secrets/issues)
for the current build plan.

## License

[MIT](LICENSE)

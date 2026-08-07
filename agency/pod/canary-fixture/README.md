# PodCanary cold-start seed

The checked-in seed for the scheduled real-adapter canary's `CLAUDE_CONFIG_DIR`
(`agency/pod/PodCanary.kt`). Every canary run creates a FRESH temp config directory and
copies this directory's files into it (this README excluded — it is the fixture's
documentation, not seed data), then discards it with the run.

Deliberately empty of seed files today: an empty config dir IS the cold start — the
canary runs `initialize` only (no session, no model turn), so the adapter needs no
configuration at all. The directory exists as the reviewed seam for any future
needed-but-cold file (e.g. a settings stub a later adapter release requires), so adding
one is a visible, reviewed act rather than a canary code change.

Cold-start discipline (binding): nothing here may ever carry state between runs or from
any agent; the canary's output is telemetry only and is never hydrated into any agent's
context.

# Running a lead

This takes one ticket through a scripted lead to approved gates. `scripted_lead` is a ticket lead with no model in it: its cognition is scripted and its pods are fakes, but its gates are real. Each gate is announced over a nostr relay, and an approval signed by a key you authorized releases it.

## What you need

- JDK 21 or later, and Bazel (see the [README](../README.md)).
- A nostr relay reachable from both the lead and the approver. It must accept NIP-59 gift wraps (kind 1059) and keep them for later readers. The tools default to `--auth nip42`; pass `--auth none` to a relay with no NIP-42.
- If the relay restricts who can publish, admit the lead's and each approver's public key. Gift wraps are signed by a fresh key each time, so the relay must decide by the key that authenticated with NIP-42, not by the event's author.
- Three places, which should stay separate:

| Key | Who holds it | Where it must not be |
|---|---|---|
| Root | You, offline when not signing a spec | On the lead's host |
| Approver | Each person who approves | On the lead's host |
| Lead | The lead | Anywhere else |

The relay is a transport, not a trusted party. It can delay or drop messages, so a gate can stall, but it cannot forge one: the approval tool shows only notices the lead signed, and the lead accepts only approvals signed by a key in the spec.

To try this without a shared relay, `nak serve` runs a throwaway relay on your machine, with `--auth none` and `--relay ws://localhost:10547`.

## 1. Build the tools

```
bazel build //agency/wiring:auth_spec_deploy.jar //agency/wiring:lead_status_deploy.jar //agency/wiring:approval_deploy.jar
```

Each jar lands in `bazel-bin/agency/wiring/`. Copy them somewhere stable, since the next build can replace them. The jars hold no secrets, so copy them wherever a step below needs them.

Add `--enable-native-access=ALL-UNNAMED` to every `java` command below if your JDK warns about native access. The `SLF4J(W)` lines that the lead and `lead_status` print at start are harmless: no logger is bundled.

## 2. Make the keys

A key file holds a secret key as 64 hex characters. Make each key where it will live, as the user who will read it, so that it never travels. Only public keys move between the three places. On each machine, run this for that machine's key, here `root.key`:

```
(umask 077; openssl rand -hex 32 > root.key)
java -jar auth_spec_deploy.jar pubkey --root-key-file root.key
```

`pubkey` prints the public key of whichever key file you give it, despite the flag's name, and it never prints the key. Below, the three results are ROOT_PUB, APPROVER_PUB and LEAD_PUB.

## 3. Sign a spec

The spec says who may approve. Write it as `spec.json`:

```json
{"principals": [{"principalId": "operator", "role": "approver",
                 "keys": [{"schemeId": "bip340", "publicKey": "APPROVER_PUB"}]}],
 "quorum": {"type": "signer", "principalId": "operator"}}
```

For more than one approver, list each principal and use a group: `{"type": "group", "threshold": 2, "children": [{"type": "signer", "principalId": "a"}, {"type": "signer", "principalId": "b"}]}`. A gate then stays `not released` until the threshold is met.

Sign it where the root key lives:

```
java -jar auth_spec_deploy.jar sign --spec spec.json --root-key-file root.key --out spec.signed.json
```

It refuses a spec that would not load or could never be met, and it never overwrites a file. Put the root key away, and copy `spec.signed.json` to the lead's host.

## 4. Build the lead with the root pinned

The root is compiled in. No flag or file of the runner's chooses it, and a build without one refuses to start.

```
bazel build //agency/wiring:scripted_lead_deploy.jar --//agency/wiring:pinned_root=ROOT_PUB
```

The pin holds only if whoever can start the lead cannot change how it starts: a launch command that puts its own classpath first can shadow the pin. So the lead's OS user must not be able to write the jar, `spec.signed.json`, the supervisor's unit file, or the directories that hold them, since a writable directory lets it replace a file it cannot write. Have another user own them. The lead does not check `spec.signed.json` yet ([#353](https://github.com/geekinasuit/agents-oss/issues/353)), and nothing checks the rest.

## 5. Start the lead

Run it as the lead's OS user, on the lead's host, from a directory that user owns. Its key, ticket file and journal live there. Step 4's files stay apart, here in `/srv/agency`, which that user can read but not write.

The ticket file lists ticket references, one per line, taken in order. Write it before you start the lead:

```
echo t1 > tickets.txt
java -jar /srv/agency/scripted_lead_deploy.jar --journal journal --component my-lead --ticket-file tickets.txt \
  --spec /srv/agency/spec.signed.json --relay wss://RELAY --lead-key-file lead.key
```

The journal directory is created if missing, readable by that user alone. A failure at start prints one line on stderr saying why. Keep `--journal` and `--component` the same across restarts, because a journal verifies only under its own component.

The lead reads the ticket file when the lead starts and when a ticket ends. A lead with no ticket left is idle: it keeps running, but do not count on anything waking it, so restart it after you add a ticket. A missing ticket file looks the same, with no error.

### Under a supervisor

| Exit | Meaning | What a supervisor should do |
|---|---|---|
| 0 | Stopped from within | Leave it stopped |
| 1 | Refused at start: no pin, a bad spec, an unreadable key file, a journal that did not open | Stop and tell someone. A restart repeats it. |
| 2 | Usage error | Stop and fix the command |
| 3 | The lead's loop ended on a fault, or the journal did not verify | Restart, with a limit. A journal that does not verify fails every time ([#359](https://github.com/geekinasuit/agents-oss/issues/359)). |
| 4 | The approval ingress ended | Restart, with a limit |
| 143, 130 | Stopped by SIGTERM, SIGINT | Treat as a clean stop |

143 and 130 are exit statuses, not deaths by signal, so a systemd unit must list them:

```
[Unit]
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
User=LEAD_USER
Restart=on-failure
RestartSec=30
RestartPreventExitStatus=1 2
SuccessExitStatus=143 130
```

launchd has no such lists. With `KeepAlive` set to `SuccessfulExit: false`, it restarts on every nonzero exit, including 143, 1 and 2, at most once per `ThrottleInterval` (10 seconds by default). So stop the lead by unloading the job, and raise `ThrottleInterval` so a refusal does not spin.

## 6. Read its status

As the lead's OS user, on the lead's host, beside the running lead:

```
java -jar lead_status_deploy.jar --journal journal --component my-lead --spec /srv/agency/spec.signed.json --root ROOT_PUB
```

It only reads. It prints each open gate as `released` or `not released`, with its nonce, then the nonces, approvals, drops and escalations. A ticket's first gate, `plan-approval:t1`, appears once the scripted planner has finished, within seconds.

## 7. Approve the gates

Where the approver's key lives:

```
java -jar approval_deploy.jar inbox --relay wss://RELAY --key-file approver.key --lead LEAD_PUB
```

It prints each gate-open notice from that lead: the gate, its nonce, its digest and the artifact you are approving. It lists every notice the relay still holds, including spent ones, so take the nonce of the gate `lead_status` shows as `not released`. If you cannot run `lead_status`, ask whoever runs the lead. Approve it:

```
java -jar approval_deploy.jar approve --relay wss://RELAY --key-file approver.key --lead LEAD_PUB --nonce NONCE
```

It prints the notice again and asks you to type the first 8 characters of the digest. Only then does it sign, wrap the approval to the lead and publish it. `the relay accepted it` means only that: the lead may still refuse the approval, so check `lead_status`.

`lead_status` then shows the gate `released`, with your approval under `verified approvals`. A rejected approval on the gate's open nonce appears under `approvals rejected on arrival`, with the reason. An approval naming a spent or unknown nonce leaves no such line: the gate just stays `not released`. Check that you used the open nonce.

A ticket has two gates. Releasing `plan-approval:t1` sends it to execution, and `commit-approval:t1` opens within seconds. Run `inbox` and `approve` again for that one.

The last approval finishes the ticket, and its gates and approvals leave the status. So done looks like `open gates (0)` and `verified approvals (0)`, with a higher `head seq`, not like `released` ([#358](https://github.com/geekinasuit/agents-oss/issues/358)). The lead then takes the next ticket in the file, or goes idle.

## When something is wrong

| What you see | What it means |
|---|---|
| `root signature does not verify against the pinned root key` | The spec was signed by another root than the one built in, or than `lead_status --root` names. Sign it again, or use the right pin. |
| `this binary was built without a pinned root` | Step 4's flag was missing from the build. |
| `no gate-open notices from the lead` | The wrong `--lead`, a wrong approver key, or no gate open yet. Check `lead_status`. |
| `approvals may not be arriving: 5 attempts in a row failed` | The lead cannot reach the relay, or the relay refuses it. The line ends with the last failure. It keeps trying to read approvals. |
| An open gate in `lead_status` whose nonce is missing from `inbox` | The notice has not reached the approver. The lead retries for about 42 minutes and prints nothing while it does, even if the relay serves reads but refuses its publishes. Check the relay now, before the next row. |
| `gate-open notify failed for GATE (KIND) after 5 attempts`, under `escalations` | The lead gave up announcing that gate. The gate stays open and nothing announces it again, not even a restart, so an approver who never received the notice cannot approve it ([#113](https://github.com/geekinasuit/agents-oss/issues/113)). |
| `the relay did not finish sending its stored notices` | The approval tool could not read the relay in time. This is a failure, not an empty inbox. Raise `--wait`, or check the relay. |
| `no notice for nonce` | The relay does not hold that notice. Check the nonce against `lead_status`. |
| `lead_status` exits 3 | The journal did not verify. If the line names another component, `--component` is wrong. If it names a schema version, this build cannot read the journal. Otherwise the journal was changed or damaged: stop and find out why. |
| A `WARNING` line naming another spec in `lead_status` | That gate was opened under a different spec, so the lead may reach other verdicts than the ones printed. |

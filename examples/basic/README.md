# Basic Example

What it shows: scoring a real script, and turning that score into a gate.

`deploy.sh` is deliberately mixed — a couple of safe lines, one that is not.

## Run

Score every command in the script, with line numbers:

```sh
scoville -f deploy.sh
```

Use it as a gate — exits 1 as soon as something reaches `high`:

```sh
scoville -f deploy.sh --fail-on high --quiet
echo "exit: $?"
```

Machine-readable, every factor included:

```sh
scoville -f deploy.sh --format json
```

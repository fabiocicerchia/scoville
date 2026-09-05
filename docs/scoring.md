# Scoring

Every command starts from a **base** (what the binary does), then collects
**amplifiers** (flags, targets, privilege, production hints) and **dampeners**
(`--dry-run`, regenerable targets like `node_modules`). The factors are summed
and clamped to 0–100.

## Bands

| Band       | Score  | Meaning                                     |
| ---------- | ------ | ------------------------------------------- |
| `safe`     | 0–14   | reads state, changes nothing                |
| `low`      | 15–34  | local, trivially undone                     |
| `medium`   | 35–59  | mutates real state, recoverable with effort |
| `high`     | 60–84  | destructive and scoped                      |
| `critical` | 85–100 | unbounded, irreversible, or both            |

Bands are deliberately coarse: the band drives decisions, the score only orders
commands within a band.

## The two facets

Two orthogonal facets are reported alongside the score, because they answer
different questions:

- **scope** — `none → file → directory → container → host → network → cluster → account`
- **reversibility** — `reversible → recoverable → irreversible`

`terraform destroy` and `rm -rf ~/notes` can score similarly and still deserve
different answers; the facets are what make that visible. A command's scope is
the widest one it touches.

## The scale it is named after

`--scale peppers` names the bands the way people already talk about risky
commands. Same analysis, same score, same factors — only the label changes, and
`--format json` always stays on the band names.

| Band       | Pepper          | Scoville units      |
| ---------- | --------------- | ------------------- |
| `safe`     | bell pepper     | 0                   |
| `low`      | jalapeño        | 2,500–8,000         |
| `medium`   | cayenne         | 30,000–50,000       |
| `high`     | habanero        | 100,000–350,000     |
| `critical` | carolina reaper | 1,600,000–2,200,000 |

```console
$ scoville 'aws s3 ls' 'apt install nginx' 'aws s3 rb s3://assets' 'rm -rf /' --scale peppers
aws s3 ls
  BELL PEPPER                 0/100  ·  scope: none  ·  reversible
apt install nginx
  🌶🌶 CAYENNE               35/100  ·  scope: host  ·  recoverable
aws s3 rb s3://assets
  🌶🌶🌶 HABANERO            75/100  ·  scope: account  ·  irreversible
rm -rf /
  🌶🌶🌶🌶 CAROLINA REAPER  100/100  ·  scope: host  ·  irreversible
```

Wilbur Scoville's 1912 test diluted an extract until a panel of tasters could no
longer detect the burn, and the dilution factor was the score. Hand-calibrated
judgement, made reproducible — which is what
[`tests/corpus.tsv`](https://github.com/fabiocicerchia/scoville/blob/main/tests/corpus.tsv)
is for.

## Calibration

Scores are calibrated judgement, not measurement. They are ordinal, and meant to
be argued with. `tests/corpus.tsv` is where that argument gets settled: it lists
every command with the band, scope and reversibility it should get, it is
executed by the test suite, and it generates
[INVENTORY.md](https://github.com/fabiocicerchia/scoville/blob/main/INVENTORY.md).

A rule change that moves a command between bands therefore fails a test rather
than silently recalibrating the tool. Adding coverage starts in the same place:
add the command and the band you expect, then make it pass.

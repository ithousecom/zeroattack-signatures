# zeroattack-signatures

Custom YARA-X rule pack for [`ithousecom/zeroattack-antivirus`](https://github.com/ithousecom/zeroattack-antivirus).

The scanner is configured by default with two signature remotes:

- [`defended-net/malwatch-signatures`](https://github.com/defended-net/malwatch-signatures) — upstream, free updates
- This repo — our own additions

`zeroattack-scanner signatures refresh` walks both remotes, merges every `.yar` rule under `sigs/`, and compiles them into a single `sigs/index-x.yrc` file used at scan time.

## Layout

```
sigs/
  ithouse/
    <category>/
      <ruleset>.yr   — YARA-X rules
```

Add new rules under `sigs/ithouse/` so they don't collide with upstream.

## Adding a rule

1. Create `sigs/ithouse/<category>/<name>.yr` with one or more YARA rules.
2. Push to this repo's `main` branch.
3. On a server: `cd /opt/antivirus-agent/scanner && ./zeroattack-scanner signatures refresh` (or wait for the next deploy / agent restart).

The compiled rule pack is regenerated and the agent's next scan picks it up.

## License

AGPL-3.0-or-later — same as the scanner. See [LICENSE](LICENSE).

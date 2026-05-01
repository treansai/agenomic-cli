# Bundle format

A bundle is a directory describing one agent. The required and recommended
layout for v0.1:

```
my-agent/
├── genome.yaml            # required
├── agent.lock.yaml        # required (or agent.lock)
├── behavior.contract.yaml # required
├── prompts/               # required (at least one file)
│   └── system.md
├── tools/                 # optional
├── memory/                # optional
├── policies/              # optional
├── knowledge/             # optional
└── .agentlockignore       # optional, gitignore-style
```

## Always excluded

`.git/`, `target/`, `node_modules/`, `__pycache__/`, `dist/`, `.agentlock/`,
plus credential files: `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`,
`id_ed25519`, `*.p12`, `*.pfx`. Use `--allow-symlinks` to permit symlinks
(off by default).

## Archive

`agentlock build` packs the bundle as a tar archive (mtime=0, mode 0644 for
regular files, deterministic header) and zstd-compresses it. Output filename
extension: `.bundle.tar.zst`.

The archive header order matches the manifest order — that is, files are
appended to tar in lexicographic POSIX-path order.

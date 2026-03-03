# CLAUDE.md — NDB Storage Engine

## Claude Context Files

Detailed documentation is organized by topic in `claude_files/`. Read the relevant files when working on a specific area.

| Topic | Directory | Description |
|-------|-----------|-------------|
| SET Config Param | `claude_files/set_config_param/` | Adding runtime-settable config parameters via the MGM client SET command |
| Range Partitioning | `claude_files/range_partitioning/` | Adding native RANGE partition support to NDB (server-side range lookup in DBDIH) |

### set_config_param

- `architecture.md` — Signal flow from MGM client through to data node, design notes
- `howto_add_new_param.md` — Step-by-step guide (only 2 files need changes)
- `reference.md` — File locations, what doesn't need changes, verification checklist

### range_partitioning

- `architecture.md` — Overview with 3 options (A/B/C), recommendation for Option A
- `option_a_detailed.md` — Detailed design: Range2FragmentMap, DBDIH/DBTC/DBSPJ changes, RCU, signal flows
- `implementation_plan.md` — 7-phase step-by-step implementation plan with per-file changes

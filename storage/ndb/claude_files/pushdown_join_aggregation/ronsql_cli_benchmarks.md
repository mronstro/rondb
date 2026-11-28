# RonSQL CLI Benchmarks (`.bench_ronsql` / `.bench_sql <name>`)

Benchmarks for RonSQL pushdown-aggregation / CTE queries, run from the
`rondb-cli` interactive shell against the TPC-H data model. The goal is to
measure end-to-end RonSQL query latency (microsecond precision) for
Feature-Store-style workloads and for TPC-H queries rewritten with CTEs,
as a foundation for understanding where time is spent in RonSQL phases and
in the RonDB data nodes.

`.bench_sql <name>` is the comparative twin: the same named queries executed
by the **MySQL server** over the same tables. Three comparisons matter:

1. `.bench_ronsql X` vs `.bench_sql X` — RonSQL pushdown vs MySQL on
   identical SQL. If RonSQL is slower, there is a RonSQL performance issue
   to investigate.
2. `.bench_sql cte_tpch_qN` vs `.bench_sql tpch_qN` — the CTE rewrite vs the
   official TPC-H formulation, both on MySQL: the cost/benefit of the
   rewrite itself.
3. `.bench_ronsql tpch_qN` vs `.bench_sql tpch_qN` — RonSQL's best shape vs
   MySQL's official shape: the end-user view.

A fifth family, `core_*` (RONDB-1121 M3.0, `fs_ronsql/m3_plan.md`), isolates
the engine primitives the shapes above are built from — PK lookup, IN lists
on the PK and on a secondary index, ordered-index range, pass-through drain,
AVG, full scans with and without a row filter, few and many groups — one
access path per entry with plan pins; and `fs_hw_*` (`fs_ronsql/benchmarks.md`)
are the Hopsworks serving shapes over the `fs_bench` data set.

## Implementation

| File | What |
|------|------|
| `tools/rondb-cli/internal/shell/ronsql_bench.go` | Shared query registry (`ronsqlBenchQueries`), RonSQL runner (`runBenchRonSQL*`), MySQL runner (`runBenchSQLNamed`/`runBenchSQLQuery`), completion |
| `tools/rondb-cli/internal/shell/query_inspect.go` | Query inspection: `.list_query_ronsql`/`.list_query_sql`, `.query_ronsql`/`.query_sql <name>`, `.explain_ronsql`/`.explain_sql <name>` |
| `tools/rondb-cli/internal/shell/repl.go` | `.bench_ronsql` dispatch, `.bench_sql` named-form dispatch (non-numeric first arg), query-inspection dispatch, `.help internal` / `.help bench` text, autocomplete |
| `tools/rondb-cli/internal/shell/tpch.go` | `.load_tpch`: DDL with the secondary indexes (see below) and the data generators, which follow the TPC-H data rules |
| `tools/rondb-cli/internal/shell/tpch_bench.go`, `tpch_queries.go` | `.bench_tpch`: the 22 TPC-H queries in official, original and rewritten form, on RonSQL and MySQL (see "TPC-H, all 22 queries") |
| `tools/rondb-cli/internal/client/rest.go` | `RestOptions.Timeout` (benchmark clients use a build-time timeout instead of the default 30s) |
| `tools/rondb-cli/internal/client/mysql.go` | `MySQLOptions.Database` (per-benchmark connections default to the query's schema) |

RonSQL queries execute over the RDRS REST endpoint `POST /0.2.0/ronsql` with
`database: "tpch"`, `outputFormat: TEXT`; recorded latency is the wall-clock
time around the HTTP request (RDRS + RonSQL parse/prepare/execute +
data-node execution + result transfer). SQL queries execute over per-thread
MySQL connections (`database/sql` + go-sql-driver); recorded latency is the
wall-clock time around query execution including full result drain. The
shared `LatencyCollector` reports min/avg/max and p95/p99/p99.9; values
under 1 ms print in microseconds.

Both runners share the registry, {KEY}/{KEY2} substitution, warmup,
progress reporting, and the results format.

## Usage

### Starting a benchmark cluster via MTR

`mysql-test/suite/rdrs2-ronsqltpch/t/ronsql_bench_setup.{test,cnf,result}`
provides a one-command cluster (mysqld + ndbmtd + RDRS, auth disabled) with a
benchmark-scale memory config (`TotalMemoryConfig=10G`, `DataMemory=4G`,
mirroring `suite/ndb/t/ndb_setup_large.cnf`):

```
cd mysql-test
./mtr --suite=rdrs2-ronsqltpch ronsql_bench_setup --start-and-exit
grep ServerPort var/rdrs.1.1_config.json   # RDRS REST port (no-TLS instance)
```

Connect the CLI with `--mysql-port <MASTER_MYPORT> --rdrs-port <ServerPort>
--no-rondis`.

### Running the benchmarks

```
cd tools/rondb-cli && go build -o rondb .   # build
./rondb                                     # start shell

.load_tpch 1 8 200            # load TPC-H scale factor 1 with 8 threads
.bench_ronsql                 # list RonSQL queries
.bench_sql list               # list SQL (MySQL-executed) queries
.bench_ronsql fs_point 4 100  # 4 threads x 100 requests via RonSQL
.bench_sql fs_point 4 100     # the same query via the MySQL server
.bench_sql cte_tpch_q15       # Q15 CTE rewrite via MySQL
.bench_sql tpch_q15           # official TPC-H Q15 via MySQL
.bench_ronsql all 1 10        # all RonSQL-capable queries sequentially
.bench_sql all 1 10           # all queries via MySQL sequentially
```

`.bench_sql` keeps its original numeric form for the key-value benchmark
(`.bench_sql [T] [N] [R] [W]`); a non-numeric first argument selects the
named analytics form (`.bench_sql <name> [T] [N]`, default 1 thread x 10
requests).

Every benchmark starts with a **warmup request** that validates the query
(unsupported RonSQL shapes fail immediately with the RonSQL error message),
primes caches, and prints the warmup latency + result row count. The timed
run follows.

Queries with `RandKey` substitute a random key per request (`{KEY}`
placeholder; `{KEY2}` = `{KEY}` + span for segment queries). The key range
is discovered via `KeySQL` over the MySQL connection at benchmark start.

### Inspecting the queries

```
.list_query_ronsql            # query names + descriptions (RonSQL namespace)
.list_query_sql               # query names + descriptions (SQL namespace)
.query_ronsql fs_batch        # print the SQL fs_batch represents
.query_sql tpch_q15           # print the official Q15 SQL
.explain_ronsql fs_batch      # RonSQL EXPLAIN (plan only, not executed)
.explain_sql tpch_q15         # MySQL EXPLAIN + SHOW WARNINGS
```

`.query_*` prints the registry entry (category, database, cross-namespace
name, SQL template, `{KEY}`/`{KEY2}` semantics). `.explain_*` substitutes a
deterministic sample key (the same seed-1 key the benchmark warmup uses) and
asks the engine for its plan: `.explain_ronsql` posts the unmodified query
with `explainMode: FORCE` and `outputFormat: TEXT` (RonSQL prints the plan
without executing; JSON EXPLAIN output is not implemented), while
`.explain_sql` runs `EXPLAIN` on a dedicated connection with the query's
schema as default database, then `SHOW WARNINGS` — where NDB reports
pushed-join status and the reasons a join could not be pushed. MySQLOnly
entries are rejected by `.explain_ronsql` with a redirect to `.explain_sql`.

**Important:** if the `tpch` database was loaded with an older CLI build, run
`.drop_tpch` and reload — the DDL now includes secondary indexes
(`orders(o_custkey)`, `orders(o_orderdate)`, `lineitem(l_suppkey)`,
`lineitem(l_shipdate)`, `supplier(s_nationkey)`, `customer(c_nationkey)`)
that the CTE-body index-scan planning (Phase I.9) and the recent-window fs
queries rely on. `CREATE TABLE IF NOT EXISTS` silently skips existing
tables.

## Data model

The CLI loader (`.load_tpch [SF]`) creates database `tpch` with the 8
standard TPC-H tables (unprefixed names). At SF=1: 150k customers, 10k
suppliers, 200k parts, 800k partsupp, 1.5M orders, about 6M lineitems, plus
fixed nation (25) and region (5).

Since 2026-11-27 the generators follow the TPC-H data rules (specification
clause 4.2.3), so the 22 queries with their standard substitution
parameters select the share of rows they select on dbgen data:

- an order has 1 to 7 lineitems (4 on average); order keys use the first 8
  of every 32 values (`tpchOrderKey`); `o_custkey` is never a multiple of 3,
  so a third of the customers have no orders;
- a lineitem's supplier is one of its part's four partsupp suppliers; its
  ship, commit and receipt dates follow the order's date (`o_orderdate` is
  uniform from 1992-01-01 to 1998-08-02); return flag and line status follow
  the dates, `o_orderstatus` the line statuses, `o_totalprice` the lines;
- `p_type` has three syllables, `p_brand` follows `p_mfgr`, `p_retailprice`
  is the function of the key, phone numbers start with the nation key
  plus 10;
- comments are text of the TPC-H grammar (about 1 order comment in 100
  matches `'%special%requests%'`), and about 5 suppliers in 10000 carry
  `Customer ... Complaints`.

The values are not dbgen's own: every row is generated from a random stream
seeded by the table and the row number (`tpchRand`), so a load gives the
same database whatever the thread count and batch size, but query results
differ from the published TPC-H answers. The word weights of the text
grammar were written from memory of dbgen's `dists.dss` and not compared
with that file. `tools/rondb-cli/internal/shell/tpch_test.go` checks the
rules above on generated rows.

**CHAR values are sent filled with spaces.** The loader writes through the
REST server's `batchwrite`, and until 2026-11-28 the REST server filled the
unused bytes of a `CHAR` column with NUL (`set_col_value` in
`rest-server2/server/src/db_operations/pk/common.cpp`, the `Column::Char`
case: one code path for a key and for a written column), where MySQL fills
them with spaces. A value written short was therefore stored as another
value: `'R'` in a `CHAR(1)` of utf8mb4 is the four bytes `52 00 00 00`, and
MySQL reads it back as a string of four characters. An equality condition
still matches on both engines (Q2's `r_name = 'EUROPE'` returned its 100
rows on each), because a NUL has no weight in `utf8mb4_0900_ai_ci`, but the
two engines return the value differently: the
MySQL server cuts it to the declared length when it groups or sorts
(`'A'`), RonSQL returns all the bytes (`'A\0\0\0'`). `.load_tpch` reads the
length in bytes of each `CHAR` column from `information_schema.COLUMNS` and
sends the value filled with spaces to that length (`tpchPadChars`), which
leaves the REST server nothing to fill, so a load is right on a REST server
without the fix too.

The REST server fix (2026-11-28): `set_col_value` and the index-scan value
encoder (`GenerateBinary` in `rdrs_dal.cpp`) fill a `CHAR` value with the
column character set's space, for a written column, a key and an index
bound alike. A NUL-filled key is the key of a row MySQL wrote only where a
NUL has no weight (the `utf8mb4_0900` collations); in `latin1` or
`utf8mb4_general_ci` it is another key, so `pk-read` did not find the row
and `pk-write` added a second one. That reasoning is from reading
`NdbSqlUtil::strnxfrm_hash`, not from a run. A row that an older REST
server wrote with a short `CHAR` key in such a collation keeps its
NUL-filled key and is not found by the fixed server (nor was it by MySQL).
Test: `TestBatchWriteCharFilledWithSpaces` in
`rest-server2/server/test_go/internal/integrationtests/batchwrite/char_fill_test.go`.

Data loaded before 2026-11-27 must be dropped and reloaded: it has other
order keys (multiples of 4) and none of the dependencies above. Data loaded
before 2026-11-28 must be reloaded too: its `CHAR` values are filled with
NUL. `.bench_tpch` warns when it finds such data. Note this
is a different physical schema from `block_unit_test/load_tpch.cpp` (which
uses `test.tpch_*` tables).

## Query set

A fifth family, `fs_hw_*` (RONDB-1121 E5), is not TPC-H based: the
Hopsworks feature-store serving shapes over the `fs_bench` data set
loaded by `.fs_load`, generated at init from the feature-store emitter
(`internal/fsq/cases/bench.go`, golden dump
`internal/fsq/cases/testdata/fs_hw_registry.golden`).  `.bench_ronsql
fs_hw` / `.bench_sql fs_hw` run the category; `all` includes it only when
`fs_bench` exists.  Design, placeholders, plan pins and results:
`storage/ndb/claude_files/fs_ronsql/benchmarks.md`.  The same framework carries the
correctness side: the case matrix (`.fs_verify`), vectors (`--vectors`),
the Java corpus (`--golden`), the fuzzers (`.fs_fuzz spec|envelope`) and
the requirements acceptance report (`.fs_verify --requirements`); see
`storage/ndb/claude_files/fs_ronsql/CLAUDE.md` for the index.

RonSQL-capable queries respect the RonSQL CTE envelope (see
`cte_test_authoring_guide.md`): aggregating main SELECT, complete-key CTE
equijoins, no HAVING / AVG / DISTINCT. ORDER BY (targets must be GROUP BY
columns or aggregate output aliases) and LIMIT ARE supported on aggregate
main SELECTs — the sort/limit runs in the RDRS ResultPrinter over the
aggregated groups (`ronsql_orderby_limit_plan.md` has the full shape
inventory; projection-only and single-table non-aggregate shapes remain
out). `SUM(DECIMAL)` in CTE bodies is used freely — the D1 fix widens
scale-0 to exact BIGINT and scale>0 to DOUBLE.

### Online Feature-Store-style (`fs_*`)

Online serving workloads: CTEs compute per-entity aggregate features joined
to entity tables, with **filters bounding the work** to hundreds .. tens of
thousands of source rows (RonDB is an online feature store; full-table
sweeps belong in `offline_fs_*`).

| Name | Shape | Source rows (SF=1) | Engines |
|------|-------|--------------------|---------|
| `fs_floor` | Single-table `COUNT(*)` over region (5 rows) — fixed-overhead floor; the denominator for phase-timing analysis | 5 | both |
| `fs_point` | CTE body filtered `o_custkey = <random>`, scalar main agg (MIN / MAX only, so RonSQL flattens it into the single-table aggregate, RONDB-1124 C2) | ~10 orders | both |
| `fs_point_cte` | `fs_point` plus an outer `COUNT(*)`, which keeps it on the single-group CTE path | ~10 orders | both |
| `fs_batch` | Per-entity feature vectors for a random 100-customer segment ({KEY}/{KEY2} range in CTE body + main WHERE), `GROUP BY c_custkey` | ~1k orders, 100 output rows | both |
| `fs_freshness` | Two CTEs (lifetime + last-order) over a random 500-customer segment, joined to the same customer range | ~10k orders | both |
| `fs_supplier` | Per-supplier features over a 3-day `l_shipdate` window (index scan), joined to one random nation's suppliers | ~7k lineitems, ~400 suppliers | both |
| `fs_nation` | Recent-window (`o_orderdate >= 1998-06-01`, index scan) per-customer CTE joined to one nation's customers, `GROUP BY c_mktsegment` | ~40k orders | both |
| `fs_topk` | Recent-spend CTE joined to customer, projection-only, client-side `ORDER BY recent.spend DESC LIMIT 100` | thousands | both |
| `fs_minmax` | Datatype-heavy MIN/MAX (DECIMAL prices, DATE ship dates, DECIMAL qty) over a 3-day `l_shipdate` window, re-aggregated per supplier nation | ~7k lineitems | both |
| `fs_dnf` | 4-disjunct DNF in the CTE body WHERE (`o_orderstatus`/`o_totalprice`/`o_orderpriority`) over a random 200-customer segment — interpreter filter cost | ~2k orders | both |
| `fs_history` | Order-history page for a 200-customer segment, single-table projection, client-side `ORDER BY o_orderdate DESC LIMIT 1000` (idx_orders_custkey serves the range, not the order) | ~2k orders | both |
| `fs_latest` | Latest 100 orders: single-table projection, no WHERE, `ORDER BY o_orderdate DESC LIMIT 100` — SF_OrderBy index-order streaming on idx_orders_orderdate, early close at the LIMIT, no client-side sort (plan Phase 4b) | ~100 orders read per fragment batch | both |

`fs_topk` ran in an interim aggregate-form rewrite (`GROUP BY c_custkey,
c_name` with `MAX()` as the per-unique-key identity) while projection-only
ORDER BY was unsupported; `ronsql_orderby_limit_plan.md` Phase 3 shipped
the buffered client-side sort for pass-through shapes, so the natural
projection-only form is restored.  `fs_history` (single-table projection +
ORDER BY + LIMIT) unlocked on the same phase — both benchmarks now buffer
rows client-side, sort with NdbSqlUtil comparators, and cut at the LIMIT
via partial_sort.  Note the aggregate-path LIMIT is a print-time cutoff,
not a scan reduction (early close is Phase N / I.14); the pass-through
LIMIT-without-ORDER-BY path does close the scan early (plan Phase 2).
`fs_latest` (plan Phase 4b) is the index-order counterpart: when the
planner's ordered index delivers the ORDER BY order (ORDER BY list = the
index columns after any leading equality-bound columns, one direction),
the single-table pass-through scan runs with `SF_OrderBy [| SF_Descending]`
— the NDB API merge-sorts the per-fragment ordered scans — and the drain
streams with the Phase 2 LIMIT cutoff, so a top-N reads roughly one batch
per fragment and never buffers.  `.explain_ronsql fs_latest` prints
`ORDER BY: index order (SF_OrderBy | SF_Descending merge ...)`;
`.explain_ronsql fs_history` prints `ORDER BY: client-side sort ...`
because its WHERE-chosen index (idx_orders_custkey) is not in date order.

### Offline Feature-Store-style (`offline_fs_*`)

Offline feature materialization: full-table per-entity CTEs re-aggregated
across the entity table (the former `fs_batch`/`fs_multi`/`fs_join_body`/
`fs_anti`/`fs_scalar`, renamed).

| Name | Shape |
|------|-------|
| `offline_fs_batch` | Per-customer CTE (COUNT/SUM/MAX over 1.5M orders) joined to 150k customers, `GROUP BY c_mktsegment` |
| `offline_fs_multi` | Two CTEs (lifetime stats + date-filtered recent stats) both joined to customer |
| `offline_fs_join_body` | CTE body = `lineitem JOIN orders` with WHERE, `GROUP BY l_suppkey`; joined to supplier. **Exploratory**: real-table⋈real-table CTE bodies are grammatically supported but not covered by existing MTR |
| `offline_fs_anti` | `customer LEFT JOIN recent-orders-CTE WHERE cnt IS NULL, GROUP BY nation` (churn detection, Phase K anti-join) |
| `offline_fs_wide` | 7-aggregate per-customer CTE re-aggregated into 10 output columns `GROUP BY c_mktsegment` (result-width cost) |
| `offline_fs_chain` | Three-level chained CTE-of-CTE (per-customer → rollup → scalar reduce): CTE materialization + redistribute cost per chain phase |
| `offline_fs_scalar` | Scalar `COUNT/SUM/MAX/MIN` reduce over the per-customer CTE (pure materialization + redistribution cost) |

### TPC-H with CTEs (`tpch_q*` in `.bench_ronsql`, `cte_tpch_q*` in `.bench_sql`)

Five TPC-H queries whose official formulation contains a subquery or derived
table, rewritten as CTEs. Deviations from the official queries (needed to
stay in the envelope) are listed per query.

| Name | Original subquery construct | Deviations |
|------|------------------------------|------------|
| `tpch_q2` | Correlated `ps_supplycost = (SELECT MIN(ps_supplycost)...)` → per-part `min_cost` CTE | The final self-join back to the supplier achieving the min cost needs a col-vs-CTE-output equijoin (unsupported); instead reports min/max min-cost per manufacturer for size-15 parts. Region/type filters dropped (kept: `p_size = 15`). `ORDER BY p_mfgr LIMIT 100` mirrors the official ordering + LIMIT |
| `tpch_q11` | `HAVING SUM(...) > (SELECT SUM(...) * fraction)` → per-supplier `stock` CTE | HAVING-vs-scalar comparison unsupported; stock value uses `SUM(ps_availqty)` (exact int) instead of `ps_supplycost * ps_availqty` (expression-of-DECIMAL SUM in CTE body unproven). Nation filter as main-query WHERE `s_nationkey = 7` (GERMANY) |
| `tpch_q13` | Derived table `(SELECT c_custkey, COUNT(o_orderkey) ... LEFT JOIN ... GROUP BY)` → `c_orders` CTE | Reports scalar distribution stats (COUNT/SUM/MIN/MAX) over the LEFT JOIN with NULL injection. When the entry was written, `GROUP BY` on a CTE aggregate output was not supported; it is now (`ronsql_cte_cross_filter_groups` cg-4), and `.bench_tpch` Q13 uses it for the histogram |
| `tpch_q15` | `revenue` view + `total_revenue = (SELECT MAX(total_revenue)...)` → date-filtered `revenue` CTE, main SELECT is the scalar MAX | Revenue is `SUM(l_extendedprice)` instead of `SUM(l_extendedprice * (1 - l_discount))` (expression-of-DECIMAL SUM in CTE body unproven); the supplier join back to the max is the same col-vs-CTE-output limitation as Q2 |
| `tpch_q22` | `NOT EXISTS (SELECT * FROM orders ...)` + scalar AVG subquery → `cust_orders` CTE anti-join | Faithful anti-join via `LEFT JOIN ... IS NULL`; the `c_acctbal > (SELECT AVG(...))` threshold is a fixed `> 0.00`; phone-prefix `SUBSTRING` filter replaced by `GROUP BY c_nationkey`. `ORDER BY c_nationkey` mirrors the official `ORDER BY cntrycode` |

### Official TPC-H (`tpch_q*` in `.bench_sql`, MySQL only)

The official formulations — region/nation joins, correlated subqueries,
HAVING-vs-scalar, derived tables, ORDER BY/LIMIT — with the TPC-H
validation literals (the data follows the TPC-H rules, see "Data model").
These five entries predate `.bench_tpch`, which has all 22 queries:

- **Q2**: region EUROPE, `p_size = 15`, `p_type LIKE '%BRASS'`, ORDER BY +
  LIMIT 100.
- **Q11**: GERMANY via nation join, `ps_supplycost * ps_availqty` value,
  HAVING vs scalar subquery with fraction 0.0001, ORDER BY value.
- **Q13**: `o_comment NOT LIKE '%special%requests%'` sets aside about 1
  order in 100.
- **Q15**: the revenue view expressed as a CTE referenced twice (view
  creation per request would not benchmark the query); otherwise faithful
  including the MAX(total_revenue) join-back and ORDER BY.
- **Q22**: phone-prefix country codes 13/31/23/29/30/18/17 (the code is
  the nation key plus 10), AVG subquery + NOT EXISTS anti-join + GROUP BY
  cntrycode.  Data loaded before 2026-09-26 gave every customer orders, so
  the anti-join found nothing (0 rows, census run 6 / 6b); reload with the
  current `.load_tpch`.

## TPC-H, all 22 queries (`.bench_tpch`)

The registry in `tpch_queries.go` has every TPC-H query in up to three
forms:

- **official**: the TPC-H formulation in MySQL dialect, with the validation
  literals. MySQL only.
- **original**: the official query in RonSQL dialect, changed only
  mechanically (comma joins written as `JOIN ... ON` in an order, `BETWEEN`
  as a range, date arithmetic as a literal or `DATE_SUB`), with the same
  columns and rows. Exists for the queries RonSQL runs as they are.
- **rewritten**: the query in a shape RonSQL runs, or runs faster.

The original and rewritten forms are SQL that mysqld accepts too, so each
runs on both engines.

**Status of the registry: written from the source, not yet run.** The
verdicts below come from reading `RonSQLParser.y`, `RonSQLPreparer.cpp`,
`QueryPlanner.cpp` and the MTR suites on 2026-11-27. No statement had been
executed when this was written. `.bench_tpch verify` is the test; record
its outcome here when it has run.

First `verify` run, 2026-11-28, debug build, scale factor not checked (a
later load that day held scale factor 0.2): Q1 (both
forms) and Q2 (rewritten) executed on both engines and were reported as
different. The numbers agreed (the Q1 sums to 15 digits); the difference
was in the `CHAR` columns, filled with NUL by the load (see "Data model").
Nothing in those three results points at RonSQL. The outcome of the other
statements and of a run on reloaded data is not recorded yet. Q1 took
6.2 s on RonSQL and 35 s on the MySQL server in that run (5.6 s and 34 s
for the rewritten form); a debug build, so not a benchmark number.

Same run, Q18 rewritten: RDRS stopped (`RonSQL CRASH ... EOF`) on the NDB
API assertion `(tupleId & skipTupleFlag) == 0` in
`NdbResultStream::buildResultCorrelations`, reached from
`RonSQLPreparer::execute_passthrough_drain`. Cause: DBLQH gave a row of a
CTE scan the number of its group in the whole scan as correlation id
(`cteScanEmitResults`, `params.correlation = groupIdx`). DBSPJ and the API
keep 16 bits of the id and find a row among the rows of its batch with it;
bit 15 is the API's skip flag and DBSPJ uses the id as a position in a map
of 4096 entries (`add_to_map`). Q18's CTE has one group per order, about
750000 per data node, so most rows had an id the protocol has no room for.
MTR did not see it because its CTEs that reach the API as rows stay under
32768 groups per node. Fix (2026-11-28): the id is the row's number in its
batch, as for a table scan (a batch is at most 256 rows). Test:
`mysql-test/suite/ronsql_cte/t/cte_scan_row_ids.test`. Not looked at: the
"all nodes" variant of the scan (`m_cteScanAllNodes`), where one DBSPJ
request reads several nodes' groups in one batch and each node numbers
from 0; and the scan loop itself, which walks every rejected group in one
signal execution (all 750000 for a filter that keeps few).

### Commands

```
.load_tpch 1 8 200            # the data (reload if loaded before 2026-11-28)
.bench_tpch                   # the 22 queries: which run, in which form
.bench_tpch missing           # RonSQL features the official queries need
.bench_tpch show q9           # the forms of Q9, why, and what differs
.bench_tpch indexes           # secondary indexes the RonSQL forms use
.bench_tpch check             # RonSQL parses and plans every form (EXPLAIN)
.bench_tpch verify            # run each once on both engines, compare results
.bench_tpch verify q18        # ... one query (also: check q18)
.bench_tpch original 1 3      # phase 1: original forms, RonSQL and MySQL
.bench_tpch rewritten 1 3     # phase 2: rewritten forms, RonSQL and MySQL
.bench_tpch rewritten q4 q18 1 3  # ... the named queries only
.bench_tpch all q5 1 3 --show # ... printing the SQL of each statement
.bench_tpch all q5 1 3 --straight  # ... MySQL joins in the statement's order
.bench_tpch explain q5 rewritten mysql --straight
.bench_tpch all 1 3           # both phases
.bench_tpch all 1 3 ronsql    # ... on one engine (ronsql | mysql | both)
.bench_tpch official 1 1      # the official formulations on MySQL
.bench_tpch q5 4 10           # every form of one query
.bench_tpch explain q5 rewritten mysql
```

`check`, `verify` and the run commands (`original`, `rewritten`, `all`,
`official`) take query names and then run those only: `q4`, `q4 q18` or
`q4,q18`. Without one they run every query. In a run the `q` is required,
since a bare number is the thread or request count. The same commands take
`--show`, which prints the SQL of each statement before it runs; without
the flag a run names the query and the form only (`.bench_ronsql` and
`.bench_sql` still print their statement).

`--straight` (on `verify`, a run, and `explain ... mysql`) makes the MySQL
server join in the order the statement names its tables: the client puts
`STRAIGHT_JOIN` after every `SELECT` of the text it sends to MySQL, since
the option fixes the order of one query block (the main query, a CTE body,
a subquery). RonSQL gets the statement unchanged. Without the flag MySQL's
optimizer picks the order, and picks the same one for the original and the
rewritten form of a query whose forms differ only in table order: for Q5
it starts at the orders of the year in every region and applies the region
last, in mysqld, after the pushed join has read lineitem and supplier for
every region (EXPLAIN on a scale-factor-0.2 load, 2026-11-28; with the
flag it follows the rewritten order, nation as the root of the pushed
join). No run time was taken with the flag when this was written. The
summary of a run says when MySQL ran with the flag.

The flag changes nothing where MySQL already picks the statement's order.
Q7 rewritten is such a case: the same plan with and without it (one pushed
join of six tables, nation → supplier → lineitem → orders → customer →
nation). One run of it on MySQL (scale factor 0.2, release build,
2026-11-28, `EXPLAIN ANALYZE` with the `Ndb_api_*_session` counters): 969 ms,
of which 966 ms waiting for the data nodes; 78,593 rows (4.1 MB) received
by mysqld for 1,054 joined rows in 2 groups; grouping in mysqld under 1 ms.
RonSQL took 0.27 to 0.5 s for the same statement in single requests on a
machine whose timings varied by a factor of three between runs.

Each phase ends with one table: average and p95 latency per engine, result
rows per engine, and how much faster or slower RonSQL is on the same
statement. The runs themselves are the `.bench_ronsql` / `.bench_sql`
runners (warmup, phase breakdown, error report).

`check` uses EXPLAIN, which stops before the pushed join is built. RonSQL
makes further checks there (the tables an aggregation reads, the operands
of a filter over two tables, the size of the aggregation program), and
some limits only show at run time, so `verify` is the real test. It
compares the two results cell by cell: DECIMAL and DOUBLE columns within
1e-9 relative or 1e-4 absolute (a SUM over a DECIMAL expression is a DOUBLE
in RonSQL, and RonSQL prints AVG with four decimals), everything else as
text; rows in order when the statement has an ORDER BY, as a set otherwise.

### What runs

| Query | Original | Rewritten | Result of the rewrite |
|-------|----------|-----------|-----------------------|
| Q1 pricing summary | yes | yes (table scan asked for with `USE INDEX ()`) | same |
| Q2 minimum cost supplier | no | yes, two CTEs and a projection | same |
| Q3 shipping priority | yes | | |
| Q4 order priority | no (fails at run time: EXISTS over 1000 keys) | yes, CTE | same |
| Q5 local supplier volume | yes | yes, region first | same |
| Q6 revenue change | yes | | |
| Q7 volume shipping | no | yes, one chain | pivot: a revenue column per year |
| Q8 market share | no | yes, one chain of nine tables | four sums, the client divides |
| Q9 product type profit | no | yes, one chain | pivot: a profit column per year |
| Q10 returned items | yes (nation first) | | |
| Q11 important stock | yes (the 0.0001 moved out of the subquery) | yes, nation first | same |
| Q12 shipping modes | yes | | |
| Q13 customer distribution | no | yes, CTE and LEFT JOIN | the zero bucket has `c_count` NULL |
| Q14 promotion effect | no | yes | two sums, the client divides |
| Q15 top supplier | no | yes, `ORDER BY ... LIMIT 1` | one supplier also on a tie |
| Q16 parts/supplier | no | yes, CTE regrouped | same |
| Q17 small-quantity revenue | no | yes, CTE and HAVING | the qualifying lineitems, the client sums and divides by 7 |
| Q18 large volume customer | no | yes, CTE scan with lookups | same (last column named `sum_qty`) |
| Q19 discounted revenue | no | yes, three `SUM(CASE)` | three sums, the client adds |
| Q20 part promotion | no | yes, CTE scan and HAVING | same |
| Q21 waiting suppliers | no | yes, two CTEs | same |
| Q22 sales opportunity | no | yes, CTE anti-join | pivot: count and sum per country code |

7 of 22 run in their original form (Q1, Q3, Q5, Q6, Q10, Q11, Q12). The
other 15 have a rewrite: 6 with the same columns and rows (Q2, Q4, Q16,
Q18, Q20, Q21) and 9 with a result the client has to finish or read
differently (Q7, Q8, Q9, Q13, Q14, Q15, Q17, Q19, Q22). No official TPC-H
text passes RonSQL's parser unchanged.

### What RonSQL lacks

Features that keep the 15 from running in their original form
(`.bench_tpch missing` prints this from the registry):

| Feature | Queries |
|---------|---------|
| IN / EXISTS / correlated subqueries returning more than 1000 rows (the result is substituted as constants, it does not run as a semi-join) | Q2 Q4 Q17 Q20 Q21 Q22 |
| Derived tables (a subquery in FROM) | Q7 Q8 Q9 Q13 Q22 |
| Scalar functions as outputs and GROUP BY on an expression (`EXTRACT(YEAR ...)`, `SUBSTRING`) | Q7 Q8 Q9 Q22 |
| Arithmetic over aggregates, and non-integer constants, in a SELECT list | Q8 Q14 Q17 Q20 |
| Correlated subqueries with a join inside, several correlations, a non-equality correlation, or arithmetic on the result | Q2 Q17 Q20 Q21 |
| A subquery condition on a column of a joined table | Q2 Q18 Q21 |
| A WHERE disjunction of AND groups that reads two tables | Q7 Q19 |
| LIKE, NOT and nested AND / OR in a CASE condition | Q14 |
| A condition other than column equality in ON | Q13 |
| `COUNT(DISTINCT col)` | Q16 |
| An aggregate over an expression as a CTE output | Q15 |
| A subquery that reads a CTE, or a comparison between outputs of two CTEs | Q15 |
| Aggregation that reads columns of sibling join branches | Q18 |

Spelling the original forms had to change: comma joins of stored tables
(17 queries), `date '...'` literals and `date ± interval` (12), `BETWEEN`
(4), `x NOT LIKE y` / `x NOT IN` (2), `SELECT *` in EXISTS (3), a table
alias without `AS` (3), arithmetic on constants in WHERE (2), a keyword as
an alias (`value`, Q11), a factor inside a scalar subquery's SELECT list
(Q11), `CREATE VIEW` (Q15).

What would make the nine inexact rewrites exact: expressions in the SELECT
list and as GROUP BY keys (Q7, Q8, Q9, Q14, Q19, Q22), `COALESCE` or a
non-equality ON condition (Q13), HAVING or expression aggregates in a CTE
body (Q15, Q17).

Rules that shaped the rewrites, each found in the preparer:

- A CTE output is a GROUP BY column, COUNT, or SUM / MIN / MAX / AVG of a
  plain column. No expression, no HAVING, no subquery in a CTE body.
- With a CTE as the FROM table, no table below it may be a scan.
- A stored DECIMAL column cannot be compared with a CTE output, and no
  comparison with a CTE output takes arithmetic; HAVING over an aggregate
  expression does (Q17, Q20).
- A CASE condition is one comparison, a flat AND or a flat OR; its atoms
  may be on different tables.
- A WHERE comparison of two tables is evaluated at the last table and
  takes integer columns (FLOAT / DOUBLE on the last table): it saves no
  join (Q5), so the table that carries it goes last.
- RonSQL has no selectivity estimate: any index bound beats a table scan
  (Q1).

### Indexes

`.bench_tpch indexes` creates what the RonSQL forms use beyond the
`.load_tpch` DDL. RonSQL joins a table only through its primary key, a
unique key or an ordered-index prefix, so the first three are needed
("No suitable index for join columns" without them); the last two only
turn a filter into an index bound.

| Index | For |
|-------|-----|
| `lineitem(l_partkey, l_suppkey)` | lineitem from part (Q17, Q19, Q20) and from part and partsupp (Q9) |
| `partsupp(ps_suppkey)` | partsupp from supplier (Q9, Q11 rewritten) |
| `nation(n_regionkey)` | nation from region (Q5 rewritten, Q8) |
| `orders(o_custkey, o_orderdate)` | the order-date range as a bound when orders is joined from customer (Q3, Q5, Q8, Q10) |
| `lineitem(l_receiptdate)` | Q12's receipt-date range instead of a scan of lineitem |

The official Q17 needs `lineitem(l_partkey, ...)` on the MySQL server too,
or its correlated subquery scans lineitem per outer row.

### Shapes no MTR test covers

The forms rely on these; `verify` settles each. A wrong result here shows
as a difference from MySQL, not as an error:

- a real table keyed from two tables above it (Q8, Q9; MTR has it for a
  CTE child, gc-17 / gc-20);
- a CASE condition on a DATE or CHAR column of a table above the last one
  (Q7, Q8, Q19), and with atoms on two tables (Q19);
- a WHERE comparison of two tables more than one level apart (Q5, Q7);
- a join inside a scalar subquery (Q11);
- MIN over a looked-up CTE output, and DOUBLE = DOUBLE between two outputs
  of a CTE (Q2);
- GROUP BY on an aggregate output of a LEFT-joined CTE (Q13);
- a CASE over the NULL rows of a CTE anti-join, and a string range in a
  CASE (Q22; its 14 CASE aggregates are an estimated 650 to 800 of the 1024
  words an aggregation program may have);
- CTEs of about 1.5M groups at SF 1 (Q18, Q21; `ronsql_large` proves 100k).

## Known risks / scaling notes

- **High-cardinality CTE group keys**: `tpch_q2` groups by `ps_partkey`
  (200k × SF groups) and the per-customer CTEs produce 150k × SF groups at
  SF=1. The `ronsql_large` regression net proves 20k groups; the D6 DBSPJ
  assert (high-cardinality CTE, not yet fixed) may bite at larger SF. Start
  at SF=1; treat crashes at higher SF as kernel findings, not benchmark bugs.
- **`offline_fs_join_body`** is deliberately exploratory (see table above).
- The REST timeout for benchmark clients defaults to 120s (300s for debug
  builds, injected at build time); very large SFs may still need more for
  the coldest full-scan queries. MySQL-side queries have no client timeout.
- MySQL executes the CTE rewrites with its own plans (indexes above help);
  differences in result *values* between `.bench_ronsql X` and
  `.bench_sql X` indicate a correctness bug and take priority over any
  latency comparison.

## Phase timing (x-ronsql-phases)

**Implemented** (RonSQL-side; see `test_benchmark_extension_plan.md` Phase
B2/B3). When RDRS is built with `RONSQL_PHASE_STATS` (default on, kill
switch in `RonSQLPerf.hpp`), a successful `/ronsql` response carries an
`x-ronsql-phases` header with per-request phase timings in µs, captured
at the pre-existing PERF_TS boundaries via a `RonSQLPhaseStats` sink on
`RonSQLExecParams`.

**Opt-in (since 2026-09-30).** The header is returned only when the
request carries an `x-ronsql-phases` request header with a value other
than `0` or `false` (convention: `x-ronsql-phases: 1`).  Without it RDRS
leaves the sink NULL (`ronsql_phases_requested()` in `ronsql_ctrl.cpp`),
so no timings are captured and no header is sent — the same null test
per phase boundary ronsql_cli pays.  Previously every successful
response carried it, which was overkill for production clients.

```
parse=…,analyze=…,load=…,plan=…,compile=…,prepare=…,subquery=…,
ndbprep=…,send=…,firstbatch=…,drain=…,print=…,execute=…,rows=…,
attempts=…,fetched=…,queue=…,loop=…,worker=…,close=…
```

- `parse/analyze/load/plan/compile` split the RonSQLPreparer constructor
  (`prepare` = its total, captured in ronsql_op); `load` isolates NDB
  dictionary access (schema-cache effectiveness).
- `ndbprep` = NdbQueryBuilder::prepare (join/CTE) or scan-op definition
  (single-table); `send` = trans->execute; `firstbatch` = wait for the
  first result row — the closest API-side proxy for data-node execution
  incl. CTE materialization; `drain` = remaining rows; `rows` = drained
  row count. On the single-table path the NDB API fuses send+drain
  inside DoAggregation, reported as `firstbatch` (send/drain stay 0).
- `print` = ResultPrinter formatting; `execute` = execute() total.
- Retry semantics: **last attempt wins**; `attempts` counts ronsql_op
  attempts (1 = no retry).
- `fetched` = rows the NDB API received (`Ndb::ReadRowCount` delta,
  `m3_run6_plan.md` C3); `queue` = µs waiting for a RonSQL worker,
  `loop` = receiving REST thread, `worker` = RonSQL worker that ran it
  (0 = IO loop; `m3_run6_plan.md` B2); `close` = µs closing the scans,
  the pushed query and the transaction (part of `execute`; an early
  scan close waits for the data nodes).

`.bench_ronsql` asks for the header on every request (`PostWithHeader`
sends `x-ronsql-phases: 1`), reads it and prints a per-phase
avg/p95/p99/max table after the end-to-end results (plus the warmup's
raw values); end-to-end latency minus `prepare`+`execute` approximates
RDRS/HTTP overhead. `fs_floor` is the fixed-cost floor to compare
against. Header format and the opt-in (no header without the request
header, or with `0` / `false`) are pinned by
`mysql-test/suite/ronsql/t/ronsql_phase_stats.test`; the header is parsed
by `ronsql_bench.go` (`phaseSamples.Record`).  Any other client that reads
it (MTR includes, `fsq/exec`, scripts) must send the request header.

### Next step: data-node-side phase counters

Still open: correlate with existing counters (`m_rows_examined`,
ScanFragConf `rowsExamined`) and add DBSPJ/DBLQH timing around
CTE_SCAN/CTE_LOOKUP materialization, JOIN_AGG_COMPLETE merge, and
redistribution, exposed via ndbinfo or DUMP. The API-side `firstbatch`
value bounds the total data-node time but cannot attribute it to
kernel phases.

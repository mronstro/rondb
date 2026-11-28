/*
   Copyright (c) 2026, 2026, Hopsworks and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is designed to work with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have either included with
   the program or referenced in the documentation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

package shell

// The registry of .bench_tpch: the 22 TPC-H queries, what RonSQL runs of
// each, and what it lacks for the rest (tpch_bench.go has the command).
//
// How the RonSQL forms are written.  RonSQL has no join optimizer: the
// FROM table is the root (scanned, or bounded through an index by its own
// WHERE conjuncts) and each JOIN is a primary key lookup, a unique key
// lookup or an ordered-index prefix scan from an earlier table, in the
// order written.  The aggregation runs on the last table and reads only
// that table and the tables on its chain up to the root.  So every form:
//   - starts at the table whose filter leaves the fewest rows,
//   - puts every table the aggregation reads on one chain, and
//   - puts a filter before the joins it should save.
//
// Where the entries come from.  They were derived by reading the grammar
// (RonSQLParser.y), the preparer and the planner in November 2026, and
// had not been run when they were written.  .bench_tpch check and
// .bench_tpch verify test them against a cluster; a statement that fails
// there is a finding about this registry or about RonSQL, and Note says
// which shapes no MTR test covered.
//
// The literals are the TPC-H validation values.  .load_tpch fills the
// tables by the TPC-H data rules (tpch.go), so they select what they
// select on dbgen data; Q11's fraction 0.0001 is the value for scale
// factor 1.

import "strings"

// tpchFeature is something the official TPC-H text uses and RonSQL does
// not have.  Spelling features only change how a query is written (the
// original forms work around them); the others keep a query from running
// in its original form.
type tpchFeature struct {
	Key      string
	Text     string
	Spelling bool
}

var tpchFeatures = []tpchFeature{
	// What keeps a query from running in its original form.
	{Key: "derived-table",
		Text: "Derived tables: a subquery in FROM (a CTE can stand in when the query needs no more than that)"},
	{Key: "groupby-expr",
		Text: "Scalar functions as outputs and GROUP BY on an expression: EXTRACT(YEAR FROM d), SUBSTRING(s, 1, 2)"},
	{Key: "select-arith",
		Text: "Arithmetic over aggregates, and non-integer constants, in a SELECT list: 100.00 * SUM(a) / SUM(b), SUM(x) / 7.0, 0.2 * AVG(y)"},
	{Key: "subquery-cap",
		Text: "IN / EXISTS / correlated subqueries that return more than 1000 rows: the result is put into the outer query as a list of constants, it does not run as a semi-join"},
	{Key: "subquery-correlation",
		Text: "Correlated subqueries with a join inside, with more than one correlation, with a correlation other than equality, or with arithmetic on the result"},
	{Key: "subquery-joined",
		Text: "A subquery condition on a column of a joined table (only the first table in FROM can have one)"},
	{Key: "or-across-tables",
		Text: "A WHERE disjunction of AND groups that reads two tables: (a.x = 1 AND b.y = 2) OR (a.x = 2 AND b.y = 1)"},
	{Key: "case-shape",
		Text: "LIKE, NOT and nested AND / OR in a CASE condition"},
	{Key: "on-predicate",
		Text: "A condition other than column equality in ON: LEFT JOIN o ON o.k = c.k AND o.c NOT LIKE p"},
	{Key: "count-distinct",
		Text: "COUNT(DISTINCT col)"},
	{Key: "cte-expr-agg",
		Text: "An aggregate over an expression as a CTE output: SUM(a * (1 - b)) in a CTE body"},
	{Key: "subquery-reads-cte",
		Text: "A subquery that reads a CTE, or a comparison between the outputs of two CTEs"},
	{Key: "fanout-agg",
		Text: "Aggregation that reads columns of sibling join branches (the tables it reads must lie on one chain)"},

	// Spelling the original forms write another way.
	{Key: "comma-join", Spelling: true,
		Text: "Comma joins of stored tables with the join condition in WHERE: written as JOIN ... ON, in the order to join"},
	{Key: "date-literal", Spelling: true,
		Text: "date '1998-12-01' literals and date +/- interval arithmetic: a string literal, DATE_ADD or DATE_SUB"},
	{Key: "between", Spelling: true,
		Text: "BETWEEN: written as >= AND <="},
	{Key: "const-arith", Spelling: true,
		Text: "Arithmetic on constants in WHERE (0.06 - 0.01): the value is written out"},
	{Key: "not-infix", Spelling: true,
		Text: "x NOT LIKE y and x NOT IN (...): written as NOT (x LIKE y)"},
	{Key: "select-star", Spelling: true,
		Text: "SELECT * (in an EXISTS subquery): a column is named"},
	{Key: "alias-as", Spelling: true,
		Text: "A table alias without AS (nation n1): written as nation AS n1"},
	{Key: "keyword-alias", Spelling: true,
		Text: "An alias that is a MySQL keyword (value): backtick-quoted, as RonSQL takes no MySQL keyword as a plain identifier"},
	{Key: "subquery-factor", Spelling: true,
		Text: "Arithmetic on the aggregate inside a scalar subquery (SELECT SUM(x) * 0.0001): the factor moves out to the comparison"},
	{Key: "view", Spelling: true,
		Text: "CREATE VIEW (Q15): written as a CTE"},
}

func tpchFeatureText(key string) string {
	for _, f := range tpchFeatures {
		if f.Key == key {
			return f.Text
		}
	}
	return key
}

// tpchIndex is a secondary index beyond the .load_tpch DDL.  A required
// index is one a RonSQL form joins through (without it RonSQL refuses the
// statement); the others only let a filter bound the join's index scan.
type tpchIndex struct {
	Name     string
	Table    string
	Columns  string // as in CREATE INDEX
	Why      string
	Required bool
}

func (x tpchIndex) columnList() []string {
	var cols []string
	for _, c := range strings.Split(x.Columns, ",") {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			cols = append(cols, c)
		}
	}
	return cols
}

var tpchExtraIndexes = []tpchIndex{
	{Name: "idx_lineitem_partkey_suppkey", Table: "lineitem", Columns: "l_partkey, l_suppkey", Required: true,
		Why: "joining lineitem from part (Q17, Q19, Q20) and from part and partsupp (Q9)"},
	{Name: "idx_partsupp_suppkey", Table: "partsupp", Columns: "ps_suppkey", Required: true,
		Why: "joining partsupp from supplier (Q9, Q11 rewritten)"},
	{Name: "idx_nation_regionkey", Table: "nation", Columns: "n_regionkey", Required: true,
		Why: "joining nation from region (Q5 rewritten, Q8)"},
	{Name: "idx_orders_custkey_orderdate", Table: "orders", Columns: "o_custkey, o_orderdate",
		Why: "the order-date range as an index bound when orders is joined from customer (Q3, Q5, Q8, Q10)"},
	{Name: "idx_lineitem_receiptdate", Table: "lineitem", Columns: "l_receiptdate",
		Why: "the receipt-date range of Q12 as an index range instead of a scan of lineitem"},
}

var tpchQueries = []tpchQuery{
	{
		Num:     1,
		Title:   "Pricing summary report",
		Dialect: []string{"date-literal"},
		Note: "RonSQL has no selectivity estimate: any index bound wins over a table scan, so the original form reads " +
			"98.7% of lineitem through idx_lineitem_shipdate. The rewritten form asks for the table scan.",
		Official: `SELECT l_returnflag, l_linestatus,
       SUM(l_quantity) AS sum_qty,
       SUM(l_extendedprice) AS sum_base_price,
       SUM(l_extendedprice * (1 - l_discount)) AS sum_disc_price,
       SUM(l_extendedprice * (1 - l_discount) * (1 + l_tax)) AS sum_charge,
       AVG(l_quantity) AS avg_qty,
       AVG(l_extendedprice) AS avg_price,
       AVG(l_discount) AS avg_disc,
       COUNT(*) AS count_order
FROM lineitem
WHERE l_shipdate <= DATE '1998-12-01' - INTERVAL '90' DAY
GROUP BY l_returnflag, l_linestatus
ORDER BY l_returnflag, l_linestatus;`,
		Original: `SELECT l_returnflag, l_linestatus,
       SUM(l_quantity) AS sum_qty,
       SUM(l_extendedprice) AS sum_base_price,
       SUM(l_extendedprice * (1 - l_discount)) AS sum_disc_price,
       SUM(l_extendedprice * (1 - l_discount) * (1 + l_tax)) AS sum_charge,
       AVG(l_quantity) AS avg_qty,
       AVG(l_extendedprice) AS avg_price,
       AVG(l_discount) AS avg_disc,
       COUNT(*) AS count_order
FROM lineitem
WHERE l_shipdate <= DATE_SUB('1998-12-01', INTERVAL '90' DAY)
GROUP BY l_returnflag, l_linestatus
ORDER BY l_returnflag, l_linestatus;`,
		Rewritten: `SELECT l_returnflag, l_linestatus,
       SUM(l_quantity) AS sum_qty,
       SUM(l_extendedprice) AS sum_base_price,
       SUM(l_extendedprice * (1 - l_discount)) AS sum_disc_price,
       SUM(l_extendedprice * (1 - l_discount) * (1 + l_tax)) AS sum_charge,
       AVG(l_quantity) AS avg_qty,
       AVG(l_extendedprice) AS avg_price,
       AVG(l_discount) AS avg_disc,
       COUNT(*) AS count_order
FROM lineitem USE INDEX ()
WHERE l_shipdate <= '1998-09-02'
GROUP BY l_returnflag, l_linestatus
ORDER BY l_returnflag, l_linestatus;`,
	},
	{
		Num:   2,
		Title: "Minimum cost supplier",
		Blockers: []string{
			"the subquery condition is on partsupp, a joined table",
			"the correlated subquery joins four tables, which is not decorrelated",
			"decorrelated it would return one row per part, far over the 1000-row limit",
		},
		Missing: []string{"subquery-joined", "subquery-correlation", "subquery-cap"},
		Dialect: []string{"comma-join"},
		Note: "The rewrite keeps the minimum per part in a CTE, puts each part's suppliers beside it in a second CTE " +
			"(both costs as DOUBLE outputs of one CTE, so they can be compared) and projects from that. No MTR test " +
			"covers MIN over a looked-up CTE output or DOUBLE = DOUBLE between two outputs of a CTE.",
		Official: `SELECT s.s_acctbal, s.s_name, n.n_name, p.p_partkey, p.p_mfgr,
       s.s_address, s.s_phone, s.s_comment
FROM part AS p, supplier AS s, partsupp AS ps, nation AS n, region AS r
WHERE p.p_partkey = ps.ps_partkey AND s.s_suppkey = ps.ps_suppkey
  AND p.p_size = 15 AND p.p_type LIKE '%BRASS'
  AND s.s_nationkey = n.n_nationkey AND n.n_regionkey = r.r_regionkey
  AND r.r_name = 'EUROPE'
  AND ps.ps_supplycost = (
    SELECT MIN(ps2.ps_supplycost)
    FROM partsupp AS ps2, supplier AS s2, nation AS n2, region AS r2
    WHERE p.p_partkey = ps2.ps_partkey AND s2.s_suppkey = ps2.ps_suppkey
      AND s2.s_nationkey = n2.n_nationkey AND n2.n_regionkey = r2.r_regionkey
      AND r2.r_name = 'EUROPE')
ORDER BY s.s_acctbal DESC, n.n_name, s.s_name, p.p_partkey
LIMIT 100;`,
		Rewritten: `WITH min_cost AS (
  SELECT pt.p_partkey AS pk, MIN(ps1.ps_supplycost) AS mc
  FROM part AS pt
  JOIN partsupp AS ps1 ON ps1.ps_partkey = pt.p_partkey
  JOIN supplier AS s1 ON s1.s_suppkey = ps1.ps_suppkey
  JOIN nation AS n1 ON n1.n_nationkey = s1.s_nationkey
  JOIN region AS r1 ON r1.r_regionkey = n1.n_regionkey
  WHERE pt.p_size = 15 AND pt.p_type LIKE '%BRASS' AND r1.r_name = 'EUROPE'
  GROUP BY pt.p_partkey),
cand AS (
  SELECT ps2.ps_partkey AS cpk, ps2.ps_suppkey AS csk, pt2.p_mfgr AS mfgr,
         MIN(ps2.ps_supplycost) AS cost, MIN(min_cost.mc) AS mincost
  FROM part AS pt2
  JOIN partsupp AS ps2 ON ps2.ps_partkey = pt2.p_partkey
  JOIN min_cost ON min_cost.pk = ps2.ps_partkey
  WHERE pt2.p_size = 15 AND pt2.p_type LIKE '%BRASS'
  GROUP BY ps2.ps_partkey, ps2.ps_suppkey, pt2.p_mfgr)
SELECT s.s_acctbal, s.s_name, n.n_name, cand.cpk AS p_partkey,
       cand.mfgr AS p_mfgr, s.s_address, s.s_phone, s.s_comment
FROM cand
JOIN supplier AS s ON s.s_suppkey = cand.csk
JOIN nation AS n ON n.n_nationkey = s.s_nationkey
JOIN region AS r ON r.r_regionkey = n.n_regionkey
WHERE cand.cost = cand.mincost AND r.r_name = 'EUROPE'
ORDER BY s.s_acctbal DESC, n.n_name, s.s_name, cand.cpk
LIMIT 100;`,
	},
	{
		Num:     3,
		Title:   "Shipping priority",
		Dialect: []string{"comma-join", "date-literal"},
		Indexes: []string{"idx_orders_custkey_orderdate"},
		Note: "The official table order is already the best chain: customer, orders through idx_orders_custkey, " +
			"lineitem through its primary key prefix. All groups (one per order) reach RDRS before the LIMIT.",
		Official: `SELECT l_orderkey, SUM(l_extendedprice * (1 - l_discount)) AS revenue,
       o_orderdate, o_shippriority
FROM customer, orders, lineitem
WHERE c_mktsegment = 'BUILDING'
  AND c_custkey = o_custkey
  AND l_orderkey = o_orderkey
  AND o_orderdate < DATE '1995-03-15'
  AND l_shipdate > DATE '1995-03-15'
GROUP BY l_orderkey, o_orderdate, o_shippriority
ORDER BY revenue DESC, o_orderdate
LIMIT 10;`,
		Original: `SELECT l.l_orderkey, SUM(l.l_extendedprice * (1 - l.l_discount)) AS revenue,
       o.o_orderdate, o.o_shippriority
FROM customer AS c
JOIN orders AS o ON o.o_custkey = c.c_custkey
JOIN lineitem AS l ON l.l_orderkey = o.o_orderkey
WHERE c.c_mktsegment = 'BUILDING'
  AND o.o_orderdate < '1995-03-15'
  AND l.l_shipdate > '1995-03-15'
GROUP BY l.l_orderkey, o.o_orderdate, o.o_shippriority
ORDER BY revenue DESC, o.o_orderdate
LIMIT 10;`,
	},
	{
		Num:   4,
		Title: "Order priority checking",
		Blockers: []string{
			"the EXISTS runs first, as its own statement over all of lineitem, and returns one key per order " +
				"with a late line (about 1.4M at scale factor 1) against a limit of 1000: it prepares and then fails",
		},
		Missing: []string{"subquery-cap"},
		Dialect: []string{"date-literal", "select-star"},
		Note: "The rewrite holds the qualifying orders in a CTE (lineitem first: a CTE body compares two columns " +
			"only on its first table) and the main query regroups it by priority.",
		Official: `SELECT o_orderpriority, COUNT(*) AS order_count
FROM orders
WHERE o_orderdate >= DATE '1993-07-01'
  AND o_orderdate < DATE '1993-07-01' + INTERVAL '3' MONTH
  AND EXISTS (
    SELECT * FROM lineitem
    WHERE l_orderkey = o_orderkey AND l_commitdate < l_receiptdate)
GROUP BY o_orderpriority
ORDER BY o_orderpriority;`,
		Rewritten: `WITH late AS (
  SELECT o.o_orderkey AS ok, o.o_orderpriority AS pri, COUNT(*) AS n
  FROM lineitem AS l
  JOIN orders AS o ON o.o_orderkey = l.l_orderkey
  WHERE l.l_commitdate < l.l_receiptdate
    AND o.o_orderdate >= '1993-07-01'
    AND o.o_orderdate < '1993-10-01'
  GROUP BY o.o_orderkey, o.o_orderpriority)
SELECT late.pri AS o_orderpriority, COUNT(*) AS order_count
FROM late
GROUP BY late.pri
ORDER BY late.pri;`,
	},
	{
		Num:     5,
		Title:   "Local supplier volume",
		Dialect: []string{"comma-join", "date-literal"},
		Indexes: []string{"idx_nation_regionkey", "idx_orders_custkey_orderdate"},
		Note: "c_nationkey = s_nationkey closes a cycle, so it stays in WHERE as a comparison of two tables, which " +
			"RonSQL evaluates at the last table: it saves no join. The original form (the official table order) " +
			"therefore reads every customer's orders; the rewritten form starts at the region and ends at supplier. " +
			"MTR tests that comparison between the last table and its parent only.",
		Official: `SELECT n_name, SUM(l_extendedprice * (1 - l_discount)) AS revenue
FROM customer, orders, lineitem, supplier, nation, region
WHERE c_custkey = o_custkey
  AND l_orderkey = o_orderkey
  AND l_suppkey = s_suppkey
  AND c_nationkey = s_nationkey
  AND s_nationkey = n_nationkey
  AND n_regionkey = r_regionkey
  AND r_name = 'ASIA'
  AND o_orderdate >= DATE '1994-01-01'
  AND o_orderdate < DATE '1994-01-01' + INTERVAL '1' YEAR
GROUP BY n_name
ORDER BY revenue DESC;`,
		Original: `SELECT n.n_name, SUM(l.l_extendedprice * (1 - l.l_discount)) AS revenue
FROM customer AS c
JOIN orders AS o ON o.o_custkey = c.c_custkey
JOIN lineitem AS l ON l.l_orderkey = o.o_orderkey
JOIN supplier AS s ON s.s_suppkey = l.l_suppkey
JOIN nation AS n ON n.n_nationkey = s.s_nationkey
JOIN region AS r ON r.r_regionkey = n.n_regionkey
WHERE s.s_nationkey = c.c_nationkey
  AND r.r_name = 'ASIA'
  AND o.o_orderdate >= '1994-01-01'
  AND o.o_orderdate < '1995-01-01'
GROUP BY n.n_name
ORDER BY revenue DESC;`,
		Rewritten: `SELECT n.n_name, SUM(l.l_extendedprice * (1 - l.l_discount)) AS revenue
FROM region AS r
JOIN nation AS n ON n.n_regionkey = r.r_regionkey
JOIN customer AS c ON c.c_nationkey = n.n_nationkey
JOIN orders AS o ON o.o_custkey = c.c_custkey
JOIN lineitem AS l ON l.l_orderkey = o.o_orderkey
JOIN supplier AS s ON s.s_suppkey = l.l_suppkey
WHERE r.r_name = 'ASIA'
  AND o.o_orderdate >= '1994-01-01'
  AND o.o_orderdate < '1995-01-01'
  AND s.s_nationkey = c.c_nationkey
GROUP BY n.n_name
ORDER BY revenue DESC;`,
	},
	{
		Num:     6,
		Title:   "Forecasting revenue change",
		Dialect: []string{"date-literal", "between", "const-arith"},
		Official: `SELECT SUM(l_extendedprice * l_discount) AS revenue
FROM lineitem
WHERE l_shipdate >= DATE '1994-01-01'
  AND l_shipdate < DATE '1994-01-01' + INTERVAL '1' YEAR
  AND l_discount BETWEEN 0.06 - 0.01 AND 0.06 + 0.01
  AND l_quantity < 24;`,
		Original: `SELECT SUM(l_extendedprice * l_discount) AS revenue
FROM lineitem
WHERE l_shipdate >= '1994-01-01'
  AND l_shipdate < '1995-01-01'
  AND l_discount >= 0.05
  AND l_discount <= 0.07
  AND l_quantity < 24;`,
	},
	{
		Num:   7,
		Title: "Volume shipping",
		Blockers: []string{
			"the derived table",
			"EXTRACT(YEAR FROM l_shipdate) as an output and a GROUP BY key",
			"the nation pair: an OR of two AND groups over two tables",
		},
		Missing:   []string{"derived-table", "groupby-expr", "or-across-tables"},
		Dialect:   []string{"comma-join", "date-literal", "between", "alias-as"},
		Deviation: "pivoted: one row per nation pair with a revenue column per year (0 for a year without rows)",
		Note: "One chain along the join graph, from the supplier's nation to the customer's. The nation pair is two " +
			"name filters and n2.n_nationkey != n1.n_nationkey (nation names are unique). No MTR test has a CASE " +
			"condition on a DATE column of a table above the last one.",
		Official: `SELECT shipping.supp_nation, shipping.cust_nation, shipping.l_year, SUM(shipping.volume) AS revenue
FROM (
  SELECT n1.n_name AS supp_nation, n2.n_name AS cust_nation,
         EXTRACT(YEAR FROM l.l_shipdate) AS l_year,
         l.l_extendedprice * (1 - l.l_discount) AS volume
  FROM supplier AS s, lineitem AS l, orders AS o, customer AS c, nation AS n1, nation AS n2
  WHERE s.s_suppkey = l.l_suppkey
    AND o.o_orderkey = l.l_orderkey
    AND c.c_custkey = o.o_custkey
    AND s.s_nationkey = n1.n_nationkey
    AND c.c_nationkey = n2.n_nationkey
    AND ((n1.n_name = 'FRANCE' AND n2.n_name = 'GERMANY')
      OR (n1.n_name = 'GERMANY' AND n2.n_name = 'FRANCE'))
    AND l.l_shipdate BETWEEN DATE '1995-01-01' AND DATE '1996-12-31'
) AS shipping
GROUP BY shipping.supp_nation, shipping.cust_nation, shipping.l_year
ORDER BY shipping.supp_nation, shipping.cust_nation, shipping.l_year;`,
		Rewritten: `SELECT n1.n_name AS supp_nation, n2.n_name AS cust_nation,
       SUM(CASE WHEN l.l_shipdate <= '1995-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS revenue_1995,
       SUM(CASE WHEN l.l_shipdate >= '1996-01-01'
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS revenue_1996
FROM nation AS n1
JOIN supplier AS s ON s.s_nationkey = n1.n_nationkey
JOIN lineitem AS l ON l.l_suppkey = s.s_suppkey
JOIN orders AS o ON o.o_orderkey = l.l_orderkey
JOIN customer AS c ON c.c_custkey = o.o_custkey
JOIN nation AS n2 ON n2.n_nationkey = c.c_nationkey
WHERE (n1.n_name = 'FRANCE' OR n1.n_name = 'GERMANY')
  AND (n2.n_name = 'FRANCE' OR n2.n_name = 'GERMANY')
  AND n2.n_nationkey != n1.n_nationkey
  AND l.l_shipdate >= '1995-01-01'
  AND l.l_shipdate <= '1996-12-31'
GROUP BY n1.n_name, n2.n_name
ORDER BY n1.n_name, n2.n_name;`,
	},
	{
		Num:   8,
		Title: "National market share",
		Blockers: []string{
			"the derived table",
			"EXTRACT(YEAR FROM o_orderdate) as an output and a GROUP BY key",
			"SUM(...) / SUM(...) in the SELECT list",
		},
		Missing:   []string{"derived-table", "groupby-expr", "select-arith"},
		Dialect:   []string{"comma-join", "date-literal", "between", "alias-as"},
		Indexes:   []string{"idx_nation_regionkey", "idx_orders_custkey_orderdate"},
		Deviation: "one row with four sums (BRAZIL and total, per year); the client divides to get mkt_share",
		Note: "The eight tables form a star around lineitem, and the aggregation reads both sides of it (the order " +
			"date and the supplier's nation). The chain goes from the region down to lineitem and on through part " +
			"to partsupp, keyed from part and lineitem, so that supplier and its nation follow below part and not " +
			"beside it; every lineitem has a partsupp row, so that join removes nothing. MTR tests a key taken from " +
			"two tables for a CTE only, and no CASE condition on a DATE column of a table above the last one.",
		Official: `SELECT all_nations.o_year,
       SUM(CASE WHEN all_nations.nation = 'BRAZIL' THEN all_nations.volume ELSE 0 END)
         / SUM(all_nations.volume) AS mkt_share
FROM (
  SELECT EXTRACT(YEAR FROM o.o_orderdate) AS o_year,
         l.l_extendedprice * (1 - l.l_discount) AS volume,
         n2.n_name AS nation
  FROM part AS p, supplier AS s, lineitem AS l, orders AS o, customer AS c,
       nation AS n1, nation AS n2, region AS r
  WHERE p.p_partkey = l.l_partkey
    AND s.s_suppkey = l.l_suppkey
    AND l.l_orderkey = o.o_orderkey
    AND o.o_custkey = c.c_custkey
    AND c.c_nationkey = n1.n_nationkey
    AND n1.n_regionkey = r.r_regionkey
    AND r.r_name = 'AMERICA'
    AND s.s_nationkey = n2.n_nationkey
    AND o.o_orderdate BETWEEN DATE '1995-01-01' AND DATE '1996-12-31'
    AND p.p_type = 'ECONOMY ANODIZED STEEL'
) AS all_nations
GROUP BY all_nations.o_year
ORDER BY all_nations.o_year;`,
		Rewritten: `SELECT SUM(CASE WHEN n2.n_name = 'BRAZIL' AND o.o_orderdate <= '1995-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS brazil_1995,
       SUM(CASE WHEN o.o_orderdate <= '1995-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS total_1995,
       SUM(CASE WHEN n2.n_name = 'BRAZIL' AND o.o_orderdate >= '1996-01-01'
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS brazil_1996,
       SUM(CASE WHEN o.o_orderdate >= '1996-01-01'
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS total_1996
FROM region AS r
JOIN nation AS n1 ON n1.n_regionkey = r.r_regionkey
JOIN customer AS c ON c.c_nationkey = n1.n_nationkey
JOIN orders AS o ON o.o_custkey = c.c_custkey
JOIN lineitem AS l ON l.l_orderkey = o.o_orderkey
JOIN part AS p ON p.p_partkey = l.l_partkey
JOIN partsupp AS ps ON ps.ps_partkey = p.p_partkey AND ps.ps_suppkey = l.l_suppkey
JOIN supplier AS s ON s.s_suppkey = ps.ps_suppkey
JOIN nation AS n2 ON n2.n_nationkey = s.s_nationkey
WHERE r.r_name = 'AMERICA'
  AND o.o_orderdate >= '1995-01-01'
  AND o.o_orderdate <= '1996-12-31'
  AND p.p_type = 'ECONOMY ANODIZED STEEL';`,
	},
	{
		Num:   9,
		Title: "Product type profit",
		Blockers: []string{
			"the derived table",
			"EXTRACT(YEAR FROM o_orderdate) as an output and a GROUP BY key",
		},
		Missing:   []string{"derived-table", "groupby-expr"},
		Dialect:   []string{"comma-join"},
		Indexes:   []string{"idx_partsupp_suppkey", "idx_lineitem_partkey_suppkey"},
		Deviation: "pivoted: one row per nation with a profit column per year, 1998 down to 1992 (0 for a year without rows)",
		Note: "With lineitem in the middle the aggregation would read sibling branches, which RonSQL refuses when " +
			"it builds the join (not at EXPLAIN). This order is one chain from nation to orders; lineitem takes its " +
			"key from two tables above it (part and partsupp), which MTR tests for a CTE only.",
		Official: `SELECT profit.nation, profit.o_year, SUM(profit.amount) AS sum_profit
FROM (
  SELECT n.n_name AS nation,
         EXTRACT(YEAR FROM o.o_orderdate) AS o_year,
         l.l_extendedprice * (1 - l.l_discount) - ps.ps_supplycost * l.l_quantity AS amount
  FROM part AS p, supplier AS s, lineitem AS l, partsupp AS ps, orders AS o, nation AS n
  WHERE s.s_suppkey = l.l_suppkey
    AND ps.ps_suppkey = l.l_suppkey
    AND ps.ps_partkey = l.l_partkey
    AND p.p_partkey = l.l_partkey
    AND o.o_orderkey = l.l_orderkey
    AND s.s_nationkey = n.n_nationkey
    AND p.p_name LIKE '%green%'
) AS profit
GROUP BY profit.nation, profit.o_year
ORDER BY profit.nation, profit.o_year DESC;`,
		Rewritten: `SELECT n.n_name AS nation,
       SUM(CASE WHEN o.o_orderdate >= '1998-01-01' AND o.o_orderdate <= '1998-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) - ps.ps_supplycost * l.l_quantity ELSE 0 END) AS sum_profit_1998,
       SUM(CASE WHEN o.o_orderdate >= '1997-01-01' AND o.o_orderdate <= '1997-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) - ps.ps_supplycost * l.l_quantity ELSE 0 END) AS sum_profit_1997,
       SUM(CASE WHEN o.o_orderdate >= '1996-01-01' AND o.o_orderdate <= '1996-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) - ps.ps_supplycost * l.l_quantity ELSE 0 END) AS sum_profit_1996,
       SUM(CASE WHEN o.o_orderdate >= '1995-01-01' AND o.o_orderdate <= '1995-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) - ps.ps_supplycost * l.l_quantity ELSE 0 END) AS sum_profit_1995,
       SUM(CASE WHEN o.o_orderdate >= '1994-01-01' AND o.o_orderdate <= '1994-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) - ps.ps_supplycost * l.l_quantity ELSE 0 END) AS sum_profit_1994,
       SUM(CASE WHEN o.o_orderdate >= '1993-01-01' AND o.o_orderdate <= '1993-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) - ps.ps_supplycost * l.l_quantity ELSE 0 END) AS sum_profit_1993,
       SUM(CASE WHEN o.o_orderdate >= '1992-01-01' AND o.o_orderdate <= '1992-12-31'
                THEN l.l_extendedprice * (1 - l.l_discount) - ps.ps_supplycost * l.l_quantity ELSE 0 END) AS sum_profit_1992
FROM nation AS n
JOIN supplier AS s ON s.s_nationkey = n.n_nationkey
JOIN partsupp AS ps ON ps.ps_suppkey = s.s_suppkey
JOIN part AS p ON p.p_partkey = ps.ps_partkey
JOIN lineitem AS l ON l.l_partkey = p.p_partkey AND l.l_suppkey = ps.ps_suppkey
JOIN orders AS o ON o.o_orderkey = l.l_orderkey
WHERE p.p_name LIKE '%green%'
GROUP BY n.n_name
ORDER BY n.n_name;`,
	},
	{
		Num:     10,
		Title:   "Returned item reporting",
		Dialect: []string{"comma-join", "date-literal"},
		Indexes: []string{"idx_orders_custkey_orderdate"},
		Note: "Only one order puts the four tables on one chain: nation first. In the official order nation is " +
			"joined from customer and becomes a branch beside orders and lineitem, and the aggregation is refused. " +
			"Seven GROUP BY columns of customer and nation travel to every lineitem read.",
		Official: `SELECT c_custkey, c_name, SUM(l_extendedprice * (1 - l_discount)) AS revenue,
       c_acctbal, n_name, c_address, c_phone, c_comment
FROM customer, orders, lineitem, nation
WHERE c_custkey = o_custkey
  AND l_orderkey = o_orderkey
  AND o_orderdate >= DATE '1993-10-01'
  AND o_orderdate < DATE '1993-10-01' + INTERVAL '3' MONTH
  AND l_returnflag = 'R'
  AND c_nationkey = n_nationkey
GROUP BY c_custkey, c_name, c_acctbal, c_phone, n_name, c_address, c_comment
ORDER BY revenue DESC
LIMIT 20;`,
		Original: `SELECT c.c_custkey, c.c_name,
       SUM(l.l_extendedprice * (1 - l.l_discount)) AS revenue,
       c.c_acctbal, n.n_name, c.c_address, c.c_phone, c.c_comment
FROM nation AS n
JOIN customer AS c ON c.c_nationkey = n.n_nationkey
JOIN orders AS o ON o.o_custkey = c.c_custkey
JOIN lineitem AS l ON l.l_orderkey = o.o_orderkey
WHERE o.o_orderdate >= '1993-10-01'
  AND o.o_orderdate < '1994-01-01'
  AND l.l_returnflag = 'R'
GROUP BY c.c_custkey, c.c_name, c.c_acctbal, c.c_phone, n.n_name,
         c.c_address, c.c_comment
ORDER BY revenue DESC
LIMIT 20;`,
	},
	{
		Num:     11,
		Title:   "Important stock identification",
		Dialect: []string{"comma-join", "keyword-alias", "subquery-factor"},
		Indexes: []string{"idx_partsupp_suppkey"},
		Note: "The scalar subquery runs first, as its own statement; HAVING takes arithmetic on its result, a SELECT " +
			"list does not, so the 0.0001 moves out of the subquery. The original form scans partsupp twice " +
			"(800k rows each at scale factor 1); the rewritten one starts at the nation. No MTR test has a join " +
			"inside a scalar subquery.",
		Official: `SELECT ps.ps_partkey, SUM(ps.ps_supplycost * ps.ps_availqty) AS value
FROM partsupp AS ps, supplier AS s, nation AS n
WHERE ps.ps_suppkey = s.s_suppkey AND s.s_nationkey = n.n_nationkey
  AND n.n_name = 'GERMANY'
GROUP BY ps.ps_partkey
HAVING SUM(ps.ps_supplycost * ps.ps_availqty) > (
  SELECT SUM(ps2.ps_supplycost * ps2.ps_availqty) * 0.0001
  FROM partsupp AS ps2, supplier AS s2, nation AS n2
  WHERE ps2.ps_suppkey = s2.s_suppkey AND s2.s_nationkey = n2.n_nationkey
    AND n2.n_name = 'GERMANY')
ORDER BY value DESC;`,
		Original: "SELECT ps.ps_partkey, SUM(ps.ps_supplycost * ps.ps_availqty) AS `value`" + `
FROM partsupp AS ps
JOIN supplier AS s ON s.s_suppkey = ps.ps_suppkey
JOIN nation AS n ON n.n_nationkey = s.s_nationkey
WHERE n.n_name = 'GERMANY'
GROUP BY ps.ps_partkey
HAVING SUM(ps.ps_supplycost * ps.ps_availqty) > (
  SELECT SUM(ps2.ps_supplycost * ps2.ps_availqty)
  FROM partsupp AS ps2
  JOIN supplier AS s2 ON s2.s_suppkey = ps2.ps_suppkey
  JOIN nation AS n2 ON n2.n_nationkey = s2.s_nationkey
  WHERE n2.n_name = 'GERMANY') * 0.0001
` + "ORDER BY `value` DESC;",
		Rewritten: "SELECT ps.ps_partkey, SUM(ps.ps_supplycost * ps.ps_availqty) AS `value`" + `
FROM nation AS n
JOIN supplier AS s ON s.s_nationkey = n.n_nationkey
JOIN partsupp AS ps ON ps.ps_suppkey = s.s_suppkey
WHERE n.n_name = 'GERMANY'
GROUP BY ps.ps_partkey
HAVING SUM(ps.ps_supplycost * ps.ps_availqty) > (
  SELECT SUM(ps2.ps_supplycost * ps2.ps_availqty)
  FROM nation AS n2
  JOIN supplier AS s2 ON s2.s_nationkey = n2.n_nationkey
  JOIN partsupp AS ps2 ON ps2.ps_suppkey = s2.s_suppkey
  WHERE n2.n_name = 'GERMANY') * 0.0001
` + "ORDER BY `value` DESC;",
	},
	{
		Num:     12,
		Title:   "Shipping modes and order priority",
		Dialect: []string{"comma-join", "date-literal"},
		Indexes: []string{"idx_lineitem_receiptdate"},
		Note: "lineitem first: every filter is on lineitem and orders is then a primary key lookup. Without " +
			"idx_lineitem_receiptdate lineitem is scanned with the filter pushed down.",
		Official: `SELECT l_shipmode,
       SUM(CASE WHEN o_orderpriority = '1-URGENT' OR o_orderpriority = '2-HIGH'
                THEN 1 ELSE 0 END) AS high_line_count,
       SUM(CASE WHEN o_orderpriority <> '1-URGENT' AND o_orderpriority <> '2-HIGH'
                THEN 1 ELSE 0 END) AS low_line_count
FROM orders, lineitem
WHERE o_orderkey = l_orderkey
  AND l_shipmode IN ('MAIL', 'SHIP')
  AND l_commitdate < l_receiptdate
  AND l_shipdate < l_commitdate
  AND l_receiptdate >= DATE '1994-01-01'
  AND l_receiptdate < DATE '1994-01-01' + INTERVAL '1' YEAR
GROUP BY l_shipmode
ORDER BY l_shipmode;`,
		Original: `SELECT l.l_shipmode,
       SUM(CASE WHEN o.o_orderpriority = '1-URGENT' OR o.o_orderpriority = '2-HIGH'
                THEN 1 ELSE 0 END) AS high_line_count,
       SUM(CASE WHEN o.o_orderpriority <> '1-URGENT' AND o.o_orderpriority <> '2-HIGH'
                THEN 1 ELSE 0 END) AS low_line_count
FROM lineitem AS l
JOIN orders AS o ON o.o_orderkey = l.l_orderkey
WHERE l.l_shipmode IN ('MAIL', 'SHIP')
  AND l.l_commitdate < l.l_receiptdate
  AND l.l_shipdate < l.l_commitdate
  AND l.l_receiptdate >= '1994-01-01'
  AND l.l_receiptdate < '1995-01-01'
GROUP BY l.l_shipmode
ORDER BY l.l_shipmode;`,
	},
	{
		Num:   13,
		Title: "Customer distribution",
		Blockers: []string{
			"the derived table",
			"ON ... AND o_comment NOT LIKE ...: ON takes column equalities only, and the condition cannot move " +
				"to WHERE (there it rejects the customers without orders)",
		},
		Missing:   []string{"derived-table", "on-predicate"},
		Dialect:   []string{"not-infix"},
		Deviation: "the customers without a counted order form the group c_count NULL, where the official query has 0",
		Note: "The orders are counted per customer in a CTE over orders alone (its WHERE is the ON condition) and " +
			"customer is LEFT JOINed to it. No MTR test groups by an aggregate output of a LEFT-joined CTE.",
		Official: `SELECT c_orders.c_count, COUNT(*) AS custdist
FROM (SELECT c.c_custkey, COUNT(o.o_orderkey) AS c_count
      FROM customer AS c LEFT OUTER JOIN orders AS o
        ON c.c_custkey = o.o_custkey AND o.o_comment NOT LIKE '%special%requests%'
      GROUP BY c.c_custkey) AS c_orders
GROUP BY c_orders.c_count
ORDER BY custdist DESC, c_orders.c_count DESC;`,
		Rewritten: `WITH c_orders AS (
  SELECT o_custkey AS ck, COUNT(*) AS c_count
  FROM orders
  WHERE NOT (o_comment LIKE '%special%requests%')
  GROUP BY o_custkey)
SELECT c_orders.c_count, COUNT(*) AS custdist
FROM customer AS c
LEFT JOIN c_orders ON c_orders.ck = c.c_custkey
GROUP BY c_orders.c_count
ORDER BY custdist DESC, c_orders.c_count DESC;`,
	},
	{
		Num:   14,
		Title: "Promotion effect",
		Blockers: []string{
			"100.00 * SUM(...) / SUM(...) in the SELECT list",
			"LIKE in the CASE condition",
		},
		Missing:   []string{"select-arith", "case-shape"},
		Dialect:   []string{"comma-join", "date-literal"},
		Deviation: "one row with the two sums; the client computes 100 * promo_revenue_sum / total_revenue_sum",
		Note:      "The LIKE becomes the list of the 25 types that start with PROMO (a CASE condition takes no LIKE).",
		Official: `SELECT 100.00 * SUM(CASE WHEN p_type LIKE 'PROMO%'
                         THEN l_extendedprice * (1 - l_discount)
                         ELSE 0 END)
       / SUM(l_extendedprice * (1 - l_discount)) AS promo_revenue
FROM lineitem, part
WHERE l_partkey = p_partkey
  AND l_shipdate >= DATE '1995-09-01'
  AND l_shipdate < DATE '1995-09-01' + INTERVAL '1' MONTH;`,
		Rewritten: `SELECT SUM(CASE WHEN p.p_type = 'PROMO ANODIZED TIN' OR p.p_type = 'PROMO ANODIZED NICKEL'
                  OR p.p_type = 'PROMO ANODIZED BRASS' OR p.p_type = 'PROMO ANODIZED STEEL'
                  OR p.p_type = 'PROMO ANODIZED COPPER'
                  OR p.p_type = 'PROMO BURNISHED TIN' OR p.p_type = 'PROMO BURNISHED NICKEL'
                  OR p.p_type = 'PROMO BURNISHED BRASS' OR p.p_type = 'PROMO BURNISHED STEEL'
                  OR p.p_type = 'PROMO BURNISHED COPPER'
                  OR p.p_type = 'PROMO PLATED TIN' OR p.p_type = 'PROMO PLATED NICKEL'
                  OR p.p_type = 'PROMO PLATED BRASS' OR p.p_type = 'PROMO PLATED STEEL'
                  OR p.p_type = 'PROMO PLATED COPPER'
                  OR p.p_type = 'PROMO POLISHED TIN' OR p.p_type = 'PROMO POLISHED NICKEL'
                  OR p.p_type = 'PROMO POLISHED BRASS' OR p.p_type = 'PROMO POLISHED STEEL'
                  OR p.p_type = 'PROMO POLISHED COPPER'
                  OR p.p_type = 'PROMO BRUSHED TIN' OR p.p_type = 'PROMO BRUSHED NICKEL'
                  OR p.p_type = 'PROMO BRUSHED BRASS' OR p.p_type = 'PROMO BRUSHED STEEL'
                  OR p.p_type = 'PROMO BRUSHED COPPER'
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS promo_revenue_sum,
       SUM(l.l_extendedprice * (1 - l.l_discount)) AS total_revenue_sum
FROM lineitem AS l
JOIN part AS p ON p.p_partkey = l.l_partkey
WHERE l.l_shipdate >= '1995-09-01'
  AND l.l_shipdate < '1995-10-01';`,
	},
	{
		Num:   15,
		Title: "Top supplier",
		Blockers: []string{
			"SUM(l_extendedprice * (1 - l_discount)) as a CTE output",
			"the scalar subquery reads the CTE (and with a second CTE in its place, two CTE outputs would be compared)",
		},
		Missing:   []string{"cte-expr-agg", "subquery-reads-cte"},
		Dialect:   []string{"view", "comma-join", "date-literal"},
		Deviation: "one supplier also when several share the maximum (the official query returns all of them)",
		Note:      "No CTE: the maximum is the first row of the revenue per supplier in descending order.",
		Official: `WITH revenue0 AS (
  SELECT l.l_suppkey AS supplier_no,
         SUM(l.l_extendedprice * (1 - l.l_discount)) AS total_revenue
  FROM lineitem AS l
  WHERE l.l_shipdate >= DATE '1996-01-01'
    AND l.l_shipdate < DATE '1996-01-01' + INTERVAL '3' MONTH
  GROUP BY l.l_suppkey)
SELECT s.s_suppkey, s.s_name, s.s_address, s.s_phone, r.total_revenue
FROM supplier AS s, revenue0 AS r
WHERE s.s_suppkey = r.supplier_no
  AND r.total_revenue = (SELECT MAX(r2.total_revenue) FROM revenue0 AS r2)
ORDER BY s.s_suppkey;`,
		Rewritten: `SELECT s.s_suppkey, s.s_name, s.s_address, s.s_phone,
       SUM(l.l_extendedprice * (1 - l.l_discount)) AS total_revenue
FROM lineitem AS l
JOIN supplier AS s ON s.s_suppkey = l.l_suppkey
WHERE l.l_shipdate >= '1996-01-01' AND l.l_shipdate < '1996-04-01'
GROUP BY s.s_suppkey, s.s_name, s.s_address, s.s_phone
ORDER BY total_revenue DESC, s.s_suppkey
LIMIT 1;`,
	},
	{
		Num:      16,
		Title:    "Parts/supplier relationship",
		Blockers: []string{"COUNT(DISTINCT ps_suppkey): DISTINCT is not a RonSQL keyword"},
		Missing:  []string{"count-distinct"},
		Dialect:  []string{"comma-join", "not-infix"},
		Note: "COUNT(DISTINCT x) is a CTE grouped by the keys and x, regrouped by the keys. The NOT IN becomes a " +
			"primary key join to supplier with the negated condition.",
		Official: `SELECT p.p_brand, p.p_type, p.p_size, COUNT(DISTINCT ps.ps_suppkey) AS supplier_cnt
FROM partsupp AS ps, part AS p
WHERE p.p_partkey = ps.ps_partkey
  AND p.p_brand <> 'Brand#45'
  AND p.p_type NOT LIKE 'MEDIUM POLISHED%'
  AND p.p_size IN (49, 14, 23, 45, 19, 3, 36, 9)
  AND ps.ps_suppkey NOT IN (
    SELECT s.s_suppkey FROM supplier AS s WHERE s.s_comment LIKE '%Customer%Complaints%')
GROUP BY p.p_brand, p.p_type, p.p_size
ORDER BY supplier_cnt DESC, p.p_brand, p.p_type, p.p_size;`,
		Rewritten: `WITH pgrp AS (
  SELECT p.p_brand AS b, p.p_type AS t, p.p_size AS sz, ps.ps_suppkey AS sk, COUNT(*) AS n
  FROM part AS p
  JOIN partsupp AS ps ON ps.ps_partkey = p.p_partkey
  JOIN supplier AS s ON s.s_suppkey = ps.ps_suppkey
  WHERE p.p_brand <> 'Brand#45'
    AND NOT (p.p_type LIKE 'MEDIUM POLISHED%')
    AND p.p_size IN (49, 14, 23, 45, 19, 3, 36, 9)
    AND (s.s_comment IS NULL OR NOT (s.s_comment LIKE '%Customer%Complaints%'))
  GROUP BY p.p_brand, p.p_type, p.p_size, ps.ps_suppkey)
SELECT pgrp.b AS p_brand, pgrp.t AS p_type, pgrp.sz AS p_size, COUNT(*) AS supplier_cnt
FROM pgrp
GROUP BY pgrp.b, pgrp.t, pgrp.sz
ORDER BY supplier_cnt DESC, pgrp.b, pgrp.t, pgrp.sz;`,
	},
	{
		Num:   17,
		Title: "Small-quantity-order revenue",
		Blockers: []string{
			"SUM(...) / 7.0 and 0.2 * AVG(...) in SELECT lists",
			"the correlated subquery: its key is on part and the compared column on lineitem, and it would " +
				"return one row per part, far over the 1000-row limit",
		},
		Missing:   []string{"select-arith", "subquery-correlation", "subquery-cap"},
		Dialect:   []string{"comma-join"},
		Indexes:   []string{"idx_lineitem_partkey_suppkey"},
		Deviation: "one row per qualifying lineitem; the client sums price and divides by 7.0",
		Note: "l_quantity < 0.2 * avg is a stored DECIMAL against a CTE output with arithmetic: only HAVING takes " +
			"that, and HAVING works per group, so the statement groups by the lineitem key. 5 * q < avg is the same " +
			"test with an integer. The official form needs the same index on the MySQL server to finish.",
		Official: `SELECT SUM(l.l_extendedprice) / 7.0 AS avg_yearly
FROM lineitem AS l, part AS p
WHERE p.p_partkey = l.l_partkey
  AND p.p_brand = 'Brand#23' AND p.p_container = 'MED BOX'
  AND l.l_quantity < (
    SELECT 0.2 * AVG(l2.l_quantity) FROM lineitem AS l2
    WHERE l2.l_partkey = p.p_partkey);`,
		Rewritten: `WITH part_avg AS (
  SELECT pt.p_partkey AS pk, AVG(l2.l_quantity) AS aq
  FROM part AS pt
  JOIN lineitem AS l2 ON l2.l_partkey = pt.p_partkey
  WHERE pt.p_brand = 'Brand#23' AND pt.p_container = 'MED BOX'
  GROUP BY pt.p_partkey)
SELECT l.l_orderkey, l.l_linenumber, SUM(l.l_extendedprice) AS price
FROM part AS p
JOIN lineitem AS l ON l.l_partkey = p.p_partkey
JOIN part_avg ON part_avg.pk = l.l_partkey
WHERE p.p_brand = 'Brand#23' AND p.p_container = 'MED BOX'
GROUP BY l.l_orderkey, l.l_linenumber
HAVING MAX(5 * l.l_quantity - part_avg.aq) < 0;`,
	},
	{
		Num:   18,
		Title: "Large volume customer",
		Blockers: []string{
			"the IN subquery is on orders, a joined table in the official order",
			"with orders first, customer and lineitem are sibling branches and the aggregation reads both",
		},
		Missing: []string{"subquery-joined", "fanout-agg"},
		Dialect: []string{"comma-join"},
		Note: "The quantity per order is a CTE, scanned with the filter on its sum, with orders and customer as " +
			"primary key lookups. The last column is named sum_qty. The CTE has one group per order (1.5M at scale " +
			"factor 1; MTR proves 100k).",
		Official: `SELECT c.c_name, c.c_custkey, o.o_orderkey, o.o_orderdate, o.o_totalprice, SUM(l.l_quantity)
FROM customer AS c, orders AS o, lineitem AS l
WHERE o.o_orderkey IN (
    SELECT l2.l_orderkey FROM lineitem AS l2
    GROUP BY l2.l_orderkey HAVING SUM(l2.l_quantity) > 300)
  AND c.c_custkey = o.o_custkey
  AND o.o_orderkey = l.l_orderkey
GROUP BY c.c_name, c.c_custkey, o.o_orderkey, o.o_orderdate, o.o_totalprice
ORDER BY o.o_totalprice DESC, o.o_orderdate
LIMIT 100;`,
		Rewritten: `WITH big AS (
  SELECT l_orderkey AS ok, SUM(l_quantity) AS sum_qty
  FROM lineitem
  GROUP BY l_orderkey)
SELECT c.c_name, c.c_custkey, o.o_orderkey, o.o_orderdate, o.o_totalprice, big.sum_qty
FROM big
JOIN orders AS o ON o.o_orderkey = big.ok
JOIN customer AS c ON c.c_custkey = o.o_custkey
WHERE big.sum_qty > 300
ORDER BY o.o_totalprice DESC, o.o_orderdate
LIMIT 100;`,
	},
	{
		Num:   19,
		Title: "Discounted revenue",
		Blockers: []string{
			"the WHERE is an OR of three AND groups, each reading part and lineitem",
		},
		Missing:   []string{"or-across-tables"},
		Dialect:   []string{"comma-join", "between", "const-arith"},
		Indexes:   []string{"idx_lineitem_partkey_suppkey"},
		Deviation: "three sums, one per brand group; the client adds them",
		Note: "The three groups have different brands, so the part side is one filter on part (an OR of ANDs on " +
			"one table is fine), the shared lineitem conditions are filters on lineitem, and each brand's quantity " +
			"range is a CASE condition. 'AIR REG' is the official text and matches nothing (the mode is REG AIR). " +
			"No MTR test has a CASE condition whose atoms are on two tables.",
		Official: `SELECT SUM(l_extendedprice * (1 - l_discount)) AS revenue
FROM lineitem, part
WHERE (p_partkey = l_partkey AND p_brand = 'Brand#12'
       AND p_container IN ('SM CASE', 'SM BOX', 'SM PACK', 'SM PKG')
       AND l_quantity >= 1 AND l_quantity <= 1 + 10
       AND p_size BETWEEN 1 AND 5
       AND l_shipmode IN ('AIR', 'AIR REG')
       AND l_shipinstruct = 'DELIVER IN PERSON')
   OR (p_partkey = l_partkey AND p_brand = 'Brand#23'
       AND p_container IN ('MED BAG', 'MED BOX', 'MED PKG', 'MED PACK')
       AND l_quantity >= 10 AND l_quantity <= 10 + 10
       AND p_size BETWEEN 1 AND 10
       AND l_shipmode IN ('AIR', 'AIR REG')
       AND l_shipinstruct = 'DELIVER IN PERSON')
   OR (p_partkey = l_partkey AND p_brand = 'Brand#34'
       AND p_container IN ('LG CASE', 'LG BOX', 'LG PACK', 'LG PKG')
       AND l_quantity >= 20 AND l_quantity <= 20 + 10
       AND p_size BETWEEN 1 AND 15
       AND l_shipmode IN ('AIR', 'AIR REG')
       AND l_shipinstruct = 'DELIVER IN PERSON');`,
		Rewritten: `SELECT SUM(CASE WHEN p.p_brand = 'Brand#12' AND l.l_quantity >= 1 AND l.l_quantity <= 11
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS revenue_1,
       SUM(CASE WHEN p.p_brand = 'Brand#23' AND l.l_quantity >= 10 AND l.l_quantity <= 20
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS revenue_2,
       SUM(CASE WHEN p.p_brand = 'Brand#34' AND l.l_quantity >= 20 AND l.l_quantity <= 30
                THEN l.l_extendedprice * (1 - l.l_discount) ELSE 0 END) AS revenue_3
FROM part AS p
JOIN lineitem AS l ON l.l_partkey = p.p_partkey
WHERE ((p.p_brand = 'Brand#12'
        AND p.p_container IN ('SM CASE', 'SM BOX', 'SM PACK', 'SM PKG')
        AND p.p_size >= 1 AND p.p_size <= 5)
    OR (p.p_brand = 'Brand#23'
        AND p.p_container IN ('MED BAG', 'MED BOX', 'MED PKG', 'MED PACK')
        AND p.p_size >= 1 AND p.p_size <= 10)
    OR (p.p_brand = 'Brand#34'
        AND p.p_container IN ('LG CASE', 'LG BOX', 'LG PACK', 'LG PKG')
        AND p.p_size >= 1 AND p.p_size <= 15))
  AND l.l_shipmode IN ('AIR', 'AIR REG')
  AND l.l_shipinstruct = 'DELIVER IN PERSON'
  AND l.l_quantity >= 1
  AND l.l_quantity <= 30;`,
	},
	{
		Num:   20,
		Title: "Potential part promotion",
		Blockers: []string{
			"0.5 * SUM(...) in the subquery's SELECT list",
			"the correlated subquery has two correlations (part and supplier)",
			"the IN lists exceed 1000 values",
		},
		Missing: []string{"select-arith", "subquery-correlation", "subquery-cap"},
		Dialect: []string{"comma-join", "date-literal"},
		Indexes: []string{"idx_lineitem_partkey_suppkey"},
		Note: "The 1994 quantity per (part, supplier) of the forest parts is a CTE; the main query scans it and " +
			"reaches partsupp, supplier and nation by primary key. The IN becomes GROUP BY supplier and the " +
			"comparison a MAX in HAVING.",
		Official: `SELECT s.s_name, s.s_address
FROM supplier AS s, nation AS n
WHERE s.s_suppkey IN (
    SELECT ps.ps_suppkey FROM partsupp AS ps
    WHERE ps.ps_partkey IN (
        SELECT p.p_partkey FROM part AS p WHERE p.p_name LIKE 'forest%')
      AND ps.ps_availqty > (
        SELECT 0.5 * SUM(l.l_quantity) FROM lineitem AS l
        WHERE l.l_partkey = ps.ps_partkey AND l.l_suppkey = ps.ps_suppkey
          AND l.l_shipdate >= DATE '1994-01-01'
          AND l.l_shipdate < DATE '1994-01-01' + INTERVAL '1' YEAR))
  AND s.s_nationkey = n.n_nationkey AND n.n_name = 'CANADA'
ORDER BY s.s_name;`,
		Rewritten: `WITH qty AS (
  SELECT l2.l_partkey AS pk, l2.l_suppkey AS sk, SUM(l2.l_quantity) AS sq
  FROM part AS pt
  JOIN lineitem AS l2 ON l2.l_partkey = pt.p_partkey
  WHERE pt.p_name LIKE 'forest%'
    AND l2.l_shipdate >= '1994-01-01' AND l2.l_shipdate < '1995-01-01'
  GROUP BY l2.l_partkey, l2.l_suppkey)
SELECT s.s_name, s.s_address
FROM qty
JOIN partsupp AS ps ON ps.ps_partkey = qty.pk AND ps.ps_suppkey = qty.sk
JOIN supplier AS s ON s.s_suppkey = ps.ps_suppkey
JOIN nation AS n ON n.n_nationkey = s.s_nationkey
WHERE n.n_name = 'CANADA'
GROUP BY s.s_name, s.s_address
HAVING MAX(2 * ps.ps_availqty - qty.sq) > 0
ORDER BY s.s_name;`,
	},
	{
		Num:   21,
		Title: "Suppliers who kept orders waiting",
		Blockers: []string{
			"each EXISTS has a second correlation, l_suppkey <> l1.l_suppkey, which is not an equality",
			"the EXISTS conditions are on lineitem, a joined table",
			"each would return over 1000 keys",
		},
		Missing: []string{"subquery-correlation", "subquery-joined", "subquery-cap"},
		Dialect: []string{"comma-join", "select-star", "alias-as"},
		Note: "Both subqueries are facts about the order: another supplier has a line when MIN(l_suppkey) <> " +
			"MAX(l_suppkey) over its lines, and no other supplier is late when MIN = MAX over its late lines. Two " +
			"CTEs keyed on the order hold them (about 1.5M groups each at scale factor 1; MTR proves 100k).",
		Official: `SELECT s.s_name, COUNT(*) AS numwait
FROM supplier AS s, lineitem AS l1, orders AS o, nation AS n
WHERE s.s_suppkey = l1.l_suppkey
  AND o.o_orderkey = l1.l_orderkey
  AND o.o_orderstatus = 'F'
  AND l1.l_receiptdate > l1.l_commitdate
  AND EXISTS (
    SELECT * FROM lineitem AS l2
    WHERE l2.l_orderkey = l1.l_orderkey AND l2.l_suppkey <> l1.l_suppkey)
  AND NOT EXISTS (
    SELECT * FROM lineitem AS l3
    WHERE l3.l_orderkey = l1.l_orderkey AND l3.l_suppkey <> l1.l_suppkey
      AND l3.l_receiptdate > l3.l_commitdate)
  AND s.s_nationkey = n.n_nationkey
  AND n.n_name = 'SAUDI ARABIA'
GROUP BY s.s_name
ORDER BY numwait DESC, s.s_name
LIMIT 100;`,
		Rewritten: `WITH ord_supp AS (
  SELECT l_orderkey AS ok, MIN(l_suppkey) AS mn, MAX(l_suppkey) AS mx
  FROM lineitem
  GROUP BY l_orderkey),
late_supp AS (
  SELECT l_orderkey AS ok, MIN(l_suppkey) AS lmn, MAX(l_suppkey) AS lmx
  FROM lineitem
  WHERE l_receiptdate > l_commitdate
  GROUP BY l_orderkey)
SELECT s.s_name, COUNT(*) AS numwait
FROM nation AS n
JOIN supplier AS s ON s.s_nationkey = n.n_nationkey
JOIN lineitem AS l1 ON l1.l_suppkey = s.s_suppkey
JOIN orders AS o ON o.o_orderkey = l1.l_orderkey
JOIN ord_supp ON ord_supp.ok = o.o_orderkey
JOIN late_supp ON late_supp.ok = o.o_orderkey
WHERE n.n_name = 'SAUDI ARABIA'
  AND l1.l_receiptdate > l1.l_commitdate
  AND o.o_orderstatus = 'F'
  AND ord_supp.mn <> ord_supp.mx
  AND late_supp.lmn = late_supp.lmx
GROUP BY s.s_name
ORDER BY numwait DESC, s.s_name
LIMIT 100;`,
	},
	{
		Num:   22,
		Title: "Global sales opportunity",
		Blockers: []string{
			"the derived table",
			"SUBSTRING(c_phone, 1, 2) as a filter, an output and the GROUP BY key",
			"NOT EXISTS over orders returns one key per customer with orders, over the 1000-row limit",
		},
		Missing:   []string{"derived-table", "groupby-expr", "subquery-cap"},
		Dialect:   []string{"select-star"},
		Deviation: "pivoted: one row with a customer count and a balance sum per country code (0 for a code without customers)",
		Note: "The AVG subquery stays (it is on the first table), the NOT EXISTS is a CTE anti-join, and " +
			"SUBSTRING = 'NN' is LIKE 'NN%' in WHERE and a string range in the CASE conditions (LIKE is not allowed " +
			"there). No MTR test has a CASE over the NULL rows of a CTE anti-join or a string range in a CASE. The " +
			"14 CASE aggregates are an estimated 650 to 800 words of the 1024 the aggregation program may have.",
		Official: `SELECT custsale.cntrycode, COUNT(*) AS numcust, SUM(custsale.c_acctbal) AS totacctbal
FROM (SELECT SUBSTRING(c.c_phone, 1, 2) AS cntrycode, c.c_acctbal
      FROM customer AS c
      WHERE SUBSTRING(c.c_phone, 1, 2) IN ('13', '31', '23', '29', '30', '18', '17')
        AND c.c_acctbal > (
          SELECT AVG(c2.c_acctbal) FROM customer AS c2
          WHERE c2.c_acctbal > 0.00
            AND SUBSTRING(c2.c_phone, 1, 2) IN ('13', '31', '23', '29', '30', '18', '17'))
        AND NOT EXISTS (
          SELECT * FROM orders AS o WHERE o.o_custkey = c.c_custkey)
      ) AS custsale
GROUP BY custsale.cntrycode
ORDER BY custsale.cntrycode;`,
		Rewritten: `WITH cust_orders AS (
  SELECT cu.c_custkey AS k, COUNT(*) AS order_cnt
  FROM customer AS cu
  JOIN orders AS o ON o.o_custkey = cu.c_custkey
  WHERE cu.c_acctbal > 0.00
    AND (cu.c_phone LIKE '13%' OR cu.c_phone LIKE '31%' OR cu.c_phone LIKE '23%'
         OR cu.c_phone LIKE '29%' OR cu.c_phone LIKE '30%' OR cu.c_phone LIKE '18%'
         OR cu.c_phone LIKE '17%')
  GROUP BY cu.c_custkey)
SELECT
  SUM(CASE WHEN c.c_phone >= '13' AND c.c_phone < '14' THEN 1 ELSE 0 END) AS numcust_13,
  SUM(CASE WHEN c.c_phone >= '13' AND c.c_phone < '14' THEN c.c_acctbal ELSE 0 END) AS totacctbal_13,
  SUM(CASE WHEN c.c_phone >= '17' AND c.c_phone < '18' THEN 1 ELSE 0 END) AS numcust_17,
  SUM(CASE WHEN c.c_phone >= '17' AND c.c_phone < '18' THEN c.c_acctbal ELSE 0 END) AS totacctbal_17,
  SUM(CASE WHEN c.c_phone >= '18' AND c.c_phone < '19' THEN 1 ELSE 0 END) AS numcust_18,
  SUM(CASE WHEN c.c_phone >= '18' AND c.c_phone < '19' THEN c.c_acctbal ELSE 0 END) AS totacctbal_18,
  SUM(CASE WHEN c.c_phone >= '23' AND c.c_phone < '24' THEN 1 ELSE 0 END) AS numcust_23,
  SUM(CASE WHEN c.c_phone >= '23' AND c.c_phone < '24' THEN c.c_acctbal ELSE 0 END) AS totacctbal_23,
  SUM(CASE WHEN c.c_phone >= '29' AND c.c_phone < '30' THEN 1 ELSE 0 END) AS numcust_29,
  SUM(CASE WHEN c.c_phone >= '29' AND c.c_phone < '30' THEN c.c_acctbal ELSE 0 END) AS totacctbal_29,
  SUM(CASE WHEN c.c_phone >= '30' AND c.c_phone < '31' THEN 1 ELSE 0 END) AS numcust_30,
  SUM(CASE WHEN c.c_phone >= '30' AND c.c_phone < '31' THEN c.c_acctbal ELSE 0 END) AS totacctbal_30,
  SUM(CASE WHEN c.c_phone >= '31' AND c.c_phone < '32' THEN 1 ELSE 0 END) AS numcust_31,
  SUM(CASE WHEN c.c_phone >= '31' AND c.c_phone < '32' THEN c.c_acctbal ELSE 0 END) AS totacctbal_31
FROM customer AS c
LEFT JOIN cust_orders ON cust_orders.k = c.c_custkey
WHERE cust_orders.order_cnt IS NULL
  AND (c.c_phone LIKE '13%' OR c.c_phone LIKE '31%' OR c.c_phone LIKE '23%'
       OR c.c_phone LIKE '29%' OR c.c_phone LIKE '30%' OR c.c_phone LIKE '18%'
       OR c.c_phone LIKE '17%')
  AND c.c_acctbal > (
    SELECT AVG(c2.c_acctbal) FROM customer AS c2
    WHERE c2.c_acctbal > 0.00
      AND (c2.c_phone LIKE '13%' OR c2.c_phone LIKE '31%' OR c2.c_phone LIKE '23%'
           OR c2.c_phone LIKE '29%' OR c2.c_phone LIKE '30%' OR c2.c_phone LIKE '18%'
           OR c2.c_phone LIKE '17%'));`,
	},
}

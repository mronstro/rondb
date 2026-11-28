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

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/logicalclocks/rondb/tools/rondb-cli/internal/fsq/exec"
)

// ronsqlKeywordsHeader is RonSQL's keyword table, relative to this
// package: the lexer refuses every MySQL keyword it does not implement,
// also as an alias or a CTE name.
const ronsqlKeywordsHeader = "../../../../storage/ndb/src/ronsql/Keywords.hpp"

var (
	tpchWord       = regexp.MustCompile(`[A-Za-z_][A-Za-z_0-9$]*`)
	tpchKwdef      = regexp.MustCompile(`kwdef\((\w+)\)`)
	tpchQuotedWord = regexp.MustCompile(`"(\w+)"`)
	// The text after a JOIN keyword: the joined table, its alias, the ON list.
	tpchJoinWord    = regexp.MustCompile(`(?i)\bJOIN\b`)
	tpchJoinHead    = regexp.MustCompile(`(?is)^\s*(\w+)(?:\s+AS\s+(\w+))?\s+ON\b(.*)$`)
	tpchJoinEnd     = regexp.MustCompile(`(?i)\bLEFT\b|\bWHERE\b|\bGROUP\b|\bORDER\b|\)|;`)
	tpchOnCondition = regexp.MustCompile(`^\s*(\w+)\.\w+\s*=\s*(\w+)\.\w+\s*$`)
	tpchAnd         = regexp.MustCompile(`(?i)\bAND\b`)
	tpchSelectList  = regexp.MustCompile(`(?is)\bSELECT\b(.*?)\bFROM\b`)
	tpchDecimal     = regexp.MustCompile(`\d+\.\d+`)
)

// tpchKeywordLists reads the keywords RonSQL implements and all MySQL
// keywords from Keywords.hpp; ok is false when the header is not there
// (the CLI built outside the RonDB tree).
func tpchKeywordLists(t *testing.T) (implemented, mysql map[string]bool, ok bool) {
	src, err := os.ReadFile(ronsqlKeywordsHeader)
	if err != nil {
		t.Logf("keyword check skipped: %v", err)
		return nil, nil, false
	}
	text := string(src)
	section := func(marker string) string {
		i := strings.Index(text, marker)
		if i < 0 {
			t.Fatalf("%s: no %q", ronsqlKeywordsHeader, marker)
		}
		rest := text[i:]
		return rest[:strings.Index(rest, "};")]
	}
	implemented = map[string]bool{}
	impl := section("keywords_implemented_in_ronsql[] =")
	for _, m := range tpchKwdef.FindAllStringSubmatch(impl, -1) {
		implemented[m[1]] = true
	}
	for _, m := range tpchQuotedWord.FindAllStringSubmatch(impl, -1) {
		implemented[m[1]] = true
	}
	mysql = map[string]bool{}
	for _, m := range tpchQuotedWord.FindAllStringSubmatch(section("keywords_defined_in_mysql[] ="), -1) {
		mysql[m[1]] = true
	}
	if len(implemented) < 50 || len(mysql) < 500 {
		t.Fatalf("%s: read %d implemented and %d MySQL keywords", ronsqlKeywordsHeader, len(implemented), len(mysql))
	}
	return implemented, mysql, true
}

// tpchWithoutStrings blanks the string literals and the backtick-quoted
// identifiers of a statement (a quoted identifier may be a keyword).
func tpchWithoutStrings(sql string) string {
	out := []byte(sql)
	quote := byte(0)
	for i := range out {
		switch {
		case quote != 0:
			if out[i] == quote {
				quote = 0
			}
			out[i] = ' '
		case out[i] == '\'' || out[i] == '`':
			quote = out[i]
			out[i] = ' '
		}
	}
	return string(out)
}

// tpchLintRonSQL returns what RonSQL's lexer and grammar would refuse in a
// statement, as far as a text check can tell.
func tpchLintRonSQL(sql string, implemented, mysql map[string]bool) []string {
	var problems []string
	bare := tpchWithoutStrings(sql)
	if !strings.HasSuffix(strings.TrimSpace(sql), ";") {
		problems = append(problems, "does not end with ;")
	}
	if strings.Count(bare, ";") != 1 {
		problems = append(problems, "not exactly one ;")
	}
	for _, marker := range []string{"--", "/*", "#", "\""} {
		if strings.Contains(bare, marker) {
			problems = append(problems, "has "+marker+" (RonSQL lexes no comments and no double quotes)")
		}
	}
	if mysql != nil {
		seen := map[string]bool{}
		for _, word := range tpchWord.FindAllString(bare, -1) {
			up := strings.ToUpper(word)
			if mysql[up] && !implemented[up] && !seen[up] {
				seen[up] = true
				problems = append(problems, "keyword RonSQL does not implement: "+word)
			}
		}
	}
	// Each ON equality is <joined table>.<column> = <earlier table>.<column>
	// (RonSQLParser.y join_condition, RonSQLPreparer check_join_conditions).
	for _, after := range tpchJoinWord.Split(bare, -1)[1:] {
		head := tpchJoinHead.FindStringSubmatch(after)
		if head == nil {
			problems = append(problems, "JOIN without ON")
			continue
		}
		joined := head[2]
		if joined == "" {
			joined = head[1]
		}
		conditions := head[3]
		if end := tpchJoinEnd.FindStringIndex(conditions); end != nil {
			conditions = conditions[:end[0]]
		}
		for _, cond := range tpchAnd.Split(conditions, -1) {
			sides := tpchOnCondition.FindStringSubmatch(cond)
			switch {
			case sides == nil:
				problems = append(problems, "ON condition is not alias.column = alias.column: "+strings.TrimSpace(cond))
			case !strings.EqualFold(sides[1], joined) || strings.EqualFold(sides[2], joined):
				problems = append(problems, "ON condition does not have the joined table on the left only: "+strings.TrimSpace(cond))
			}
		}
	}
	// A SELECT list takes integer constants only (arith_expr has T_INT).
	for _, list := range tpchSelectList.FindAllStringSubmatch(bare, -1) {
		if tpchDecimal.MatchString(list[1]) {
			problems = append(problems, "non-integer constant in a SELECT list")
		}
	}
	return problems
}

func TestTPCHRegistry(t *testing.T) {
	if len(tpchQueries) != 22 {
		t.Fatalf("%d TPC-H queries, want 22", len(tpchQueries))
	}
	features := map[string]tpchFeature{}
	for _, f := range tpchFeatures {
		if _, dup := features[f.Key]; dup || f.Key == "" || f.Text == "" {
			t.Errorf("feature %q: empty or registered twice", f.Key)
		}
		features[f.Key] = f
	}
	indexes := map[string]bool{}
	for _, idx := range tpchExtraIndexes {
		if indexes[idx.Name] || idx.Table == "" || len(idx.columnList()) == 0 || idx.Why == "" {
			t.Errorf("index %q: incomplete or registered twice", idx.Name)
		}
		indexes[idx.Name] = true
	}
	implemented, mysql, _ := tpchKeywordLists(t)
	usedIndexes := map[string]bool{}
	for i := range tpchQueries {
		q := &tpchQueries[i]
		if q.Num != i+1 {
			t.Errorf("entry %d is Q%d", i, q.Num)
		}
		if q.Title == "" || strings.TrimSpace(q.Official) == "" {
			t.Errorf("%s: no title or no official form", q.label())
		}
		if (q.Original == "") != (len(q.Blockers) > 0) {
			t.Errorf("%s: Blockers say why there is no original form, and only that", q.label())
		}
		if (q.Original == "") != (len(q.Missing) > 0) {
			t.Errorf("%s: Missing lists what blocks the original form, and only that", q.label())
		}
		if q.Rewritten == "" && q.Deviation != "" {
			t.Errorf("%s: a deviation without a rewritten form", q.label())
		}
		if len(q.Dialect) == 0 {
			t.Errorf("%s: no official TPC-H text passes RonSQL's parser unchanged; say what differs", q.label())
		}
		for _, key := range q.Missing {
			if f, ok := features[key]; !ok || f.Spelling {
				t.Errorf("%s: Missing key %q is not a blocking feature of tpchFeatures", q.label(), key)
			}
		}
		for _, key := range q.Dialect {
			if f, ok := features[key]; !ok || !f.Spelling {
				t.Errorf("%s: Dialect key %q is not a spelling feature of tpchFeatures", q.label(), key)
			}
		}
		for _, name := range q.Indexes {
			if !indexes[name] {
				t.Errorf("%s: index %q is not in tpchExtraIndexes", q.label(), name)
			}
			usedIndexes[name] = true
		}
		if strings.TrimSpace(q.Official) != "" && !strings.HasSuffix(strings.TrimSpace(q.Official), ";") {
			t.Errorf("%s official: does not end with ;", q.label())
		}
		for _, f := range tpchRonSQLForms(q) {
			for _, problem := range tpchLintRonSQL(q.sqlOf(f), implemented, mysql) {
				t.Errorf("%s %s: %s", q.label(), f, problem)
			}
			entry := q.benchEntry(f)
			if entry.MySQLOnly || entry.Database != tpchDatabase || entry.SQL != q.sqlOf(f) || !entry.QuietSQL {
				t.Errorf("%s %s: wrong bench entry %+v", q.label(), f, entry)
			}
		}
		if !q.benchEntry(tpchFormOfficial).MySQLOnly {
			t.Errorf("%s: the official form runs on MySQL only", q.label())
		}
		if findTPCHQuery(q.label()) != q || findTPCHQuery(strings.ToUpper(q.label())) != q {
			t.Errorf("%s: not found by its label", q.label())
		}
	}
	for name := range indexes {
		if !usedIndexes[name] {
			t.Errorf("index %q is used by no query", name)
		}
	}
	original, rewrittenOnly, none := tpchCounts()
	if original+rewrittenOnly+none != 22 {
		t.Errorf("counts %d + %d + %d do not add up", original, rewrittenOnly, none)
	}
	if findTPCHQuery("q0") != nil || findTPCHQuery("q23") != nil || findTPCHQuery("all") != nil {
		t.Error("findTPCHQuery accepts a name that is no query")
	}
}

func TestTPCHLintRonSQL(t *testing.T) {
	implemented, mysql, ok := tpchKeywordLists(t)
	clean := "SELECT COUNT(*) AS cnt FROM orders AS o JOIN lineitem AS l ON l.l_orderkey = o.o_orderkey " +
		"WHERE o.o_comment LIKE '%special -- requests%';"
	if p := tpchLintRonSQL(clean, implemented, mysql); len(p) != 0 {
		t.Errorf("clean statement: %v", p)
	}
	refused := map[string]string{
		"SELECT COUNT(*) FROM orders":                                                                                                     "does not end with ;",
		"SELECT COUNT(*) FROM orders; SELECT COUNT(*) FROM region;":                                                                       "not exactly one ;",
		"SELECT COUNT(*) FROM orders -- all of them\n;":                                                                                   "has --",
		"SELECT COUNT(*) FROM orders AS o JOIN lineitem AS l ON o.o_orderkey = 1;":                                                        "ON condition is not",
		"SELECT COUNT(*) FROM orders AS o JOIN lineitem AS l ON l_orderkey = o.o_id;":                                                     "ON condition is not",
		"SELECT COUNT(*) FROM orders AS o JOIN lineitem AS l ON o.o_orderkey = l.l_orderkey;":                                             "joined table on the left",
		"SELECT COUNT(*) FROM orders AS o JOIN lineitem ON lineitem.l_orderkey = o.o_orderkey JOIN part AS p ON p.k = o.k AND o.x = p.y;": "joined table on the left",
		"SELECT COUNT(*) FROM orders AS o JOIN lineitem AS l WHERE l.l_orderkey = o.o_orderkey;":                                          "JOIN without ON",
		"SELECT SUM(l_extendedprice * 0.5) AS half FROM lineitem;":                                                                        "non-integer constant",
	}
	if ok {
		refused["SELECT COUNT(*) FROM lineitem WHERE l_discount BETWEEN 0.05 AND 0.07;"] = "BETWEEN"
		refused["SELECT COUNT(DISTINCT l_suppkey) FROM lineitem;"] = "DISTINCT"
		refused["SELECT SUM(ps_availqty) AS value FROM partsupp;"] = "value"
	}
	for sql, want := range refused {
		problems := strings.Join(tpchLintRonSQL(sql, implemented, mysql), "; ")
		if !strings.Contains(problems, want) {
			t.Errorf("%s: problems %q, want one with %q", sql, problems, want)
		}
	}
}

func TestTPCHHasOrderBy(t *testing.T) {
	cases := map[string]bool{
		"SELECT a, COUNT(*) FROM t GROUP BY a ORDER BY a;":                                             true,
		"SELECT a, COUNT(*) FROM t GROUP BY a\norder\tby a DESC LIMIT 10;":                             true,
		"SELECT a, COUNT(*) FROM t GROUP BY a;":                                                        false,
		"WITH c AS (SELECT a, COUNT(*) AS n FROM t GROUP BY a ORDER BY n LIMIT 5) SELECT c.a FROM c;":  false,
		"SELECT COUNT(*) FROM t WHERE b = 'ORDER BY';":                                                 false,
		"WITH c AS (SELECT a, COUNT(*) AS n FROM t GROUP BY a) SELECT c.a, c.n FROM c ORDER BY c.n;":   true,
		"SELECT a FROM t WHERE a IN (SELECT MAX(b) FROM u GROUP BY b ORDER BY b) AND c = ')' LIMIT 1;": false,
	}
	for sql, want := range cases {
		if got := tpchHasOrderBy(sql); got != want {
			t.Errorf("tpchHasOrderBy(%q) = %v, want %v", sql, got, want)
		}
	}
}

// tpchTestResult builds a result: with column types as MySQL returns one,
// without as RonSQL does.
func tpchTestResult(types []string, rows ...[]string) *exec.Result {
	r := &exec.Result{Types: types}
	width := len(types)
	if width == 0 && len(rows) > 0 {
		width = len(rows[0])
	}
	for i := 0; i < width; i++ {
		r.Columns = append(r.Columns, "c")
	}
	for _, row := range rows {
		cells := make([]exec.Cell, len(row))
		for i, text := range row {
			cells[i] = exec.Cell{Text: text, Null: text == "NULL"}
		}
		r.Rows = append(r.Rows, cells)
	}
	return r
}

func TestTPCHCompare(t *testing.T) {
	types := []string{"CHAR", "DECIMAL", "BIGINT"}
	mysql := tpchTestResult(types, []string{"A", "20321.5008", "7"}, []string{"N", "0.050003", "9"})

	// SUM over a DECIMAL expression is a double in RonSQL; AVG has four decimals.
	ronsql := tpchTestResult(nil, []string{"A", "20321.500799999998", "7"}, []string{"N", "0.0500", "9"})
	if equal, verdict, _ := tpchCompare(mysql, ronsql, true); !equal || !strings.Contains(verdict, "same order") {
		t.Errorf("equal within tolerance: %v %q", equal, verdict)
	}

	swapped := tpchTestResult(nil, []string{"N", "0.0500", "9"}, []string{"A", "20321.500799999998", "7"})
	if equal, verdict, _ := tpchCompare(mysql, swapped, true); !equal || !strings.Contains(verdict, "another order") {
		t.Errorf("same rows in another order: %v %q", equal, verdict)
	}
	if equal, _, _ := tpchCompare(mysql, swapped, false); !equal {
		t.Error("an unordered comparison ignores the row order")
	}

	// A count is compared exactly, a sum beyond the tolerance differs.
	for _, wrong := range []*exec.Result{
		tpchTestResult(nil, []string{"A", "20321.5008", "8"}, []string{"N", "0.0500", "9"}),
		tpchTestResult(nil, []string{"A", "20321.6008", "7"}, []string{"N", "0.0500", "9"}),
		tpchTestResult(nil, []string{"A", "20321.5008", "7"}),
		tpchTestResult(nil, []string{"A", "20321.5008", "7"}, []string{"NULL", "0.0500", "9"}),
	} {
		equal, verdict, detail := tpchCompare(mysql, wrong, true)
		if equal || verdict == "" || len(detail) == 0 {
			t.Errorf("a wrong result compares equal: %q %v", verdict, detail)
		}
	}

	// CHAR padding is not a difference; an empty result has no columns in RonSQL.
	padded := tpchTestResult(nil, []string{"A  ", "20321.5008", "7"}, []string{"N", "0.050003", "9"})
	if equal, _, _ := tpchCompare(mysql, padded, true); !equal {
		t.Error("trailing spaces differ")
	}
	if equal, verdict, _ := tpchCompare(tpchTestResult(types), &exec.Result{}, true); !equal || !strings.Contains(verdict, "0 rows") {
		t.Errorf("two empty results: %v %q", equal, verdict)
	}

	// A CHAR value filled with NUL is another value, and the rows shown
	// say so: a terminal prints "A\0\0\0" as "A".
	nulFilled := tpchTestResult(nil, []string{"A\x00\x00\x00", "20321.5008", "7"}, []string{"N", "0.050003", "9"})
	equal, _, detail := tpchCompare(mysql, nulFilled, true)
	if equal {
		t.Error("a value filled with NUL compares equal")
	}
	if shown := strings.Join(detail, "\n"); !strings.Contains(shown, `RonSQL: A\x00{3} | `) {
		t.Errorf("the NUL bytes are not shown:\n%s", shown)
	}
}

func TestTPCHVisible(t *testing.T) {
	for text, want := range map[string]string{
		"":                   "",
		"plain text 1.50":    "plain text 1.50",
		"A\x00\x00\x00":      `A\x00{3}`,
		"\x00A":              `\x00A`,
		"a\tb\n":             `a\x09b\x0a`,
		"x\x00\x00y\x7f\x7f": `x\x00{2}y\x7f{2}`,
		"räksmörgås":         "räksmörgås",
	} {
		if got := tpchVisible(text); got != want {
			t.Errorf("tpchVisible(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestTPCHIndexPresent(t *testing.T) {
	existing := map[string][][]string{
		"lineitem": {{"l_orderkey", "l_linenumber"}, {"l_suppkey"}, {"l_suppkey", "l_partkey", "l_shipdate"}},
	}
	want := func(table, columns string) tpchIndex { return tpchIndex{Name: "x", Table: table, Columns: columns} }
	for _, present := range []tpchIndex{
		want("lineitem", "l_orderkey"),
		want("lineitem", "l_suppkey"),
		want("lineitem", "L_SUPPKEY, l_partkey"),
	} {
		if !tpchIndexPresent(existing, present) {
			t.Errorf("%s(%s) is there", present.Table, present.Columns)
		}
	}
	for _, absent := range []tpchIndex{
		want("lineitem", "l_partkey"),
		want("lineitem", "l_partkey, l_suppkey"), // the columns in another order
		want("lineitem", "l_linenumber"),
		want("orders", "o_custkey"),
	} {
		if tpchIndexPresent(existing, absent) {
			t.Errorf("%s(%s) is not there", absent.Table, absent.Columns)
		}
	}
}

func TestTPCHRunOpts(t *testing.T) {
	// No connections: the default (both engines) has nothing to run on.
	s := &Shell{}
	if _, err := s.parseTPCHRunOpts(nil, false); err == nil {
		t.Error("no engine connected must fail")
	}
	if _, err := s.parseTPCHRunOpts([]string{"mysql"}, false); err == nil {
		t.Error("an engine asked for and not connected must fail")
	}
	for _, bad := range [][]string{{"0"}, {"x"}, {"1", "2", "3"}, {"-1"}, {"2", "q23"}} {
		if _, err := s.parseTPCHRunOpts(bad, false); err == nil || !strings.Contains(err.Error(), bad[len(bad)-1]) {
			t.Errorf("arguments %v: error %v", bad, err)
		}
	}

	// Queries, counts and the engine in any order; a bare number is a count.
	// The statements are printed only when the flag asks for it.
	o, engineGiven, err := parseTPCHRunArgs([]string{"q18", "2", "ronsql", "q4", "5"})
	if err != nil || o.threads != 2 || o.requests != 5 || !o.ronsql || o.mysql || !engineGiven ||
		o.queries.labels() != "q4 q18" || o.showSQL {
		t.Errorf("queries among the arguments: %+v, engine given %v, error %v", o, engineGiven, err)
	}
	// No query named: every query, with the defaults for what is left out.
	o, engineGiven, err = parseTPCHRunArgs([]string{"4"})
	if err != nil || o.threads != 4 || o.requests != tpchDefaultRequests || !o.ronsql || !o.mysql || engineGiven ||
		len(o.queries.list()) != len(tpchQueries) {
		t.Errorf("no query among the arguments: %+v, engine given %v, error %v", o, engineGiven, err)
	}
	o, _, err = parseTPCHRunArgs([]string{"q5", tpchShowFlag, "1", "3"})
	if err != nil || !o.showSQL || o.straight || o.threads != 1 || o.requests != 3 || o.queries.labels() != "q5" {
		t.Errorf("the show flag among the arguments: %+v, error %v", o, err)
	}
	for _, flag := range []string{"--straight", "--straight-join", "--STRAIGHT_JOIN"} {
		o, _, err = parseTPCHRunArgs([]string{flag, "q5", "mysql"})
		if err != nil || !o.straight || o.showSQL || o.ronsql || !o.mysql || o.queries.labels() != "q5" {
			t.Errorf("%s among the arguments: %+v, error %v", flag, o, err)
		}
	}
}

// --straight: every query block of the text MySQL gets has STRAIGHT_JOIN,
// and nothing else of the statement changes.
func TestTPCHStraightJoin(t *testing.T) {
	for _, c := range []struct{ sql, want string }{
		{"SELECT a FROM t JOIN u ON u.k = t.k",
			"SELECT STRAIGHT_JOIN a FROM t JOIN u ON u.k = t.k"},
		{"WITH c AS (select k FROM t)\nSelect c.k FROM c WHERE c.k IN (SELECT k FROM u)",
			"WITH c AS (select STRAIGHT_JOIN k FROM t)\nSelect STRAIGHT_JOIN c.k FROM c WHERE c.k IN (SELECT STRAIGHT_JOIN k FROM u)"},
		// not the keyword: inside a literal, a quoted name, or a longer word
		{"SELECT 'select x', 'it''s select', \"select\", `select`, selected, pre_select FROM t",
			"SELECT STRAIGHT_JOIN 'select x', 'it''s select', \"select\", `select`, selected, pre_select FROM t"},
		{"SELECT 'a\\' select' FROM t",
			"SELECT STRAIGHT_JOIN 'a\\' select' FROM t"},
	} {
		if got := tpchStraightJoin(c.sql); got != c.want {
			t.Errorf("tpchStraightJoin(%q)\n got %q\nwant %q", c.sql, got, c.want)
		}
	}

	keyword := regexp.MustCompile(`(?i)\bselect\b`)
	for i := range tpchQueries {
		q := &tpchQueries[i]
		for _, f := range []tpchForm{tpchFormOfficial, tpchFormOriginal, tpchFormRewritten} {
			sql := q.sqlOf(f)
			if sql == "" {
				continue
			}
			// The registry's statements have no literal or comment with the
			// word in it, so every occurrence is a query block.
			blocks := len(keyword.FindAllString(sql, -1))
			forced := tpchStraightJoin(sql)
			if n := strings.Count(forced, " STRAIGHT_JOIN"); n != blocks || blocks == 0 {
				t.Errorf("%s %s: STRAIGHT_JOIN in %d of %d query blocks", q.label(), f, n, blocks)
			}
			if strings.ReplaceAll(forced, " STRAIGHT_JOIN", "") != sql {
				t.Errorf("%s %s: the statement changes beyond the option:\n%s", q.label(), f, forced)
			}
		}
	}
}

func TestTPCHSelection(t *testing.T) {
	// An empty selection, and one a caller never made, is every query in
	// the order of the registry.
	var unset tpchSelection
	for _, sel := range []tpchSelection{unset, {}} {
		all := sel.list()
		if len(all) != len(tpchQueries) || all[0] != &tpchQueries[0] || all[len(all)-1] != &tpchQueries[len(tpchQueries)-1] {
			t.Errorf("an empty selection lists %d queries, want all %d", len(all), len(tpchQueries))
		}
	}

	for _, c := range []struct {
		arg     string
		bare    bool
		isQuery bool
		want    string // the queries selected; "" with isQuery: an error
	}{
		{"q5", false, true, "q5"},
		{"Q05", false, true, "q5"},
		{"q18,q4", false, true, "q4 q18"},
		{"q18,4", false, true, "q4 q18"},
		{"q4,", false, true, "q4"},
		{"5", true, true, "q5"},
		{"4,18", true, true, "q4 q18"},
		// in a run a number is a thread or request count
		{"5", false, false, ""},
		{"4,18", false, false, ""},
		// other words are left to the caller
		{"ronsql", true, false, ""},
		{"query", true, false, ""},
		{"q", true, false, ""},
		{"", true, false, ""},
		{"-5", true, false, ""},
		// a query name that is none of the 22
		{"q0", false, true, ""},
		{"q23", false, true, ""},
		{"23", true, true, ""},
		{"q4,x", false, true, ""},
	} {
		sel := tpchSelection{}
		isQuery, err := tpchSelectArg(c.arg, c.bare, sel)
		switch {
		case isQuery != c.isQuery:
			t.Errorf("%q (bare %v): read as a query: %v, want %v", c.arg, c.bare, isQuery, c.isQuery)
		case !isQuery && (err != nil || len(sel) != 0):
			t.Errorf("%q (bare %v) is no query and gives error %v, selection %v", c.arg, c.bare, err, sel)
		case isQuery && c.want == "" && err == nil:
			t.Errorf("%q (bare %v) names no TPC-H query and selects %s", c.arg, c.bare, sel.labels())
		case isQuery && c.want != "" && (err != nil || sel.labels() != c.want):
			t.Errorf("%q (bare %v) selects %s (error %v), want %s", c.arg, c.bare, sel.labels(), err, c.want)
		}
	}
}

// The commands read their arguments before they need a connection, so a
// Shell without one tells a bad argument from a good one.
func TestTPCHCommandArguments(t *testing.T) {
	s := &Shell{}
	for _, c := range []struct {
		args []string
		want string // part of the error
	}{
		{[]string{"verify", "q4", "rewritten"}, "not connected"},
		{[]string{"verify", "rewritten", "q4,q18"}, "not connected"},
		{[]string{"verify", "all"}, "not connected"},
		{[]string{"verify", "--show", "q4"}, "not connected"},
		{[]string{"verify", "--sql"}, "usage: .bench_tpch verify"},
		{[]string{"check", "q4", "--show"}, "not connected"},
		{[]string{"all", "--sql"}, "invalid argument: --sql"},
		{[]string{"verify", "q5", "--straight"}, "not connected"},
		{[]string{"check", "q5", "--straight"}, "usage: .bench_tpch check"},
		{[]string{"explain", "q5", "rewritten", "--straight"}, "forces the join order on the MySQL server"},
		{[]string{"explain", "q5", "rewritten", "mysql", "--straight"}, "MySQL not connected"},
		{[]string{"verify", "q23"}, "no such TPC-H query: q23"},
		{[]string{"verify", "official"}, "usage: .bench_tpch verify"},
		{[]string{"check", "q4", "18"}, "not connected"},
		{[]string{"check", "q23"}, "no such TPC-H query: q23"},
		{[]string{"check", "rewritten"}, "usage: .bench_tpch check"},
		{[]string{"rewritten", "q23"}, "no such TPC-H query: q23"},
		{[]string{"all", "q4", "x"}, "invalid argument: x"},
		{[]string{"q23"}, "no such TPC-H query: q23"},
		{[]string{"q4", "q23"}, "no such TPC-H query: q23"},
		{[]string{"bogus"}, "unknown .bench_tpch argument: bogus"},
	} {
		if err := s.runBenchTPCH(c.args); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf(".bench_tpch %s: error %v, want one with %q", strings.Join(c.args, " "), err, c.want)
		}
	}
}

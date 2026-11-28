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

// .bench_tpch: the 22 TPC-H queries against RonSQL, with the MySQL server
// as the comparison on the same statement.
//
// Every query of the registry (tpchQueries, tpch_queries.go) has up to
// three forms:
//
//   - official:  the TPC-H formulation in MySQL dialect.  MySQL only: the
//     reference result and the "what the user would write" baseline.
//   - original:  the official query in RonSQL dialect, changed only
//     mechanically (comma joins written as JOIN ... ON in an order, BETWEEN
//     as a range, date arithmetic as a literal), with the same columns and
//     rows.  Empty when RonSQL cannot run the query as it is.
//   - rewritten: the query in a shape RonSQL runs (CTEs for subqueries and
//     derived tables, a join order RonSQL's fixed order makes efficient, a
//     pivot for a GROUP BY expression).  Empty when the original form is
//     already the efficient one, or when there is no rewrite.
//
// The original and rewritten forms are plain SQL that mysqld accepts too,
// so each of them runs on both engines: .bench_tpch original and
// .bench_tpch rewritten report RonSQL and MySQL side by side, and
// .bench_tpch verify compares the two results.
//
// The command reuses the .bench_ronsql / .bench_sql runners
// (benchRonSQLQuery, benchSQLQuery in ronsql_bench.go); it only adds the
// registry, the phases and the summary.

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/logicalclocks/rondb/tools/rondb-cli/internal/fsq/exec"
	"github.com/logicalclocks/rondb/tools/rondb-cli/internal/ui"
)

const (
	benchCatTPCH22 = "tpch22" // the 22 TPC-H queries of .bench_tpch
	tpchDatabase   = "tpch"
	// Defaults of a .bench_tpch run: the queries take seconds, not
	// microseconds, so fewer requests than .bench_ronsql's 10.
	tpchDefaultThreads  = 1
	tpchDefaultRequests = 3
)

// tpchForm selects one of the formulations of a TPC-H query.
type tpchForm int

const (
	tpchFormOfficial tpchForm = iota
	tpchFormOriginal
	tpchFormRewritten
)

var tpchFormNames = [...]string{"official", "original", "rewritten"}

func (f tpchForm) String() string { return tpchFormNames[f] }

func parseTPCHForm(name string) (tpchForm, bool) {
	for i, n := range tpchFormNames {
		if strings.EqualFold(n, name) {
			return tpchForm(i), true
		}
	}
	return 0, false
}

// tpchQuery is one TPC-H query and what RonSQL can do with it.
type tpchQuery struct {
	Num   int
	Title string
	// Official is the TPC-H formulation in MySQL dialect, with the
	// validation values of the specification as literals.
	Official string
	// Original is the official query in RonSQL dialect (see the file
	// comment); empty when RonSQL cannot run it.
	Original string
	// Rewritten is the RonSQL-shaped rewrite; empty when there is none.
	Rewritten string
	// Blockers names the constructs of the official query that RonSQL
	// refuses (why Original is empty).
	Blockers []string
	// Deviation says how the result of Rewritten differs from the official
	// one (a pivot, a division left to the client); empty when it has the
	// same columns and rows.
	Deviation string
	// Missing lists keys of tpchFeatures: what RonSQL lacks to run the
	// official query, beyond its spelling.  Set exactly when Original is
	// empty.
	Missing []string
	// Dialect lists keys of tpchFeatures for the spelling the official
	// text uses and RonSQL's parser refuses (comma joins, BETWEEN, date
	// literals): what the original form had to change.
	Dialect []string
	// Indexes lists names of tpchExtraIndexes the RonSQL forms use.
	Indexes []string
	// Note is anything else worth knowing before reading the figures.
	Note string
}

func (q *tpchQuery) label() string { return "q" + strconv.Itoa(q.Num) }

// sqlOf returns the statement of a form, "" when the query has none.
func (q *tpchQuery) sqlOf(f tpchForm) string {
	switch f {
	case tpchFormOriginal:
		return q.Original
	case tpchFormRewritten:
		return q.Rewritten
	default:
		return q.Official
	}
}

// benchEntry is the form as an entry the .bench_ronsql / .bench_sql
// runners take.
func (q *tpchQuery) benchEntry(f tpchForm) *RonSQLBenchQuery {
	return &RonSQLBenchQuery{
		Name:        fmt.Sprintf("tpch_q%d_%s", q.Num, f),
		Category:    benchCatTPCH22,
		MySQLOnly:   f == tpchFormOfficial,
		Description: fmt.Sprintf("TPC-H Q%d %s, %s form", q.Num, q.Title, f),
		Database:    tpchDatabase,
		SQL:         q.sqlOf(f),
		// tpchRunForm prints the statement, once for both engines and only
		// when asked to.
		QuietSQL: true,
	}
}

// tpchShowFlag is the argument that makes check, verify and the runs print
// each statement.
const tpchShowFlag = "--show"

// tpchStraightFlag is the argument that makes the MySQL server join in the
// order a statement names its tables, as RonSQL does: what its optimizer
// costs a statement when it does not choose the order.
const tpchStraightFlag = "--straight"

func tpchIsStraightFlag(arg string) bool {
	switch strings.ToLower(arg) {
	case tpchStraightFlag, "--straight-join", "--straight_join":
		return true
	}
	return false
}

// tpchSelectKeyword matches a quoted span or the SELECT keyword.  The
// quoted spans come first, so a SELECT inside a literal or a quoted name is
// part of their match and not a keyword.
var tpchSelectKeyword = regexp.MustCompile(
	`(?i)'(?:[^'\\]|\\.|'')*'|"(?:[^"\\]|\\.|"")*"|` + "`[^`]*`" + `|\bSELECT\b`)

// tpchStraightJoin returns the statement with STRAIGHT_JOIN in every
// SELECT: the main query, CTE bodies and subqueries are each a query block
// with a join order of its own, and the option fixes the order of the one
// block it stands in.
func tpchStraightJoin(sql string) string {
	return tpchSelectKeyword.ReplaceAllStringFunc(sql, func(match string) string {
		if strings.EqualFold(match, "SELECT") {
			return match + " STRAIGHT_JOIN"
		}
		return match
	})
}

// tpchPrintSQL prints the statement of a form under a heading.
func tpchPrintSQL(q *tpchQuery, f tpchForm) {
	fmt.Println()
	fmt.Println(ui.Info(fmt.Sprintf("-- %s %s", q.label(), f)))
	fmt.Println(strings.TrimSpace(q.sqlOf(f)))
}

// findTPCHQuery resolves "q5", "Q05" or "5".
func findTPCHQuery(arg string) *tpchQuery {
	arg = strings.TrimLeft(strings.ToLower(arg), "q")
	n, err := strconv.Atoi(arg)
	if err != nil {
		return nil
	}
	for i := range tpchQueries {
		if tpchQueries[i].Num == n {
			return &tpchQueries[i]
		}
	}
	return nil
}

// tpchSelection is the queries a command runs, by number: all 22 when it
// is empty.
type tpchSelection map[int]bool

// list returns the selected queries in the order of the registry.
func (sel tpchSelection) list() []*tpchQuery {
	var queries []*tpchQuery
	for i := range tpchQueries {
		if len(sel) == 0 || sel[tpchQueries[i].Num] {
			queries = append(queries, &tpchQueries[i])
		}
	}
	return queries
}

// labels names the selected queries: "q4 q18".
func (sel tpchSelection) labels() string {
	var names []string
	for _, q := range sel.list() {
		names = append(names, q.label())
	}
	return strings.Join(names, " ")
}

// tpchQueryWord reports whether a word has the form of a query name: q and
// digits, or digits alone where bare is set.
func tpchQueryWord(word string, bare bool) bool {
	digits := word
	if strings.HasPrefix(strings.ToLower(word), "q") {
		digits = word[1:]
	} else if !bare {
		return false
	}
	if digits == "" {
		return false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// tpchSelectArg adds the queries an argument names to sel: "q5", or a list
// "q5,q18".  It reports false for an argument that is no query name, which
// the caller reads as something else; a query name that is none of the 22
// is an error.  bare also takes "5", for a command where a number cannot be
// a thread or request count; after the first name of a list the q is
// optional everywhere ("q5,18").
func tpchSelectArg(arg string, bare bool, sel tpchSelection) (bool, error) {
	words := strings.Split(arg, ",")
	if !tpchQueryWord(words[0], bare) {
		return false, nil
	}
	for _, word := range words {
		if word == "" {
			continue
		}
		q := findTPCHQuery(word)
		if q == nil {
			return true, fmt.Errorf("no such TPC-H query: %s (q1 .. q%d)", word, len(tpchQueries))
		}
		sel[q.Num] = true
	}
	return true, nil
}

// tpchBenchCompletions returns completer items for .bench_tpch.
func tpchBenchCompletions() []readline.PrefixCompleterInterface {
	queries := make([]readline.PrefixCompleterInterface, 0, len(tpchQueries))
	for i := range tpchQueries {
		queries = append(queries, readline.PcItem(tpchQueries[i].label()))
	}
	// what check, verify and the runs take: queries and the flag
	run := append([]readline.PrefixCompleterInterface{
		readline.PcItem(tpchShowFlag), readline.PcItem(tpchStraightFlag)}, queries...)
	items := []readline.PrefixCompleterInterface{
		readline.PcItem("list"),
		readline.PcItem("missing"),
		readline.PcItem("show", queries...),
		readline.PcItem("explain", queries...),
		readline.PcItem("indexes"),
		readline.PcItem("check", run...),
		readline.PcItem("verify", run...),
		readline.PcItem("original", run...),
		readline.PcItem("rewritten", run...),
		readline.PcItem("official", run...),
		readline.PcItem("all", run...),
	}
	for i := range tpchQueries {
		items = append(items, readline.PcItem(tpchQueries[i].label(), run...))
	}
	return items
}

func tpchUsage() string {
	return `usage:
  .bench_tpch [list]                        The 22 queries and what RonSQL runs of each
  .bench_tpch missing                       RonSQL features the official queries need, by query
  .bench_tpch show <qN> [form]              Print the SQL of a query (official | original | rewritten)
  .bench_tpch explain <qN> [form] [engine]  EXPLAIN through RonSQL (default) or mysql
  .bench_tpch indexes                       Create the secondary indexes the RonSQL forms join through
  .bench_tpch check [qN ...]                Parse and plan the RonSQL forms (EXPLAIN, nothing executes)
  .bench_tpch verify [qN ...] [original|rewritten]  Run once on both engines and compare the results
  .bench_tpch original [qN ...] [T] [N] [engine]   Phase 1: the queries RonSQL runs as they are
  .bench_tpch rewritten [qN ...] [T] [N] [engine]  Phase 2: the rewritten queries
  .bench_tpch all [qN ...] [T] [N] [engine]        Phase 1, then phase 2
  .bench_tpch official [qN ...] [T] [N]            The official formulations on the MySQL server
  .bench_tpch <qN> [qN ...] [T] [N] [engine]       Every form of the named queries
  qN: the queries to run (q4, q4 q18 or q4,q18).  Every query when none is named.
  --show: with check, verify or a run, print the SQL of each statement.
  --straight: with verify, a run or explain ... mysql, the MySQL server joins in the order
              of the statement (SELECT STRAIGHT_JOIN in every SELECT), as RonSQL does.
  engine: both (default) | ronsql | mysql.  T threads x N requests, default 1 x 3.`
}

// runBenchTPCH dispatches .bench_tpch.
func (s *Shell) runBenchTPCH(args []string) error {
	if len(args) == 0 {
		s.listTPCH()
		return nil
	}
	sub := strings.ToLower(args[0])
	rest := args[1:]
	switch sub {
	case "list":
		s.listTPCH()
		return nil
	case "missing", "features":
		s.listTPCHMissing()
		return nil
	case "help":
		fmt.Println(tpchUsage())
		return nil
	case "show", "query":
		return s.showTPCH(rest)
	case "explain":
		return s.explainTPCH(rest)
	case "indexes":
		return s.tpchCreateIndexes()
	case "check":
		return s.tpchCheck(rest)
	case "verify":
		return s.tpchVerify(rest)
	case "original", "rewritten", "official", "all":
		opts, err := s.parseTPCHRunOpts(rest, sub == "official")
		if err != nil {
			return err
		}
		return s.tpchBenchPhases(sub, opts)
	}
	named := tpchSelection{}
	if isQuery, err := tpchSelectArg(sub, true, named); isQuery {
		if err != nil {
			return err
		}
		opts, err := s.parseTPCHRunOpts(rest, false)
		if err != nil {
			return err
		}
		for num := range named {
			opts.queries[num] = true
		}
		return s.tpchBenchQueries(opts)
	}
	return fmt.Errorf("unknown .bench_tpch argument: %s\n%s", args[0], tpchUsage())
}

// ---- listing ----------------------------------------------------------

func tpchYesNo(sql string) string {
	if sql == "" {
		return "no"
	}
	return "yes"
}

// tpchCounts returns how many queries run in their original form, how many
// of the others have a rewrite, and how many have no RonSQL form.
func tpchCounts() (original, rewrittenOnly, none int) {
	for i := range tpchQueries {
		q := &tpchQueries[i]
		switch {
		case q.Original != "":
			original++
		case q.Rewritten != "":
			rewrittenOnly++
		default:
			none++
		}
	}
	return
}

// listTPCH prints the support matrix of the registry.
func (s *Shell) listTPCH() {
	fmt.Println()
	fmt.Println(ui.Info("TPC-H on RonSQL: the 22 queries (database tpch, load with .load_tpch)"))
	fmt.Println()
	fmt.Printf("  %-5s %-34s %-9s %-10s %s\n", "query", "title", "original", "rewritten", "result of the rewrite")
	for i := range tpchQueries {
		q := &tpchQueries[i]
		result := ""
		switch {
		case q.Rewritten == "" && q.Original == "":
			result = "no RonSQL form"
		case q.Rewritten != "" && q.Deviation == "":
			result = "same columns and rows"
		case q.Rewritten != "":
			result = q.Deviation
		}
		fmt.Printf("  %-5s %-34s %-9s %-10s %s\n", q.label(), q.Title,
			tpchYesNo(q.Original), tpchYesNo(q.Rewritten), result)
	}
	original, rewrittenOnly, none := tpchCounts()
	fmt.Println()
	fmt.Printf("  %d of %d run in their original form; %d more run rewritten; %d have no RonSQL form.\n",
		original, len(tpchQueries), rewrittenOnly, none)
	fmt.Println("  \"original\" is the official query in RonSQL dialect: comma joins written as JOIN ... ON,")
	fmt.Println("  BETWEEN as a range, date arithmetic as a literal; same columns and rows.  No official")
	fmt.Println("  TPC-H text passes RonSQL's parser unchanged (.bench_tpch missing).")
	fmt.Println()
	fmt.Println(tpchUsage())
	fmt.Println()
}

// listTPCHMissing prints the features RonSQL lacks, each with the queries
// whose official form needs it: first those that block a query, then the
// spelling the original forms had to change.
func (s *Shell) listTPCHMissing() {
	blocking := map[string][]string{}
	spelling := map[string][]string{}
	for i := range tpchQueries {
		q := &tpchQueries[i]
		for _, key := range q.Missing {
			blocking[key] = append(blocking[key], q.label())
		}
		for _, key := range q.Dialect {
			spelling[key] = append(spelling[key], q.label())
		}
	}
	printGroup := func(title string, byFeature map[string][]string) {
		fmt.Println(ui.Info(title))
		fmt.Println()
		for _, f := range tpchFeatures {
			queries := byFeature[f.Key]
			if len(queries) == 0 {
				continue
			}
			fmt.Printf("  %s\n", f.Text)
			fmt.Printf("      %d: %s\n", len(queries), strings.Join(queries, " "))
			delete(byFeature, f.Key)
		}
		// A key missing from tpchFeatures is a registry error; show it
		// rather than drop it (TestTPCHRegistry fails on it too).
		var unknown []string
		for key := range byFeature {
			unknown = append(unknown, key)
		}
		sort.Strings(unknown)
		for _, key := range unknown {
			fmt.Printf("  %s (not described in tpchFeatures)\n      %s\n", key, strings.Join(byFeature[key], " "))
		}
		fmt.Println()
	}
	original, _, _ := tpchCounts()
	fmt.Println()
	printGroup(fmt.Sprintf("Features that keep %d of the %d official queries from running, by the queries that need each",
		len(tpchQueries)-original, len(tpchQueries)), blocking)
	printGroup("Spelling of the official text that RonSQL's parser refuses (the original forms write it another way)",
		spelling)
}

// showTPCH prints one query: what runs, why not, and the SQL.
func (s *Shell) showTPCH(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: .bench_tpch show <qN> [official|original|rewritten]")
	}
	q := findTPCHQuery(args[0])
	if q == nil {
		return fmt.Errorf("unknown TPC-H query: %s (q1 .. q22)", args[0])
	}
	forms := []tpchForm{tpchFormOfficial, tpchFormOriginal, tpchFormRewritten}
	if len(args) > 1 {
		f, ok := parseTPCHForm(args[1])
		if !ok {
			return fmt.Errorf("unknown form: %s (official, original or rewritten)", args[1])
		}
		forms = []tpchForm{f}
	}
	fmt.Println()
	fmt.Println(ui.Info(fmt.Sprintf("TPC-H Q%d - %s", q.Num, q.Title)))
	fmt.Printf("  Original form on RonSQL: %s   Rewritten form: %s\n", tpchYesNo(q.Original), tpchYesNo(q.Rewritten))
	for _, b := range q.Blockers {
		fmt.Printf("  Blocks the original: %s\n", b)
	}
	if q.Deviation != "" {
		fmt.Printf("  Result of the rewrite: %s\n", q.Deviation)
	}
	if len(q.Missing) > 0 {
		fmt.Println("  RonSQL lacks:")
		for _, key := range q.Missing {
			fmt.Printf("    - %s\n", tpchFeatureText(key))
		}
	}
	if len(q.Dialect) > 0 {
		fmt.Println("  Spelling of the official text RonSQL's parser refuses:")
		for _, key := range q.Dialect {
			fmt.Printf("    - %s\n", tpchFeatureText(key))
		}
	}
	if len(q.Indexes) > 0 {
		fmt.Printf("  Indexes beyond .load_tpch: %s (.bench_tpch indexes)\n", strings.Join(q.Indexes, ", "))
	}
	if q.Note != "" {
		fmt.Printf("  Note: %s\n", q.Note)
	}
	for _, f := range forms {
		fmt.Println()
		sql := q.sqlOf(f)
		if sql == "" {
			fmt.Println(ui.Info(fmt.Sprintf("-- %s: none", f)))
			continue
		}
		engines := "RonSQL and MySQL"
		if f == tpchFormOfficial {
			engines = "MySQL only"
		}
		fmt.Println(ui.Info(fmt.Sprintf("-- %s (%s)", f, engines)))
		fmt.Println(strings.TrimSpace(sql))
	}
	fmt.Println()
	return nil
}

// explainTPCH implements .bench_tpch explain <qN> [form] [ronsql|mysql].
func (s *Shell) explainTPCH(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: .bench_tpch explain <qN> [original|rewritten|official] [ronsql|mysql]")
	}
	q := findTPCHQuery(args[0])
	if q == nil {
		return fmt.Errorf("unknown TPC-H query: %s (q1 .. q22)", args[0])
	}
	form := tpchFormOriginal
	if q.Original == "" {
		form = tpchFormRewritten
	}
	formGiven := false
	onMySQL := false
	straight := false
	for _, a := range args[1:] {
		if tpchIsStraightFlag(a) {
			straight = true
			continue
		}
		switch strings.ToLower(a) {
		case "mysql", "sql":
			onMySQL = true
		case "ronsql":
			onMySQL = false
		default:
			f, ok := parseTPCHForm(a)
			if !ok {
				return fmt.Errorf("unknown argument: %s (a form, ronsql | mysql, or %s)", a, tpchStraightFlag)
			}
			form, formGiven = f, true
		}
	}
	if form == tpchFormOfficial {
		onMySQL = true
	}
	if straight && !onMySQL {
		return fmt.Errorf("%s forces the join order on the MySQL server: .bench_tpch explain %s %s mysql %s",
			tpchStraightFlag, q.label(), form, tpchStraightFlag)
	}
	if q.sqlOf(form) == "" {
		if formGiven {
			return fmt.Errorf("%s has no %s form (.bench_tpch show %s)", q.label(), form, q.label())
		}
		return fmt.Errorf("%s has no RonSQL form (.bench_tpch show %s); explain the official one with: .bench_tpch explain %s official",
			q.label(), q.label(), q.label())
	}
	entry := q.benchEntry(form)
	if onMySQL {
		if s.mysqlClient == nil {
			return fmt.Errorf("MySQL not connected. Cannot explain on the MySQL server.")
		}
		if straight {
			entry.SQL = tpchStraightJoin(entry.SQL)
			entry.Description += ", join order forced with STRAIGHT_JOIN"
		}
		return s.explainSQLQuery(entry)
	}
	if s.restClient == nil {
		return fmt.Errorf("REST API not connected. Cannot explain through RonSQL.")
	}
	return s.explainRonSQLQuery(entry)
}

// ---- indexes ----------------------------------------------------------

// tpchCellString renders a value database/sql returned for a string column.
func tpchCellString(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(x)
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// tpchIndexColumns returns, per table of the tpch database, the column
// lists of its ordered indexes (the primary key included unless it is
// USING HASH).
func (s *Shell) tpchIndexColumns() (map[string][][]string, error) {
	if s.mysqlClient == nil {
		return nil, fmt.Errorf("MySQL not connected")
	}
	_, rows, _, err := s.mysqlClient.Query(
		"SELECT TABLE_NAME, INDEX_NAME, COLUMN_NAME FROM information_schema.STATISTICS " +
			"WHERE TABLE_SCHEMA = '" + tpchDatabase + "' AND INDEX_TYPE <> 'HASH' " +
			"ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX")
	if err != nil {
		return nil, err
	}
	result := map[string][][]string{}
	lastTable, lastIndex := "", ""
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		table := strings.ToLower(tpchCellString(row[0]))
		index := tpchCellString(row[1])
		column := strings.ToLower(tpchCellString(row[2]))
		if table != lastTable || index != lastIndex {
			result[table] = append(result[table], nil)
			lastTable, lastIndex = table, index
		}
		last := len(result[table]) - 1
		result[table][last] = append(result[table][last], column)
	}
	return result, nil
}

// tpchIndexPresent reports whether some ordered index of the table starts
// with the wanted columns, in that order: the forms also join through a
// shorter prefix of the index (lineitem from part alone).
func tpchIndexPresent(existing map[string][][]string, want tpchIndex) bool {
	wanted := want.columnList()
	for _, cols := range existing[want.Table] {
		if len(cols) < len(wanted) {
			continue
		}
		same := true
		for i, w := range wanted {
			if cols[i] != w {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// tpchMissingIndexes returns the extra indexes that are not there yet.
func (s *Shell) tpchMissingIndexes() ([]tpchIndex, error) {
	existing, err := s.tpchIndexColumns()
	if err != nil {
		return nil, err
	}
	if len(existing) == 0 {
		return nil, fmt.Errorf("the %s database has no tables", tpchDatabase)
	}
	var missing []tpchIndex
	for _, idx := range tpchExtraIndexes {
		if !tpchIndexPresent(existing, idx) {
			missing = append(missing, idx)
		}
	}
	return missing, nil
}

// tpchWarnMissingIndexes tells, before a run, which RonSQL forms will be
// refused for lack of an index.  It never fails the run.
func (s *Shell) tpchWarnMissingIndexes() {
	if s.mysqlClient == nil {
		return
	}
	missing, err := s.tpchMissingIndexes()
	if err != nil || len(missing) == 0 {
		return
	}
	var required, optional []string
	for _, idx := range missing {
		if idx.Required {
			required = append(required, idx.Name)
		} else {
			optional = append(optional, idx.Name)
		}
	}
	if len(required) > 0 {
		fmt.Println(ui.Warning(fmt.Sprintf(
			"Missing indexes: %s. RonSQL joins only through a key or an ordered index, so the forms that "+
				"join through them are refused (\"No suitable index for join columns\"). Create them with: .bench_tpch indexes",
			strings.Join(required, ", "))))
	}
	if len(optional) > 0 {
		fmt.Println(ui.Info(fmt.Sprintf(
			"Indexes not created: %s. The forms run without them but read more rows (.bench_tpch indexes)",
			strings.Join(optional, ", "))))
	}
	fmt.Println()
}

// tpchWarnNulFilledChars tells when the loaded data has CHAR values filled
// with NUL bytes: what .load_tpch stored before it filled them with spaces
// itself (tpchPadChars).  The MySQL server and RonSQL return such a value
// differently, so no result with a CHAR column compares equal.
func (s *Shell) tpchWarnNulFilledChars() {
	if s.mysqlClient == nil {
		return
	}
	// HEX: a NUL has no weight in the default collation, so a comparison
	// of the text does not see it.
	_, rows, _, err := s.mysqlClient.Query(
		"SELECT COUNT(*) FROM " + tpchDatabase + ".region WHERE HEX(r_name) LIKE '%00'")
	if err != nil || len(rows) == 0 || len(rows[0]) == 0 || tpchCellString(rows[0][0]) == "0" {
		return
	}
	fmt.Println(ui.Warning(
		"The tpch data has CHAR values filled with NUL bytes instead of spaces (loaded by an older .load_tpch). " +
			"The MySQL server and RonSQL return such values differently, so the results will not compare, " +
			"and a condition on a CHAR column may select other rows. Reload the data: .drop_tpch, then .load_tpch"))
	fmt.Println()
}

// tpchPreflight warns, before a run, about what will make it fail: data
// that needs a reload, indexes that are missing.  It never fails the run.
func (s *Shell) tpchPreflight() {
	s.tpchWarnNulFilledChars()
	s.tpchWarnMissingIndexes()
}

// tpchCreateIndexes creates the extra indexes that are missing.
func (s *Shell) tpchCreateIndexes() error {
	if s.mysqlClient == nil {
		return fmt.Errorf("MySQL not connected. Cannot create indexes.")
	}
	missing, err := s.tpchMissingIndexes()
	if err != nil {
		return fmt.Errorf("cannot read the indexes of the %s database (run .load_tpch first?): %w", tpchDatabase, err)
	}
	fmt.Println()
	if len(missing) == 0 {
		fmt.Println(ui.Success(fmt.Sprintf("All %d indexes of .bench_tpch are in place", len(tpchExtraIndexes))))
		fmt.Println()
		return nil
	}
	for _, idx := range missing {
		ddl := fmt.Sprintf("CREATE INDEX %s ON %s.%s (%s)", idx.Name, tpchDatabase, idx.Table, idx.Columns)
		fmt.Printf("%s\n   for %s\n", ddl, idx.Why)
		_, duration, err := s.mysqlClient.Execute(ddl)
		if err != nil {
			return fmt.Errorf("%s failed: %w", ddl, err)
		}
		fmt.Printf("   done in %v\n", duration.Round(time.Millisecond))
	}
	fmt.Println()
	fmt.Println(ui.Success(fmt.Sprintf("Created %d indexes", len(missing))))
	fmt.Println()
	return nil
}

// ---- engines for check and verify -------------------------------------

// tpchStatementTimeout bounds one statement of check / verify on the MySQL
// server (the RonSQL side has the REST timeout of the benchmarks).
const tpchStatementTimeout = 30 * time.Minute

func (s *Shell) tpchRDRS() *exec.RDRS {
	host := s.config.RDRSHost
	if host == "" {
		host = s.config.Host
	}
	return exec.NewRDRS(host, s.config.RestPort, s.config.RDRSTLS, s.config.RDRSAPIKey,
		tpchDatabase, APIVersion, "SELECT COUNT(*) FROM region;", ronsqlBenchTimeout())
}

func (s *Shell) tpchMySQL() (*exec.MySQL, error) {
	host := s.config.MySQLHost
	if host == "" {
		host = s.config.Host
	}
	return exec.NewMySQL(host, s.config.MySQLPort, s.mysqlUser, s.mysqlPass, s.config.TLS, tpchDatabase)
}

// tpchRonSQLForms lists the forms of a query that run on RonSQL.
func tpchRonSQLForms(q *tpchQuery) []tpchForm {
	var forms []tpchForm
	if q.Original != "" {
		forms = append(forms, tpchFormOriginal)
	}
	if q.Rewritten != "" {
		forms = append(forms, tpchFormRewritten)
	}
	return forms
}

// tpchCheck prepares every RonSQL form without executing it (EXPLAIN): the
// registry's claim of what RonSQL accepts, tested against the server.  It
// catches what the parser and the planner refuse.  RonSQL makes more
// checks when it builds the pushed join (the tables an aggregation reads,
// the operands of a filter over two tables, the size of the aggregation
// program), which EXPLAIN does not reach, and a statement can fail on a
// limit when it runs (a subquery result over 1000 rows): .bench_tpch
// verify runs each statement.  args names the queries to check, none for
// all of them.
func (s *Shell) tpchCheck(args []string) error {
	sel := tpchSelection{}
	show := false
	for _, a := range args {
		if strings.EqualFold(a, tpchShowFlag) {
			show = true
			continue
		}
		isQuery, err := tpchSelectArg(a, true, sel)
		if err != nil {
			return err
		}
		if !isQuery {
			return fmt.Errorf("usage: .bench_tpch check [qN ...] [%s]", tpchShowFlag)
		}
	}
	if s.restClient == nil {
		return fmt.Errorf("REST API not connected. Cannot check the RonSQL forms.")
	}
	what := "every RonSQL form of the TPC-H queries"
	if len(sel) > 0 {
		what = "the RonSQL forms of " + sel.labels()
	}
	fmt.Println()
	fmt.Println(ui.Info("Preparing " + what + " (EXPLAIN, nothing executes)"))
	fmt.Println()
	s.tpchPreflight()
	rd := s.tpchRDRS()
	defer rd.Close()
	accepted, refused := 0, 0
	for _, q := range sel.list() {
		forms := tpchRonSQLForms(q)
		if len(forms) == 0 {
			fmt.Printf("  %-5s %-10s %s\n", q.label(), "-", "no RonSQL form in the registry")
			continue
		}
		for _, f := range forms {
			if show {
				tpchPrintSQL(q, f)
			}
			ctx, cancel := context.WithTimeout(context.Background(), ronsqlBenchTimeout())
			_, err := rd.Explain(ctx, q.sqlOf(f))
			cancel()
			if err != nil {
				refused++
				fmt.Printf("  %-5s %-10s %s\n", q.label(), f, ui.Error("REFUSED: "+firstLine(err.Error())))
				continue
			}
			accepted++
			fmt.Printf("  %-5s %-10s %s\n", q.label(), f, "prepares")
		}
	}
	fmt.Println()
	if refused > 0 {
		return fmt.Errorf("RonSQL refused %d of %d statements the registry expects it to run", refused, accepted+refused)
	}
	fmt.Println(ui.Success(fmt.Sprintf("RonSQL prepares all %d statements", accepted)))
	fmt.Println(ui.Info("EXPLAIN stops before the pushed join is built, where RonSQL makes further checks: " +
		".bench_tpch verify runs each statement and compares the result with MySQL"))
	fmt.Println()
	return nil
}

// ---- result comparison ------------------------------------------------

const (
	// A SUM over DECIMAL is a DOUBLE in RonSQL and an exact DECIMAL in
	// MySQL: equal within the relative tolerance.
	tpchRelTolerance = 1e-9
	// RonSQL prints AVG with four decimals, MySQL with six for DECIMAL
	// input: equal within the absolute tolerance.
	tpchAbsTolerance = 1e-4
)

// tpchNumericType reports whether a MySQL column type is compared with
// tolerance; every other type is compared as text.
func tpchNumericType(dbType string) bool {
	switch strings.ToUpper(dbType) {
	case "DECIMAL", "NEWDECIMAL", "DOUBLE", "FLOAT":
		return true
	}
	return false
}

func tpchCellsEqual(a, b exec.Cell, numeric bool) bool {
	if a.Null || b.Null {
		return a.Null && b.Null
	}
	if a.Text == b.Text {
		return true
	}
	if numeric {
		fa, ea := strconv.ParseFloat(a.Text, 64)
		fb, eb := strconv.ParseFloat(b.Text, 64)
		if ea == nil && eb == nil {
			d := math.Abs(fa - fb)
			return d <= tpchAbsTolerance ||
				d <= tpchRelTolerance*math.Max(math.Abs(fa), math.Abs(fb))
		}
	}
	// CHAR columns: a difference in trailing spaces is not a difference.
	return strings.TrimRight(a.Text, " ") == strings.TrimRight(b.Text, " ")
}

func tpchRowsEqual(a, b []exec.Cell, numeric []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for c := range a {
		if !tpchCellsEqual(a[c], b[c], c < len(numeric) && numeric[c]) {
			return false
		}
	}
	return true
}

// tpchVisible writes out the bytes a terminal does not show (a CHAR value
// filled with NUL), so that two rows that differ never print the same.  A
// run of one byte prints once, with its length.
func tpchVisible(text string) string {
	hidden := func(ch byte) bool { return ch < 0x20 || ch == 0x7f }
	first := 0
	for first < len(text) && !hidden(text[first]) {
		first++
	}
	if first == len(text) {
		return text
	}
	var b strings.Builder
	b.WriteString(text[:first])
	for i := first; i < len(text); {
		ch := text[i]
		if !hidden(ch) {
			b.WriteByte(ch)
			i++
			continue
		}
		run := 1
		for i+run < len(text) && text[i+run] == ch {
			run++
		}
		fmt.Fprintf(&b, "\\x%02x", ch)
		if run > 1 {
			fmt.Fprintf(&b, "{%d}", run)
		}
		i += run
	}
	return b.String()
}

func tpchRowText(row []exec.Cell) string {
	parts := make([]string, len(row))
	for i, c := range row {
		if c.Null {
			parts[i] = "NULL"
		} else {
			parts[i] = tpchVisible(c.Text)
		}
	}
	return strings.Join(parts, " | ")
}

// tpchRowKey is the text of the cells compared exactly: rows with another
// key cannot be equal.
func tpchRowKey(row []exec.Cell, numeric []bool) string {
	var b strings.Builder
	for c, cell := range row {
		if c < len(numeric) && numeric[c] {
			continue
		}
		if cell.Null {
			b.WriteString("\x00N")
		} else {
			b.WriteString(strings.TrimRight(cell.Text, " "))
		}
		b.WriteByte('\x01')
	}
	return b.String()
}

// tpchUnmatchedRows pairs the rows of the two results whatever their
// order and returns those left without a partner.
func tpchUnmatchedRows(ref, got [][]exec.Cell, numeric []bool) (onlyRef, onlyGot [][]exec.Cell) {
	byKey := map[string][]int{}
	for i, row := range ref {
		k := tpchRowKey(row, numeric)
		byKey[k] = append(byKey[k], i)
	}
	used := make([]bool, len(ref))
	for _, row := range got {
		k := tpchRowKey(row, numeric)
		found := false
		for _, i := range byKey[k] {
			if !used[i] && tpchRowsEqual(ref[i], row, numeric) {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			onlyGot = append(onlyGot, row)
		}
	}
	for i, row := range ref {
		if !used[i] {
			onlyRef = append(onlyRef, row)
		}
	}
	return onlyRef, onlyGot
}

// tpchHasOrderBy reports whether the statement ends in an ORDER BY of its
// own (one in a CTE body or a subquery does not order the result).
func tpchHasOrderBy(sql string) bool {
	var top strings.Builder
	depth := 0
	inString := false
	for i := 0; i < len(sql); i++ {
		ch := sql[i]
		switch {
		case inString:
			if ch == '\'' {
				inString = false
			}
		case ch == '\'':
			inString = true
		case ch == '(':
			depth++
		case ch == ')':
			depth--
			top.WriteByte(' ')
		case depth == 0:
			top.WriteByte(ch)
		}
	}
	fields := strings.Fields(strings.ToUpper(top.String()))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "ORDER" && fields[i+1] == "BY" {
			return true
		}
	}
	return false
}

// tpchCompare compares the MySQL result (ref, which has the column types)
// with the RonSQL result.  It returns a verdict line and, when the results
// differ, a few of the rows that do.
func tpchCompare(ref, got *exec.Result, ordered bool) (equal bool, verdict string, detail []string) {
	numeric := make([]bool, len(ref.Columns))
	for c := range numeric {
		numeric[c] = c < len(ref.Types) && tpchNumericType(ref.Types[c])
	}
	if len(ref.Rows) != len(got.Rows) {
		verdict = fmt.Sprintf("row count: MySQL %d, RonSQL %d", len(ref.Rows), len(got.Rows))
	} else if len(ref.Rows) == 0 {
		return true, "0 rows on both engines", nil
	} else if len(ref.Columns) != len(got.Columns) {
		verdict = fmt.Sprintf("column count: MySQL %d, RonSQL %d", len(ref.Columns), len(got.Columns))
		return false, verdict, nil
	}
	names := ""
	if len(got.Columns) == len(ref.Columns) &&
		strings.Join(ref.Columns, "\x00") != strings.Join(got.Columns, "\x00") {
		names = "; output names differ"
	}
	if verdict == "" && ordered {
		inOrder := true
		for i := range ref.Rows {
			if !tpchRowsEqual(ref.Rows[i], got.Rows[i], numeric) {
				inOrder = false
				break
			}
		}
		if inOrder {
			return true, fmt.Sprintf("%d rows, same order%s", len(ref.Rows), names), nil
		}
	}
	onlyRef, onlyGot := tpchUnmatchedRows(ref.Rows, got.Rows, numeric)
	if len(onlyRef) == 0 && len(onlyGot) == 0 {
		if ordered {
			return true, fmt.Sprintf("%d rows, same rows in another order (ties in ORDER BY?)%s",
				len(ref.Rows), names), nil
		}
		return true, fmt.Sprintf("%d rows%s", len(ref.Rows), names), nil
	}
	if verdict == "" {
		verdict = fmt.Sprintf("%d rows only in MySQL, %d only in RonSQL", len(onlyRef), len(onlyGot))
	}
	const shown = 3
	for i, row := range onlyRef {
		if i == shown {
			break
		}
		detail = append(detail, "MySQL : "+tpchRowText(row))
	}
	for i, row := range onlyGot {
		if i == shown {
			break
		}
		detail = append(detail, "RonSQL: "+tpchRowText(row))
	}
	return false, verdict, detail
}

// tpchVerify runs the selected RonSQL forms once on both engines and
// compares the results: the same statement must give the same answer.
// args names queries and a form, in any order: every query and both forms
// when it names none.  With the show flag each statement is printed before
// it runs; with the straight flag the MySQL server joins in the order of
// the statement.
func (s *Shell) tpchVerify(args []string) error {
	sel := tpchSelection{}
	forms := map[tpchForm]bool{}
	show, straight := false, false
	for _, a := range args {
		if strings.EqualFold(a, "all") {
			continue
		}
		if strings.EqualFold(a, tpchShowFlag) {
			show = true
			continue
		}
		if tpchIsStraightFlag(a) {
			straight = true
			continue
		}
		if f, ok := parseTPCHForm(a); ok && f != tpchFormOfficial {
			forms[f] = true
			continue
		}
		isQuery, err := tpchSelectArg(a, true, sel)
		if err != nil {
			return err
		}
		if !isQuery {
			return fmt.Errorf("usage: .bench_tpch verify [qN ...] [original | rewritten] [%s] [%s]",
				tpchShowFlag, tpchStraightFlag)
		}
	}
	// wanted names the forms asked for, in a message about a query that
	// has none of them.
	wanted := "RonSQL"
	if len(forms) == 1 {
		for f := range forms {
			wanted = f.String()
		}
	} else {
		forms = map[tpchForm]bool{tpchFormOriginal: true, tpchFormRewritten: true}
	}
	if s.restClient == nil {
		return fmt.Errorf("REST API not connected. Cannot verify the RonSQL forms.")
	}
	if s.mysqlClient == nil {
		return fmt.Errorf("MySQL not connected. Verification compares RonSQL with the MySQL server.")
	}
	my, err := s.tpchMySQL()
	if err != nil {
		return fmt.Errorf("mysql: %w", err)
	}
	defer my.Close()
	rd := s.tpchRDRS()
	defer rd.Close()

	fmt.Println()
	fmt.Println(ui.Info("Running each RonSQL form once on RonSQL and on the MySQL server, comparing the results"))
	fmt.Println(ui.Info(fmt.Sprintf("Numbers of DECIMAL / DOUBLE columns compare equal within %g relative or %g absolute",
		tpchRelTolerance, tpchAbsTolerance)))
	if straight {
		fmt.Println(ui.Info("The MySQL server runs every SELECT as SELECT STRAIGHT_JOIN: the join order of the statement"))
	}
	fmt.Println()
	s.tpchPreflight()
	matched, failed := 0, 0
	for _, q := range sel.list() {
		ran := false
		for _, f := range tpchRonSQLForms(q) {
			if !forms[f] {
				continue
			}
			ran = true
			sql := q.sqlOf(f)
			if show {
				tpchPrintSQL(q, f)
			}
			ctx, cancel := context.WithTimeout(context.Background(), ronsqlBenchTimeout())
			ron := rd.Query(ctx, sql)
			cancel()
			if ron.Outcome != exec.OK {
				failed++
				fmt.Printf("  %-5s %-10s %s\n", q.label(), f,
					ui.Error(fmt.Sprintf("RonSQL %s: %s", ron.Outcome, firstLine(ron.Message))))
				continue
			}
			mysqlSQL := sql
			if straight {
				mysqlSQL = tpchStraightJoin(sql)
			}
			ctx, cancel = context.WithTimeout(context.Background(), tpchStatementTimeout)
			ref := my.Query(ctx, mysqlSQL)
			cancel()
			if ref.Outcome != exec.OK {
				failed++
				fmt.Printf("  %-5s %-10s %s\n", q.label(), f,
					ui.Error(fmt.Sprintf("MySQL %s: %s", ref.Outcome, firstLine(ref.Message))))
				continue
			}
			equal, verdict, detail := tpchCompare(ref.Result, ron.Result, tpchHasOrderBy(sql))
			timing := fmt.Sprintf("RonSQL %s, MySQL %s",
				formatLatency(ron.Result.Latency), formatLatency(ref.Result.Latency))
			if equal {
				matched++
				fmt.Printf("  %-5s %-10s MATCH  %s (%s)\n", q.label(), f, verdict, timing)
				continue
			}
			failed++
			fmt.Printf("  %-5s %-10s %s (%s)\n", q.label(), f, ui.Error("DIFFER "+verdict), timing)
			for _, line := range detail {
				fmt.Printf("        %s\n", line)
			}
		}
		if !ran && len(sel) > 0 {
			fmt.Printf("  %-5s %-10s no such form (.bench_tpch show %s says why)\n", q.label(), wanted, q.label())
		}
	}
	fmt.Println()
	if failed > 0 {
		return fmt.Errorf("%d of %d statements failed or differ between RonSQL and MySQL", failed, matched+failed)
	}
	if matched == 0 {
		return fmt.Errorf("nothing was verified: %s has no %s form", sel.labels(), wanted)
	}
	fmt.Println(ui.Success(fmt.Sprintf("RonSQL and MySQL agree on all %d statements", matched)))
	fmt.Println()
	return nil
}

// ---- benchmark phases -------------------------------------------------

type tpchRunOpts struct {
	threads  int
	requests int
	ronsql   bool
	mysql    bool
	// queries is the queries to run, every query when empty.
	queries tpchSelection
	// showSQL prints each statement before it runs.
	showSQL bool
	// straight makes the MySQL server join in the order of the statement
	// (tpchStraightJoin).
	straight bool
}

// parseTPCHRunArgs reads "[qN ...] [T] [N] [ronsql|mysql|both] [--show]
// [--straight]".
// The queries, the engine and the flags may stand anywhere; of the numbers
// the first is the threads.  A query takes its q here: a bare number is a
// count.  engineGiven says that the arguments name an engine.
func parseTPCHRunArgs(args []string) (o tpchRunOpts, engineGiven bool, err error) {
	o = tpchRunOpts{threads: tpchDefaultThreads, requests: tpchDefaultRequests,
		ronsql: true, mysql: true, queries: tpchSelection{}}
	numbers := 0
	for _, a := range args {
		if tpchIsStraightFlag(a) {
			o.straight = true
			continue
		}
		switch strings.ToLower(a) {
		case "both":
			o.ronsql, o.mysql, engineGiven = true, true, true
			continue
		case "ronsql":
			o.ronsql, o.mysql, engineGiven = true, false, true
			continue
		case "mysql", "sql":
			o.ronsql, o.mysql, engineGiven = false, true, true
			continue
		case tpchShowFlag:
			o.showSQL = true
			continue
		}
		isQuery, err := tpchSelectArg(a, false, o.queries)
		if err != nil {
			return o, engineGiven, err
		}
		if isQuery {
			continue
		}
		n, err := strconv.Atoi(a)
		if err != nil || n <= 0 {
			return o, engineGiven, fmt.Errorf(
				"invalid argument: %s (a query qN, threads, requests, ronsql | mysql | both, %s or %s)",
				a, tpchShowFlag, tpchStraightFlag)
		}
		switch numbers {
		case 0:
			o.threads = n
		case 1:
			o.requests = n
		default:
			return o, engineGiven, fmt.Errorf("too many numbers: %s (threads and requests only)", a)
		}
		numbers++
	}
	return o, engineGiven, nil
}

// parseTPCHRunOpts reads the arguments of a run (parseTPCHRunArgs) and
// drops an engine that is not connected.  mysqlOnly is the official phase,
// which RonSQL does not run.
func (s *Shell) parseTPCHRunOpts(args []string, mysqlOnly bool) (tpchRunOpts, error) {
	o, engineGiven, err := parseTPCHRunArgs(args)
	if err != nil {
		return o, err
	}
	if mysqlOnly {
		o.ronsql, o.mysql = false, true
	}
	if o.ronsql && s.restClient == nil {
		if engineGiven {
			return o, fmt.Errorf("REST API not connected. Cannot run the RonSQL side.")
		}
		fmt.Println(ui.Warning("REST API not connected: running the MySQL side only"))
		o.ronsql = false
	}
	if o.mysql && s.mysqlClient == nil {
		if engineGiven || mysqlOnly {
			return o, fmt.Errorf("MySQL not connected. Cannot run the MySQL side.")
		}
		fmt.Println(ui.Warning("MySQL not connected: running the RonSQL side only"))
		o.mysql = false
	}
	if !o.ronsql && !o.mysql {
		return o, fmt.Errorf("neither the REST API nor MySQL is connected")
	}
	if o.straight && !o.mysql {
		return o, fmt.Errorf("%s forces the join order on the MySQL server, which this run does not use", tpchStraightFlag)
	}
	return o, nil
}

// tpchResult is one line of a summary: one form of one query on the
// engines that ran it.
type tpchResult struct {
	query     *tpchQuery
	form      tpchForm
	ronsql    *benchRunStats
	ronsqlErr error
	mysql     *benchRunStats
	mysqlErr  error
}

// tpchRunForm benchmarks one form on the selected engines.
func (s *Shell) tpchRunForm(q *tpchQuery, f tpchForm, o tpchRunOpts) tpchResult {
	res := tpchResult{query: q, form: f}
	entry := q.benchEntry(f)
	if o.showSQL {
		tpchPrintSQL(q, f)
	}
	if o.ronsql && f != tpchFormOfficial {
		res.ronsql, res.ronsqlErr = s.benchRonSQLQuery(entry, o.threads, o.requests)
		if res.ronsqlErr != nil {
			fmt.Println(ui.Error(fmt.Sprintf("RonSQL %s failed: %v", entry.Name, res.ronsqlErr)))
		}
	}
	if o.mysql {
		if o.straight {
			forced := *entry
			forced.SQL = tpchStraightJoin(entry.SQL)
			forced.Description += ", join order forced with STRAIGHT_JOIN"
			entry = &forced
		}
		res.mysql, res.mysqlErr = s.benchSQLQuery(entry, o.threads, o.requests)
		if res.mysqlErr != nil {
			fmt.Println(ui.Error(fmt.Sprintf("MySQL %s failed: %v", entry.Name, res.mysqlErr)))
		}
	}
	return res
}

// tpchSideColumns renders the average and p95 of one engine's run.
func tpchSideColumns(stats *benchRunStats, err error, ran bool) (avg, p95 string) {
	switch {
	case !ran:
		return "-", "-"
	case err != nil || stats == nil:
		return "failed", "-"
	case stats.Requests == 0:
		return "no result", "-"
	}
	return formatLatency(stats.Avg), formatLatency(stats.P95)
}

func tpchSideOK(stats *benchRunStats, err error) bool {
	return err == nil && stats != nil && stats.Requests > 0
}

// tpchPrintSummary prints one table over the results of a phase.
func tpchPrintSummary(title string, results []tpchResult, o tpchRunOpts) {
	if len(results) == 0 {
		return
	}
	fmt.Println()
	fmt.Println(ui.Info(fmt.Sprintf("%s (%d threads x %d requests, average and p95 latency)",
		title, o.threads, o.requests)))
	if o.straight && o.mysql {
		fmt.Println(ui.Info("MySQL ran every SELECT as SELECT STRAIGHT_JOIN: the join order of the statement, as on RonSQL"))
	}
	fmt.Println()
	fmt.Printf("  %-5s %-10s %12s %12s %12s %12s  %-11s %s\n",
		"query", "form", "RonSQL avg", "RonSQL p95", "MySQL avg", "MySQL p95", "rows R/M", "RonSQL vs MySQL")
	for _, r := range results {
		ronRan := o.ronsql && r.form != tpchFormOfficial
		ronAvg, ronP95 := tpchSideColumns(r.ronsql, r.ronsqlErr, ronRan)
		myAvg, myP95 := tpchSideColumns(r.mysql, r.mysqlErr, o.mysql)
		rows, verdict := "-", ""
		ronOK := ronRan && tpchSideOK(r.ronsql, r.ronsqlErr)
		myOK := o.mysql && tpchSideOK(r.mysql, r.mysqlErr)
		switch {
		case ronOK && myOK:
			rows = fmt.Sprintf("%d/%d", r.ronsql.WarmupRows, r.mysql.WarmupRows)
			if r.ronsql.Avg > 0 && r.mysql.Avg > 0 {
				ratio := float64(r.mysql.Avg) / float64(r.ronsql.Avg)
				if ratio >= 1 {
					verdict = fmt.Sprintf("%.2fx faster", ratio)
				} else {
					verdict = fmt.Sprintf("%.2fx slower", 1/ratio)
				}
			}
			if r.ronsql.WarmupRows != r.mysql.WarmupRows {
				verdict += "  ROW COUNTS DIFFER"
			}
		case ronOK:
			rows = fmt.Sprintf("%d/-", r.ronsql.WarmupRows)
		case myOK:
			rows = fmt.Sprintf("-/%d", r.mysql.WarmupRows)
		}
		if ronRan && r.ronsql != nil && r.ronsql.Errors > 0 {
			verdict += fmt.Sprintf("  (%d RonSQL errors)", r.ronsql.Errors)
		}
		if o.mysql && r.mysql != nil && r.mysql.Errors > 0 {
			verdict += fmt.Sprintf("  (%d MySQL errors)", r.mysql.Errors)
		}
		fmt.Printf("  %-5s %-10s %12s %12s %12s %12s  %-11s %s\n",
			r.query.label(), r.form, ronAvg, ronP95, myAvg, myP95, rows, strings.TrimSpace(verdict))
	}
	for _, r := range results {
		if r.ronsqlErr != nil {
			fmt.Printf("  %s %s on RonSQL: %s\n", r.query.label(), r.form, firstLine(r.ronsqlErr.Error()))
		}
		if r.mysqlErr != nil {
			fmt.Printf("  %s %s on MySQL: %s\n", r.query.label(), r.form, firstLine(r.mysqlErr.Error()))
		}
	}
	fmt.Println()
}

// tpchFailures counts the runs of a phase that failed outright.
func tpchFailures(results []tpchResult) int {
	n := 0
	for _, r := range results {
		if r.ronsqlErr != nil {
			n++
		}
		if r.mysqlErr != nil {
			n++
		}
	}
	return n
}

// tpchRunPhase benchmarks one form of every selected query that has it.
func (s *Shell) tpchRunPhase(f tpchForm, o tpchRunOpts) []tpchResult {
	var results []tpchResult
	var skipped []string
	for _, q := range o.queries.list() {
		if q.sqlOf(f) == "" {
			skipped = append(skipped, q.label())
			continue
		}
		results = append(results, s.tpchRunForm(q, f, o))
	}
	if len(skipped) > 0 {
		fmt.Println(ui.Info(fmt.Sprintf("No %s form: %s (.bench_tpch show <qN> says why)", f, strings.Join(skipped, " "))))
	}
	return results
}

// tpchBenchPhases implements .bench_tpch original | rewritten | official | all.
func (s *Shell) tpchBenchPhases(phase string, o tpchRunOpts) error {
	if o.ronsql && phase != "official" {
		s.tpchPreflight()
	}
	failures := 0
	run := func(f tpchForm, title string) {
		results := s.tpchRunPhase(f, o)
		tpchPrintSummary(title, results, o)
		failures += tpchFailures(results)
	}
	switch phase {
	case "original":
		run(tpchFormOriginal, "TPC-H phase 1: the queries RonSQL runs in their original form")
	case "rewritten":
		run(tpchFormRewritten, "TPC-H phase 2: the rewritten queries")
	case "official":
		run(tpchFormOfficial, "TPC-H official formulations on the MySQL server")
	default: // all
		// Both summaries again at the end: the per-query reports of the
		// second phase scroll the first one away.
		first := s.tpchRunPhase(tpchFormOriginal, o)
		tpchPrintSummary("TPC-H phase 1: the queries RonSQL runs in their original form", first, o)
		second := s.tpchRunPhase(tpchFormRewritten, o)
		tpchPrintSummary("TPC-H phase 1: the queries RonSQL runs in their original form", first, o)
		tpchPrintSummary("TPC-H phase 2: the rewritten queries", second, o)
		failures = tpchFailures(first) + tpchFailures(second)
	}
	if failures > 0 {
		return fmt.Errorf("%d benchmark runs failed", failures)
	}
	return nil
}

// tpchBenchQueries implements .bench_tpch <qN> ...: every form of the
// selected queries, the official one on the MySQL server.
func (s *Shell) tpchBenchQueries(o tpchRunOpts) error {
	if o.ronsql {
		s.tpchPreflight()
	}
	queries := o.queries.list()
	var results []tpchResult
	for _, q := range queries {
		forms := tpchRonSQLForms(q)
		if len(forms) == 0 {
			fmt.Println(ui.Info(fmt.Sprintf("%s has no RonSQL form (.bench_tpch show %s says why)", q.label(), q.label())))
		}
		for _, f := range forms {
			results = append(results, s.tpchRunForm(q, f, o))
		}
		if o.mysql {
			results = append(results, s.tpchRunForm(q, tpchFormOfficial, o))
		}
	}
	title := "TPC-H, every form of " + o.queries.labels()
	if len(queries) == 1 {
		title = fmt.Sprintf("TPC-H Q%d %s", queries[0].Num, queries[0].Title)
	}
	tpchPrintSummary(title, results, o)
	if n := tpchFailures(results); n > 0 {
		return fmt.Errorf("%d benchmark runs failed", n)
	}
	return nil
}

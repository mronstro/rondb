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

// The .load_tpch generators against the TPC-H data rules (clause 4.2.3)
// that the 22 queries depend on.

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/logicalclocks/rondb/tools/rondb-cli/internal/dsl"
)

// tpchRowValues returns the columns of a generated row by name.
func tpchRowValues(op dsl.BatchWriteOperation) map[string]interface{} {
	values := map[string]interface{}{}
	for _, f := range op.Body.Filters {
		values[f.Column] = f.Value
	}
	for _, c := range op.Body.WriteColumns {
		values[c.Column] = c.Value
	}
	return values
}

// tpchCentsOf parses a DECIMAL(15,2) literal the generators wrote.
func tpchCentsOf(t *testing.T, value interface{}) int64 {
	t.Helper()
	text, ok := value.(string)
	if !ok || len(text) < 4 || text[len(text)-3] != '.' {
		t.Fatalf("%v is not an amount with two decimals", value)
	}
	cents, err := strconv.ParseInt(strings.Replace(text, ".", "", 1), 10, 64)
	if err != nil {
		t.Fatalf("%v is not an amount: %v", value, err)
	}
	return cents
}

func tpchContains(list []string, word string) bool {
	for _, w := range list {
		if w == word {
			return true
		}
	}
	return false
}

func TestTPCHOrderKeys(t *testing.T) {
	// The first 8 keys of every 32, in order, and back.
	want := []int64{1, 2, 3, 4, 5, 6, 7, 32, 33, 34, 35, 36, 37, 38, 39, 64, 65}
	for i, key := range want {
		if got := tpchOrderKey(i + 1); got != key {
			t.Errorf("order %d has key %d, want %d", i+1, got, key)
		}
	}
	last := int64(0)
	for i := 1; i <= 100000; i++ {
		key := tpchOrderKey(i)
		if key <= last || key%32 > 7 || tpchOrderIndex(key) != i {
			t.Fatalf("order %d: key %d after %d, index %d", i, key, last, tpchOrderIndex(key))
		}
		last = key
	}
	if got := tpchOrderKey(tpchOrdersBase); got != 4*tpchOrdersBase {
		t.Errorf("the last order key at scale factor 1 is %d, the registry defaults say %d", got, 4*tpchOrdersBase)
	}

	// The benchmark placeholders resolve to keys that exist.
	maxKey := int(tpchOrderKey(1000))
	sql := tpchOrderKeyResolver("{KEY} / {KEYS:50}", rand.New(rand.NewSource(1)), maxKey)
	keys := strings.FieldsFunc(sql, func(c rune) bool { return c < '0' || c > '9' })
	if len(keys) != 51 {
		t.Fatalf("resolved %q to %d keys, want 51", sql, len(keys))
	}
	seen := map[string]bool{}
	for n, text := range keys {
		key, _ := strconv.ParseInt(text, 10, 64)
		index := tpchOrderIndex(key)
		if index < 1 || index > 1000 || tpchOrderKey(index) != key {
			t.Errorf("resolved key %d is not an order key up to %d", key, maxKey)
		}
		if n > 0 && seen[text] {
			t.Errorf("{KEYS:50} repeats key %s", text)
		}
		seen[text] = n > 0
	}
}

func TestTPCHRowsDoNotDependOnBatches(t *testing.T) {
	const sf = 0.01
	for _, table := range GetTPCHTables() {
		units := table.unitCount(sf)
		if units > 60 {
			units = 60
		}
		whole := fmt.Sprint(table.Generator(sf, 0, units))
		split := units / 3
		parts := fmt.Sprint(append(table.Generator(sf, 0, split), table.Generator(sf, split, units)...))
		if whole != parts {
			t.Errorf("%s: the rows of units 0..%d differ when generated in two batches", table.Name, units)
		}
		if again := fmt.Sprint(table.Generator(sf, 0, units)); again != whole {
			t.Errorf("%s: a second generation gives other rows", table.Name)
		}
	}
}

func TestTPCHLineitemsFollowTheirOrder(t *testing.T) {
	const sf = 0.01
	const orders = 3000
	const currentDate = "1995-06-17"
	suppliers := tpchScaled(tpchSupplierBase, sf)
	parts := tpchScaled(tpchPartBase, sf)
	customers := tpchScaled(tpchCustomerBase, sf)

	linesOf := map[int64][]map[string]interface{}{}
	lineCount := 0
	for _, op := range generateLineitemRows(sf, 0, orders) {
		line := tpchRowValues(op)
		key := line["l_orderkey"].(int64)
		linesOf[key] = append(linesOf[key], line)
		lineCount++
	}
	if lineCount < 3*orders || lineCount > 5*orders {
		t.Errorf("%d lineitems for %d orders, want 4 per order on average", lineCount, orders)
	}

	statuses := map[string]int{}
	flags := map[string]int{}
	orderRows := generateOrdersRows(sf, 0, orders)
	if len(orderRows) != orders {
		t.Fatalf("%d order rows, want %d", len(orderRows), orders)
	}
	for i, op := range orderRows {
		order := tpchRowValues(op)
		key := order["o_orderkey"].(int64)
		if key != tpchOrderKey(i+1) {
			t.Fatalf("order %d has key %d, want %d", i+1, key, tpchOrderKey(i+1))
		}
		custKey := order["o_custkey"].(int)
		if custKey < 1 || custKey > customers || custKey%3 == 0 {
			t.Errorf("order %d: customer %d (a third of the customers, the multiples of 3, have no orders)", key, custKey)
		}
		orderDate := order["o_orderdate"].(string)
		if orderDate < "1992-01-01" || orderDate > "1998-08-02" {
			t.Errorf("order %d: date %s", key, orderDate)
		}
		if !tpchContains(tpchPriorities, order["o_orderpriority"].(string)) {
			t.Errorf("order %d: priority %v", key, order["o_orderpriority"])
		}

		lines := linesOf[key]
		if len(lines) < 1 || len(lines) > 7 {
			t.Fatalf("order %d has %d lineitems, want 1 to 7", key, len(lines))
		}
		total := int64(0)
		shipped, open := 0, 0
		for n, line := range lines {
			if line["l_linenumber"].(int) != n+1 {
				t.Errorf("order %d: line %d has number %v", key, n+1, line["l_linenumber"])
			}
			// The supplier is one of the part's four partsupp suppliers.
			part, supplier := line["l_partkey"].(int), line["l_suppkey"].(int)
			inPartsupp := false
			for j := 0; j < 4; j++ {
				inPartsupp = inPartsupp || tpchPartSupplier(part, j, suppliers) == supplier
			}
			if part < 1 || part > parts || !inPartsupp {
				t.Errorf("order %d line %d: (part %d, supplier %d) is not a partsupp row", key, n+1, part, supplier)
			}
			// Price, and the dates after the order's.
			quantity := tpchCentsOf(t, line["l_quantity"])
			extended := tpchCentsOf(t, line["l_extendedprice"])
			if quantity%100 != 0 || quantity < 100 || quantity > 5000 ||
				extended != quantity/100*tpchRetailPriceCents(part) {
				t.Errorf("order %d line %d: quantity %v, price %v", key, n+1, line["l_quantity"], line["l_extendedprice"])
			}
			discount, tax := tpchCentsOf(t, line["l_discount"]), tpchCentsOf(t, line["l_tax"])
			if discount < 0 || discount > 10 || tax < 0 || tax > 8 {
				t.Errorf("order %d line %d: discount %v, tax %v", key, n+1, line["l_discount"], line["l_tax"])
			}
			ship := line["l_shipdate"].(string)
			commit := line["l_commitdate"].(string)
			receipt := line["l_receiptdate"].(string)
			if ship <= orderDate || commit <= orderDate || receipt <= ship {
				t.Errorf("order %d (%s) line %d: shipped %s, committed %s, received %s", key, orderDate, n+1, ship, commit, receipt)
			}
			status, flag := line["l_linestatus"].(string), line["l_returnflag"].(string)
			if (ship > currentDate) != (status == "O") || (status != "O" && status != "F") {
				t.Errorf("order %d line %d: status %s, shipped %s", key, n+1, status, ship)
			}
			if (receipt > currentDate) != (flag == "N") || (flag != "N" && flag != "R" && flag != "A") {
				t.Errorf("order %d line %d: return flag %s, received %s", key, n+1, flag, receipt)
			}
			flags[flag]++
			if status == "F" {
				shipped++
			} else {
				open++
			}
			total += extended * (100 - discount) / 100 * (100 + tax) / 100
		}
		// The order's status and total are those of its lineitems.
		status := "P"
		if open == 0 {
			status = "F"
		} else if shipped == 0 {
			status = "O"
		}
		if order["o_orderstatus"] != status || order["o_totalprice"] != tpchMoney(total) {
			t.Errorf("order %d: status %v and total %v, its lineitems give %s and %s",
				key, order["o_orderstatus"], order["o_totalprice"], status, tpchMoney(total))
		}
		statuses[status]++
	}
	for _, status := range []string{"F", "O", "P"} {
		if statuses[status] == 0 {
			t.Errorf("no order with status %s in %d orders", status, orders)
		}
	}
	for _, flag := range []string{"N", "R", "A"} {
		if flags[flag] == 0 {
			t.Errorf("no lineitem with return flag %s", flag)
		}
	}
}

func TestTPCHValueDomains(t *testing.T) {
	const sf = 0.01
	phone := regexp.MustCompile(`^[0-9]{2}-[0-9]{3}-[0-9]{3}-[0-9]{4}$`)

	for _, op := range generatePartRows(sf, 0, 2000) {
		part := tpchRowValues(op)
		key := part["p_partkey"].(int)
		words := strings.Split(part["p_name"].(string), " ")
		distinct := map[string]bool{}
		for _, w := range words {
			distinct[w] = tpchContains(partNameWords, w)
		}
		if len(words) != 5 || len(distinct) != 5 {
			t.Errorf("part %d: name %q is not five different words", key, part["p_name"])
		}
		for w, known := range distinct {
			if !known {
				t.Errorf("part %d: %q is not a part name word", key, w)
			}
		}
		// Brand#MN follows Manufacturer#M.
		mfgr, brand := part["p_mfgr"].(string), part["p_brand"].(string)
		if len(mfgr) != len("Manufacturer#1") || len(brand) != len("Brand#11") ||
			mfgr[len(mfgr)-1] != brand[len(brand)-2] || mfgr[len(mfgr)-1] < '1' || mfgr[len(mfgr)-1] > '5' ||
			brand[len(brand)-1] < '1' || brand[len(brand)-1] > '5' {
			t.Errorf("part %d: %s and %s", key, mfgr, brand)
		}
		syllables := strings.Split(part["p_type"].(string), " ")
		if len(syllables) != 3 || !tpchContains(tpchTypeSyllable1, syllables[0]) ||
			!tpchContains(tpchTypeSyllable2, syllables[1]) || !tpchContains(tpchTypeSyllable3, syllables[2]) ||
			len(part["p_type"].(string)) > 25 {
			t.Errorf("part %d: type %q", key, part["p_type"])
		}
		container := strings.Split(part["p_container"].(string), " ")
		if len(container) != 2 || !tpchContains(tpchContainerSyllable1, container[0]) ||
			!tpchContains(tpchContainerSyllable2, container[1]) || len(part["p_container"].(string)) > 10 {
			t.Errorf("part %d: container %q", key, part["p_container"])
		}
		if size := part["p_size"].(int); size < 1 || size > 50 {
			t.Errorf("part %d: size %d", key, size)
		}
		if part["p_retailprice"] != tpchMoney(tpchRetailPriceCents(key)) || len(part["p_comment"].(string)) > 22 {
			t.Errorf("part %d: price %v, comment %q", key, part["p_retailprice"], part["p_comment"])
		}
	}
	if tpchMoney(tpchRetailPriceCents(1)) != "901.00" || tpchMoney(-1) != "-0.01" || tpchMoney(999999) != "9999.99" {
		t.Errorf("amounts: %s %s %s", tpchMoney(tpchRetailPriceCents(1)), tpchMoney(-1), tpchMoney(999999))
	}

	// Supplier and customer: the phone's country code is the nation key + 10.
	people := append(generateSupplierRows(sf, 0, 1000), generateCustomerRows(sf, 0, 1000)...)
	for _, op := range people {
		row := tpchRowValues(op)
		prefix := "s_"
		if _, customer := row["c_custkey"]; customer {
			prefix = "c_"
			if !tpchContains(tpchSegments, row["c_mktsegment"].(string)) {
				t.Errorf("customer %v: segment %v", row["c_custkey"], row["c_mktsegment"])
			}
		}
		nation := row[prefix+"nationkey"].(int)
		number := row[prefix+"phone"].(string)
		if nation < 0 || nation > 24 || !phone.MatchString(number) || number[:2] != strconv.Itoa(nation+10) {
			t.Errorf("%s: nation %d, phone %s", op.Body.OperationID, nation, number)
		}
		if balance := tpchCentsOf(t, row[prefix+"acctbal"]); balance < -99999 || balance > 999999 {
			t.Errorf("%s: balance %v", op.Body.OperationID, row[prefix+"acctbal"])
		}
		if address := row[prefix+"address"].(string); len(address) < 10 || len(address) > 40 {
			t.Errorf("%s: address of %d characters", op.Body.OperationID, len(address))
		}
	}
	if name := tpchRowValues(people[0])["s_name"]; name != "Supplier#000000001" {
		t.Errorf("the first supplier is named %v", name)
	}

	// Partsupp: four rows per part, on the suppliers of the formula.
	suppliers := tpchScaled(tpchSupplierBase, sf)
	for i, op := range generatePartsuppRows(sf, 0, 400) {
		row := tpchRowValues(op)
		if row["ps_partkey"] != i/4+1 || row["ps_suppkey"] != tpchPartSupplier(i/4+1, i%4, suppliers) {
			t.Errorf("partsupp row %d: part %v, supplier %v", i, row["ps_partkey"], row["ps_suppkey"])
		}
		cost := tpchCentsOf(t, row["ps_supplycost"])
		if qty := row["ps_availqty"].(int); qty < 1 || qty > 9999 || cost < 100 || cost > 100000 {
			t.Errorf("partsupp row %d: quantity %d, cost %v", i, qty, row["ps_supplycost"])
		}
	}
	// At scale factor 1 a part has four different suppliers.
	for part := 1; part <= tpchPartBase; part += 97 {
		distinct := map[int]bool{}
		for j := 0; j < 4; j++ {
			distinct[tpchPartSupplier(part, j, tpchSupplierBase)] = true
		}
		if len(distinct) != 4 {
			t.Fatalf("part %d has %d suppliers at scale factor 1", part, len(distinct))
		}
	}

	if regions := generateRegionRows(sf, 0, 10); len(regions) != tpchRegionCount {
		t.Errorf("%d regions", len(regions))
	}
	nations := generateNationRows(sf, 0, 100)
	if len(nations) != tpchNationCount || tpchRowValues(nations[7])["n_name"] != "GERMANY" ||
		tpchRowValues(nations[7])["n_regionkey"] != 3 {
		t.Errorf("%d nations, nation 7 is %v", len(nations), tpchRowValues(nations[7])["n_name"])
	}
}

// The text grammar gives the comments the patterns the queries look for.
func TestTPCHCommentPatterns(t *testing.T) {
	// Q13: o_comment NOT LIKE '%special%requests%' sets aside about one
	// order in a hundred.
	special := regexp.MustCompile(`special.*requests`)
	const orders = 20000
	matches := 0
	for _, op := range generateOrdersRows(0.1, 0, orders) {
		comment := tpchRowValues(op)["o_comment"].(string)
		if len(comment) < 18 || len(comment) > 78 {
			t.Fatalf("order comment of %d characters: %q", len(comment), comment)
		}
		if special.MatchString(comment) {
			matches++
		}
	}
	if matches < orders/500 || matches > orders*6/100 {
		t.Errorf("%d of %d order comments match '%%special%%requests%%', want about 1 in 100", matches, orders)
	}

	// Q16: about 5 suppliers in 10000 have '%Customer%Complaints%', as
	// many '%Customer%Recommends%', and no other comment has "Customer".
	complaints := regexp.MustCompile(`Customer.*Complaints`)
	recommends := regexp.MustCompile(`Customer.*Recommends`)
	const suppliers = 200000
	complained, recommended, customer := 0, 0, 0
	for i := 0; i < suppliers; i++ {
		r := newTPCHRand(tpchStreamSupplier, i)
		comment := tpchSupplierComment(&r)
		if len(comment) < 24 || len(comment) > 100 {
			t.Fatalf("supplier comment of %d characters: %q", len(comment), comment)
		}
		if strings.Contains(comment, "Customer") {
			customer++
		}
		if complaints.MatchString(comment) {
			complained++
		}
		if recommends.MatchString(comment) {
			recommended++
		}
	}
	if complained < 50 || complained > 160 || recommended < 50 || recommended > 160 || customer != complained+recommended {
		t.Errorf("%d supplier comments: %d complaints and %d recommendations (want about 100 each), %d with Customer",
			suppliers, complained, recommended, customer)
	}
}

// A CHAR value goes to the REST server filled with spaces to the length
// of its column: every CHAR column of the DDL, in every table.
func TestTPCHPadChars(t *testing.T) {
	const sf = 0.01
	const bytesPerChar = 4 // utf8mb4, the default character set
	charColumn := regexp.MustCompile(`(\w+) CHAR\((\d+)\)`)
	for _, table := range GetTPCHTables() {
		widths := map[string]int{}
		chars := map[string]int{}
		for _, m := range charColumn.FindAllStringSubmatch(tpchTableDDL[table.Name], -1) {
			n, _ := strconv.Atoi(m[2])
			chars[m[1]] = n
			widths[m[1]] = n * bytesPerChar
		}
		units := table.unitCount(sf)
		if units > 200 {
			units = 200
		}
		plain := table.Generator(sf, 0, units)
		padded := table.Generator(sf, 0, units)
		tpchPadChars(padded, widths)
		if len(plain) == 0 {
			t.Fatalf("%s: no rows generated", table.Name)
		}
		for i := range plain {
			before, after := tpchRowValues(plain[i]), tpchRowValues(padded[i])
			for column, value := range before {
				width, isChar := widths[column]
				if !isChar {
					if fmt.Sprint(after[column]) != fmt.Sprint(value) {
						t.Fatalf("%s.%s is not a CHAR column and changed: %q to %q",
							table.Name, column, value, after[column])
					}
					continue
				}
				text, isString := value.(string)
				if !isString {
					t.Fatalf("%s.%s is a CHAR column written as %T: tpchPadChars fills strings only",
						table.Name, column, value)
				}
				if len([]rune(text)) > chars[column] {
					t.Fatalf("%s.%s: %q is longer than CHAR(%d)", table.Name, column, text, chars[column])
				}
				got, _ := after[column].(string)
				if len(got) != width || strings.TrimRight(got, " ") != text {
					t.Fatalf("%s.%s: %q became %q, want it filled with spaces to %d bytes",
						table.Name, column, text, got, width)
				}
			}
			for column := range widths {
				if _, written := before[column]; !written {
					t.Fatalf("%s: the row does not write the CHAR column %s", table.Name, column)
				}
			}
		}
	}

	// a value already at the length of the column, a column that is not
	// CHAR and a load without the lengths are left alone
	ops := []dsl.BatchWriteOperation{tpchWriteOp("t", "op", nil, []dsl.WriteColumn{
		{Column: "full", Value: "abcd"},
		{Column: "short", Value: "a"},
		{Column: "number", Value: 7},
		{Column: "other", Value: "x"},
	})}
	tpchPadChars(ops, nil)
	if got := fmt.Sprint(tpchRowValues(ops[0])); got != fmt.Sprint(map[string]interface{}{"full": "abcd", "short": "a", "number": 7, "other": "x"}) {
		t.Errorf("without lengths the values changed: %s", got)
	}
	tpchPadChars(ops, map[string]int{"full": 4, "short": 4, "number": 4})
	want := map[string]interface{}{"full": "abcd", "short": "a   ", "number": 7, "other": "x"}
	if got := fmt.Sprint(tpchRowValues(ops[0])); got != fmt.Sprint(want) {
		t.Errorf("got %s, want %s", got, fmt.Sprint(want))
	}
}

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

// .load_tpch: the TPC-H tables, filled as the TPC-H specification says
// (clause 4.2.3, "Test Database Data Generation"): the value domains, the
// keys that tie the tables together and the dependencies between columns
// are the standard ones, so the 22 queries, with their standard
// substitution parameters, select the share of rows they select on dbgen
// data.  The values themselves are not dbgen's: dbgen draws them from its
// seeded random streams, this loader from a generator of its own, seeded
// per row, so a result differs from the published TPC-H answers.
//
// What the queries rely on, all kept:
//   - a lineitem's supplier is one of its part's four partsupp suppliers;
//   - the ship, commit and receipt dates of a lineitem follow its order's
//     date, the return flag and line status follow the dates, the order
//     status follows the line statuses and the order total the lines;
//   - an order has 1 to 7 lineitems; a third of the customers has none;
//   - order keys use the first 8 of every 32 values;
//   - a phone number starts with the nation key plus 10;
//   - p_brand follows p_mfgr, p_type has three syllables, comments are
//     text of the TPC-H grammar, and a few supplier comments carry
//     "Customer ... Complaints".

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/logicalclocks/rondb/tools/rondb-cli/internal/client"
	"github.com/logicalclocks/rondb/tools/rondb-cli/internal/dsl"
	"github.com/logicalclocks/rondb/tools/rondb-cli/internal/ui"
)

// Rows at scale factor 1 (TPC-H clause 4.2.5).
const (
	tpchRegionCount  = 5  // Fixed
	tpchNationCount  = 25 // Fixed
	tpchCustomerBase = 150000
	tpchSupplierBase = 10000
	tpchPartBase     = 200000  // and 4 partsupp rows per part
	tpchOrdersBase   = 1500000 // and 1 to 7 lineitems per order, 4 on average
	tpchClerkBase    = 1000
)

// tpchScaled returns base rows scaled by a (possibly fractional) scale
// factor: SF 0.1 loads a tenth of every scaled table (region/nation stay
// fixed), handy for quick benchmark runs. Never below one row.
func tpchScaled(base int, sf float64) int {
	n := int(math.Round(float64(base) * sf))
	if n < 1 {
		n = 1
	}
	return n
}

// tpchCustomersWithOrders is the number of customers in 1..customerCount
// that get orders: TPC-H never gives an order to a customer whose key is
// a multiple of 3, so a third of the customers have none (Q13's
// zero-order bucket, Q22's NOT EXISTS anti-join).
func tpchCustomersWithOrders(customerCount int) int {
	return customerCount - customerCount/3
}

// tpchOrderCustKey maps i in [0, tpchCustomersWithOrders(n)) to the i-th
// customer key that is not a multiple of 3: 1, 2, 4, 5, 7, ...
func tpchOrderCustKey(i int) int {
	return 3*(i/2) + i%2 + 1
}

// tpchOrderKey is the key of the i-th order, i from 1.  TPC-H populates
// the first 8 keys of every 32: the key keeps the low 3 bits of i and
// moves the rest two bits up (1..7, 32..39, 64..71, ...).
func tpchOrderKey(i int) int64 {
	return (int64(i)>>3)<<5 | int64(i)&7
}

// tpchOrderIndex is the inverse of tpchOrderKey: the number of the order
// with that key, which is also how many orders have a key up to it.
func tpchOrderIndex(key int64) int {
	return int((key>>5)<<3 | key&7)
}

// tpchPartSupplier is the j-th (0..3) supplier of a part, the PS_SUPPKEY
// formula of the specification; a lineitem takes its supplier from it.
func tpchPartSupplier(partKey, j, supplierCount int) int {
	return (partKey+j*(supplierCount/4+(partKey-1)/supplierCount))%supplierCount + 1
}

// tpchRetailPriceCents is P_RETAILPRICE in cents, a function of the key.
func tpchRetailPriceCents(partKey int) int64 {
	return int64(90000 + (partKey/10)%20001 + 100*(partKey%1000))
}

// Dates are day numbers counted from STARTDATE.
var (
	tpchStartDate  = time.Date(1992, 1, 1, 0, 0, 0, 0, time.UTC)
	tpchCurrentDay = tpchDayNumber(1995, time.June, 17) // CURRENTDATE
	// O_ORDERDATE is uniform in [STARTDATE, ENDDATE - 151 days].
	tpchOrderDays = tpchDayNumber(1998, time.December, 31) - 151 + 1
	// The last date a row can carry: an order date plus 121 days to ship
	// plus 30 days to receive.
	tpchDateText = tpchDateTexts(tpchOrderDays + 121 + 30)
)

func tpchDayNumber(year int, month time.Month, day int) int {
	return int(time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Sub(tpchStartDate).Hours() / 24)
}

func tpchDateTexts(days int) []string {
	texts := make([]string, days+1)
	for d := range texts {
		texts[d] = tpchStartDate.AddDate(0, 0, d).Format("2006-01-02")
	}
	return texts
}

// tpchMoney renders an amount in cents as a DECIMAL(15,2) literal.
func tpchMoney(cents int64) string {
	sign := ""
	if cents < 0 {
		sign = "-"
		cents = -cents
	}
	return fmt.Sprintf("%s%d.%02d", sign, cents/100, cents%100)
}

// TPC-H reference data
var tpchRegions = []string{"AFRICA", "AMERICA", "ASIA", "EUROPE", "MIDDLE EAST"}

var tpchNations = []struct {
	name      string
	regionKey int
}{
	{"ALGERIA", 0}, {"ARGENTINA", 1}, {"BRAZIL", 1}, {"CANADA", 1}, {"EGYPT", 4},
	{"ETHIOPIA", 0}, {"FRANCE", 3}, {"GERMANY", 3}, {"INDIA", 2}, {"INDONESIA", 2},
	{"IRAN", 4}, {"IRAQ", 4}, {"JAPAN", 2}, {"JORDAN", 4}, {"KENYA", 0},
	{"MOROCCO", 0}, {"MOZAMBIQUE", 0}, {"PERU", 1}, {"CHINA", 2}, {"ROMANIA", 3},
	{"SAUDI ARABIA", 4}, {"VIETNAM", 2}, {"RUSSIA", 3}, {"UNITED KINGDOM", 3}, {"UNITED STATES", 1},
}

var tpchSegments = []string{"AUTOMOBILE", "BUILDING", "FURNITURE", "MACHINERY", "HOUSEHOLD"}
var tpchPriorities = []string{"1-URGENT", "2-HIGH", "3-MEDIUM", "4-NOT SPECIFIED", "5-LOW"}
var tpchShipModes = []string{"REG AIR", "AIR", "RAIL", "SHIP", "TRUCK", "MAIL", "FOB"}
var tpchShipInstructs = []string{"DELIVER IN PERSON", "COLLECT COD", "NONE", "TAKE BACK RETURN"}

// P_TYPE is one syllable of each list, P_CONTAINER likewise.
var tpchTypeSyllable1 = []string{"STANDARD", "SMALL", "MEDIUM", "LARGE", "ECONOMY", "PROMO"}
var tpchTypeSyllable2 = []string{"ANODIZED", "BURNISHED", "PLATED", "POLISHED", "BRUSHED"}
var tpchTypeSyllable3 = []string{"TIN", "NICKEL", "BRASS", "STEEL", "COPPER"}
var tpchContainerSyllable1 = []string{"SM", "LG", "MED", "JUMBO", "WRAP"}
var tpchContainerSyllable2 = []string{"CASE", "BOX", "BAG", "JAR", "PKG", "PACK", "CAN", "DRUM"}

// P_NAME is five different words of this list.
var partNameWords = []string{
	"almond", "antique", "aquamarine", "azure", "beige", "bisque", "black", "blanched", "blue",
	"blush", "brown", "burlywood", "burnished", "chartreuse", "chiffon", "chocolate", "coral",
	"cornflower", "cornsilk", "cream", "cyan", "dark", "deep", "dim", "dodger", "drab", "firebrick",
	"floral", "forest", "frosted", "gainsboro", "ghost", "goldenrod", "green", "grey", "honeydew",
	"hot", "indian", "ivory", "khaki", "lace", "lavender", "lawn", "lemon", "light", "lime", "linen",
	"magenta", "maroon", "medium", "metallic", "midnight", "mint", "misty", "moccasin", "navajo",
	"navy", "olive", "orange", "orchid", "pale", "papaya", "peach", "peru", "pink", "plum", "powder",
	"puff", "purple", "red", "rose", "rosy", "royal", "saddle", "salmon", "sandy", "seashell", "sienna",
	"sky", "slate", "smoke", "snow", "spring", "steel", "tan", "thistle", "tomato", "turquoise", "violet",
	"wheat", "white", "yellow",
}

// ---- random values ------------------------------------------------------

// The random streams: one per table, so that row n of one table shares
// nothing with row n of another.
const (
	tpchStreamRegion = iota + 1
	tpchStreamNation
	tpchStreamSupplier
	tpchStreamCustomer
	tpchStreamPart
	tpchStreamPartsupp
	tpchStreamOrders
	tpchStreamOrderDate
	tpchStreamLines
	tpchStreamLineText
)

// tpchRand generates the values of one row (splitmix64).  It is seeded
// from the stream and the row number alone, so a row has the same values
// whatever thread generates it, in whatever order and batch size: a load
// gives the same database every time, and the lineitems an order's row is
// computed from are the ones the lineitem table gets.
type tpchRand struct {
	state uint64
}

func tpchMix(z uint64) uint64 {
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func newTPCHRand(stream, row int) tpchRand {
	return tpchRand{state: tpchMix(uint64(stream)<<48 + uint64(row) + 1)}
}

func (r *tpchRand) next() uint64 {
	r.state += 0x9E3779B97F4A7C15
	return tpchMix(r.state)
}

// between returns a value in [lo, hi], each as likely as the others.
func (r *tpchRand) between(lo, hi int) int {
	return lo + int(r.next()%uint64(hi-lo+1))
}

func (r *tpchRand) oneOf(list []string) string {
	return list[r.between(0, len(list)-1)]
}

// ---- text ---------------------------------------------------------------

// tpchTextWord is a word of the text grammar with its weight.
type tpchTextWord struct {
	text   string
	weight int
}

type tpchTextDist struct {
	words []tpchTextWord
	total int
}

func newTPCHTextDist(words []tpchTextWord) tpchTextDist {
	total := 0
	for _, w := range words {
		total += w.weight
	}
	return tpchTextDist{words: words, total: total}
}

func (d *tpchTextDist) pick(r *tpchRand) string {
	n := r.between(0, d.total-1)
	for i := range d.words {
		if n < d.words[i].weight {
			return d.words[i].text
		}
		n -= d.words[i].weight
	}
	return d.words[len(d.words)-1].text
}

// The word lists of the TPC-H text grammar (clause 4.2.2.14), with weights
// after dbgen's distributions (dists.dss): a few words carry most of the
// text, which is what makes '%special%requests%' select about one order
// comment in a hundred (TestTPCHCommentPatterns).
var (
	tpchNouns = newTPCHTextDist([]tpchTextWord{
		{"packages", 40}, {"requests", 40}, {"accounts", 40}, {"deposits", 40},
		{"foxes", 20}, {"ideas", 20}, {"theodolites", 20}, {"pinto beans", 20}, {"instructions", 20},
		{"dependencies", 10}, {"excuses", 10}, {"platelets", 10}, {"asymptotes", 10},
		{"courts", 5}, {"dolphins", 5},
		{"multipliers", 1}, {"sauternes", 1}, {"warthogs", 1}, {"frets", 1}, {"dinos", 1},
		{"attainments", 1}, {"somas", 1}, {"Tiresias", 1}, {"patterns", 1}, {"forges", 1},
		{"braids", 1}, {"frays", 1}, {"warhorses", 1}, {"dugouts", 1}, {"notornis", 1},
		{"epitaphs", 1}, {"pearls", 1}, {"tithes", 1}, {"waters", 1}, {"orbits", 1},
		{"gifts", 1}, {"sheaves", 1}, {"depths", 1}, {"sentiments", 1}, {"decoys", 1},
		{"realms", 1}, {"pains", 1}, {"grouches", 1}, {"escapades", 1}, {"hockey players", 1},
	})
	tpchVerbs = newTPCHTextDist([]tpchTextWord{
		{"sleep", 20}, {"wake", 20}, {"are", 20}, {"cajole", 20}, {"haggle", 20},
		{"nag", 10}, {"use", 10}, {"boost", 10},
		{"affix", 5}, {"detect", 5}, {"integrate", 5},
		{"maintain", 1}, {"nod", 1}, {"was", 1}, {"lose", 1}, {"sublate", 1}, {"solve", 1},
		{"thrash", 1}, {"promise", 1}, {"engage", 1}, {"hinder", 1}, {"print", 1}, {"x-ray", 1},
		{"breach", 1}, {"eat", 1}, {"grow", 1}, {"impress", 1}, {"mold", 1}, {"poach", 1},
		{"serve", 1}, {"run", 1}, {"dazzle", 1}, {"snooze", 1}, {"doze", 1}, {"unwind", 1},
		{"kindle", 1}, {"play", 1}, {"hang", 1}, {"believe", 1}, {"doubt", 1},
	})
	tpchAdjectives = newTPCHTextDist([]tpchTextWord{
		{"regular", 50}, {"final", 40}, {"ironic", 40}, {"even", 30},
		{"special", 20}, {"pending", 20}, {"unusual", 20}, {"express", 20}, {"bold", 20},
		{"silent", 10},
		{"furious", 1}, {"sly", 1}, {"careful", 1}, {"blithe", 1}, {"quick", 1}, {"fluffy", 1},
		{"slow", 1}, {"quiet", 1}, {"ruthless", 1}, {"thin", 1}, {"close", 1}, {"dogged", 1},
		{"daring", 1}, {"brave", 1}, {"stealthy", 1}, {"permanent", 1}, {"enticing", 1},
		{"idle", 1}, {"busy", 1},
	})
	tpchAdverbs = newTPCHTextDist([]tpchTextWord{
		{"furiously", 50}, {"slyly", 50}, {"carefully", 50}, {"blithely", 40}, {"quickly", 30},
		{"fluffily", 20},
		{"sometimes", 1}, {"always", 1}, {"never", 1}, {"slowly", 1}, {"quietly", 1},
		{"ruthlessly", 1}, {"thinly", 1}, {"closely", 1}, {"doggedly", 1}, {"daringly", 1},
		{"bravely", 1}, {"stealthily", 1}, {"permanently", 1}, {"enticingly", 1}, {"idly", 1},
		{"busily", 1}, {"regularly", 1}, {"finally", 1}, {"ironically", 1}, {"evenly", 1},
		{"boldly", 1}, {"silently", 1},
	})
	tpchPrepositions = newTPCHTextDist([]tpchTextWord{
		{"about", 50}, {"above", 50}, {"according to", 50}, {"across", 50}, {"after", 50},
		{"against", 40}, {"along", 40}, {"alongside of", 30}, {"among", 30}, {"around", 20},
		{"at", 10},
		{"atop", 1}, {"before", 1}, {"behind", 1}, {"beneath", 1}, {"beside", 1}, {"besides", 1},
		{"between", 1}, {"beyond", 1}, {"by", 1}, {"despite", 1}, {"during", 1}, {"except", 1},
		{"for", 1}, {"from", 1}, {"in place of", 1}, {"inside", 1}, {"instead of", 1}, {"into", 1},
		{"near", 1}, {"of", 1}, {"on", 1}, {"outside", 1}, {"over", 1}, {"past", 1}, {"since", 1},
		{"through", 1}, {"throughout", 1}, {"to", 1}, {"toward", 1}, {"under", 1}, {"until", 1},
		{"up", 1}, {"upon", 1}, {"without", 1}, {"with", 1}, {"within", 1},
	})
	tpchAuxiliaries = newTPCHTextDist([]tpchTextWord{
		{"do", 1}, {"may", 1}, {"might", 1}, {"shall", 1}, {"will", 1}, {"would", 1}, {"can", 1},
		{"could", 1}, {"should", 1}, {"ought to", 1}, {"must", 1}, {"will have to", 1},
		{"shall have to", 1}, {"could have to", 1}, {"should have to", 1}, {"must have to", 1},
		{"need to", 1}, {"try to", 1},
	})
	tpchTerminators = newTPCHTextDist([]tpchTextWord{
		{".", 50}, {";", 1}, {":", 1}, {"?", 1}, {"!", 1}, {"--", 1},
	})
)

// tpchAppendNounPhrase: noun | adjective noun | adjective, adjective noun |
// adverb adjective noun.
func tpchAppendNounPhrase(b []byte, r *tpchRand) []byte {
	switch n := r.between(0, 89); {
	case n < 10:
	case n < 30:
		b = append(append(b, tpchAdjectives.pick(r)...), ' ')
	case n < 40:
		b = append(append(b, tpchAdjectives.pick(r)...), ',', ' ')
		b = append(append(b, tpchAdjectives.pick(r)...), ' ')
	default:
		b = append(append(b, tpchAdverbs.pick(r)...), ' ')
		b = append(append(b, tpchAdjectives.pick(r)...), ' ')
	}
	return append(b, tpchNouns.pick(r)...)
}

// tpchAppendVerbPhrase: verb | auxiliary verb | verb adverb | auxiliary
// verb adverb.
func tpchAppendVerbPhrase(b []byte, r *tpchRand) []byte {
	n := r.between(0, 71)
	if n == 30 || n == 71 {
		b = append(append(b, tpchAuxiliaries.pick(r)...), ' ')
	}
	b = append(b, tpchVerbs.pick(r)...)
	if n > 30 {
		b = append(append(b, ' '), tpchAdverbs.pick(r)...)
	}
	return b
}

// tpchAppendPrepositionalPhrase: preposition the noun phrase.
func tpchAppendPrepositionalPhrase(b []byte, r *tpchRand) []byte {
	b = append(append(b, tpchPrepositions.pick(r)...), " the "...)
	return tpchAppendNounPhrase(b, r)
}

// tpchAppendSentence appends one sentence of the five forms of the
// grammar; N, V and P are the phrases above and T a terminator:
// N V T | N V P T | N V N T | N P V N T | N P V P T.
func tpchAppendSentence(b []byte, r *tpchRand) []byte {
	form := r.between(0, 10) // weights 3, 3, 3, 1, 1
	b = tpchAppendNounPhrase(b, r)
	if form >= 9 {
		b = tpchAppendPrepositionalPhrase(append(b, ' '), r)
	}
	b = tpchAppendVerbPhrase(append(b, ' '), r)
	switch {
	case form >= 3 && form <= 5, form == 10:
		b = tpchAppendPrepositionalPhrase(append(b, ' '), r)
	case form >= 6 && form <= 9:
		b = tpchAppendNounPhrase(append(b, ' '), r)
	}
	return append(b, tpchTerminators.pick(r)...)
}

// tpchTextBytes returns text of a length drawn from [minLen, maxLen]: sentences
// of the grammar, cut at the length (as dbgen cuts a piece out of its
// text pool, a comment can end in the middle of a word).
func tpchTextBytes(r *tpchRand, minLen, maxLen int) []byte {
	length := r.between(minLen, maxLen)
	b := make([]byte, 0, length+80)
	for len(b) < length {
		if len(b) > 0 {
			b = append(b, ' ')
		}
		b = tpchAppendSentence(b, r)
	}
	return b[:length]
}

func tpchText(r *tpchRand, minLen, maxLen int) string {
	return strings.TrimRight(string(tpchTextBytes(r, minLen, maxLen)), " ")
}

// tpchAlphaNumeric is the alphabet of the random strings (addresses).
const tpchAlphaNumeric = "0123456789abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ,"

// tpchVString returns a random string of a length drawn from [minLen, maxLen].
func tpchVString(r *tpchRand, minLen, maxLen int) string {
	b := make([]byte, r.between(minLen, maxLen))
	for i := range b {
		b[i] = tpchAlphaNumeric[r.between(0, len(tpchAlphaNumeric)-1)]
	}
	return string(b)
}

// tpchPhone returns a phone number of a nation: the country code is the
// nation key plus 10 (Q22 groups customers by it).
func tpchPhone(r *tpchRand, nationKey int) string {
	return fmt.Sprintf("%02d-%03d-%03d-%04d", nationKey+10,
		r.between(100, 999), r.between(100, 999), r.between(1000, 9999))
}

// tpchPartName returns five different words of partNameWords.
func tpchPartName(r *tpchRand) string {
	var words [5]string
	var used [5]int
	for i := range words {
		for {
			idx := r.between(0, len(partNameWords)-1)
			taken := false
			for _, u := range used[:i] {
				taken = taken || u == idx
			}
			if !taken {
				used[i] = idx
				words[i] = partNameWords[idx]
				break
			}
		}
	}
	return strings.Join(words[:], " ")
}

// The supplier comments of Q16: ten suppliers in 10000 have "Customer"
// and, further on, "Complaints" or "Recommends" (half each) written into
// their comment.
const (
	tpchSupplierNotesPer10000 = 10
	tpchSupplierNoteBase      = "Customer "
	tpchSupplierComplaints    = "Complaints"
	tpchSupplierRecommends    = "Recommends"
)

func tpchSupplierComment(r *tpchRand) string {
	b := tpchTextBytes(r, 25, 100)
	if r.between(1, 10000) <= tpchSupplierNotesPer10000 {
		word := tpchSupplierComplaints
		if r.between(0, 1) == 1 {
			word = tpchSupplierRecommends
		}
		// Both words have 10 letters; the shortest comment (25) holds them.
		noteLen := len(tpchSupplierNoteBase) + len(word)
		noise := r.between(0, len(b)-noteLen)
		offset := r.between(0, len(b)-noteLen-noise)
		copy(b[offset:], tpchSupplierNoteBase)
		copy(b[offset+len(tpchSupplierNoteBase)+noise:], word)
	}
	return strings.TrimRight(string(b), " ")
}

// ---- tables -------------------------------------------------------------

// TPCHTableInfo contains information about a TPC-H table to load
type TPCHTableInfo struct {
	Name string
	// RowCount is the number of rows; for lineitem the expected number
	// (an order has 1 to 7 lineitems, 4 on average).
	RowCount func(sf float64) int
	// Units is the number of generator units when that is not RowCount:
	// lineitem is generated order by order.
	Units func(sf float64) int
	// RowsPerUnit is the average number of rows of a unit (0 = 1).
	RowsPerUnit int
	// Generator returns the rows of the units start (included) to end.
	Generator func(sf float64, start, end int) []dsl.BatchWriteOperation
}

func (t *TPCHTableInfo) unitCount(sf float64) int {
	if t.Units != nil {
		return t.Units(sf)
	}
	return t.RowCount(sf)
}

// GetTPCHTables returns the list of TPC-H tables in dependency order
func GetTPCHTables() []TPCHTableInfo {
	orders := func(sf float64) int { return tpchScaled(tpchOrdersBase, sf) }
	return []TPCHTableInfo{
		{Name: "region", RowCount: func(sf float64) int { return tpchRegionCount }, Generator: generateRegionRows},
		{Name: "nation", RowCount: func(sf float64) int { return tpchNationCount }, Generator: generateNationRows},
		{Name: "supplier", RowCount: func(sf float64) int { return tpchScaled(tpchSupplierBase, sf) }, Generator: generateSupplierRows},
		{Name: "customer", RowCount: func(sf float64) int { return tpchScaled(tpchCustomerBase, sf) }, Generator: generateCustomerRows},
		{Name: "part", RowCount: func(sf float64) int { return tpchScaled(tpchPartBase, sf) }, Generator: generatePartRows},
		{Name: "partsupp", RowCount: func(sf float64) int { return 4 * tpchScaled(tpchPartBase, sf) }, Generator: generatePartsuppRows},
		{Name: "orders", RowCount: orders, Generator: generateOrdersRows},
		{Name: "lineitem", RowCount: func(sf float64) int { return 4 * orders(sf) }, Units: orders, RowsPerUnit: 4,
			Generator: generateLineitemRows},
	}
}

// TPC-H table creation SQL statements
var tpchTableDDL = map[string]string{
	"region": `CREATE TABLE IF NOT EXISTS tpch.region (
		r_regionkey INT NOT NULL,
		r_name CHAR(25) NOT NULL,
		r_comment VARCHAR(152),
		PRIMARY KEY (r_regionkey)
	) ENGINE=NDB`,

	"nation": `CREATE TABLE IF NOT EXISTS tpch.nation (
		n_nationkey INT NOT NULL,
		n_name CHAR(25) NOT NULL,
		n_regionkey INT NOT NULL,
		n_comment VARCHAR(152),
		PRIMARY KEY (n_nationkey)
	) ENGINE=NDB`,

	"supplier": `CREATE TABLE IF NOT EXISTS tpch.supplier (
		s_suppkey INT NOT NULL,
		s_name CHAR(25) NOT NULL,
		s_address VARCHAR(40) NOT NULL,
		s_nationkey INT NOT NULL,
		s_phone CHAR(15) NOT NULL,
		s_acctbal DECIMAL(15,2) NOT NULL,
		s_comment VARCHAR(101),
		PRIMARY KEY (s_suppkey),
		KEY idx_supplier_nationkey (s_nationkey)
	) ENGINE=NDB`,

	"customer": `CREATE TABLE IF NOT EXISTS tpch.customer (
		c_custkey INT NOT NULL,
		c_name VARCHAR(25) NOT NULL,
		c_address VARCHAR(40) NOT NULL,
		c_nationkey INT NOT NULL,
		c_phone CHAR(15) NOT NULL,
		c_acctbal DECIMAL(15,2) NOT NULL,
		c_mktsegment CHAR(10) NOT NULL,
		c_comment VARCHAR(117),
		PRIMARY KEY (c_custkey),
		KEY idx_customer_nationkey (c_nationkey)
	) ENGINE=NDB`,

	"part": `CREATE TABLE IF NOT EXISTS tpch.part (
		p_partkey INT NOT NULL,
		p_name VARCHAR(55) NOT NULL,
		p_mfgr CHAR(25) NOT NULL,
		p_brand CHAR(10) NOT NULL,
		p_type VARCHAR(25) NOT NULL,
		p_size INT NOT NULL,
		p_container CHAR(10) NOT NULL,
		p_retailprice DECIMAL(15,2) NOT NULL,
		p_comment VARCHAR(23),
		PRIMARY KEY (p_partkey)
	) ENGINE=NDB`,

	"partsupp": `CREATE TABLE IF NOT EXISTS tpch.partsupp (
		ps_partkey INT NOT NULL,
		ps_suppkey INT NOT NULL,
		ps_availqty INT NOT NULL,
		ps_supplycost DECIMAL(15,2) NOT NULL,
		ps_comment VARCHAR(199),
		PRIMARY KEY (ps_partkey, ps_suppkey)
	) ENGINE=NDB`,

	"orders": `CREATE TABLE IF NOT EXISTS tpch.orders (
		o_orderkey BIGINT NOT NULL,
		o_custkey INT NOT NULL,
		o_orderstatus CHAR(1) NOT NULL,
		o_totalprice DECIMAL(15,2) NOT NULL,
		o_orderdate DATE NOT NULL,
		o_orderpriority CHAR(15) NOT NULL,
		o_clerk CHAR(15) NOT NULL,
		o_shippriority INT NOT NULL,
		o_comment VARCHAR(79),
		PRIMARY KEY (o_orderkey),
		KEY idx_orders_custkey (o_custkey),
		KEY idx_orders_orderdate (o_orderdate)
	) ENGINE=NDB`,

	"lineitem": `CREATE TABLE IF NOT EXISTS tpch.lineitem (
		l_orderkey BIGINT NOT NULL,
		l_partkey INT NOT NULL,
		l_suppkey INT NOT NULL,
		l_linenumber INT NOT NULL,
		l_quantity DECIMAL(15,2) NOT NULL,
		l_extendedprice DECIMAL(15,2) NOT NULL,
		l_discount DECIMAL(15,2) NOT NULL,
		l_tax DECIMAL(15,2) NOT NULL,
		l_returnflag CHAR(1) NOT NULL,
		l_linestatus CHAR(1) NOT NULL,
		l_shipdate DATE NOT NULL,
		l_commitdate DATE NOT NULL,
		l_receiptdate DATE NOT NULL,
		l_shipinstruct CHAR(25) NOT NULL,
		l_shipmode CHAR(10) NOT NULL,
		l_comment VARCHAR(44),
		PRIMARY KEY (l_orderkey, l_linenumber),
		KEY idx_lineitem_suppkey (l_suppkey),
		KEY idx_lineitem_shipdate (l_shipdate)
	) ENGINE=NDB`,
}

// Row generators for each TPC-H table.  A generator returns the rows of
// the units start to end; a unit is a row, for lineitem an order.

func tpchWriteOp(table, operationID string, key []dsl.Filter, columns []dsl.WriteColumn) dsl.BatchWriteOperation {
	return dsl.BatchWriteOperation{
		Method:      "POST",
		RelativeURL: "tpch/" + table + "/pk-write",
		Body: dsl.PkWriteRequest{
			Filters:      key,
			WriteColumns: columns,
			OperationID:  operationID,
		},
	}
}

func generateRegionRows(sf float64, start, end int) []dsl.BatchWriteOperation {
	var ops []dsl.BatchWriteOperation
	for i := start; i < end && i < tpchRegionCount; i++ {
		r := newTPCHRand(tpchStreamRegion, i)
		ops = append(ops, tpchWriteOp("region", fmt.Sprintf("region_%d", i),
			[]dsl.Filter{{Column: "r_regionkey", Value: i}},
			[]dsl.WriteColumn{
				{Column: "r_name", Value: tpchRegions[i]},
				{Column: "r_comment", Value: tpchText(&r, 31, 115)},
			}))
	}
	return ops
}

func generateNationRows(sf float64, start, end int) []dsl.BatchWriteOperation {
	var ops []dsl.BatchWriteOperation
	for i := start; i < end && i < tpchNationCount; i++ {
		r := newTPCHRand(tpchStreamNation, i)
		ops = append(ops, tpchWriteOp("nation", fmt.Sprintf("nation_%d", i),
			[]dsl.Filter{{Column: "n_nationkey", Value: i}},
			[]dsl.WriteColumn{
				{Column: "n_name", Value: tpchNations[i].name},
				{Column: "n_regionkey", Value: tpchNations[i].regionKey},
				{Column: "n_comment", Value: tpchText(&r, 31, 114)},
			}))
	}
	return ops
}

func generateSupplierRows(sf float64, start, end int) []dsl.BatchWriteOperation {
	ops := make([]dsl.BatchWriteOperation, 0, end-start)
	for i := start; i < end; i++ {
		r := newTPCHRand(tpchStreamSupplier, i)
		suppKey := i + 1
		address := tpchVString(&r, 10, 40)
		nationKey := r.between(0, tpchNationCount-1)
		phone := tpchPhone(&r, nationKey)
		acctbal := tpchMoney(int64(r.between(-99999, 999999)))
		comment := tpchSupplierComment(&r)
		ops = append(ops, tpchWriteOp("supplier", fmt.Sprintf("supplier_%d", suppKey),
			[]dsl.Filter{{Column: "s_suppkey", Value: suppKey}},
			[]dsl.WriteColumn{
				{Column: "s_name", Value: fmt.Sprintf("Supplier#%09d", suppKey)},
				{Column: "s_address", Value: address},
				{Column: "s_nationkey", Value: nationKey},
				{Column: "s_phone", Value: phone},
				{Column: "s_acctbal", Value: acctbal},
				{Column: "s_comment", Value: comment},
			}))
	}
	return ops
}

func generateCustomerRows(sf float64, start, end int) []dsl.BatchWriteOperation {
	ops := make([]dsl.BatchWriteOperation, 0, end-start)
	for i := start; i < end; i++ {
		r := newTPCHRand(tpchStreamCustomer, i)
		custKey := i + 1
		address := tpchVString(&r, 10, 40)
		nationKey := r.between(0, tpchNationCount-1)
		phone := tpchPhone(&r, nationKey)
		acctbal := tpchMoney(int64(r.between(-99999, 999999)))
		segment := r.oneOf(tpchSegments)
		comment := tpchText(&r, 29, 116)
		ops = append(ops, tpchWriteOp("customer", fmt.Sprintf("customer_%d", custKey),
			[]dsl.Filter{{Column: "c_custkey", Value: custKey}},
			[]dsl.WriteColumn{
				{Column: "c_name", Value: fmt.Sprintf("Customer#%09d", custKey)},
				{Column: "c_address", Value: address},
				{Column: "c_nationkey", Value: nationKey},
				{Column: "c_phone", Value: phone},
				{Column: "c_acctbal", Value: acctbal},
				{Column: "c_mktsegment", Value: segment},
				{Column: "c_comment", Value: comment},
			}))
	}
	return ops
}

func generatePartRows(sf float64, start, end int) []dsl.BatchWriteOperation {
	ops := make([]dsl.BatchWriteOperation, 0, end-start)
	for i := start; i < end; i++ {
		r := newTPCHRand(tpchStreamPart, i)
		partKey := i + 1
		name := tpchPartName(&r)
		manufacturer := r.between(1, 5)
		brand := manufacturer*10 + r.between(1, 5)
		partType := r.oneOf(tpchTypeSyllable1) + " " + r.oneOf(tpchTypeSyllable2) + " " + r.oneOf(tpchTypeSyllable3)
		size := r.between(1, 50)
		container := r.oneOf(tpchContainerSyllable1) + " " + r.oneOf(tpchContainerSyllable2)
		comment := tpchText(&r, 5, 22)
		ops = append(ops, tpchWriteOp("part", fmt.Sprintf("part_%d", partKey),
			[]dsl.Filter{{Column: "p_partkey", Value: partKey}},
			[]dsl.WriteColumn{
				{Column: "p_name", Value: name},
				{Column: "p_mfgr", Value: fmt.Sprintf("Manufacturer#%d", manufacturer)},
				{Column: "p_brand", Value: fmt.Sprintf("Brand#%d", brand)},
				{Column: "p_type", Value: partType},
				{Column: "p_size", Value: size},
				{Column: "p_container", Value: container},
				{Column: "p_retailprice", Value: tpchMoney(tpchRetailPriceCents(partKey))},
				{Column: "p_comment", Value: comment},
			}))
	}
	return ops
}

func generatePartsuppRows(sf float64, start, end int) []dsl.BatchWriteOperation {
	ops := make([]dsl.BatchWriteOperation, 0, end-start)
	supplierCount := tpchScaled(tpchSupplierBase, sf)
	for i := start; i < end; i++ {
		r := newTPCHRand(tpchStreamPartsupp, i)
		partKey := i/4 + 1
		suppKey := tpchPartSupplier(partKey, i%4, supplierCount)
		availQty := r.between(1, 9999)
		supplyCost := tpchMoney(int64(r.between(100, 100000)))
		comment := tpchText(&r, 49, 198)
		ops = append(ops, tpchWriteOp("partsupp", fmt.Sprintf("partsupp_%d_%d", partKey, suppKey),
			[]dsl.Filter{
				{Column: "ps_partkey", Value: partKey},
				{Column: "ps_suppkey", Value: suppKey},
			},
			[]dsl.WriteColumn{
				{Column: "ps_availqty", Value: availQty},
				{Column: "ps_supplycost", Value: supplyCost},
				{Column: "ps_comment", Value: comment},
			}))
	}
	return ops
}

// tpchLine holds the values of a lineitem that its order's row depends
// on, and the rest of its numbers.
type tpchLine struct {
	partKey       int
	suppKey       int
	quantity      int
	extendedCents int64
	discount      int // hundredths
	tax           int // hundredths
	shipDay       int
	commitDay     int
	receiptDay    int
	returnFlag    string
	lineStatus    string
}

// tpchOrderDay is the order date (a day number) of the order with index
// i, counted from 0.
func tpchOrderDay(i int) int {
	r := newTPCHRand(tpchStreamOrderDate, i)
	return r.between(0, tpchOrderDays-1)
}

// tpchOrderLines returns the lineitems of the order with index i.  Both
// the orders and the lineitem generator call it, so an order's status and
// total price are those of the lineitems that are loaded.
func tpchOrderLines(sf float64, i int) []tpchLine {
	partCount := tpchScaled(tpchPartBase, sf)
	supplierCount := tpchScaled(tpchSupplierBase, sf)
	orderDay := tpchOrderDay(i)
	r := newTPCHRand(tpchStreamLines, i)
	lines := make([]tpchLine, r.between(1, 7))
	for n := range lines {
		l := &lines[n]
		l.partKey = r.between(1, partCount)
		l.suppKey = tpchPartSupplier(l.partKey, r.between(0, 3), supplierCount)
		l.quantity = r.between(1, 50)
		l.extendedCents = int64(l.quantity) * tpchRetailPriceCents(l.partKey)
		l.discount = r.between(0, 10)
		l.tax = r.between(0, 8)
		l.shipDay = orderDay + r.between(1, 121)
		l.commitDay = orderDay + r.between(30, 90)
		l.receiptDay = l.shipDay + r.between(1, 30)
		// Returned or accepted once received by CURRENTDATE; shipped or not.
		l.returnFlag = "N"
		if l.receiptDay <= tpchCurrentDay {
			l.returnFlag = "R"
			if r.between(0, 1) == 1 {
				l.returnFlag = "A"
			}
		}
		l.lineStatus = "F"
		if l.shipDay > tpchCurrentDay {
			l.lineStatus = "O"
		}
	}
	return lines
}

func generateOrdersRows(sf float64, start, end int) []dsl.BatchWriteOperation {
	ops := make([]dsl.BatchWriteOperation, 0, end-start)
	withOrders := tpchCustomersWithOrders(tpchScaled(tpchCustomerBase, sf))
	if withOrders < 1 {
		withOrders = 1
	}
	clerks := tpchScaled(tpchClerkBase, sf)
	for i := start; i < end; i++ {
		r := newTPCHRand(tpchStreamOrders, i)
		orderKey := tpchOrderKey(i + 1)
		// Never a multiple of 3: a third of the customers have no orders.
		custKey := tpchOrderCustKey(r.between(0, withOrders-1))
		priority := r.oneOf(tpchPriorities)
		clerk := fmt.Sprintf("Clerk#%09d", r.between(1, clerks))
		comment := tpchText(&r, 19, 78)

		// F when every lineitem is shipped, O when none is, P otherwise;
		// the total is the sum of the lineitems' price after discount and
		// tax, each rounded down to cents as dbgen does.
		total := int64(0)
		shipped, open := 0, 0
		for _, l := range tpchOrderLines(sf, i) {
			total += l.extendedCents * int64(100-l.discount) / 100 * int64(100+l.tax) / 100
			if l.lineStatus == "F" {
				shipped++
			} else {
				open++
			}
		}
		status := "P"
		if open == 0 {
			status = "F"
		} else if shipped == 0 {
			status = "O"
		}

		ops = append(ops, tpchWriteOp("orders", fmt.Sprintf("orders_%d", orderKey),
			[]dsl.Filter{{Column: "o_orderkey", Value: orderKey}},
			[]dsl.WriteColumn{
				{Column: "o_custkey", Value: custKey},
				{Column: "o_orderstatus", Value: status},
				{Column: "o_totalprice", Value: tpchMoney(total)},
				{Column: "o_orderdate", Value: tpchDateText[tpchOrderDay(i)]},
				{Column: "o_orderpriority", Value: priority},
				{Column: "o_clerk", Value: clerk},
				{Column: "o_shippriority", Value: 0},
				{Column: "o_comment", Value: comment},
			}))
	}
	return ops
}

// generateLineitemRows returns the lineitems of the orders with index
// start to end: 1 to 7 rows per order.
func generateLineitemRows(sf float64, start, end int) []dsl.BatchWriteOperation {
	ops := make([]dsl.BatchWriteOperation, 0, 4*(end-start))
	for i := start; i < end; i++ {
		orderKey := tpchOrderKey(i + 1)
		r := newTPCHRand(tpchStreamLineText, i)
		for n, l := range tpchOrderLines(sf, i) {
			lineNumber := n + 1
			instruct := r.oneOf(tpchShipInstructs)
			mode := r.oneOf(tpchShipModes)
			comment := tpchText(&r, 10, 43)
			ops = append(ops, tpchWriteOp("lineitem", fmt.Sprintf("lineitem_%d_%d", orderKey, lineNumber),
				[]dsl.Filter{
					{Column: "l_orderkey", Value: orderKey},
					{Column: "l_linenumber", Value: lineNumber},
				},
				[]dsl.WriteColumn{
					{Column: "l_partkey", Value: l.partKey},
					{Column: "l_suppkey", Value: l.suppKey},
					{Column: "l_quantity", Value: tpchMoney(int64(l.quantity) * 100)},
					{Column: "l_extendedprice", Value: tpchMoney(l.extendedCents)},
					{Column: "l_discount", Value: tpchMoney(int64(l.discount))},
					{Column: "l_tax", Value: tpchMoney(int64(l.tax))},
					{Column: "l_returnflag", Value: l.returnFlag},
					{Column: "l_linestatus", Value: l.lineStatus},
					{Column: "l_shipdate", Value: tpchDateText[l.shipDay]},
					{Column: "l_commitdate", Value: tpchDateText[l.commitDay]},
					{Column: "l_receiptdate", Value: tpchDateText[l.receiptDay]},
					{Column: "l_shipinstruct", Value: instruct},
					{Column: "l_shipmode", Value: mode},
					{Column: "l_comment", Value: comment},
				}))
		}
	}
	return ops
}

// tpchSpaces is what a CHAR value is filled with: a CHAR column is at most
// 255 characters of at most 4 bytes.
var tpchSpaces = strings.Repeat(" ", 255*4)

// tpchPadChars fills the CHAR values of the operations with spaces to the
// length in bytes of their columns (widths, by column name).
//
// The loader writes through the REST server, which until 2026-11-28
// filled the unused bytes of a CHAR column with NUL where MySQL fills them
// with spaces (set_col_value in rest-server2, fixed that day).  A value
// written short was then stored as another value than the one MySQL would
// store: 'R' in a CHAR(1) of utf8mb4 read back as the four characters
// 'R\0\0\0', and the MySQL server and RonSQL returned it differently (the
// MySQL server cuts it to the length of the column when it groups or
// sorts, RonSQL returns all of it).  A value sent at the full length of
// the column leaves the REST server nothing to fill, so a load is right
// on a REST server without the fix too.
func tpchPadChars(ops []dsl.BatchWriteOperation, widths map[string]int) {
	if len(widths) == 0 {
		return
	}
	for i := range ops {
		columns := ops[i].Body.WriteColumns
		for c := range columns {
			width, isChar := widths[columns[c].Column]
			if !isChar {
				continue
			}
			value, isString := columns[c].Value.(string)
			if missing := width - len(value); isString && missing > 0 && missing <= len(tpchSpaces) {
				columns[c].Value = value + tpchSpaces[:missing]
			}
		}
	}
}

// tpchCharWidths returns, per table of the tpch database, the length in
// bytes of its CHAR columns (the length in characters times the longest
// character of the character set): what tpchPadChars fills a value to.
func (s *Shell) tpchCharWidths() (map[string]map[string]int, error) {
	_, rows, _, err := s.mysqlClient.Query(
		"SELECT TABLE_NAME, COLUMN_NAME, CHARACTER_OCTET_LENGTH, CHARACTER_SET_NAME " +
			"FROM information_schema.COLUMNS " +
			"WHERE TABLE_SCHEMA = '" + tpchDatabase + "' AND DATA_TYPE = 'char'")
	if err != nil {
		return nil, err
	}
	widths := map[string]map[string]int{}
	for _, row := range rows {
		if len(row) < 4 {
			continue
		}
		table := strings.ToLower(tpchCellString(row[0]))
		column := strings.ToLower(tpchCellString(row[1]))
		width, err := strconv.Atoi(tpchCellString(row[2]))
		if err != nil {
			return nil, fmt.Errorf("length of %s.%s: %w", table, column, err)
		}
		switch charset := strings.ToLower(tpchCellString(row[3])); charset {
		case "ucs2", "utf16", "utf16le", "utf32":
			// a space is two or four bytes there: a fill of one-byte
			// spaces would store text that is not valid in the column
			return nil, fmt.Errorf("%s.%s has character set %s, which .load_tpch cannot fill a CHAR column of: "+
				"drop the tpch database and create it with utf8mb4 or latin1", table, column, charset)
		}
		if widths[table] == nil {
			widths[table] = map[string]int{}
		}
		widths[table][column] = width
	}
	return widths, nil
}

// runLoadTPCH loads TPC-H data using the batchwrite endpoint
func (s *Shell) runLoadTPCH(scaleFactor float64, numThreads int, batchSize int) error {
	if s.mysqlClient == nil {
		return fmt.Errorf("MySQL not connected. Cannot create TPC-H tables.")
	}
	if s.restClient == nil {
		return fmt.Errorf("REST API not connected. Cannot load TPC-H data.")
	}

	tables := GetTPCHTables()

	// Calculate total rows
	var totalRows int
	for _, table := range tables {
		totalRows += table.RowCount(scaleFactor)
	}

	fmt.Println()
	fmt.Println(ui.Info(fmt.Sprintf("Loading TPC-H data with scale factor %g", scaleFactor)))
	fmt.Println(ui.Info(fmt.Sprintf("Rows to load: about %d (an order has 1 to 7 lineitems)", totalRows)))
	fmt.Println(ui.Info(fmt.Sprintf("Using %d threads, batch size %d", numThreads, batchSize)))
	fmt.Println()

	// Create database and tables
	fmt.Println("Creating tpch database and tables...")
	_, _, err := s.mysqlClient.Execute("CREATE DATABASE IF NOT EXISTS tpch")
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}

	for _, table := range tables {
		ddl, ok := tpchTableDDL[table.Name]
		if !ok {
			return fmt.Errorf("no DDL for table %s", table.Name)
		}
		_, _, err = s.mysqlClient.Execute(ddl)
		if err != nil {
			return fmt.Errorf("failed to create table %s: %w", table.Name, err)
		}
		fmt.Printf("   Created table tpch.%s\n", table.Name)
	}
	fmt.Println()

	charWidths, err := s.tpchCharWidths()
	if err != nil {
		return fmt.Errorf("failed to read the CHAR columns of the tpch tables: %w", err)
	}

	// Load each table
	loadStart := time.Now()
	var totalRowsLoaded int64

	for i := range tables {
		table := &tables[i]
		if table.unitCount(scaleFactor) == 0 {
			continue
		}

		if table.Units != nil {
			fmt.Printf("Loading tpch.%s (about %d rows)...\n", table.Name, table.RowCount(scaleFactor))
		} else {
			fmt.Printf("Loading tpch.%s (%d rows)...\n", table.Name, table.RowCount(scaleFactor))
		}
		tableStart := time.Now()

		rowsLoaded, err := s.loadTPCHTable(table, charWidths[table.Name], scaleFactor, numThreads, batchSize)
		if err != nil {
			return fmt.Errorf("failed to load table %s: %w", table.Name, err)
		}
		totalRowsLoaded += rowsLoaded

		tableDuration := time.Since(tableStart)
		rowsPerSec := float64(rowsLoaded) / tableDuration.Seconds()
		fmt.Printf("   Loaded %d rows in %v (%.0f rows/sec)\n", rowsLoaded, tableDuration.Round(time.Millisecond), rowsPerSec)
	}

	totalDuration := time.Since(loadStart)
	totalRowsPerSec := float64(totalRowsLoaded) / totalDuration.Seconds()

	fmt.Println()
	fmt.Println(ui.Success(fmt.Sprintf("TPC-H load complete: %d rows in %v (%.0f rows/sec)",
		totalRowsLoaded, totalDuration.Round(time.Millisecond), totalRowsPerSec)))
	fmt.Println()

	return nil
}

// loadTPCHTable loads a single TPC-H table using multiple threads and
// returns the number of rows it sent.  charWidths has the length in bytes
// of the table's CHAR columns (tpchPadChars).
func (s *Shell) loadTPCHTable(table *TPCHTableInfo, charWidths map[string]int, scaleFactor float64, numThreads int, batchSize int) (int64, error) {
	units := table.unitCount(scaleFactor)
	if units == 0 {
		return 0, nil
	}
	// A batch request holds about batchSize rows: fewer units when a unit
	// is several rows (an order's lineitems).
	unitsPerBatch := batchSize
	if table.RowsPerUnit > 1 {
		unitsPerBatch = batchSize / table.RowsPerUnit
	}
	if unitsPerBatch < 1 {
		unitsPerBatch = 1
	}

	// Create REST clients for each thread
	clients := make([]*client.RestClient, numThreads)
	for i := 0; i < numThreads; i++ {
		c, err := client.NewRestClientWithOptions(client.RestOptions{
			Host:   s.config.RDRSHost,
			Port:   s.config.RestPort,
			TLS:    s.config.RDRSTLS,
			APIKey: s.config.RDRSAPIKey,
		})
		if err != nil {
			for j := 0; j < i; j++ {
				clients[j].Close()
			}
			return 0, fmt.Errorf("failed to create REST client: %w", err)
		}
		clients[i] = c
	}
	defer func() {
		for _, c := range clients {
			if c != nil {
				c.Close()
			}
		}
	}()

	// Split work among threads
	unitsPerThread := (units + numThreads - 1) / numThreads
	errorCollector := NewErrorCollector()
	var completedUnits int64
	var completedRows int64
	var wg sync.WaitGroup

	// Progress reporting
	stopProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rows := atomic.LoadInt64(&completedRows)
				pct := float64(atomic.LoadInt64(&completedUnits)) / float64(units) * 100
				errs := errorCollector.Count()
				fmt.Printf("   Progress: %d rows (%.1f%%), errors=%d\n", rows, pct, errs)
			case <-stopProgress:
				return
			}
		}
	}()

	for t := 0; t < numThreads; t++ {
		start := t * unitsPerThread
		end := start + unitsPerThread
		if end > units {
			end = units
		}
		if start >= units {
			continue
		}

		wg.Add(1)
		go func(restClient *client.RestClient, start, end int) {
			defer wg.Done()

			// Process in batches.  The rows of a unit do not depend on
			// the thread or the batch that generates them (tpchRand).
			for batchStart := start; batchStart < end; batchStart += unitsPerBatch {
				batchEnd := batchStart + unitsPerBatch
				if batchEnd > end {
					batchEnd = end
				}

				ops := table.Generator(scaleFactor, batchStart, batchEnd)
				atomic.AddInt64(&completedUnits, int64(batchEnd-batchStart))
				if len(ops) == 0 {
					continue
				}
				tpchPadChars(ops, charWidths)

				request := dsl.BatchWriteRequest{
					Operations: ops,
				}

				_, _, err := restClient.Post("/"+APIVersion+"/batchwrite", request)
				if err != nil {
					errorCollector.Record(err)
				}

				atomic.AddInt64(&completedRows, int64(len(ops)))
			}
		}(clients[t], start, end)
	}

	wg.Wait()
	close(stopProgress)

	if errorCollector.Count() > 0 {
		errorCollector.PrintErrors()
	}

	return atomic.LoadInt64(&completedRows), nil
}

// runDropTPCH drops all TPC-H tables and the tpch database
func (s *Shell) runDropTPCH() error {
	fmt.Println()
	fmt.Println("Dropping TPC-H tables and database...")

	tables := GetTPCHTables()
	// Drop tables in reverse order (due to potential FK relationships)
	for i := len(tables) - 1; i >= 0; i-- {
		table := tables[i]
		_, _, err := s.mysqlClient.Execute(fmt.Sprintf("DROP TABLE IF EXISTS tpch.%s", table.Name))
		if err != nil {
			fmt.Printf("   Warning: failed to drop table %s: %v\n", table.Name, err)
		} else {
			fmt.Printf("   Dropped table tpch.%s\n", table.Name)
		}
	}

	_, _, err := s.mysqlClient.Execute("DROP DATABASE IF EXISTS tpch")
	if err != nil {
		return fmt.Errorf("failed to drop database: %w", err)
	}

	fmt.Println(ui.Success("TPC-H database dropped"))
	fmt.Println()

	return nil
}

/*
 * Copyright (C) 2026, 2026 Hopsworks AB
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

package batchwrite

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"hopsworks.ai/rdrs2/internal/config"
	"hopsworks.ai/rdrs2/internal/integrationtests/testclient"
	"hopsworks.ai/rdrs2/internal/testutils"
	"hopsworks.ai/rdrs2/pkg/api"
	"hopsworks.ai/rdrs2/resources/testdbs"
)

// A CHAR value shorter than its column is stored filled with spaces, as the
// MySQL server stores it, in a written column and in a key.  The server
// filled it with NUL bytes before, which stored another value: the MySQL
// server read the NUL bytes back as part of the value, and in a collation
// where a NUL has a weight (latin1) a NUL-filled key was not the key of the
// row the MySQL server wrote, so a read of that row found nothing and a
// write added a second row.
func TestBatchWriteCharFilledWithSpaces(t *testing.T) {
	const db = testdbs.DB004
	for _, charset := range []string{"latin1", "utf8mb4"} {
		t.Run(charset, func(t *testing.T) {
			table := "char_fill_" + charset
			if err := testutils.RunQueriesOnDataCluster(fmt.Sprintf(
				"DROP TABLE IF EXISTS %[1]s.%[2]s;"+
					"CREATE TABLE %[1]s.%[2]s ("+
					"k CHAR(8) CHARACTER SET %[3]s NOT NULL, "+
					"v CHAR(12) CHARACTER SET %[3]s NOT NULL, "+
					"n INT NOT NULL, PRIMARY KEY (k)) ENGINE=ndbcluster;"+
					"INSERT INTO %[1]s.%[2]s VALUES ('sql', 'by mysql', 1);",
				db, table, charset)); err != nil {
				t.Fatalf("create %s: %v", table, err)
			}
			t.Cleanup(func() {
				_ = testutils.RunQueriesOnDataCluster(fmt.Sprintf("DROP TABLE IF EXISTS %s.%s;", db, table))
			})

			write := func(key, value string, n int) {
				t.Helper()
				batchWriteTest(t, api.BatchWriteOperationTestInfo{
					HttpCode: []int{http.StatusOK},
					Operations: []api.BatchWriteSubOperationTestInfo{{
						SubOperation: api.BatchWriteSubOp{
							Method:      &[]string{config.PK_HTTP_VERB}[0],
							RelativeURL: &[]string{db + "/" + table + "/" + config.PK_WRITE_OPERATION}[0],
							Body: &api.PKWriteBody{
								Filters:      testclient.NewFiltersKVs("k", key),
								WriteColumns: testclient.NewWriteColumnsKVs("v", value, "n", n),
								OperationID:  testclient.NewOperationID(8),
							},
						},
						Table:    table,
						DB:       db,
						HttpCode: []int{http.StatusOK},
					}},
				})
			}
			read := func(key string) string {
				t.Helper()
				_, resp := testclient.SendHttpRequest(t, config.PK_HTTP_VERB, testutils.NewPKReadURL(db, table),
					fmt.Sprintf(`{"filters":[{"column":"k","value":%q}]}`, key), "", http.StatusOK)
				var row api.PKReadResponseJSON
				if err := json.Unmarshal(resp, &row); err != nil || row.Data == nil {
					t.Fatalf("pk-read of %q: %v: %s", key, err, resp)
				}
				var value string
				if raw := (*row.Data)["v"]; raw == nil || json.Unmarshal(*raw, &value) != nil {
					t.Fatalf("pk-read of %q returns no v: %s", key, resp)
				}
				return value
			}

			mysql, err := testutils.CreateMySQLConnectionDataCluster()
			if err != nil {
				t.Fatal(err)
			}
			defer mysql.Close()
			// what the MySQL server reads back for the row with this n: the
			// bytes of the key and of the value, and the value's length
			stored := func(n int) (keyHex, valueHex string, valueChars int) {
				t.Helper()
				if err := mysql.QueryRow(fmt.Sprintf(
					"SELECT HEX(k), HEX(v), CHAR_LENGTH(v) FROM %s.%s WHERE n = %d", db, table, n)).
					Scan(&keyHex, &valueHex, &valueChars); err != nil {
					t.Fatalf("row with n = %d: %v", n, err)
				}
				return keyHex, valueHex, valueChars
			}
			count := func(where string) int {
				t.Helper()
				var rows int
				if err := mysql.QueryRow(fmt.Sprintf(
					"SELECT COUNT(*) FROM %s.%s WHERE %s", db, table, where)).Scan(&rows); err != nil {
					t.Fatalf("count where %s: %v", where, err)
				}
				return rows
			}
			hexOf := func(text string) string { return strings.ToUpper(hex.EncodeToString([]byte(text))) }

			// A row the REST server writes is the row the MySQL server would
			// have written.
			write("rest", "by rest", 2)
			keyHex, valueHex, valueChars := stored(2)
			if keyHex != hexOf("rest") || valueHex != hexOf("by rest") || valueChars != len("by rest") {
				t.Errorf("the MySQL server reads the written row as k = 0x%s, v = 0x%s (%d characters); "+
					"want 0x%s, 0x%s (%d characters)",
					keyHex, valueHex, valueChars, hexOf("rest"), hexOf("by rest"), len("by rest"))
			}
			if rows := count("k = 'rest'"); rows != 1 {
				t.Errorf("the MySQL server finds %d rows with k = 'rest', want 1", rows)
			}
			if got := read("rest"); got != "by rest" {
				t.Errorf("pk-read returns %q for the written value, want %q", got, "by rest")
			}

			// A row the MySQL server wrote is found by its CHAR key, for a
			// read and for a write: the write changes that row, it does not
			// add a row with another fill.
			if got := read("sql"); got != "by mysql" {
				t.Errorf("pk-read of the MySQL server's row returns %q, want %q", got, "by mysql")
			}
			write("sql", "updated", 1)
			if rows := count("1 = 1"); rows != 2 {
				t.Errorf("the table has %d rows after a write to the MySQL server's row, want 2", rows)
			}
			if _, valueHex, _ := stored(1); valueHex != hexOf("updated") {
				t.Errorf("the MySQL server's row holds v = 0x%s after the write, want 0x%s", valueHex, hexOf("updated"))
			}

			// A value as long as its column needs no fill.
			write("12345678", "123456789012", 3)
			if keyHex, valueHex, _ := stored(3); keyHex != hexOf("12345678") || valueHex != hexOf("123456789012") {
				t.Errorf("a full-length row reads back as k = 0x%s, v = 0x%s", keyHex, valueHex)
			}
		})
	}
}

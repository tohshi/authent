package rebac_test

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/tohshi/authent/integration/testenv"
	"github.com/tohshi/authent/rebac"
	"github.com/tohshi/authent/rebac/rebactest"
	"github.com/tohshi/authent/rebac/sqlstore"
)

func TestSQLStorePostgres(t *testing.T) {
	db := testenv.Postgres(t)
	rebactest.TestTupleStore(t, func(t *testing.T) rebac.TupleStore {
		table := "tuples_" + strings.ToLower(rand.Text()[:12])
		s, err := sqlstore.New(db, sqlstore.PostgreSQL, sqlstore.WithTable(table))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.CreateTable(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Exec("DROP TABLE " + table + ", " + table + "_revision") })
		return s
	})
}

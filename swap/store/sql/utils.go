package sqlstore

import (
	"database/sql"
	"fmt"

	swapdomain "github.com/arkade-os/go-sdk/swap/store/domain"
)

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func stringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullableInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: value != 0}
}

func int64Value(value sql.NullInt64) int64 {
	if !value.Valid {
		return 0
	}
	return value.Int64
}

func requireAffected(count int64, format, id string) error {
	if count == 0 {
		return fmt.Errorf("%w: "+format, swapdomain.ErrNotFound, id)
	}
	return nil
}

package sqlstore

import (
	"database/sql"
	"encoding/hex"
	"time"
)

func nullableString(value string) sql.NullString {
	if len(value) <= 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func stringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullableUnixTime(value time.Time) sql.NullInt64 {
	if value.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: value.Unix(), Valid: true}
}

func unixTimeValue(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(value.Int64, 0)
}

func decodeNullableHex(value sql.NullString) ([]byte, error) {
	if !value.Valid {
		return nil, nil
	}
	return hex.DecodeString(value.String)
}

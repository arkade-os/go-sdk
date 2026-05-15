package arksdk

import (
	"testing"

	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestListVtxosOptions(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		o := defaultListVtxosOpts()
		require.Equal(t, types.VtxoStatusAll, o.status)
		require.Equal(t, 1000, o.limit)
		require.Empty(t, o.assetID)
		require.Empty(t, o.cursor)
	})

	t.Run("WithLimit valid range", func(t *testing.T) {
		o := defaultListVtxosOpts()
		require.NoError(t, WithLimit(1)(o))
		require.Equal(t, 1, o.limit)
		require.NoError(t, WithLimit(1000)(o))
		require.Equal(t, 1000, o.limit)
		require.NoError(t, WithLimit(500)(o))
		require.Equal(t, 500, o.limit)
	})

	t.Run("WithLimit invalid", func(t *testing.T) {
		o := defaultListVtxosOpts()
		require.ErrorIs(t, WithLimit(0)(o), ErrInvalidLimit)
		require.ErrorIs(t, WithLimit(-1)(o), ErrInvalidLimit)
		require.ErrorIs(t, WithLimit(1001)(o), ErrInvalidLimit)
	})

	t.Run("WithAssetID rejects empty", func(t *testing.T) {
		o := defaultListVtxosOpts()
		require.Error(t, WithAssetID("")(o))
		require.NoError(t, WithAssetID("usdt")(o))
		require.Equal(t, "usdt", o.assetID)
	})

	t.Run("status options mutually exclusive", func(t *testing.T) {
		o := defaultListVtxosOpts()
		require.NoError(t, WithSpendableOnly()(o))
		require.ErrorIs(t, WithSpentOnly()(o), ErrConflictingStatusOption)

		o2 := defaultListVtxosOpts()
		require.NoError(t, WithSpentOnly()(o2))
		require.ErrorIs(t, WithSpendableOnly()(o2), ErrConflictingStatusOption)
	})

	t.Run("repeating same status option is fine", func(t *testing.T) {
		o := defaultListVtxosOpts()
		require.NoError(t, WithSpendableOnly()(o))
		require.NoError(t, WithSpendableOnly()(o))
		require.Equal(t, types.VtxoStatusSpendable, o.status)
	})
}

func TestVtxoCursorCodec(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		in := vtxoCursor{CreatedAt: 1234567, Txid: "abc", VOut: 7, FilterHash: "deadbeef"}
		s := encodeCursor(in)
		out, err := decodeCursor(s)
		require.NoError(t, err)
		require.Equal(t, in, out)
	})

	t.Run("empty cursor decodes to zero value with no error", func(t *testing.T) {
		out, err := decodeCursor("")
		require.NoError(t, err)
		require.Equal(t, vtxoCursor{}, out)
	})

	t.Run("malformed base64", func(t *testing.T) {
		_, err := decodeCursor("!!!not-base64!!!")
		require.ErrorIs(t, err, ErrInvalidCursor)
	})

	t.Run("malformed json", func(t *testing.T) {
		// base64url of "not json"
		_, err := decodeCursor("bm90IGpzb24")
		require.ErrorIs(t, err, ErrInvalidCursor)
	})

	t.Run("missing required fields", func(t *testing.T) {
		s := encodeCursor(vtxoCursor{CreatedAt: 1, Txid: "", VOut: 0, FilterHash: "x"})
		_, err := decodeCursor(s)
		require.ErrorIs(t, err, ErrInvalidCursor)

		s = encodeCursor(vtxoCursor{CreatedAt: 1, Txid: "abc", VOut: 0, FilterHash: ""})
		_, err = decodeCursor(s)
		require.ErrorIs(t, err, ErrInvalidCursor)
	})
}

func TestFilterHash(t *testing.T) {
	t.Run("differs by status", func(t *testing.T) {
		a := defaultListVtxosOpts()
		a.status = types.VtxoStatusSpendable
		b := defaultListVtxosOpts()
		b.status = types.VtxoStatusSpent
		require.NotEqual(t, filterHash(a), filterHash(b))
	})

	t.Run("differs by asset", func(t *testing.T) {
		a := defaultListVtxosOpts()
		a.assetID = "usdt"
		b := defaultListVtxosOpts()
		b.assetID = "btc"
		require.NotEqual(t, filterHash(a), filterHash(b))
	})

	t.Run("does NOT differ by limit or cursor", func(t *testing.T) {
		a := defaultListVtxosOpts()
		a.limit = 100
		a.cursor = "abc"
		b := defaultListVtxosOpts()
		b.limit = 500
		b.cursor = "xyz"
		require.Equal(t, filterHash(a), filterHash(b))
	})
}

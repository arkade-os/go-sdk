package arksdk

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/arkade-os/go-sdk/types"
)

// ListVtxosOption configures a Wallet.ListVtxos call. Options are validated
// when applied; an invalid option causes ListVtxos to return the corresponding
// sentinel error.
type ListVtxosOption func(*listVtxosOpts) error

const (
	defaultListVtxosLimit = 1000
	maxListVtxosLimit     = 1000
	minListVtxosLimit     = 1
)

var (
	ErrInvalidLimit            = errors.New("limit must be between 1 and 1000")
	ErrConflictingStatusOption = errors.New(
		"WithSpendableOnly and WithSpentOnly are mutually exclusive",
	)
	ErrInvalidCursor        = errors.New("cursor is malformed")
	ErrCursorFilterMismatch = errors.New("cursor was issued under a different filter set")
)

// WithSpendableOnly restricts results to VTXOs with spent = false AND unrolled = false.
func WithSpendableOnly() ListVtxosOption {
	return func(o *listVtxosOpts) error {
		if o.statusSet && o.status != types.VtxoStatusSpendable {
			return ErrConflictingStatusOption
		}
		o.status = types.VtxoStatusSpendable
		o.statusSet = true
		return nil
	}
}

// WithSpentOnly restricts results to VTXOs with spent = true OR unrolled = true.
func WithSpentOnly() ListVtxosOption {
	return func(o *listVtxosOpts) error {
		if o.statusSet && o.status != types.VtxoStatusSpent {
			return ErrConflictingStatusOption
		}
		o.status = types.VtxoStatusSpent
		o.statusSet = true
		return nil
	}
}

// WithAssetID restricts results to VTXOs that hold the given asset.
// Selected VTXOs include all their assets in the response, not just the
// filtered one.
func WithAssetID(id string) ListVtxosOption {
	return func(o *listVtxosOpts) error {
		if id == "" {
			return fmt.Errorf("asset id must not be empty")
		}
		o.assetID = id
		return nil
	}
}

// WithLimit sets the maximum number of VTXOs to return in one page.
// Valid range: [1, 1000]. Default and max are both 1000.
func WithLimit(n int) ListVtxosOption {
	return func(o *listVtxosOpts) error {
		if n < minListVtxosLimit || n > maxListVtxosLimit {
			return ErrInvalidLimit
		}
		o.limit = n
		return nil
	}
}

// WithCursor resumes pagination from the given opaque cursor. An empty string
// starts from the first page.
func WithCursor(c string) ListVtxosOption {
	return func(o *listVtxosOpts) error {
		o.cursor = c
		return nil
	}
}

type listVtxosOpts struct {
	status  types.VtxoStatusFilter
	assetID string
	limit   int
	cursor  string // empty = first page

	// statusSet tracks whether the caller explicitly set a status option, so
	// WithSpendableOnly() + WithSpentOnly() can be detected as conflicting
	// regardless of declaration order.
	statusSet bool
}

func defaultListVtxosOpts() *listVtxosOpts {
	return &listVtxosOpts{
		status: types.VtxoStatusAll,
		limit:  defaultListVtxosLimit,
	}
}

// vtxoCursor is the internal cursor structure. The wire format is
// base64url(json.Marshal(vtxoCursor)). Callers MUST treat the cursor as opaque.
type vtxoCursor struct {
	CreatedAt  int64  `json:"c"`
	Txid       string `json:"t"`
	VOut       uint32 `json:"v"`
	FilterHash string `json:"f"`
}

// filterHash returns a short fingerprint of the filter parameters of opts.
// Two option sets that differ only in pagination params (limit, cursor) yield
// the same hash. Used to bind a cursor to its filter set.
func filterHash(o *listVtxosOpts) string {
	payload := fmt.Sprintf("status=%d&asset=%s", o.status, o.assetID)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:8])
}

func encodeCursor(c vtxoCursor) string {
	// nolint
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (*vtxoCursor, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	var c vtxoCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, ErrInvalidCursor
	}
	if c.Txid == "" || c.FilterHash == "" {
		return nil, ErrInvalidCursor
	}
	return &c, nil
}

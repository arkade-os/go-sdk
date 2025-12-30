package arksdk

import (
	"fmt"
)

type DigestMismatchError struct {
	Expected string
	Actual   string
}

func (e DigestMismatchError) Error() string {
	return fmt.Sprintf("arkd info digest mismatch: expected %s, actual %s", e.Expected, e.Actual)
}

package arksdk

import (
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempoolexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
)

// regtestFeeRate is the fee rate (sat/vB) used on regtest. The mempool explorer
// derives its fee rate from the esplora `GET /fee-estimates` endpoint, which the
// local regtest stack (Fulcrum + mempool) does not serve — mempool only exposes
// `GET /api/v1/fees/recommended`. The regtest bitcoin node runs with
// minrelaytxfee=0, so a nominal 1 sat/vB is always sufficient.
const regtestFeeRate = 1.0

// regtestExplorer wraps a mempool explorer so that GetFeeRate returns a static
// value on regtest, where /fee-estimates is unavailable. Every other method is
// inherited unchanged from the embedded explorer.
type regtestExplorer struct {
	explorer.Explorer
}

func (regtestExplorer) GetFeeRate() (float64, error) {
	return regtestFeeRate, nil
}

// newExplorer builds a mempool explorer for the given network, transparently
// substituting a static fee rate on regtest (see regtestExplorer) so the SDK
// matches the endpoints the local regtest stack actually serves.
func newExplorer(
	url string, network arklib.Network, opts ...mempoolexplorer.Option,
) (explorer.Explorer, error) {
	svc, err := mempoolexplorer.NewExplorer(url, network, opts...)
	if err != nil {
		return nil, err
	}
	if network.Name == arklib.BitcoinRegTest.Name {
		return regtestExplorer{svc}, nil
	}
	return svc, nil
}

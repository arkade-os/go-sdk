package arksdk

import (
	"context"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

const mainnetUnilateralExitDelaySeconds uint32 = 605184

var mainnetUnilateralExitDelay = arklib.RelativeLocktime{
	Type:  arklib.LocktimeTypeSecond,
	Value: mainnetUnilateralExitDelaySeconds,
}

func effectiveUnilateralExitDelay(
	network arklib.Network,
	current arklib.RelativeLocktime,
) arklib.RelativeLocktime {
	if network.Name == arklib.Bitcoin.Name {
		return mainnetUnilateralExitDelay
	}

	return current
}

func normalizeConfigUnilateralExitDelay(
	cfg clientTypes.Config,
) (clientTypes.Config, bool) {
	effective := effectiveUnilateralExitDelay(cfg.Network, cfg.UnilateralExitDelay)
	if cfg.UnilateralExitDelay == effective {
		return cfg, false
	}

	cfg.UnilateralExitDelay = effective
	return cfg, true
}

func normalizePersistedUnilateralExitDelay(
	ctx context.Context,
	configStore clientTypes.ConfigStore,
) (*clientTypes.Config, bool, error) {
	cfg, err := configStore.GetData(ctx)
	if err != nil || cfg == nil {
		return cfg, false, err
	}

	normalized, changed := normalizeConfigUnilateralExitDelay(*cfg)
	if !changed {
		return cfg, false, nil
	}

	if err := configStore.AddData(ctx, normalized); err != nil {
		return nil, false, err
	}

	return &normalized, true, nil
}

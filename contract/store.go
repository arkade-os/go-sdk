package contract

import "context"

// ContractStore is the persistence layer for contracts.
// A nil ContractStore causes the Manager to keep contracts in memory only.
type ContractStore interface {
	UpsertContract(ctx context.Context, c Contract) error
	GetContractByScript(ctx context.Context, script string) (*Contract, error)
	ListContracts(ctx context.Context, f Filter) ([]Contract, error)
	UpdateContractState(ctx context.Context, script string, state State) error
}

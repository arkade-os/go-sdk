package handlers

type ContractOption func(*contractOption)

func WithIsOnchain() ContractOption {
	return func(o *contractOption) {
		o.IsOnchain = true
	}
}

func NewDefaultContractOption() *contractOption {
	return &contractOption{}
}

type contractOption struct {
	IsOnchain bool
}

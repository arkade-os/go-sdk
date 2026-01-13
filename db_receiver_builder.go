package arksdk

import "github.com/arkade-os/go-sdk/types"

type dbReceiverBuilder struct {
	dust      uint64
	nextIndex uint32
	receivers []types.DBReceiver
}

func newDBReceiverBuilder(startIndex uint32, dust uint64) *dbReceiverBuilder {
	return &dbReceiverBuilder{
		dust:      dust,
		nextIndex: startIndex,
		receivers: make([]types.DBReceiver, 0),
	}
}

func (b *dbReceiverBuilder) NextIndex() uint32 {
	return b.nextIndex
}

func (b *dbReceiverBuilder) Receivers() []types.DBReceiver {
	return b.receivers
}

func (b *dbReceiverBuilder) add(
	receiver types.Receiver,
	index uint32,
	receiverType types.VtxoType,
) types.DBReceiver {
	dbReceiver := types.DBReceiver{
		Receiver:     receiver,
		Index:        index,
		ReceiverType: receiverType,
	}
	b.receivers = append(b.receivers, dbReceiver)
	if index >= b.nextIndex {
		b.nextIndex = index + 1
	}
	return dbReceiver
}

func (b *dbReceiverBuilder) AddAssetReceiver(receiver types.Receiver) types.DBReceiver {
	receiver.Amount = b.dust
	return b.add(receiver, b.nextIndex, types.VtxoTypeAsset)
}

func (b *dbReceiverBuilder) AddAssetReceiverAt(
	receiver types.Receiver,
	index uint32,
) types.DBReceiver {
	receiver.Amount = b.dust
	return b.add(receiver, index, types.VtxoTypeAsset)
}

func (b *dbReceiverBuilder) AddNormalReceiver(receiver types.Receiver) types.DBReceiver {
	return b.add(receiver, b.nextIndex, types.VtxoTypeNormal)
}

func (b *dbReceiverBuilder) AddNormalReceiverAt(
	receiver types.Receiver,
	index uint32,
) types.DBReceiver {
	return b.add(receiver, index, types.VtxoTypeNormal)
}

func (b *dbReceiverBuilder) AddNormalChangeAfterAnchor(
	changeReceiver types.Receiver,
	changeAmount uint64,
) types.DBReceiver {
	changeIndex := assetAnchorChangeIndex(b.nextIndex, changeAmount, b.dust)
	return b.add(changeReceiver, changeIndex, types.VtxoTypeNormal)
}

func assetAnchorChangeIndex(assetOutputCount uint32, changeAmount uint64, dust uint64) uint32 {
	if changeAmount < dust {
		return assetOutputCount
	}
	return assetOutputCount + 1
}

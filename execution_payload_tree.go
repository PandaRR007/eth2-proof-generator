package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	ssz "github.com/prysmaticlabs/fastssz"
	v1 "github.com/prysmaticlabs/prysm/v4/proto/engine/v1"
)

type ExecutionPayloadTree struct {
	tree *ssz.Node
}

const ExecutionPayloadTreeBlockHashIndex int = 12

// HashTreeRootWith ssz hashes the BeaconBlockBellatrix object with a hasher
func newExecutionPayloadTree(e *v1.ExecutionPayloadCapella) (*ExecutionPayloadTree, error) {
	var chunks [][]byte
	hh := ssz.DefaultHasherPool.Get()

	{
		// Field (0) 'ParentHash'
		if size := len(e.ParentHash); size != 32 {
			return nil, ssz.ErrBytesLengthFn("--.ParentHash", size, 32)
		}
		hh.PutBytes(e.ParentHash)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (1) 'FeeRecipient'
		hh.Reset()
		if size := len(e.FeeRecipient); size != 20 {
			return nil, ssz.ErrBytesLengthFn("--.FeeRecipient", size, 20)
		}
		hh.PutBytes(e.FeeRecipient)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (2) 'StateRoot'
		hh.Reset()
		if size := len(e.StateRoot); size != 32 {
			return nil, ssz.ErrBytesLengthFn("--.StateRoot", size, 32)
		}
		hh.PutBytes(e.StateRoot)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (3) 'ReceiptsRoot'
		hh.Reset()
		if size := len(e.ReceiptsRoot); size != 32 {
			return nil, ssz.ErrBytesLengthFn("--.ReceiptsRoot", size, 32)
		}
		hh.PutBytes(e.ReceiptsRoot)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (4) 'LogsBloom'
		hh.Reset()
		if size := len(e.LogsBloom); size != 256 {
			return nil, ssz.ErrBytesLengthFn("--.LogsBloom", size, 256)
		}
		hh.PutBytes(e.LogsBloom)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (5) 'PrevRandao'
		hh.Reset()
		if size := len(e.PrevRandao); size != 32 {
			return nil, ssz.ErrBytesLengthFn("--.PrevRandao", size, 32)
		}
		hh.PutBytes(e.PrevRandao)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (6) 'BlockNumber'
		hh.Reset()
		hh.PutUint64(e.BlockNumber)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (7) 'GasLimit'
		hh.Reset()
		hh.PutUint64(e.GasLimit)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (8) 'GasUsed'
		hh.Reset()
		hh.PutUint64(e.GasUsed)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (9) 'Timestamp'
		hh.Reset()
		hh.PutUint64(e.Timestamp)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	// Field (10) 'ExtraData'
	{
		hh.Reset()
		elemIndx := hh.Index()
		byteLen := uint64(len(e.ExtraData))
		if byteLen > 32 {
			return nil, ssz.ErrIncorrectListSize
		}
		hh.PutBytes(e.ExtraData)
		if ssz.EnableVectorizedHTR {
			hh.MerkleizeWithMixinVectorizedHTR(elemIndx, byteLen, (32+31)/32)
		} else {
			hh.MerkleizeWithMixin(elemIndx, byteLen, (32+31)/32)
		}
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (11) 'BaseFeePerGas'
		hh.Reset()
		if size := len(e.BaseFeePerGas); size != 32 {
			return nil, ssz.ErrBytesLengthFn("--.BaseFeePerGas", size, 32)
		}
		hh.PutBytes(e.BaseFeePerGas)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (12) 'BlockHash'
		hh.Reset()
		if size := len(e.BlockHash); size != 32 {
			return nil, ssz.ErrBytesLengthFn("--.BlockHash", size, 32)
		}
		hh.PutBytes(e.BlockHash)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	// Field (13) 'Transactions'
	{
		hh.Reset()
		subIndx := hh.Index()
		num := uint64(len(e.Transactions))
		if num > 1048576 {
			return nil, ssz.ErrIncorrectListSize
		}
		for _, elem := range e.Transactions {
			elemIndx := hh.Index()
			byteLen := uint64(len(elem))
			if byteLen > 1073741824 {
				return nil, ssz.ErrIncorrectListSize
			}
			hh.AppendBytes32(elem)
			if ssz.EnableVectorizedHTR {
				hh.MerkleizeWithMixinVectorizedHTR(elemIndx, byteLen, (1073741824+31)/32)
			} else {
				hh.MerkleizeWithMixin(elemIndx, byteLen, (1073741824+31)/32)
			}
		}
		if ssz.EnableVectorizedHTR {
			hh.MerkleizeWithMixinVectorizedHTR(subIndx, num, 1048576)
		} else {
			hh.MerkleizeWithMixin(subIndx, num, 1048576)
		}
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
		fmt.Println("tx hash", common.BytesToHash(root[:]).String())
	}

	{
		// Field (14) 'Withdrawals'
		hh.Reset()
		subIndx := hh.Index()
		num := uint64(len(e.Withdrawals))
		if num > 16 {
			return nil, ssz.ErrIncorrectListSize
		}
		for _, elem := range e.Withdrawals {
			if err := elem.HashTreeRootWith(hh); err != nil {
				return nil, err
			}
		}
		if ssz.EnableVectorizedHTR {
			hh.MerkleizeWithMixinVectorizedHTR(subIndx, num, 16)
		} else {
			hh.MerkleizeWithMixin(subIndx, num, 16)
		}

		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	for i := 0; i < 1; i++ {
		chunks = append(chunks, zeroBytes)
	}

	node, err := ssz.TreeFromChunks(chunks)
	if err != nil {
		return nil, err
	}

	return &ExecutionPayloadTree{tree: node}, nil
}

func (tree *ExecutionPayloadTree) getBlockHashProof() (*ssz.Proof, error) {
	return tree.tree.Prove(ExecutionPayloadTreeBlockHashIndex + 16)
}

func (tree *ExecutionPayloadTree) getRoot() []byte {
	return tree.tree.Hash()
}

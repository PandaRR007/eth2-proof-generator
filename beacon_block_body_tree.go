package main

import (
	ssz "github.com/prysmaticlabs/fastssz"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
)

type BeaconBlockBodyTree struct {
	tree *ssz.Node
}

const BeaconBlockBodyTreeExecutionPayloadIndex int = 9

var zeroBytes = make([]byte, 32)

// HashTreeRootWith ssz hashes the BeaconBlockBellatrix object with a hasher
func newBeaconBlockBodyTree(b *eth.BeaconBlockBodyCapella, capella bool) (*BeaconBlockBodyTree, error) {
	var chunks [][]byte

	hh := ssz.DefaultHasherPool.Get()

	{
		// Field (0) 'RandaoReveal'
		if size := len(b.RandaoReveal); size != 96 {
			return nil, ssz.ErrBytesLengthFn("--.RandaoReveal", size, 96)
		}
		hh.PutBytes(b.RandaoReveal)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (1) 'Eth1Data'
		root, err := b.Eth1Data.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (2) 'Graffiti'
		hh.Reset()
		if size := len(b.Graffiti); size != 32 {
			return nil, ssz.ErrBytesLengthFn("--.Graffiti", size, 32)
		}
		hh.PutBytes(b.Graffiti)
		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	// Field (3) 'ProposerSlashings'
	{
		hh.Reset()
		subIndx := hh.Index()
		num := uint64(len(b.ProposerSlashings))
		if num > 16 {
			return nil, ssz.ErrIncorrectListSize
		}
		for _, elem := range b.ProposerSlashings {
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

	// Field (4) 'AttesterSlashings'
	{
		hh.Reset()
		subIndx := hh.Index()
		num := uint64(len(b.AttesterSlashings))
		if num > 2 {
			return nil, ssz.ErrIncorrectListSize
		}
		for _, elem := range b.AttesterSlashings {
			if err := elem.HashTreeRootWith(hh); err != nil {
				return nil, err
			}
		}
		if ssz.EnableVectorizedHTR {
			hh.MerkleizeWithMixinVectorizedHTR(subIndx, num, 2)
		} else {
			hh.MerkleizeWithMixin(subIndx, num, 2)
		}

		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}

		chunks = append(chunks, root[:])
	}

	// Field (5) 'Attestations'
	{
		hh.Reset()
		subIndx := hh.Index()
		num := uint64(len(b.Attestations))
		if num > 128 {
			return nil, ssz.ErrIncorrectListSize
		}
		for _, elem := range b.Attestations {
			if err := elem.HashTreeRootWith(hh); err != nil {
				return nil, err
			}
		}
		if ssz.EnableVectorizedHTR {
			hh.MerkleizeWithMixinVectorizedHTR(subIndx, num, 128)
		} else {
			hh.MerkleizeWithMixin(subIndx, num, 128)
		}

		root, err := hh.HashRoot()
		if err != nil {
			return nil, err
		}

		chunks = append(chunks, root[:])
	}

	// Field (6) 'Deposits'
	{
		hh.Reset()
		subIndx := hh.Index()
		num := uint64(len(b.Deposits))
		if num > 16 {
			return nil, ssz.ErrIncorrectListSize
		}
		for _, elem := range b.Deposits {
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

	// Field (7) 'VoluntaryExits'
	{
		hh.Reset()
		subIndx := hh.Index()
		num := uint64(len(b.VoluntaryExits))
		if num > 16 {
			return nil, ssz.ErrIncorrectListSize
		}
		for _, elem := range b.VoluntaryExits {
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

	{
		// Field (8) 'SyncAggregate'
		root, err := b.SyncAggregate.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	{
		// Field (9) 'ExecutionPayload'
		root, err := b.ExecutionPayload.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, root[:])
	}

	if capella {
		// Field (10) 'BlsToExecutionChanges'
		hh.Reset()
		subIndx := hh.Index()
		num := uint64(len(b.BlsToExecutionChanges))
		if num > 16 {
			return nil, ssz.ErrIncorrectListSize
		}
		for _, elem := range b.BlsToExecutionChanges {
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
	} else {
		chunks = append(chunks, zeroBytes)
	}

	for i := 0; i < 5; i++ {
		chunks = append(chunks, zeroBytes)
	}

	node, err := ssz.TreeFromChunks(chunks)
	if err != nil {
		return nil, err
	}

	return &BeaconBlockBodyTree{tree: node}, nil
}

func (tree *BeaconBlockBodyTree) getExecutionPayloadProof() (*ssz.Proof, error) {
	return tree.tree.Prove(BeaconBlockBodyTreeExecutionPayloadIndex + 16)
}

func (tree *BeaconBlockBodyTree) getRoot() []byte {
	return tree.tree.Hash()
}

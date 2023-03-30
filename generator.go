package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	fssz "github.com/prysmaticlabs/fastssz"
	"github.com/prysmaticlabs/prysm/v4/api/client/beacon"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/apimiddleware"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v4/encoding/bytesutil"
	"github.com/prysmaticlabs/prysm/v4/encoding/ssz"
	v1 "github.com/prysmaticlabs/prysm/v4/proto/engine/v1"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/urfave/cli/v2"
	"math/big"
	"strconv"
)

const HOST = "https://lodestar-mainnet.chainsafe.io/"

type beaconBlockResponseJson struct {
	Version             string                                               `json:"version"`
	Data                *apimiddleware.SignedBeaconBlockCapellaContainerJson `json:"data"`
	ExecutionOptimistic bool                                                 `json:"execution_optimistic"`
}

func generateCMD() *cli.Command {
	return &cli.Command{
		Name:   "generate",
		Usage:  "Generate exe proof",
		Action: generate,
		Flags: []cli.Flag{
			&cli.Uint64Flag{
				Name:     "slot",
				Usage:    "beacon chain slot",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "endpoint",
				Usage: "beacon chain endpoint",
				Value: HOST,
			},
		},
	}
}

func generate(cliCtx *cli.Context) error {
	slot := cliCtx.Uint64("slot")
	url := cliCtx.String("endpoint")
	client, err := beacon.NewClient(url)
	if err != nil {
		return err
	}

	data, err := client.GetBlock(context.Background(), beacon.StateOrBlockId(strconv.Itoa(int(slot))))
	if err != nil {
		panic(err)
	}

	blockResp := beaconBlockResponseJson{}
	if err := json.Unmarshal(data, &blockResp); err != nil {
		panic(err)
	}

	isCapella := blockResp.Version == "capella"
	body := blockResp.Data.Message.Body

	beaconBlockBody := eth.BeaconBlockBodyCapella{
		RandaoReveal: common.FromHex(body.RandaoReveal),
		Eth1Data: &eth.Eth1Data{
			DepositRoot:  common.FromHex(body.Eth1Data.DepositRoot),
			DepositCount: stringToUint64(body.Eth1Data.DepositCount),
			BlockHash:    common.FromHex(body.Eth1Data.BlockHash),
		},
		Graffiti:          common.FromHex(body.Graffiti),
		ProposerSlashings: nil,
		AttesterSlashings: nil,
		Attestations:      nil,
		Deposits:          nil,
		VoluntaryExits:    nil,
		SyncAggregate: &eth.SyncAggregate{
			SyncCommitteeBits:      common.FromHex(body.SyncAggregate.SyncCommitteeBits),
			SyncCommitteeSignature: common.FromHex(body.SyncAggregate.SyncCommitteeSignature),
		},
		ExecutionPayload: &v1.ExecutionPayloadCapella{
			ParentHash:    common.FromHex(body.ExecutionPayload.ParentHash),
			FeeRecipient:  common.FromHex(body.ExecutionPayload.FeeRecipient),
			StateRoot:     common.FromHex(body.ExecutionPayload.StateRoot),
			ReceiptsRoot:  common.FromHex(body.ExecutionPayload.ReceiptsRoot),
			LogsBloom:     common.FromHex(body.ExecutionPayload.LogsBloom),
			PrevRandao:    common.FromHex(body.ExecutionPayload.PrevRandao),
			BlockNumber:   stringToUint64(body.ExecutionPayload.BlockNumber),
			GasLimit:      stringToUint64(body.ExecutionPayload.GasLimit),
			GasUsed:       stringToUint64(body.ExecutionPayload.GasUsed),
			Timestamp:     stringToUint64(body.ExecutionPayload.TimeStamp),
			ExtraData:     common.FromHex(body.ExecutionPayload.ExtraData),
			BaseFeePerGas: nil,
			BlockHash:     common.FromHex(body.ExecutionPayload.BlockHash),
			Transactions:  nil,
			Withdrawals:   nil,
		},
		BlsToExecutionChanges: nil,
	}

	baseFee, ret := new(big.Int).SetString(body.ExecutionPayload.BaseFeePerGas, 10)
	if !ret {
		panic("DecodeBig")
	}
	beaconBlockBody.ExecutionPayload.BaseFeePerGas = bytesutil.PadTo(bytesutil.ReverseByteOrder(baseFee.Bytes()), 32)

	for _, pSlash := range body.ProposerSlashings {
		header1 := &eth.SignedBeaconBlockHeader{
			Header:    convertToBeaconBlockHeader(pSlash.Header_1.Header),
			Signature: common.FromHex(pSlash.Header_1.Signature),
		}
		header2 := &eth.SignedBeaconBlockHeader{
			Header:    convertToBeaconBlockHeader(pSlash.Header_2.Header),
			Signature: common.FromHex(pSlash.Header_2.Signature),
		}
		beaconBlockBody.ProposerSlashings = append(beaconBlockBody.ProposerSlashings, &eth.ProposerSlashing{
			Header_1: header1,
			Header_2: header2,
		})
	}
	for _, aSlash := range body.AttesterSlashings {
		att1 := &eth.IndexedAttestation{
			AttestingIndices: stringsToUint64s(aSlash.Attestation_1.AttestingIndices),
			Data:             convertToAttestationData(aSlash.Attestation_1.Data),
			Signature:        common.FromHex(aSlash.Attestation_1.Signature),
		}
		att2 := &eth.IndexedAttestation{
			AttestingIndices: stringsToUint64s(aSlash.Attestation_2.AttestingIndices),
			Data:             convertToAttestationData(aSlash.Attestation_2.Data),
			Signature:        common.FromHex(aSlash.Attestation_2.Signature),
		}
		beaconBlockBody.AttesterSlashings = append(beaconBlockBody.AttesterSlashings, &eth.AttesterSlashing{
			Attestation_1: att1,
			Attestation_2: att2,
		})
	}

	for _, att := range body.Attestations {
		attestaton := &eth.Attestation{
			AggregationBits: common.FromHex(att.AggregationBits),
			Data: &eth.AttestationData{
				Slot:            primitives.Slot(stringToUint64(att.Data.Slot)),
				CommitteeIndex:  primitives.CommitteeIndex(stringToUint64(att.Data.CommitteeIndex)),
				BeaconBlockRoot: common.FromHex(att.Data.BeaconBlockRoot),
				Source: &eth.Checkpoint{
					Epoch: primitives.Epoch(stringToUint64(att.Data.Source.Epoch)),
					Root:  common.FromHex(att.Data.Source.Root),
				},
				Target: &eth.Checkpoint{
					Epoch: primitives.Epoch(stringToUint64(att.Data.Target.Epoch)),
					Root:  common.FromHex(att.Data.Target.Root),
				},
			},
			Signature: common.FromHex(att.Signature),
		}

		beaconBlockBody.Attestations = append(beaconBlockBody.Attestations, attestaton)
	}

	for _, dep := range body.Deposits {
		deposit := &eth.Deposit{
			Data: &eth.Deposit_Data{
				PublicKey:             common.FromHex(dep.Data.PublicKey),
				WithdrawalCredentials: common.FromHex(dep.Data.WithdrawalCredentials),
				Amount:                stringToUint64(dep.Data.Amount),
				Signature:             common.FromHex(dep.Data.Signature),
			},
		}

		for _, proof := range dep.Proof {
			deposit.Proof = append(deposit.Proof, common.FromHex(proof))
		}

		beaconBlockBody.Deposits = append(beaconBlockBody.Deposits, deposit)
	}

	for _, ve := range body.VoluntaryExits {
		voluntaryExist := &eth.SignedVoluntaryExit{
			Exit: &eth.VoluntaryExit{
				Epoch:          primitives.Epoch(stringToUint64(ve.Exit.Epoch)),
				ValidatorIndex: primitives.ValidatorIndex(stringToUint64(ve.Exit.ValidatorIndex)),
			},
			Signature: common.FromHex(ve.Signature),
		}
		beaconBlockBody.VoluntaryExits = append(beaconBlockBody.VoluntaryExits, voluntaryExist)
	}

	for _, tx := range body.ExecutionPayload.Transactions {
		beaconBlockBody.ExecutionPayload.Transactions = append(beaconBlockBody.ExecutionPayload.Transactions, common.FromHex(tx))
	}

	if isCapella {
		for _, wd := range body.ExecutionPayload.Withdrawals {
			withdraw := &v1.Withdrawal{
				Index:          stringToUint64(wd.WithdrawalIndex),
				ValidatorIndex: primitives.ValidatorIndex(stringToUint64(wd.ValidatorIndex)),
				Address:        common.FromHex(wd.ExecutionAddress),
				Amount:         stringToUint64(wd.Amount),
			}
			beaconBlockBody.ExecutionPayload.Withdrawals = append(beaconBlockBody.ExecutionPayload.Withdrawals, withdraw)
		}

		for _, changes := range body.BLSToExecutionChanges {
			change := &eth.SignedBLSToExecutionChange{
				Message: &eth.BLSToExecutionChange{
					ValidatorIndex:     primitives.ValidatorIndex(stringToUint64(changes.Message.ValidatorIndex)),
					FromBlsPubkey:      common.FromHex(changes.Message.FromBLSPubkey),
					ToExecutionAddress: common.FromHex(changes.Message.ToExecutionAddress),
				},
				Signature: common.FromHex(changes.Signature),
			}
			beaconBlockBody.BlsToExecutionChanges = append(beaconBlockBody.BlsToExecutionChanges, change)
		}
	}

	tree1, err := newBeaconBlockBodyTree(&beaconBlockBody, isCapella)
	if err != nil {
		panic(err)
	}

	proof1, err := tree1.getExecutionPayloadProof()
	if err != nil {
		panic(err)
	}

	ret, err = fssz.VerifyProof(tree1.getRoot(), proof1)
	if err != nil {
		panic(err)
	}

	if !ret {
		return fmt.Errorf("VerifyProof fail")
	}

	for _, hash := range proof1.Hashes {
		fmt.Println(hexutil.Encode(hash[:]))
	}

	txRoot, err := ssz.TransactionsRoot(beaconBlockBody.ExecutionPayload.Transactions)
	if err != nil {
		return fmt.Errorf("TransactionsRoot fail: %v", err)
	}

	fmt.Println("txRoot", hexutil.Encode(txRoot[:]))

	if isCapella {
		wdRoot, err := ssz.WithdrawalSliceRoot(beaconBlockBody.ExecutionPayload.Withdrawals, 16)
		if err != nil {
			return fmt.Errorf("WithdrawalsRoot fail: %v", err)
		}
		fmt.Println("wdRoot", hexutil.Encode(wdRoot[:]))
	} else {
		fmt.Println("wdRoot", hexutil.Encode(common.Hash{}.Bytes()[:]))
	}

	return nil

}

func convertToBeaconBlockHeader(header *apimiddleware.BeaconBlockHeaderJson) *eth.BeaconBlockHeader {
	return &eth.BeaconBlockHeader{
		Slot:          primitives.Slot(stringToUint64(header.Slot)),
		ProposerIndex: primitives.ValidatorIndex(stringToUint64(header.ProposerIndex)),
		ParentRoot:    common.FromHex(header.ParentRoot),
		StateRoot:     common.FromHex(header.StateRoot),
		BodyRoot:      common.FromHex(header.BodyRoot),
	}
}

func convertToAttestationData(data *apimiddleware.AttestationDataJson) *eth.AttestationData {
	return &eth.AttestationData{
		Slot:            primitives.Slot(stringToUint64(data.Slot)),
		CommitteeIndex:  primitives.CommitteeIndex(stringToUint64(data.CommitteeIndex)),
		BeaconBlockRoot: common.FromHex(data.BeaconBlockRoot),
		Source: &eth.Checkpoint{
			Epoch: primitives.Epoch(stringToUint64(data.Source.Epoch)),
			Root:  common.FromHex(data.Source.Root),
		},
		Target: &eth.Checkpoint{
			Epoch: primitives.Epoch(stringToUint64(data.Target.Epoch)),
			Root:  common.FromHex(data.Target.Root),
		},
	}
}

func stringToUint64(s string) uint64 {
	i, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		panic(e)
	}

	return uint64(i)
}

func stringsToUint64s(ss []string) []uint64 {
	var ret []uint64
	for _, s := range ss {
		i, e := strconv.ParseUint(s, 10, 64)
		if e != nil {
			panic(e)
		}
		ret = append(ret, uint64(i))
	}

	return ret
}

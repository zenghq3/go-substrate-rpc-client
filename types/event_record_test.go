// Go Substrate RPC Client (GSRPC) provides APIs and types around Polkadot and any Substrate-based chain RPC calls
//
// Copyright 2019 Centrifuge GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types_test

import (
	"fmt"
	"math/big"
	"testing"

	. "github.com/zenghq3/go-substrate-rpc-client/types"
	"github.com/stretchr/testify/assert"
)

var examplePhaseApp = Phase{
	IsApplyExtrinsic: true,
	AsApplyExtrinsic: 42,
}

var examplePhaseFin = Phase{
	IsFinalization: true,
}

var exampleEventApp = EventSystemExtrinsicSuccess{
	Phase:        examplePhaseApp,
	DispatchInfo: DispatchInfo{Weight: 10000, Class: DispatchClass{IsNormal: true}, PaysFee: true},
	Topics:       []Hash{{1, 2}},
}

var exampleEventFin = EventSystemExtrinsicSuccess{
	Phase:        examplePhaseFin,
	DispatchInfo: DispatchInfo{Weight: 10000, Class: DispatchClass{IsNormal: true}, PaysFee: true},
	Topics:       []Hash{{1, 2}},
}

var exampleEventAppEnc = []byte{0x0, 0x2a, 0x0, 0x0, 0x0, 0x10, 0x27, 0x0, 0x0, 0x0, 0x1, 0x4, 0x1, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0} //nolint:lll

var exampleEventFinEnc = []byte{0x1, 0x10, 0x27, 0x0, 0x0, 0x0, 0x1, 0x4, 0x1, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0} //nolint:lll

func TestEventSystemExtrinsicSuccess_Encode(t *testing.T) {
	encoded, err := EncodeToBytes(exampleEventFin)
	assert.NoError(t, err)
	assert.Equal(t, exampleEventFinEnc, encoded)

	encoded, err = EncodeToBytes(exampleEventApp)
	assert.NoError(t, err)
	assert.Equal(t, exampleEventAppEnc, encoded)
}

func TestEventSystemExtrinsicSuccess_Decode(t *testing.T) {
	decoded := EventSystemExtrinsicSuccess{}
	err := DecodeFromBytes(exampleEventFinEnc, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, exampleEventFin, decoded)

	decoded = EventSystemExtrinsicSuccess{}
	err = DecodeFromBytes(exampleEventAppEnc, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, exampleEventApp, decoded)
}

func TestEventRecordsRaw_Decode_FailsNumFields(t *testing.T) {
	e := EventRecordsRaw(MustHexDecodeString("0x0400020000000302d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48266d00000000000000000000000000000010a5d4e8000000000000000000000000")) //nolint:lll

	events := struct {
		Balances_Transfer []struct{ Abc uint8 } //nolint:stylecheck,golint
	}{}
	err := e.DecodeEventRecords(ExamplaryMetadataV8, &events)
	assert.EqualError(t, err, "expected event #0 with EventID [3 2], field Balances_Transfer to have at least 2 fields (for Phase and Topics), but has 1 fields") //nolint:lll
}

func TestEventRecordsRaw_Decode_FailsFirstNotPhase(t *testing.T) {
	e := EventRecordsRaw(MustHexDecodeString("0x0400020000000302d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48266d00000000000000000000000000000010a5d4e8000000000000000000000000")) //nolint:lll

	events := struct {
		Balances_Transfer []struct { //nolint:stylecheck,golint
			P     uint8
			Other uint32
			T     []Hash
		}
	}{}
	err := e.DecodeEventRecords(ExamplaryMetadataV8, &events)
	assert.EqualError(t, err, "expected the first field of event #0 with EventID [3 2], field Balances_Transfer to be of type types.Phase, but got uint8") //nolint:lll
}

func TestEventRecordsRaw_Decode_FailsLastNotHash(t *testing.T) {
	e := EventRecordsRaw(MustHexDecodeString("0x0400020000000302d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48266d00000000000000000000000000000010a5d4e8000000000000000000000000")) //nolint:lll

	events := struct {
		Balances_Transfer []struct { //nolint:stylecheck,golint
			P     Phase
			Other uint32
			T     Phase
		}
	}{}
	err := e.DecodeEventRecords(ExamplaryMetadataV8, &events)
	assert.EqualError(t, err, "expected the last field of event #0 with EventID [3 2], field Balances_Transfer to be of type []types.Hash for Topics, but got types.Phase") //nolint:lll
}

func ExampleEventRecordsRaw_Decode() {
	e := EventRecordsRaw(MustHexDecodeString(
		"0x10" +
			"0000000000" +
			"0000" +
			"10270000" + // Weight
			"01" + // Operational
			"01" + // PaysFee
			"00" +

			"0001000000" +
			"0000" +
			"10270000" + // Weight
			"01" + // operational
			"01" + // PaysFee
			"00" +

			"0001000000" + // ApplyExtrinsic(1)
			"0302" + // Balances_Transfer
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d" + // From
			"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48" + // To
			"391b0000000000000000000000000000" + // Value
			"00" + // Topics

			"0002000000" +
			"0000" +
			"10270000" + // Weight
			"00" + // Normal
			"01" + // PaysFee
			"00",
	))

	events := EventRecords{}
	err := e.DecodeEventRecords(ExamplaryMetadataV8, &events)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Got %v System_ExtrinsicSuccess events\n", len(events.System_ExtrinsicSuccess))
	fmt.Printf("Got %v Balances_Transfer events\n", len(events.Balances_Transfer))
	t := events.Balances_Transfer[0]
	fmt.Printf("Transfer: %v tokens from %#x to\n%#x", t.Value, t.From, t.To)

	// Output: Got 3 System_ExtrinsicSuccess events
	// Got 1 Balances_Transfer events
	// Transfer: 6969 tokens from 0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d to
	// 0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48
}

func TestEventRecordsRaw_Decode(t *testing.T) {
	e := EventRecordsRaw(MustHexDecodeString(
		"0x40" + // (len 15) << 2

			"0000000000" + // ApplyExtrinsic(0)
			"0300" + // Balances_Endowed
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d" + // Who
			"676b95d82b0400000000000000000000" + // Balance U128
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0301" + // Balances_DustLost
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d" + // Who
			"676b95d82b0400000000000000000000" + // Balance U128
			"00" + // Topics

			"0001000000" + // ApplyExtrinsic(1)
			"0302" + // Balances_Transfer
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d" + // From
			"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48" + // To
			"391b0000000000000000000000000000" + // Value
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0303" + // Balances_BalanceSet
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d" + // Who
			"676b95d82b0400000000000000000000" + // Free U128
			"676b95d82b0400000000000000000000" + // Reserved U128
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0304" + // Balances_Deposit
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d" + // Who
			"676b95d82b0400000000000000000000" + // Balance U128
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0200" + // Indices_IndexAssigned
			"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48" + // Who
			"39300000" + // AccountIndex
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0201" + // Indices_IndexFreed
			"39300000" + // AccountIndex
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"1000" + // Offences_Offence
			"696d2d6f6e6c696e653a6f66666c696e" + // Kind
			"10c5000000" + // OpaqueTimeSlot
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0400" + // Staking_Reward
			"676b95d82b0400000000000000000000" + // Balance U128
			"00000000000000000000000000000000" + // Remainder U128
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0500" + // Session_NewSession
			"c6000000" + // SessionIndex U32
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0000" + // System_ExtrinsicSuccess
			"10270000" + // Weight
			"01" + // DispatchClass: Operational
			"01" + // PaysFees
			"00" + // Topics

			"0001000000" + // ApplyExtrinsic(1)
			"0000" + // System_ExtrinsicSuccess
			"10270000" + // Weight
			"00" + // DispatchClass: Normal
			"01" + // PaysFees
			"00" + // Topics

			"0002000000" + // ApplyExtrinsic(2)
			"0001" + // System_ExtrinsicFailed
			"01" + // HasModule
			"0b" + // Module
			"00" + // Error
			"10270000" + // Weight
			"01" + // DispatchClass: Operational
			"01" + // PaysFees
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0002" + // System_CodeUpdated
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0003" + // System_NewAccount
			"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48" + // Who
			"00" + // Topics

			"0000000000" + // ApplyExtrinsic(0)
			"0004" + // System_KilledAccount
			"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48" + // Who
			"00", // Topics
	)) //nolint:lll

	events := EventRecords{}
	err := e.DecodeEventRecords(ExamplaryMetadataV11Substrate, &events)
	if err != nil {
		panic(err)
	}

	exp := EventRecords{
		Balances_Endowed:                   []EventBalancesEndowed{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, Who: AccountID{0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x4, 0xa9, 0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d}, Balance: NewU128(*big.NewInt(4586363775847)), Topics: []Hash(nil)}},
		Balances_DustLost:                  []EventBalancesDustLost{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, Who: AccountID{0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x4, 0xa9, 0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d}, Balance: NewU128(*big.NewInt(4586363775847)), Topics: []Hash(nil)}},
		Balances_Transfer:                  []EventBalancesTransfer{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x1, IsFinalization: false}, From: AccountID{0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x4, 0xa9, 0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d}, To: AccountID{0x8e, 0xaf, 0x4, 0x15, 0x16, 0x87, 0x73, 0x63, 0x26, 0xc9, 0xfe, 0xa1, 0x7e, 0x25, 0xfc, 0x52, 0x87, 0x61, 0x36, 0x93, 0xc9, 0x12, 0x90, 0x9c, 0xb2, 0x26, 0xaa, 0x47, 0x94, 0xf2, 0x6a, 0x48}, Value: NewU128(*big.NewInt(6969)), Topics: []Hash(nil)}},
		Balances_BalanceSet:                []EventBalancesBalanceSet{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, Who: AccountID{0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x4, 0xa9, 0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d}, Free: NewU128(*big.NewInt(4586363775847)), Reserved: NewU128(*big.NewInt(4586363775847)), Topics: []Hash(nil)}},
		Balances_Deposit:                   []EventBalancesDeposit{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, Who: AccountID{0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x4, 0xa9, 0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d, 0xa2, 0x7d}, Balance: NewU128(*big.NewInt(4586363775847)), Topics: []Hash(nil)}},
		Grandpa_NewAuthorities:             []EventGrandpaNewAuthorities(nil),
		Grandpa_Paused:                     []EventGrandpaPaused(nil),
		Grandpa_Resumed:                    []EventGrandpaResumed(nil),
		ImOnline_HeartbeatReceived:         []EventImOnlineHeartbeatReceived(nil),
		Indices_IndexAssigned:              []EventIndicesIndexAssigned{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, AccountID: AccountID{0x8e, 0xaf, 0x4, 0x15, 0x16, 0x87, 0x73, 0x63, 0x26, 0xc9, 0xfe, 0xa1, 0x7e, 0x25, 0xfc, 0x52, 0x87, 0x61, 0x36, 0x93, 0xc9, 0x12, 0x90, 0x9c, 0xb2, 0x26, 0xaa, 0x47, 0x94, 0xf2, 0x6a, 0x48}, AccountIndex: AccountIndex(12345), Topics: []Hash(nil)}},
		Indices_IndexFreed:                 []EventIndicesIndexFreed{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, AccountIndex: AccountIndex(12345), Topics: []Hash(nil)}},
		Offences_Offence:                   []EventOffencesOffence{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, Kind: Bytes16{0x69, 0x6d, 0x2d, 0x6f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x3a, 0x6f, 0x66, 0x66, 0x6c, 0x69, 0x6e}, OpaqueTimeSlot: Bytes{0xc5, 0x0, 0x0, 0x0}, Topics: []Hash(nil)}},
		Session_NewSession:                 []EventSessionNewSession{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, SessionIndex: 0xc6, Topics: []Hash(nil)}},
		Staking_OldSlashingReportDiscarded: []EventStakingOldSlashingReportDiscarded(nil),
		Staking_Reward:                     []EventStakingReward{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, Balance: NewU128(*big.NewInt(4586363775847)), Remainder: NewU128(*big.NewInt(0)), Topics: []Hash(nil)}},
		Staking_Slash:                      []EventStakingSlash(nil),
		System_ExtrinsicSuccess:            []EventSystemExtrinsicSuccess{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, DispatchInfo: DispatchInfo{Weight: 10000, Class: DispatchClass{IsOperational: true}, PaysFee: true}, Topics: []Hash(nil)}, {Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x1, IsFinalization: false}, DispatchInfo: DispatchInfo{Weight: 10000, Class: DispatchClass{IsNormal: true}, PaysFee: true}, Topics: []Hash(nil)}},
		System_ExtrinsicFailed:             []EventSystemExtrinsicFailed{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x2, IsFinalization: false}, DispatchError: DispatchError{HasModule: true, Module: 0xb, Error: 0x0}, DispatchInfo: DispatchInfo{Weight: 10000, Class: DispatchClass{IsOperational: true}, PaysFee: true}, Topics: []Hash(nil)}},
		System_CodeUpdated:                 []EventSystemCodeUpdated{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, Topics: []Hash(nil)}},
		System_NewAccount:                  []EventSystemNewAccount{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, Who: AccountID{0x8e, 0xaf, 0x4, 0x15, 0x16, 0x87, 0x73, 0x63, 0x26, 0xc9, 0xfe, 0xa1, 0x7e, 0x25, 0xfc, 0x52, 0x87, 0x61, 0x36, 0x93, 0xc9, 0x12, 0x90, 0x9c, 0xb2, 0x26, 0xaa, 0x47, 0x94, 0xf2, 0x6a, 0x48}, Topics: []Hash(nil)}},
		System_KilledAccount:               []EventSystemKilledAccount{{Phase: Phase{IsApplyExtrinsic: true, AsApplyExtrinsic: 0x0, IsFinalization: false}, Who: AccountID{0x8e, 0xaf, 0x4, 0x15, 0x16, 0x87, 0x73, 0x63, 0x26, 0xc9, 0xfe, 0xa1, 0x7e, 0x25, 0xfc, 0x52, 0x87, 0x61, 0x36, 0x93, 0xc9, 0x12, 0x90, 0x9c, 0xb2, 0x26, 0xaa, 0x47, 0x94, 0xf2, 0x6a, 0x48}, Topics: []Hash(nil)}},
	} //nolint:lll

	assert.Equal(t, exp, events)
}

func TestDispatchError(t *testing.T) {
	assertRoundtrip(t, DispatchError{HasModule: true, Module: 0xf1, Error: 0xa2})
	assertRoundtrip(t, DispatchError{HasModule: false, Error: 0xa2})
}

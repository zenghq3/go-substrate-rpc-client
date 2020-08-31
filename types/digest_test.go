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
	"testing"

	. "github.com/zenghq3/go-substrate-rpc-client/types"
)

func TestDigest_EncodeDecode(t *testing.T) {
	assertRoundtrip(t, Digest{testDigestItem1, testDigestItem2, testDigestItem3})
}

func TestDigest_Encode(t *testing.T) {
	assertEncode(t, []encodingAssert{
		{Digest{testDigestItem1, testDigestItem2, testDigestItem3},
			MustHexDecodeString("0x0c0004ab0108ab00000000000000000000000000000000000000000000000000000000000000cd00000000000000000000000000000000000000000000000000000000000000020102030000000000000000000000000000000000000000000000000000000000")}, //nolint:lll
	})
}

func TestDigest_Decode(t *testing.T) {
	assertDecode(t, []decodingAssert{
		{MustHexDecodeString("0x0c0004ab0108ab00000000000000000000000000000000000000000000000000000000000000cd00000000000000000000000000000000000000000000000000000000000000020102030000000000000000000000000000000000000000000000000000000000"), //nolint:lll
			Digest{testDigestItem1, testDigestItem2, testDigestItem3}},
	})
}

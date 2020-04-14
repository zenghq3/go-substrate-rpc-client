package types

import (
	"errors"
	"fmt"
	"hash"
	"strings"

	blake2 "github.com/centrifuge/go-substrate-rpc-client/crypto/blake2b"
	"github.com/centrifuge/go-substrate-rpc-client/scale"
	"github.com/centrifuge/go-substrate-rpc-client/xxhash"
	"golang.org/x/crypto/blake2b"
)

// Modelled after packages/types/src/Metadata/v10/toV11.ts
type MetadataV11 struct {
	Modules   []ModuleMetadataV11
	Extrinsic ExtrinsicV11
}

func (m *MetadataV11) Decode(decoder scale.Decoder) error {
	err := decoder.Decode(&m.Modules)
	if err != nil {
		return err
	}
	return decoder.Decode(&m.Extrinsic)
}

func (m MetadataV11) Encode(encoder scale.Encoder) error {
	err := encoder.Encode(m.Modules)
	if err != nil {
		return err
	}
	return encoder.Encode(m.Extrinsic)
}

func (m *MetadataV11) FindCallIndex(call string) (CallIndex, error) {
	s := strings.Split(call, ".")
	mi := uint8(0)
	for _, mod := range m.Modules {
		if !mod.HasCalls {
			continue
		}
		if string(mod.Name) != s[0] {
			mi++
			continue
		}
		for ci, f := range mod.Calls {
			if string(f.Name) == s[1] {
				return CallIndex{mi, uint8(ci)}, nil
			}
		}
		return CallIndex{}, fmt.Errorf("method %v not found within module %v for call %v", s[1], mod.Name, call)
	}
	return CallIndex{}, fmt.Errorf("module %v not found in metadata for call %v", s[0], call)
}

func (m *MetadataV11) FindEventNamesForEventID(eventID EventID) (Text, Text, error) {
	mi := uint8(0)
	for _, mod := range m.Modules {
		if !mod.HasEvents {
			continue
		}
		if mi != eventID[0] {
			mi++
			continue
		}
		if int(eventID[1]) >= len(mod.Events) {
			return "", "", fmt.Errorf("event index %v for module %v out of range", eventID[1], mod.Name)
		}
		return mod.Name, mod.Events[eventID[1]].Name, nil
	}
	return "", "", fmt.Errorf("module index %v out of range", eventID[0])
}

func (m *MetadataV11) FindStorageEntryMetadata(module string, fn string) (StorageEntryMetadata, error) {
	for _, mod := range m.Modules {
		if !mod.HasStorage {
			continue
		}
		if string(mod.Storage.Prefix) != module {
			continue
		}
		for _, s := range mod.Storage.Items {
			if string(s.Name) != fn {
				continue
			}
			return s, nil
		}
		return nil, fmt.Errorf("storage %v not found within module %v", fn, module)
	}
	return nil, fmt.Errorf("module %v not found in metadata", module)
}

type ModuleMetadataV11 struct {
	Name       Text
	HasStorage bool
	Storage    StorageMetadataV11
	HasCalls   bool
	Calls      []FunctionMetadataV4
	HasEvents  bool
	Events     []EventMetadataV4
	Constants  []ModuleConstantMetadataV6
	Errors     []ErrorMetadataV8
}

func (m *ModuleMetadataV11) Decode(decoder scale.Decoder) error {
	err := decoder.Decode(&m.Name)
	if err != nil {
		return err
	}

	err = decoder.Decode(&m.HasStorage)
	if err != nil {
		return err
	}

	if m.HasStorage {
		err = decoder.Decode(&m.Storage)
		if err != nil {
			return err
		}
	}

	err = decoder.Decode(&m.HasCalls)
	if err != nil {
		return err
	}

	if m.HasCalls {
		err = decoder.Decode(&m.Calls)
		if err != nil {
			return err
		}
	}

	err = decoder.Decode(&m.HasEvents)
	if err != nil {
		return err
	}

	if m.HasEvents {
		err = decoder.Decode(&m.Events)
		if err != nil {
			return err
		}
	}

	err = decoder.Decode(&m.Constants)
	if err != nil {
		return err
	}

	return decoder.Decode(&m.Errors)
}

func (m ModuleMetadataV11) Encode(encoder scale.Encoder) error {
	err := encoder.Encode(m.Name)
	if err != nil {
		return err
	}

	err = encoder.Encode(m.HasStorage)
	if err != nil {
		return err
	}

	if m.HasStorage {
		err = encoder.Encode(m.Storage)
		if err != nil {
			return err
		}
	}

	err = encoder.Encode(m.HasCalls)
	if err != nil {
		return err
	}

	if m.HasCalls {
		err = encoder.Encode(m.Calls)
		if err != nil {
			return err
		}
	}

	err = encoder.Encode(m.HasEvents)
	if err != nil {
		return err
	}

	if m.HasEvents {
		err = encoder.Encode(m.Events)
		if err != nil {
			return err
		}
	}

	err = encoder.Encode(m.Constants)
	if err != nil {
		return err
	}

	return encoder.Encode(m.Errors)
}

type StorageMetadataV11 struct {
	Prefix Text
	Items  []StorageFunctionMetadataV11
}

type StorageFunctionMetadataV11 struct {
	Name          Text
	Modifier      StorageFunctionModifierV0
	Type          StorageFunctionTypeV11
	Fallback      Bytes
	Documentation []Text
}

func (s StorageFunctionMetadataV11) IsPlain() bool {
	return s.Type.IsType
}

func (s StorageFunctionMetadataV11) IsMap() bool {
	return s.Type.IsMap
}

func (s StorageFunctionMetadataV11) IsDoubleMap() bool {
	return s.Type.IsDoubleMap
}

func (s StorageFunctionMetadataV11) Hasher() (hash.Hash, error) {
	if s.Type.IsMap {
		return s.Type.AsMap.Hasher.HashFunc()
	}
	if s.Type.IsDoubleMap {
		return s.Type.AsDoubleMap.Hasher.HashFunc()
	}
	return xxhash.New128(nil), nil
}

func (s StorageFunctionMetadataV11) Hasher2() (hash.Hash, error) {
	if !s.Type.IsDoubleMap {
		return nil, fmt.Errorf("only DoubleMaps have a Hasher2")
	}
	return s.Type.AsDoubleMap.Key2Hasher.HashFunc()
}

type StorageFunctionTypeV11 struct {
	IsType      bool
	AsType      Type // 0
	IsMap       bool
	AsMap       MapTypeV11 // 1
	IsDoubleMap bool
	AsDoubleMap DoubleMapTypeV11 // 2
}

func (s *StorageFunctionTypeV11) Decode(decoder scale.Decoder) error {
	var t uint8
	err := decoder.Decode(&t)
	if err != nil {
		return err
	}

	switch t {
	case 0:
		s.IsType = true
		err = decoder.Decode(&s.AsType)
		if err != nil {
			return err
		}
	case 1:
		s.IsMap = true
		err = decoder.Decode(&s.AsMap)
		if err != nil {
			return err
		}
	case 2:
		s.IsDoubleMap = true
		err = decoder.Decode(&s.AsDoubleMap)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("received unexpected type %v", t)
	}
	return nil
}

func (s StorageFunctionTypeV11) Encode(encoder scale.Encoder) error {
	switch {
	case s.IsType:
		err := encoder.PushByte(0)
		if err != nil {
			return err
		}
		err = encoder.Encode(s.AsType)
		if err != nil {
			return err
		}
	case s.IsMap:
		err := encoder.PushByte(1)
		if err != nil {
			return err
		}
		err = encoder.Encode(s.AsMap)
		if err != nil {
			return err
		}
	case s.IsDoubleMap:
		err := encoder.PushByte(2)
		if err != nil {
			return err
		}
		err = encoder.Encode(s.AsDoubleMap)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("expected to be either type, map or double map, but none was set: %v", s)
	}
	return nil
}

type MapTypeV11 struct {
	Hasher StorageHasherV11
	Key    Type
	Value  Type
	Linked bool
}

type DoubleMapTypeV11 struct {
	Hasher     StorageHasherV11
	Key1       Type
	Key2       Type
	Value      Type
	Key2Hasher StorageHasherV11
}

// Modelled after packages/types/src/Metadata/v10/toV11.ts
type ExtrinsicV11 struct {
	Version          uint8
	SignedExtensions []string
}

func (e *ExtrinsicV11) Decode(decoder scale.Decoder) error {
	err := decoder.Decode(&e.Version)
	if err != nil {
		return err
	}

	return decoder.Decode(&e.SignedExtensions)
}

func (e ExtrinsicV11) Encode(encoder scale.Encoder) error {
	err := encoder.Encode(e.Version)
	if err != nil {
		return err
	}

	return encoder.Encode(e.SignedExtensions)
}

type StorageHasherV11 struct {
	IsBlake2_128       bool // 0
	IsBlake2_256       bool // 1
	IsBlake2_128Concat bool // 2
	IsTwox128          bool // 3
	IsTwox256          bool // 4
	IsTwox64Concat     bool // 5
	IsIdentity         bool // 6
}

func (s *StorageHasherV11) Decode(decoder scale.Decoder) error {
	var t uint8
	err := decoder.Decode(&t)
	if err != nil {
		return err
	}

	switch t {
	case 0:
		s.IsBlake2_128 = true
	case 1:
		s.IsBlake2_256 = true
	case 2:
		s.IsBlake2_128Concat = true
	case 3:
		s.IsTwox128 = true
	case 4:
		s.IsTwox256 = true
	case 5:
		s.IsTwox64Concat = true
	case 6:
		s.IsIdentity = true
	default:
		return fmt.Errorf("received unexpected storage hasher type %v", t)
	}
	return nil
}

func (s StorageHasherV11) Encode(encoder scale.Encoder) error {
	var t uint8
	switch {
	case s.IsBlake2_128:
		t = 0
	case s.IsBlake2_256:
		t = 1
	case s.IsBlake2_128Concat:
		t = 2
	case s.IsTwox128:
		t = 3
	case s.IsTwox256:
		t = 4
	case s.IsTwox64Concat:
		t = 5
	case s.IsIdentity:
		t = 6
	default:
		return fmt.Errorf("expected storage hasher, but none was set: %v", s)
	}
	return encoder.PushByte(t)
}

func (s StorageHasherV11) HashFunc() (hash.Hash, error) {
	// Blake2_128
	if s.IsBlake2_128 {
		return blake2b.New(16, nil)
	}

	// Blake2_256
	if s.IsBlake2_256 {
		return blake2b.New256(nil)
	}

	// Blake2_128concat
	if s.IsBlake2_128Concat {
		return blake2.New128Concat(nil)
	}

	// Twox128
	if s.IsTwox128 {
		return xxhash.New128(nil), nil
	}

	// Twox256
	if s.IsTwox256 {
		return xxhash.New256(nil), nil
	}

	// Twox64Concat
	if s.IsTwox64Concat {
		return xxhash.New64Concat(nil), nil
	}

	// Identity
	if s.IsIdentity {
		return blake2.New128Concat(nil)
	}

	return nil, errors.New("hash function type not yet supported")
}

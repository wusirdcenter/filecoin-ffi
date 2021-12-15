package ffi

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/specs-actors/actors/runtime/proof"
	"github.com/ipfs/go-cid"
)

// BLS

// SignatureBytes is the length of a BLS signature
const SignatureBytes = 96

// PrivateKeyBytes is the length of a BLS private key
const PrivateKeyBytes = 32

// PublicKeyBytes is the length of a BLS public key
const PublicKeyBytes = 48

// DigestBytes is the length of a BLS message hash/digest
const DigestBytes = 96

// Signature is a compressed affine
type Signature [SignatureBytes]byte

// PrivateKey is a compressed affine
type PrivateKey [PrivateKeyBytes]byte

// PublicKey is a compressed affine
type PublicKey [PublicKeyBytes]byte

// Message is a byte slice
type Message []byte

// Digest is a compressed affine
type Digest [DigestBytes]byte

// Used when generating a private key deterministically
type PrivateKeyGenSeed [32]byte

// Proofs

// SortedPublicSectorInfo is a slice of publicSectorInfo sorted
// (lexicographically, ascending) by sealed (replica) CID.
type SortedPublicSectorInfo struct {
	f []publicSectorInfo
}

// SortedPrivateSectorInfo is a slice of PrivateSectorInfo sorted
// (lexicographically, ascending) by sealed (replica) CID.
type SortedPrivateSectorInfo struct {
	f []PrivateSectorInfo
}

func newSortedPublicSectorInfo(sectorInfo ...publicSectorInfo) SortedPublicSectorInfo {
	fn := func(i, j int) bool {
		return bytes.Compare(sectorInfo[i].SealedCID.Bytes(), sectorInfo[j].SealedCID.Bytes()) == -1
	}

	sort.Slice(sectorInfo[:], fn)

	return SortedPublicSectorInfo{
		f: sectorInfo,
	}
}

// Values returns the sorted publicSectorInfo as a slice
func (s *SortedPublicSectorInfo) Values() []publicSectorInfo {
	return s.f
}

// MarshalJSON JSON-encodes and serializes the SortedPublicSectorInfo.
func (s SortedPublicSectorInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.f)
}

// UnmarshalJSON parses the JSON-encoded byte slice and stores the result in the
// value pointed to by s.f. Note that this method allows for construction of a
// SortedPublicSectorInfo which violates its invariant (that its publicSectorInfo are sorted
// in some defined way). Callers should take care to never provide a byte slice
// which would violate this invariant.
func (s *SortedPublicSectorInfo) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.f)
}

// NewSortedPrivateSectorInfo returns a SortedPrivateSectorInfo
func NewSortedPrivateSectorInfo(sectorInfo ...PrivateSectorInfo) SortedPrivateSectorInfo {
	var remove_duplicate_privSector = make([]PrivateSectorInfo, 0)
	for i := range sectorInfo {
		for j := range remove_duplicate_privSector {
			if !(remove_duplicate_privSector[j].SectorNumber == sectorInfo[i].SectorNumber) {
				remove_duplicate_privSector = append(remove_duplicate_privSector, sectorInfo[i])
			}
		}
	}

	new_sector_len := len(remove_duplicate_privSector)
	if new_sector_len < 2 {
		return SortedPrivateSectorInfo{
			f: remove_duplicate_privSector,
		}
	}

	for i := 0; i < new_sector_len; i++ {
		flag := false
		for j := 0; j < new_sector_len-i-1; j++ {
			if remove_duplicate_privSector[j].SectorNumber > remove_duplicate_privSector[j+1].SectorNumber {
				remove_duplicate_privSector[j], remove_duplicate_privSector[j+1] = remove_duplicate_privSector[j+1], remove_duplicate_privSector[j]
				flag = true
			}
		}
		if !flag {
			break
		}
	}

	return SortedPrivateSectorInfo{
		f: remove_duplicate_privSector,
	}
}

// Values returns the sorted PrivateSectorInfo as a slice
func (s *SortedPrivateSectorInfo) Values() []PrivateSectorInfo {
	return s.f
}

// MarshalJSON JSON-encodes and serializes the SortedPrivateSectorInfo.
func (s SortedPrivateSectorInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.f)
}

func (s *SortedPrivateSectorInfo) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &s.f)
}

type publicSectorInfo struct {
	PoStProofType abi.RegisteredPoStProof
	SealedCID     cid.Cid
	SectorNum     abi.SectorNumber
}

type PrivateSectorInfo struct {
	proof.SectorInfo
	CacheDirPath     string
	PoStProofType    abi.RegisteredPoStProof
	SealedSectorPath string
}

// AllocationManager is an interface that provides Free() capability.
type AllocationManager interface {
	Free()
}

func SplitSortedPrivateSectorInfo(ctx context.Context, sortPrivSectors SortedPrivateSectorInfo, start int, end int) (SortedPrivateSectorInfo, error) {
	var newSortPrivSectors SortedPrivateSectorInfo
	newSortPrivSectors.f = make([]PrivateSectorInfo, 0)
	newSortPrivSectors.f = append(newSortPrivSectors.f, sortPrivSectors.f[start:end]...)

	return newSortPrivSectors, nil
}

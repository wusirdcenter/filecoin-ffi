package ffi

import (
	"encoding/json"
	"os"
	"testing"

	proof5 "github.com/filecoin-project/specs-actors/v5/actors/runtime/proof"
)

func BenchmarkAggregate(b *testing.B) {
	f, err := os.Open("agg1.ndjson")
	if err != nil {
		b.Fatal(err)
	}

	d := json.NewDecoder(f)
	var agg proof5.AggregateSealVerifyProofAndInfos
	err = d.Decode(&agg)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = VerifyAggregateSeals(agg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := VerifyAggregateSeals(agg)
		if !ok {
			b.Fatal(err)
		}
	}
}
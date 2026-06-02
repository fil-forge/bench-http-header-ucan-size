package main

import (
	crand "crypto/rand"
	"fmt"

	"github.com/dustin/go-humanize"
	contentcmds "github.com/fil-forge/libforge/commands/content"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func main() {
	space, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}

	bytes := randomBytes(1024)
	digest, err := mh.Sum(bytes, mh.SHA2_256, -1)
	if err != nil {
		panic(err)
	}

	service, err := did.Parse("did:web:forge.fil.one")
	if err != nil {
		panic(err)
	}

	agent := space

	dlgs := []ucan.Delegation{}

	for range 20 {
		next, err := ed25519.Generate()
		if err != nil {
			panic(err)
		}

		dlg, err := contentcmds.Retrieve.Delegate(
			agent,
			next.DID(),
			space.DID(),
		)
		if err != nil {
			panic(err)
		}
		dlgs = append(dlgs, dlg)

		proofs := []cid.Cid{}
		for _, dlg := range dlgs {
			proofs = append(proofs, dlg.Link())
		}

		inv, err := contentcmds.Retrieve.Invoke(
			next,
			space.DID(),
			&contentcmds.RetrieveArguments{
				Blob: contentcmds.Blob{
					Digest: digest,
				},
				Range: contentcmds.Range{
					Start: 0,
					End:   uint64(len(bytes)),
				},
			},
			invocation.WithAudience(service),
			invocation.WithProofs(proofs...),
		)

		ct := container.New(
			container.WithInvocations(inv),
			container.WithDelegations(dlgs...),
		)

		ctBytes, err := container.Encode(container.Base64Gzip, ct)
		if err != nil {
			panic(err)
		}

		fmt.Printf("X-UCAN-Container: %s\n", string(ctBytes))
		fmt.Printf("Encoding: Base64Gzip\nDelegations: %d\nInvocations: 1\n", len(dlgs))
		fmt.Printf("Size: %s\n", humanize.Bytes(uint64(len(ctBytes))))
		fmt.Println()

		agent = next
	}

}

func randomBytes(size int) []byte {
	bytes := make([]byte, size)
	_, _ = crand.Read(bytes)
	return bytes
}

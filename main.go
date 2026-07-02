package main

import (
	crand "crypto/rand"
	"fmt"

	"github.com/dustin/go-humanize"
	contentcmds "github.com/fil-forge/libforge/commands/content"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// generateSigner produces a UCAN Issuer (a signer bound to a Principal) for the
// named key type. Under the post-PR#30 API a bare ucan.Signer is no longer a
// Principal and has no DID; the identities this benchmark delegates and invokes
// with must be ucan.Issuers, so we construct one via each multikey package's
// GenerateIssuer helper (which pairs a freshly generated signer with its
// did:key). Defaults to ed25519.
//
// Note: the mldsa44 key type is no longer provided by ucantone after the
// Attested Signatures refactor, so only ed25519 (default) and secp256k1 remain.
func generateSigner(name string) (ucan.Issuer, error) {
	switch name {
	case "secp256k1":
		return secp256k1.GenerateIssuer()
	}
	return ed25519.GenerateIssuer()
}

func main() {
	signerName := "ed25519"

	space, err := generateSigner(signerName)
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
		next, err := generateSigner(signerName)
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

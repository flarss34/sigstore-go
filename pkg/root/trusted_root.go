// Copyright 2023 The Sigstore Authors.
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

package root

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"google.golang.org/protobuf/encoding/protojson"
)

const TrustedRootMediaType01 = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

type TrustedRoot struct {
	BaseTrustedMaterial
	trustedRoot             *prototrustroot.TrustedRoot
	rekorLogs               map[string]*TransparencyLog
	fulcioCertAuthorities   []CertificateAuthority
	ctLogs                  map[string]*TransparencyLog
	timestampingAuthorities []CertificateAuthority
}

type CertificateAuthority struct {
	Root                *x509.Certificate
	Intermediates       []*x509.Certificate
	Leaf                *x509.Certificate
	ValidityPeriodStart time.Time
	ValidityPeriodEnd   time.Time
}

type TransparencyLog struct {
	BaseURL             string
	ID                  []byte
	ValidityPeriodStart time.Time
	ValidityPeriodEnd   time.Time
	// This is the hash algorithm used by the Merkle tree
	HashFunc  crypto.Hash
	PublicKey crypto.PublicKey
	// The hash algorithm used during signature creation
	SignatureHashFunc crypto.Hash
}

func (tr *TrustedRoot) TimestampingAuthorities() []CertificateAuthority {
	return tr.timestampingAuthorities
}

func (tr *TrustedRoot) FulcioCertificateAuthorities() []CertificateAuthority {
	return tr.fulcioCertAuthorities
}

func (tr *TrustedRoot) RekorLogs() map[string]*TransparencyLog {
	return tr.rekorLogs
}

func (tr *TrustedRoot) CTLogs() map[string]*TransparencyLog {
	return tr.ctLogs
}

func NewTrustedRootFromProtobuf(protobufTrustedRoot *prototrustroot.TrustedRoot) (trustedRoot *TrustedRoot, err error) {
	if protobufTrustedRoot.GetMediaType() != TrustedRootMediaType01 {
		return nil, fmt.Errorf("unsupported TrustedRoot media type: %s", protobufTrustedRoot.GetMediaType())
	}

	trustedRoot = &TrustedRoot{trustedRoot: protobufTrustedRoot}
	trustedRoot.rekorLogs, err = ParseTransparencyLogs(protobufTrustedRoot.GetTlogs())
	if err != nil {
		return nil, err
	}

	trustedRoot.fulcioCertAuthorities, err = ParseCertificateAuthorities(protobufTrustedRoot.GetCertificateAuthorities())
	if err != nil {
		return nil, err
	}

	trustedRoot.timestampingAuthorities, err = ParseCertificateAuthorities(protobufTrustedRoot.GetTimestampAuthorities())
	if err != nil {
		return nil, err
	}

	trustedRoot.ctLogs, err = ParseTransparencyLogs(protobufTrustedRoot.GetCtlogs())
	if err != nil {
		return nil, err
	}

	return trustedRoot, nil
}

func ParseTransparencyLogs(tlogs []*prototrustroot.TransparencyLogInstance) (transparencyLogs map[string]*TransparencyLog, err error) {
	transparencyLogs = make(map[string]*TransparencyLog)
	for _, tlog := range tlogs {
		if tlog.GetHashAlgorithm() != protocommon.HashAlgorithm_SHA2_256 {
			return nil, fmt.Errorf("unsupported tlog hash algorithm: %s", tlog.GetHashAlgorithm())
		}
		if tlog.GetLogId() == nil {
			return nil, fmt.Errorf("tlog missing log ID")
		}
		if tlog.GetLogId().GetKeyId() == nil {
			return nil, fmt.Errorf("tlog missing log ID key ID")
		}
		encodedKeyID := hex.EncodeToString(tlog.GetLogId().GetKeyId())

		if tlog.GetPublicKey() == nil {
			return nil, fmt.Errorf("tlog missing public key")
		}
		if tlog.GetPublicKey().GetRawBytes() == nil {
			return nil, fmt.Errorf("tlog missing public key raw bytes")
		}

		var hashFunc crypto.Hash
		switch tlog.GetHashAlgorithm() {
		case protocommon.HashAlgorithm_SHA2_256:
			hashFunc = crypto.SHA256
		default:
			return nil, fmt.Errorf("unsupported hash function for the tlog")
		}

		switch tlog.GetPublicKey().GetKeyDetails() {
		case protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256:
			key, err := x509.ParsePKIXPublicKey(tlog.GetPublicKey().GetRawBytes())
			if err != nil {
				return nil, err
			}
			var ecKey *ecdsa.PublicKey
			var ok bool
			if ecKey, ok = key.(*ecdsa.PublicKey); !ok {
				return nil, fmt.Errorf("tlog public key is not ECDSA P256")
			}
			transparencyLogs[encodedKeyID] = &TransparencyLog{
				BaseURL:           tlog.GetBaseUrl(),
				ID:                tlog.GetLogId().GetKeyId(),
				HashFunc:          hashFunc,
				PublicKey:         ecKey,
				SignatureHashFunc: crypto.SHA256,
			}
			if validFor := tlog.GetPublicKey().GetValidFor(); validFor != nil {
				if validFor.GetStart() != nil {
					transparencyLogs[encodedKeyID].ValidityPeriodStart = validFor.GetStart().AsTime()
				} else {
					return nil, fmt.Errorf("tlog missing public key validity period start time")
				}
				if validFor.GetEnd() != nil {
					transparencyLogs[encodedKeyID].ValidityPeriodEnd = validFor.GetEnd().AsTime()
				}
			} else {
				return nil, fmt.Errorf("tlog missing public key validity period")
			}
		default:
			return nil, fmt.Errorf("unsupported tlog public key type: %s", tlog.GetPublicKey().GetKeyDetails())
		}
	}
	return transparencyLogs, nil
}

func ParseCertificateAuthorities(certAuthorities []*prototrustroot.CertificateAuthority) (certificateAuthorities []CertificateAuthority, err error) {
	certificateAuthorities = make([]CertificateAuthority, len(certAuthorities))
	for i, certAuthority := range certAuthorities {
		certificateAuthority, err := ParseCertificateAuthority(certAuthority)
		if err != nil {
			return nil, err
		}
		certificateAuthorities[i] = *certificateAuthority
	}
	return certificateAuthorities, nil
}

func ParseCertificateAuthority(certAuthority *prototrustroot.CertificateAuthority) (certificateAuthority *CertificateAuthority, err error) {
	if certAuthority == nil {
		return nil, fmt.Errorf("CertificateAuthority is nil")
	}
	certChain := certAuthority.GetCertChain()
	if certChain == nil {
		return nil, fmt.Errorf("CertificateAuthority missing cert chain")
	}
	chainLen := len(certChain.GetCertificates())
	if chainLen < 1 {
		return nil, fmt.Errorf("CertificateAuthority cert chain is empty")
	}

	certificateAuthority = &CertificateAuthority{}
	for i, cert := range certChain.GetCertificates() {
		parsedCert, err := x509.ParseCertificate(cert.RawBytes)
		if err != nil {
			return nil, err
		}
		switch {
		case i == 0 && !parsedCert.IsCA:
			certificateAuthority.Leaf = parsedCert
		case i < chainLen-1:
			certificateAuthority.Intermediates = append(certificateAuthority.Intermediates, parsedCert)
		case i == chainLen-1:
			certificateAuthority.Root = parsedCert
		}
	}
	validFor := certAuthority.GetValidFor()
	if validFor != nil {
		start := validFor.GetStart()
		if start != nil {
			certificateAuthority.ValidityPeriodStart = start.AsTime()
		}
		end := validFor.GetEnd()
		if end != nil {
			certificateAuthority.ValidityPeriodEnd = end.AsTime()
		}
	}

	// TODO: Should we inspect/enforce ca.Subject and ca.Uri?
	// TODO: Handle validity period (ca.ValidFor)

	return certificateAuthority, nil
}

func NewTrustedRootFromPath(path string) (*TrustedRoot, error) {
	trustedrootJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return NewTrustedRootFromJSON(trustedrootJSON)
}

// NewTrustedRootFromJSON returns the Sigstore trusted root.
func NewTrustedRootFromJSON(rootJSON []byte) (*TrustedRoot, error) {
	pbTrustedRoot, err := NewTrustedRootProtobuf(rootJSON)
	if err != nil {
		return nil, err
	}

	return NewTrustedRootFromProtobuf(pbTrustedRoot)
}

// NewTrustedRootProtobuf returns the Sigstore trusted root as a protobuf.
func NewTrustedRootProtobuf(rootJSON []byte) (*prototrustroot.TrustedRoot, error) {
	pbTrustedRoot := &prototrustroot.TrustedRoot{}
	err := protojson.Unmarshal(rootJSON, pbTrustedRoot)
	if err != nil {
		return nil, err
	}
	return pbTrustedRoot, nil
}

// FetchTrustedRoot fetches the Sigstore trusted root from TUF and returns it.
func FetchTrustedRoot() (*TrustedRoot, error) {
	return FetchTrustedRootWithOptions(tuf.DefaultOptions())
}

// FetchTrustedRootWithOptions fetches the trusted root from TUF with the given options and returns it.
func FetchTrustedRootWithOptions(opts *tuf.Options) (*TrustedRoot, error) {
	client, err := tuf.New(opts)
	if err != nil {
		return nil, err
	}
	return GetTrustedRoot(client)
}

// GetTrustedRoot returns the trusted root
func GetTrustedRoot(c *tuf.Client) (*TrustedRoot, error) {
	jsonBytes, err := c.GetTarget("trusted_root.json")
	if err != nil {
		return nil, err
	}
	return NewTrustedRootFromJSON(jsonBytes)
}

// LiveTrustedRoot is a wrapper around TrustedRoot that periodically
// refreshes the trusted root from TUF. This is needed for long-running
// processes to ensure that the trusted root does not expire.
type LiveTrustedRoot struct {
	*TrustedRoot
	mu sync.RWMutex
}

// NewLiveTrustedRoot returns a LiveTrustedRoot that will periodically
// refresh the trusted root from TUF.
func NewLiveTrustedRoot(opts *tuf.Options) (*LiveTrustedRoot, error) {
	client, err := tuf.New(opts)
	if err != nil {
		return nil, err
	}
	tr, err := GetTrustedRoot(client)
	if err != nil {
		return nil, err
	}
	ltr := &LiveTrustedRoot{
		TrustedRoot: tr,
		mu:          sync.RWMutex{},
	}
	ticker := time.NewTicker(time.Hour * 24)
	go func() {
		for {
			select {
			case <-ticker.C:
				client, err = tuf.New(opts)
				if err != nil {
					log.Printf("error creating TUF client: %v", err)
				}
				newTr, err := GetTrustedRoot(client)
				if err != nil {
					log.Printf("error fetching trusted root: %v", err)
					continue
				}
				ltr.mu.Lock()
				ltr.TrustedRoot = newTr
				ltr.mu.Unlock()
			}
		}
	}()
	return ltr, nil
}

func (l *LiveTrustedRoot) TimestampingAuthorities() []CertificateAuthority {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.TrustedRoot.TimestampingAuthorities()
}

func (l *LiveTrustedRoot) FulcioCertificateAuthorities() []CertificateAuthority {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.TrustedRoot.FulcioCertificateAuthorities()
}

func (l *LiveTrustedRoot) RekorLogs() map[string]*TransparencyLog {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.TrustedRoot.RekorLogs()
}

func (l *LiveTrustedRoot) CTLogs() map[string]*TransparencyLog {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.TrustedRoot.CTLogs()
}

func (l *LiveTrustedRoot) PublicKeyVerifier(keyID string) (TimeConstrainedVerifier, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.TrustedRoot.PublicKeyVerifier(keyID)
}

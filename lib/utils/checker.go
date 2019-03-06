/*
Copyright 2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"crypto/rsa"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/trace"
)

type CertChecker struct {
	ssh.CertChecker
}

func (c *CertChecker) Authenticate(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	err := validate(key)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return c.CertChecker.Authenticate(conn, key)
}
func (c *CertChecker) CheckCert(principal string, cert *ssh.Certificate) error {
	err := validate(cert)
	if err != nil {
		return trace.Wrap(err)
	}

	return c.CertChecker.CheckCert(principal, cert)
}

func (c *CertChecker) CheckHostKey(addr string, remote net.Addr, key ssh.PublicKey) error {
	err := validate(key)
	if err != nil {
		return trace.Wrap(err)
	}

	return c.CertChecker.CheckHostKey(addr, remote, key)
}

func validate(key ssh.PublicKey) error {
	switch cert := key.(type) {
	case *ssh.Certificate:
		err := validateAlgorithm(cert.Key)
		if err != nil {
			return trace.Wrap(err)
		}
		err = validateAlgorithm(cert.SignatureKey)
		if err != nil {
			return trace.Wrap(err)
		}
		return nil
	default:
		return validateAlgorithm(key)
	}
}

func validateAlgorithm(key ssh.PublicKey) error {
	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return trace.BadParameter("unable to determine underlying public key")
	}
	k, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return trace.BadParameter("only RSA keys supported")
	}
	if k.N.BitLen() != 2048 {
		return trace.BadParameter("found %v-bit key, only 2048-bit supported", k.N.BitLen())
	}

	return nil
}

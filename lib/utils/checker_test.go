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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/ssh"

	"gopkg.in/check.v1"
)

type CheckerSuite struct{}

var _ = fmt.Printf
var _ = check.Suite(&CheckerSuite{})

// TestValidate makes sure the public key is a valid algorithm
// that Teleport supports.
func (s *CheckerSuite) TestValidate(c *check.C) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, check.IsNil)
	smallRSAKey, err := rsa.GenerateKey(rand.Reader, 1024)
	c.Assert(err, check.IsNil)
	ellipticKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, check.IsNil)

	// 2048-bit RSA keys are valid.
	cryptoKey := rsaKey.Public()
	sshKey, err := ssh.NewPublicKey(cryptoKey)
	c.Assert(err, check.IsNil)
	ok := validate(sshKey)
	c.Assert(ok, check.Equals, true)

	// 1024-bit RSA keys are not valid.
	cryptoKey = smallRSAKey.Public()
	sshKey, err = ssh.NewPublicKey(cryptoKey)
	c.Assert(err, check.IsNil)
	ok = validate(sshKey)
	c.Assert(ok, check.Equals, false)

	// ECDSA keys are not valid.
	cryptoKey = ellipticKey.Public()
	sshKey, err = ssh.NewPublicKey(cryptoKey)
	c.Assert(err, check.IsNil)
	ok = validate(sshKey)
	c.Assert(ok, check.Equals, false)
}

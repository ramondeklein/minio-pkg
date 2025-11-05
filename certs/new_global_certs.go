// Copyright (c) 2015-2022 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package certs

import (
	"crypto/tls"
	"path/filepath"
	"sync"
)

var (
	globalCerts     map[string]*Certificate2
	globalCertsLock sync.Mutex
)

func globalCertificate(certFile, keyFile string) (*Certificate2, error) {
	var err error
	certFile, err = filepath.Abs(certFile)
	if err != nil {
		return nil, err
	}
	keyFile, err = filepath.Abs(keyFile)
	if err != nil {
		return nil, err
	}
	key := certFile + "|" + keyFile
	globalCertsLock.Lock()
	defer globalCertsLock.Unlock()
	if globalCerts == nil {
		globalCerts = make(map[string]*Certificate2)
	} else if c, ok := globalCerts[key]; ok {
		return c, nil
	}
	c, err := NewCertificate2(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	globalCerts[key] = c
	return c, nil
}

// GetClientCertificate returns a function that returns the given
// certificate/key pair for use in tls.Config.ClientCertificate.
func GetClientCertificate(certFile, keyFile string) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	cert, err := globalCertificate(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return cert.Load(), nil
	}, nil
}

// GetCertificate returns a function that returns the given
// certificate/key pair for use in tls.Config.GetCertificate.
func GetCertificate(certFile, keyFile string) (func(*tls.ClientHelloInfo) (*tls.Certificate, error), error) {
	cert, err := globalCertificate(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return cert.Load(), nil
	}, nil
}

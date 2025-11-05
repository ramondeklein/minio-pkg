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
	"crypto/x509"
	"errors"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// Manager2 manages TLS certificates and automatically reloads them
// when the underlying files change or a SIGHUP signal is received.
type Manager2 struct {
	closed int32
	close  chan<- struct{}
	certs  atomic.Pointer[[]*Certificate2]
}

// NewManager2 creates a new certificate manager which loads certificates
// using the provided loadCerts function. The manager will automatically
// update the loaded certificates when:
//   - The underlying file changed (reloads a single certificate)
//   - A SIGHUP signal is received (this will rescan all certificates)
//
// The manager is using internal synchronization and is safe for concurrent
// use. Make sure to call Close when the manager is no longer needed.
func NewManager2(loadCerts func() ([]*Certificate2, error)) (*Manager2, error) {
	// Load initial certificates
	certs, err := loadCerts()
	if err != nil {
		return nil, err
	}

	closeCh := make(chan struct{})

	mgr := Manager2{
		close: closeCh,
	}
	mgr.certs.Store(&certs)

	replaceCerts := func(newCerts []*Certificate2) {
		oldCerts := mgr.certs.Swap(&newCerts)
		for i := range *oldCerts {
			(*oldCerts)[i].Close()
		}
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)

		for {
			select {
			case <-closeCh:
				// clear certificates on close
				replaceCerts([]*Certificate2{})
				return
			case <-ch:
				certs, err := loadCerts()
				if err != nil {
					log.Printf("reloading certificates failed: %s", err)
				} else {
					replaceCerts(certs)
				}
			}
		}
	}()

	return &mgr, nil
}

// Close stops the certificate manager and releases all resources.
func (m *Manager2) Close() {
	// only close once
	if atomic.CompareAndSwapInt32(&m.closed, 0, 1) {
		close(m.close)
	}
}

// GetCertificate returns a TLS certificate based on the client hello.
//
// It tries to find a certificate that would be accepted by the client
// according to the client hello. However, if no certificate can be
// found GetCertificate returns the first certificate as the "default"
func (m *Manager2) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m == nil {
		return nil, errors.New("certs: no server certificate is supported by peer")
	}

	certs := m.certs.Load()
	switch len(*certs) {
	case 0:
		// No certificates available
		return nil, errors.New("certs: no server certificate is supported by peer")
	case 1:
		// Optimization: If there is just one certificate, always serve that one.
		return (*certs)[0].Load(), nil
	}

	// If the client does not send a SNI we return the "default"
	// certificate. A client may not send a SNI - e.g. when trying
	// to connect to an IP directly (https://<ip>:<port>).
	//
	// In this case we don't know which the certificate the client
	// asks for. It may be a public-facing certificate issued by a
	// public CA or an internal certificate containing internal domain
	// names.
	// Now, we should not serve "the first" certificate that would be
	// accepted by the client based on the Client Hello. Otherwise, we
	// may expose an internal certificate to the client that contains
	// internal domain names. That way we would disclose internal
	// infrastructure details.
	//
	// Therefore, we serve the "default" certificate - which by convention
	// is the first certificate added to the Manager. It's the calling code's
	// responsibility to ensure that the "public-facing" certificate is used
	// when creating a Manager instance.
	if hello.ServerName == "" {
		return (*certs)[0].Load(), nil
	}

	// Iterate over all certificates and return the first one that would
	// be accepted by the peer (TLS client) based on the client hello.
	// In particular, the client usually specifies the requested host/domain
	// via SNI.
	//
	// Note: The certificate.Leaf should be non-nil and contain the actual
	// client certificate of MinIO that should be presented to the peer (TLS client).
	// Otherwise, the leaf certificate has to be parsed again - which is kind of
	// expensive and may cause a performance issue. For more information, check the
	// docs of tls.ClientHelloInfo.SupportsCertificate.
	for i := range *certs {
		cert := (*certs)[i].Load()
		if err := hello.SupportsCertificate(cert); err == nil {
			return cert, nil
		}
	}

	// Return default certificate if nothing matched
	return (*certs)[0].Load(), nil
}

// GetClientCertificate returns a TLS certificate for mTLS based on the
// certificate request.
//
// It tries to find a certificate that would be accepted by the server
// according to the certificate request. However, if no certificate can be
// found GetClientCertificate returns the certificate loaded from the
// Public file.
func (m *Manager2) GetClientCertificate(reqInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if m == nil {
		return nil, errors.New("certs: no client certificate is supported by peer")
	}

	certs := m.certs.Load()
	switch len(*certs) {
	case 0:
		// No certificates available
		return nil, errors.New("certs: no client certificate is supported by peer")
	case 1:
		// Optimization: If there is just one certificate, always serve that one.
		return (*certs)[0].Load(), nil
	}

	// Iterate over all certificates and return the first one that would
	// be accepted by the peer (TLS server) based on reqInfo.
	//
	// Note: The certificate.Leaf should be non-nil and contain the actual
	// client certificate of MinIO that should be presented to the peer (TLS server).
	// Otherwise, the leaf certificate has to be parsed again - which is kind of
	// expensive and may cause a performance issue. For more information, check the
	// docs of tls.CertificateRequestInfo.SupportsCertificate.
	for i := range *certs {
		cert := (*certs)[i].Load()
		if err := reqInfo.SupportsCertificate(cert); err == nil {
			return cert, nil
		}
	}

	return nil, errors.New("certs: no client certificate is supported by peer")
}

// GetAllCertificates returns all the certificates loaded
func (m *Manager2) GetAllCertificates() []*x509.Certificate {
	if m == nil {
		return nil
	}

	certs := m.certs.Load()
	result := make([]*x509.Certificate, 0, len(*certs))
	for i := range *certs {
		c := *((*certs)[i].Load())
		if c.Leaf != nil {
			// marshal and parse to create a deep copy
			cBytes := c.Leaf.Raw
			cert, err := x509.ParseCertificate(cBytes)
			if err != nil {
				continue
			}
			result = append(result, cert)
		}
	}
	return result
}

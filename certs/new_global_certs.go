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

func globalCertificate(certFile, keyFile string) (*tls.Certificate, error) {
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
		return c.Load(), nil
	}
	c, err := NewCertificate2(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	globalCerts[key] = c
	return c.Load(), nil
}

// GetClientCertificate returns a function that returns the given
// certificate/key pair for use in tls.Config.ClientCertificate.
func GetClientCertificate(certFile, keyFile string) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	cert, err := globalCertificate(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return cert, nil
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
		return cert, nil
	}, nil
}

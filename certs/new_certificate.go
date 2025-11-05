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
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/rjeczalik/notify"
)

var symlinkReloadInterval = 10 * time.Second

// Certificate2 wraps a tls.Certificate and automatically reloads it
// when the underlying files change.
type Certificate2 struct {
	atomic.Pointer[tls.Certificate]
	close func()
}

// NewCertificate2 creates a new Certificate which watches the given certFile
// and keyFile for changes and reloads them automatically.
func NewCertificate2(certFile, keyFile string) (*Certificate2, error) {
	return loadCertificatePair(certFile, keyFile)
}

// Close stops watching the certificate files and releases all resources.
func (c *Certificate2) Close() {
	if c.close != nil {
		c.close()
	}
}

func loadCertificatePair(certFile, keyFile string) (*Certificate2, error) {
	cert, err := loadTLSCertificate(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	ch := make(chan notify.EventInfo, 1)
	ctx, cancel := context.WithCancel(context.Background())
	watchFile(ctx, certFile, ch)
	if keyFile != "" {
		watchFile(ctx, keyFile, ch)
	}

	c := Certificate2{
		close: func() {
			notify.Stop(ch)
			close(ch)
			cancel()
		},
	}
	c.Store(&cert)

	go func() {
		for range ch {
			newCert, err := loadTLSCertificate(certFile, keyFile)
			if err != nil {
				if keyFile != "" {
					log.Printf("reloading certificate %s and key %s failed: %s", certFile, keyFile, err)
				} else {
					log.Printf("reloading certificate %s failed: %s", certFile, err)
				}
				continue
			}
			c.Store(&newCert)
		}
	}()
	return &c, nil
}

func loadTLSCertificate(certFile, keyFile string) (tls.Certificate, error) {
	if keyFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	var cert tls.Certificate
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return cert, err
	}
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return cert, fmt.Errorf("no CERTIFICATE blocks in %s", certFile)
	}
	return cert, nil
}

func watchFile(ctx context.Context, path string, c chan notify.EventInfo) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	symLink := st.Mode()&os.ModeSymlink == os.ModeSymlink
	if !symLink {
		return notify.Watch(path, c, notify.InCloseWrite)
	}

	hashFile := func() ([]byte, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		h := md5.New()
		_, err = io.Copy(h, f)
		if err != nil {
			return nil, err
		}
		return h.Sum(nil), nil
	}

	lastHash, err := hashFile()
	if err != nil {
		return err
	}

	go func() {
		t := time.NewTicker(symlinkReloadInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				newHash, err := hashFile()
				if err == nil && !bytes.Equal(lastHash, newHash) {
					lastHash = newHash
					c <- eventInfo{path, notify.Write}
				}
			}
		}
	}()
	return nil
}

type eventInfo struct {
	path  string
	event notify.Event
}

func (e eventInfo) Event() notify.Event { return e.event }
func (e eventInfo) Path() string        { return e.path }
func (e eventInfo) Sys() interface{}    { return nil }

package acme

import (
	"crypto/tls"
	"sync"

	"crypto/x509"
	"github.com/containous/traefik/cluster"
	"github.com/xenolf/lego/acme"
)

var _ acme.ChallengeProvider = (*challengeProvider)(nil)

type challengeProvider struct {
	store cluster.Store
	lock  sync.RWMutex
}

func newMemoryChallengeProvider(store cluster.Store) *challengeProvider {
	return &challengeProvider{
		store: store,
	}
}

func (c *challengeProvider) getCertificate(domain string) (cert *tls.Certificate, exists bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	account := c.store.Get().(*Account)
	if cert, ok := account.ChallengeCerts[domain]; ok {
		return cert, true
	}
	return nil, false
}

func (c *challengeProvider) Present(domain, token, keyAuth string) error {
	cert, _, err := acme.TLSSNI01ChallengeCert(keyAuth)
	if err != nil {
		return err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	transaction, err := c.store.Begin()
	if err != nil {
		return err
	}
	account := c.store.Get().(*Account)
	for i := range cert.Leaf.DNSNames {
		account.ChallengeCerts[cert.Leaf.DNSNames[i]] = &cert
	}
	return transaction.Commit(account)
}

func (c *challengeProvider) CleanUp(domain, token, keyAuth string) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	transaction, err := c.store.Begin()
	if err != nil {
		return err
	}
	account := c.store.Get().(*Account)
	delete(account.ChallengeCerts, domain)
	return transaction.Commit(account)
}

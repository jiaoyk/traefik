package acme

import (
	"crypto/tls"
	"sync"

	"crypto/x509"
	"encoding/json"
	"github.com/containous/traefik/cluster"
	"github.com/xenolf/lego/acme"
	"time"
)

var _ acme.ChallengeProviderTimeout = (*challengeProvider)(nil)

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
	log.Debugf("Challenge GetCertificate %s", domain)
	c.lock.RLock()
	defer c.lock.RUnlock()
	account := c.store.Get().(*Account)
	if account.ChallengeCerts == nil {
		return nil, false
	}
	if certBinary, ok := account.ChallengeCerts[domain]; ok {
		cert := &tls.Certificate{}
		err := json.Unmarshal(certBinary, cert)
		if err != nil {
			log.Errorf("Error unmarshaling challenge cert %s", err.Error())
			return nil, false
		}
		return cert, true
	}
	return nil, false
}

func (c *challengeProvider) Present(domain, token, keyAuth string) error {
	log.Debugf("Challenge Present %s", domain)
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
	if account.ChallengeCerts == nil {
		account.ChallengeCerts = map[string][]byte{}
	}
	for i := range cert.Leaf.DNSNames {
		account.ChallengeCerts[cert.Leaf.DNSNames[i]], err = json.Marshal(&cert)
		if err != nil {
			return err
		}
	}
	return transaction.Commit(account)
}

func (c *challengeProvider) CleanUp(domain, token, keyAuth string) error {
	log.Debugf("Challenge CleanUp %s", domain)
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

func (c *challengeProvider) Timeout() (timeout, interval time.Duration) {
	return 60 * time.Second, 5 * time.Second
}

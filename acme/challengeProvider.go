package acme

import (
	"crypto/tls"
	"sync"

	"crypto/x509"
	"github.com/containous/traefik/cluster"
	"github.com/containous/traefik/log"
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
	if challenge, ok := account.ChallengeCerts[domain]; ok {
		cert, err := tls.X509KeyPair(challenge.Certificate, challenge.PrivateKey)
		if err != nil {
			log.Errorf("Error loading challenge cert %s", err.Error())
			return nil, false
		}
		return &cert, true
	}
	return nil, false
}

func (c *challengeProvider) Present(domain, token, keyAuth string) error {
	log.Debugf("Challenge Present %s", domain)
	cert, _, err := TLSSNI01ChallengeCert(keyAuth)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.certificate.Certificate[0])
	if err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	transaction, object, err := c.store.Begin()
	if err != nil {
		return err
	}
	account := object.(*Account)
	if account.ChallengeCerts == nil {
		account.ChallengeCerts = map[string]ChallengeCert{}
	}
	for i := range leaf.DNSNames {
		account.ChallengeCerts[leaf.DNSNames[i]] = cert
		log.Debugf("Challenge Present cert: %s", leaf.DNSNames[i])
	}
	return transaction.Commit(account)
}

func (c *challengeProvider) CleanUp(domain, token, keyAuth string) error {
	log.Debugf("Challenge CleanUp %s", domain)
	c.lock.Lock()
	defer c.lock.Unlock()
	transaction, object, err := c.store.Begin()
	if err != nil {
		return err
	}
	account := object.(*Account)
	delete(account.ChallengeCerts, domain)
	return transaction.Commit(account)
}

func (c *challengeProvider) Timeout() (timeout, interval time.Duration) {
	return 60 * time.Second, 5 * time.Second
}

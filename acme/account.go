package acme

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/xenolf/lego/acme"
	"reflect"
	"strings"
	"sync"
	"time"
)

// Account is used to store lets encrypt registration info
type Account struct {
	Email              string
	Registration       []byte
	PrivateKey         []byte
	DomainsCertificate DomainsCertificates
	ChallengeCerts     map[string]*tls.Certificate
	registration       *acme.RegistrationResource
}

// GetEmail returns email
func (a Account) GetEmail() string {
	return a.Email
}

// GetRegistration returns lets encrypt registration resource
func (a Account) GetRegistration() *acme.RegistrationResource {
	if a.registration != nil {
		return a.registration
	}
	reg := &acme.RegistrationResource{}
	json.NewDecoder(strings.NewReader(string(a.Registration))).Decode(reg)
	fmt.Printf("GetRegistration: %+v\n", reg)
	return reg
}

// GetPrivateKey returns private key
func (a Account) GetPrivateKey() crypto.PrivateKey {
	if privateKey, err := x509.ParsePKCS1PrivateKey(a.PrivateKey); err == nil {
		return privateKey
	}
	log.Errorf("Cannot unmarshall private key %+v", a.PrivateKey)
	return nil
}

// Certificate is used to store certificate info
type Certificate struct {
	Domain        string
	CertURL       string
	CertStableURL string
	PrivateKey    []byte
	Certificate   []byte
}

// DomainsCertificates stores a certificate for multiple domains
type DomainsCertificates struct {
	Certs []*DomainsCertificate
	lock  *sync.RWMutex
}

func (dc *DomainsCertificates) Init() error {
	if dc.lock == nil {
		dc.lock = &sync.RWMutex{}
	}
	dc.lock.Lock()
	defer dc.lock.Unlock()
	for _, domainsCertificate := range dc.Certs {
		tlsCert, err := tls.X509KeyPair(domainsCertificate.Certificate.Certificate, domainsCertificate.Certificate.PrivateKey)
		if err != nil {
			return err
		}
		domainsCertificate.tlsCert = &tlsCert
	}
	return nil
}

func (dc *DomainsCertificates) renewCertificates(acmeCert *Certificate, domain Domain) error {
	dc.lock.Lock()
	defer dc.lock.Unlock()

	for _, domainsCertificate := range dc.Certs {
		if reflect.DeepEqual(domain, domainsCertificate.Domains) {
			tlsCert, err := tls.X509KeyPair(acmeCert.Certificate, acmeCert.PrivateKey)
			if err != nil {
				return err
			}
			domainsCertificate.Certificate = acmeCert
			domainsCertificate.tlsCert = &tlsCert
			return nil
		}
	}
	return errors.New("Certificate to renew not found for domain " + domain.Main)
}

func (dc *DomainsCertificates) addCertificateForDomains(acmeCert *Certificate, domain Domain) (*DomainsCertificate, error) {
	dc.lock.Lock()
	defer dc.lock.Unlock()

	tlsCert, err := tls.X509KeyPair(acmeCert.Certificate, acmeCert.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := DomainsCertificate{Domains: domain, Certificate: acmeCert, tlsCert: &tlsCert}
	dc.Certs = append(dc.Certs, &cert)
	return &cert, nil
}

func (dc *DomainsCertificates) getCertificateForDomain(domainToFind string) (*DomainsCertificate, bool) {
	dc.lock.RLock()
	defer dc.lock.RUnlock()
	for _, domainsCertificate := range dc.Certs {
		domains := []string{}
		domains = append(domains, domainsCertificate.Domains.Main)
		domains = append(domains, domainsCertificate.Domains.SANs...)
		for _, domain := range domains {
			if domain == domainToFind {
				return domainsCertificate, true
			}
		}
	}
	return nil, false
}

func (dc *DomainsCertificates) exists(domainToFind Domain) (*DomainsCertificate, bool) {
	dc.lock.RLock()
	defer dc.lock.RUnlock()
	for _, domainsCertificate := range dc.Certs {
		if reflect.DeepEqual(domainToFind, domainsCertificate.Domains) {
			return domainsCertificate, true
		}
	}
	return nil, false
}

// DomainsCertificate contains a certificate for multiple domains
type DomainsCertificate struct {
	Domains     Domain
	Certificate *Certificate
	tlsCert     *tls.Certificate
}

func (dc *DomainsCertificate) needRenew() bool {
	for _, c := range dc.tlsCert.Certificate {
		crt, err := x509.ParseCertificate(c)
		if err != nil {
			// If there's an error, we assume the cert is broken, and needs update
			return true
		}
		// <= 7 days left, renew certificate
		if crt.NotAfter.Before(time.Now().Add(time.Duration(24 * 7 * time.Hour))) {
			return true
		}
	}

	return false
}

package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/containous/staert"
	"github.com/containous/traefik/cluster"
	"github.com/containous/traefik/safe"
	"github.com/xenolf/lego/acme"
	"io/ioutil"
	fmtlog "log"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/containous/traefik/safe"
	"github.com/xenolf/lego/acme"
)


// ACME allows to connect to lets encrypt and retrieve certs
type ACME struct {
	Email               string   `description:"Email address used for registration"`
	Domains             []Domain `description:"SANs (alternative domains) to each main domain using format: --acme.domains='main.com,san1.com,san2.com' --acme.domains='main.net,san1.net,san2.net'"`
	Storage             string   `description:"File or key used for certificates storage."`
	OnDemand            bool     `description:"Enable on demand certificate. This will request a certificate from Let's Encrypt during the first TLS handshake for a hostname that does not yet have a certificate."`
	OnHostRule          bool     `description:"Enable certificate generation on frontends Host rules."`
	CAServer            string   `description:"CA server to use."`
	EntryPoint          string   `description:"Entrypoint to proxy acme challenge to."`
	client              *acme.Client
	defaultCertificate  *tls.Certificate
	store               cluster.Store
	challengeProvider   *challengeProvider
	checkOnDemandDomain func(domain string) bool
}

//Domains parse []Domain
type Domains []Domain

//Set []Domain
func (ds *Domains) Set(str string) error {
	fargs := func(c rune) bool {
		return c == ',' || c == ';'
	}
	// get function
	slice := strings.FieldsFunc(str, fargs)
	if len(slice) < 1 {
		return fmt.Errorf("Parse error ACME.Domain. Imposible to parse %s", str)
	}
	d := Domain{
		Main: slice[0],
		SANs: []string{},
	}
	if len(slice) > 1 {
		d.SANs = slice[1:]
	}
	*ds = append(*ds, d)
	return nil
}

//Get []Domain
func (ds *Domains) Get() interface{} { return []Domain(*ds) }

//String returns []Domain in string
func (ds *Domains) String() string { return fmt.Sprintf("%+v", *ds) }

//SetValue sets []Domain into the parser
func (ds *Domains) SetValue(val interface{}) {
	*ds = Domains(val.([]Domain))
}

// Domain holds a domain name with SANs
type Domain struct {
	Main string
	SANs []string
}

func (a *ACME) init() error {
	acme.Logger = fmtlog.New(ioutil.Discard, "", 0)
	log.Debugf("Generating default certificate...")
	// no certificates in TLS config, so we add a default one
	cert, err := generateDefaultCertificate()
	if err != nil {
		return err
	}
	a.defaultCertificate = cert
	return nil
}

// CreateClusterConfig creates a tls.config using ACME configuration in cluster mode
func (a *ACME) CreateClusterConfig(kvSource staert.KvSource, leadership *cluster.Leadership, pool *safe.Pool, tlsConfig *tls.Config, checkOnDemandDomain func(domain string) bool) error {
	err := a.init()
	if err != nil {
		return err
	}
	if len(a.Storage) == 0 {
		return errors.New("Empty Store, please provide a filename/key for certs storage")
	}
	a.checkOnDemandDomain = checkOnDemandDomain
	tlsConfig.Certificates = append(tlsConfig.Certificates, *a.defaultCertificate)
	tlsConfig.GetCertificate = a.getCertificate

	kvSource.Prefix += "/acme/account"
	a.store, err = cluster.NewDataStore(kvSource, pool.Ctx(), &Account{})
	if err != nil {
		return err
	}
	a.challengeProvider = newMemoryChallengeProvider(a.store)

	var needRegister bool
	var account *Account

	// load account
	account = a.store.Get().(*Account)

	if account == nil || len(account.Email) == 0 {
		log.Infof("Generating ACME Account...")
		account, err = a.generateAccount()
		if err != nil {
			return err
		}
		needRegister = true
	}

	a.client, err = a.buildACMEClient()
	if err != nil {
		return err
	}

	if needRegister {
		// New users will need to register; be sure to save it
		reg, err := a.client.Register()
		if err != nil {
			return err
		}
		account.Registration = reg
	}

	// The client has a URL to the current Let's Encrypt Subscriber
	// Agreement. The user will need to agree to it.
	err = a.client.AgreeToTOS()
	if err != nil {
		return err
	}

	safe.Go(func() {
		a.retrieveCertificates()
		if err := a.renewCertificates(); err != nil {
			log.Errorf("Error renewing ACME certificate %+v: %s", account, err.Error())
		}
	})

	ticker := time.NewTicker(24 * time.Hour)
	safe.Go(func() {
		for range ticker.C {
			if err := a.renewCertificates(); err != nil {
				log.Errorf("Error renewing ACME certificate %+v: %s", account, err.Error())
			}
		}

	})
	return nil
}

// CreateLocalConfig creates a tls.config using local ACME configuration
func (a *ACME) CreateLocalConfig(tlsConfig *tls.Config, checkOnDemandDomain func(domain string) bool) error {
	err := a.init()
	if err != nil {
		return err
	}
	if len(a.Storage) == 0 {
		return errors.New("Empty Store, please provide a filename/key for certs storage")
	}
	a.checkOnDemandDomain = checkOnDemandDomain
	tlsConfig.Certificates = append(tlsConfig.Certificates, *a.defaultCertificate)
	tlsConfig.GetCertificate = a.getCertificate

	localStore := NewLocalStore(a.Storage)
	a.store = localStore
	a.challengeProvider = newMemoryChallengeProvider(a.store)

	var needRegister bool
	var account *Account

	if fileInfo, fileErr := os.Stat(a.Storage); fileErr == nil && fileInfo.Size() != 0 {
		log.Infof("Loading ACME Account...")
		// load account
		account, err = localStore.Load()
		if err != nil {
			return err
		}
	} else {
		log.Infof("Generating ACME Account...")
		account, err = a.generateAccount()
		if err != nil {
			return err
		}
		needRegister = true
	}

	a.client, err = a.buildACMEClient()
	if err != nil {
		return err
	}

	if needRegister {
		// New users will need to register; be sure to save it
		reg, err := a.client.Register()
		if err != nil {
			return err
		}
		account.Registration = reg
	}

	// The client has a URL to the current Let's Encrypt Subscriber
	// Agreement. The user will need to agree to it.
	err = a.client.AgreeToTOS()
	if err != nil {
		// Let's Encrypt Subscriber Agreement renew ?
		reg, err := a.client.QueryRegistration()
		if err != nil {
			return err
		}
		a.account.Registration = reg
		err = a.client.AgreeToTOS()
		if err != nil {
			log.Errorf("Error sending ACME agreement to TOS: %+v: %s", a.account, err.Error())
		}
	}
	// save account
	err = a.saveAccount()
	if err != nil {
		return err
	}

	safe.Go(func() {
		a.retrieveCertificates()
		if err := a.renewCertificates(); err != nil {
			log.Errorf("Error renewing ACME certificate %+v: %s", account, err.Error())
		}
	})

	ticker := time.NewTicker(24 * time.Hour)
	safe.Go(func() {
		for range ticker.C {
			if err := a.renewCertificates(); err != nil {
				log.Errorf("Error renewing ACME certificate %+v: %s", account, err.Error())
			}
		}

	})
	return nil
}

func (a *ACME) getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	account := a.store.Get().(*Account)
	if challengeCert, ok := a.challengeProvider.getCertificate(clientHello.ServerName); ok {
		return challengeCert, nil
	}
	if domainCert, ok := account.DomainsCertificate.getCertificateForDomain(clientHello.ServerName); ok {
		return domainCert.tlsCert, nil
	}
	if a.OnDemand {
		if a.checkOnDemandDomain != nil && !a.checkOnDemandDomain(clientHello.ServerName) {
			return nil, nil
		}
		return a.loadCertificateOnDemand(clientHello)
	}
	return nil, nil
}

func (a *ACME) generateAccount() (*Account, error) {
	// Create a user. New accounts need an email and private key to start
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return &Account{
		Email:              a.Email,
		PrivateKey:         x509.MarshalPKCS1PrivateKey(privateKey),
		DomainsCertificate: DomainsCertificates{Certs: []*DomainsCertificate{}, lock: &sync.RWMutex{}},
	}, nil
}

func (a *ACME) retrieveCertificates() {
	log.Infof("Retrieving ACME certificates...")
	for _, domain := range a.Domains {
		// check if cert isn't already loaded
		account := a.store.Get().(*Account)
		if _, exists := account.DomainsCertificate.exists(domain); !exists {
			transaction, err := a.store.Begin()
			if err != nil {
				log.Errorf("Error creating ACME store transaction from domain %s: %s", domain, err.Error())
				continue
			}
			account = a.store.Get().(*Account)
			domains := []string{}
			domains = append(domains, domain.Main)
			domains = append(domains, domain.SANs...)
			certificateResource, err := a.getDomainsCertificates(domains)
			if err != nil {
				log.Errorf("Error getting ACME certificate for domain %s: %s", domains, err.Error())
				continue
			}
			_, err = account.DomainsCertificate.addCertificateForDomains(certificateResource, domain)
			if err != nil {
				log.Errorf("Error adding ACME certificate for domain %s: %s", domains, err.Error())
				continue
			}

			if err = transaction.Commit(account); err != nil {
				log.Errorf("Error Saving ACME account %+v: %s", account, err.Error())
				continue
			}
		}
	}
	log.Infof("Retrieved ACME certificates")
}

func (a *ACME) renewCertificates() error {
	log.Debugf("Testing certificate renew...")
	account := a.store.Get().(*Account)
	for _, certificateResource := range account.DomainsCertificate.Certs {
		if certificateResource.needRenew() {
			transaction, err := a.store.Begin()
			if err != nil {
				return err
			}
			account = a.store.Get().(*Account)
			log.Debugf("Renewing certificate %+v", certificateResource.Domains)
			renewedCert, err := a.client.RenewCertificate(acme.CertificateResource{
				Domain:        certificateResource.Certificate.Domain,
				CertURL:       certificateResource.Certificate.CertURL,
				CertStableURL: certificateResource.Certificate.CertStableURL,
				PrivateKey:    certificateResource.Certificate.PrivateKey,
				Certificate:   certificateResource.Certificate.Certificate,
			}, true)
			if err != nil {
				log.Errorf("Error renewing certificate: %v", err)
				continue
			}
			log.Debugf("Renewed certificate %+v", certificateResource.Domains)
			renewedACMECert := &Certificate{
				Domain:        renewedCert.Domain,
				CertURL:       renewedCert.CertURL,
				CertStableURL: renewedCert.CertStableURL,
				PrivateKey:    renewedCert.PrivateKey,
				Certificate:   renewedCert.Certificate,
			}
			err = account.DomainsCertificate.renewCertificates(renewedACMECert, certificateResource.Domains)
			if err != nil {
				log.Errorf("Error renewing certificate: %v", err)
				continue
			}

			if err = transaction.Commit(account); err != nil {
				log.Errorf("Error Saving ACME account %+v: %s", account, err.Error())
				continue
			}
		}
	}
	return nil
}

func (a *ACME) buildACMEClient() (*acme.Client, error) {
	caServer := "https://acme-v01.api.letsencrypt.org/directory"
	if len(a.CAServer) > 0 {
		caServer = a.CAServer
	}
	account := a.store.Get().(*Account)
	client, err := acme.NewClient(caServer, account, acme.RSA4096)
	if err != nil {
		return nil, err
	}
	a.client.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.DNS01})
	err = a.client.SetChallengeProvider(acme.TLSSNI01, a.challengeProvider)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (a *ACME) loadCertificateOnDemand(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	transaction, err := a.store.Begin()
	if err != nil {
		return nil, err
	}
	account := a.store.Get().(*Account)
	if certificateResource, ok := account.DomainsCertificate.getCertificateForDomain(clientHello.ServerName); ok {
		return certificateResource.tlsCert, nil
	}
	certificate, err := a.getDomainsCertificates([]string{clientHello.ServerName})
	if err != nil {
		return nil, err
	}
	log.Debugf("Got certificate on demand for domain %s", clientHello.ServerName)
	cert, err := account.DomainsCertificate.addCertificateForDomains(certificate, Domain{Main: clientHello.ServerName})
	if err != nil {
		return nil, err
	}
	if err = transaction.Commit(account); err != nil {
		return nil, err
	}
	return cert.tlsCert, nil
}

// LoadCertificateForDomains loads certificates from ACME for given domains
func (a *ACME) LoadCertificateForDomains(domains []string) {
	safe.Go(func() {
		transaction, err := a.store.Begin()
		if err != nil {
			log.Errorf("Error creating transaction %+v : %v", domains, err)
			return
		}
		account := a.store.Get().(*Account)
		var domain Domain
		if len(domains) == 0 {
			// no domain
			return

		} else if len(domains) > 1 {
			domain = Domain{Main: domains[0], SANs: domains[1:]}
		} else {
			domain = Domain{Main: domains[0]}
		}
		if _, exists := account.DomainsCertificate.exists(domain); exists {
			// domain already exists
			return
		}
		certificate, err := a.getDomainsCertificates(domains)
		if err != nil {
			log.Errorf("Error getting ACME certificates %+v : %v", domains, err)
			return
		}
		log.Debugf("Got certificate for domains %+v", domains)
		_, err = account.DomainsCertificate.addCertificateForDomains(certificate, domain)
		if err != nil {
			log.Errorf("Error adding ACME certificates %+v : %v", domains, err)
			return
		}
		if err = transaction.Commit(account); err != nil {
			log.Errorf("Error Saving ACME account %+v: %v", account, err)
			return
		}
	})
}

func (a *ACME) getDomainsCertificates(domains []string) (*Certificate, error) {
	log.Debugf("Loading ACME certificates %s...", domains)
	bundle := true
	certificate, failures := a.client.ObtainCertificate(domains, bundle, nil)
	if len(failures) > 0 {
		log.Error(failures)
		return nil, fmt.Errorf("Cannot obtain certificates %s+v", failures)
	}
	log.Debugf("Loaded ACME certificates %s", domains)
	return &Certificate{
		Domain:        certificate.Domain,
		CertURL:       certificate.CertURL,
		CertStableURL: certificate.CertStableURL,
		PrivateKey:    certificate.PrivateKey,
		Certificate:   certificate.Certificate,
	}, nil
}

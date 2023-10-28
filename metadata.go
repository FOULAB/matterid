package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// https://github.com/crewjam/saml/blob/main/samlidp/util.go
func getSPMetadata(r io.Reader) (spMetadata *saml.EntityDescriptor, err error) {
	var data []byte
	if data, err = io.ReadAll(r); err != nil {
		return nil, err
	}

	spMetadata = &saml.EntityDescriptor{}
	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	if err := xml.Unmarshal(data, &spMetadata); err != nil {
		if err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			entities := &saml.EntitiesDescriptor{}
			if err := xml.Unmarshal(data, &entities); err != nil {
				return nil, err
			}

			for _, e := range entities.EntityDescriptors {
				if len(e.SPSSODescriptors) > 0 {
					return &e, nil
				}
			}

			// there were no SPSSODescriptors in the response
			return nil, errors.New("metadata contained no service provider metadata")
		}

		return nil, err
	}

	return spMetadata, nil
}

type fileServiceProvider struct {
	serviceProviders map[string]*saml.EntityDescriptor
}

func NewFileServiceProvider(glob string) *fileServiceProvider {
	matches, err := filepath.Glob(glob)
	if err != nil {
		log.Fatalf("cannot glob service providers: %v", err)
		return nil
	}

	p := &fileServiceProvider{
		serviceProviders: map[string]*saml.EntityDescriptor{},
	}
	for _, m := range matches {
		f, err := os.Open(m)
		if err != nil {
			log.Fatalf("cannot open service provider file: %v", err)
			return nil
		}
		defer f.Close()
		metadata, err := getSPMetadata(f)
		if err != nil {
			log.Fatalf("cannot parse service provider file: %v", err)
			return nil
		}
		p.serviceProviders[metadata.EntityID] = metadata
		log.Printf("loaded service provider: %s", metadata.EntityID)
	}

	return p
}

func (p *fileServiceProvider) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	rv, ok := p.serviceProviders[serviceProviderID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return rv, nil
}

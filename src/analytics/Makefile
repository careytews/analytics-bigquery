
VERSION=unknown

TOPDIR=$(shell git rev-parse --show-toplevel)

GOFILES=bigquery

all: godeps build container

build: ${GOFILES}

${GOFILES}: %: %.go
	GOPATH=${TOPDIR} go build $<

godeps:
	GOPATH=${TOPDIR} ${TOPDIR}/bin/dep ensure

container:
	docker build -t \
		gcr.io/trust-networks/analytics-bigquery:${VERSION} \
	 	-f Dockerfile.bigquery .

.PHONY: push
push:
	gcloud docker -- push \
	  gcr.io/trust-networks/analytics-bigquery:${VERSION}

clean:
	git clean -Xffdi

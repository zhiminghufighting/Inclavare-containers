CURRENTDIR := $(shell readlink -f .)
TOPDIR := $(shell readlink -f ..)

DEBUG ?=
EXTRA_FLAGS ?=


CFLAGS += -std=gnu99 -I$(SGX_RA_TLS) -I$(SGX_SDK)/include -I$(INCDIR) $(SGX_DCAP_INC) -fPIC
#CFLAGSERRORS := -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
CFLAGS += $(CFLAGSERRORS) -g -O0 

CC ?= gcc
GO ?= go

all: shelter

ifneq ($(GO111MODULE),off)
  MOD_VENDOR := "-mod=vendor"
endif

ifeq ($(DEBUG),1)
  GCFLAGS=-gcflags "-N -l"
endif

# App_C_Flags := $VERIFICATION/opensslevp.c

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT ?= $(if $(shell git status --porcelain --untracked-files=no),"$(COMMIT_NO)-dirty","$(COMMIT_NO)")

# glibc-static is required for the static linkage
GO_BUILD := CGO_ENABLED=1 $(GO) build $(MOD_VENDOR) -buildmode=pie $(GCFLAGS) $(EXTRA_FLAGS) \
  -ldflags "$(EXTRA_LDFLAGS)"

shelter: verification/verification.a  utils/utils.a remoteattestation/remoteattestation.a $(CURRENTDIR)/racommand.o $(CURRENTDIR)/mrenclaveverifycomand.o $(CURRENTDIR)/main.o
	@echo $(GO_BUILD) -o $@ .
	$(GO_BUILD) -o $@ .

utils/utils.a:
#	@echo cp -rf utils vendor/github.com/shelter/
#	cp -r utils vendor/github.com/shelter/
	make -C utils
	
$(CURRENTDIR)/racommand.o: racommand.go
#	rm -f /usr/local/go/src/shelter/racommand.go
	cp -rf racommand.go /usr/local/go/src/shelter
	$(GO_BUILD) -o $@ .

$(CURRENTDIR)/mrenclaveverifycomand.o: mrenclaveverifycomand.go
	#rm -f /usr/local/go/src/shelter/mrenclaveverifycomand.go
	cp -rf mrenclaveverifycomand.go /usr/local/go/src/shelter
	$(GO_BUILD) -o $@ .	

$(CURRENTDIR)/main.o: main.go
	#rm -f /usr/local/go/src/shelter/main.go
	cp -rf main.go /usr/local/go/src/shelter
	$(GO_BUILD) -o $@ .	

verification/verification.a:
	@echo make -C verification
	make -C verification

remoteattestation/remoteattestation.a: 
	@echo make -C remoteattestation
	make -C remoteattestation


clean:
	rm -f *.o shelter
	make -C verification clean
	make -C remoteattestation clean
	make -C utils clean

.PHONY: clean 
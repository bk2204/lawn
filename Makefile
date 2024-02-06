# Test configuration.
GROUPS := bookworm stable nightly oldest
DOCKER_FILES := $(patsubst %,test/Dockerfile.%,$(GROUPS))
DOCKER_STAMPS := $(patsubst %,test/Dockerfile.%.stamp,$(GROUPS))
CI_TARGETS := $(patsubst %,ci-%,$(GROUPS))
INCLUDES := $(wildcard test/include/*.erb)

CRATES := lawn-constants lawn-protocol lawn-fs lawn-9p lawn-sftp lawn
PACKAGE_TARGETS := $(patsubst %,package-%,$(CRATES))

# Set this to a Docker target to build for a specific platform.
PLATFORM ?=
ifneq ($(PLATFORM),)
PLATFORM_ARG := --platform $(PLATFORM)
else
PLATFORM_ARG :=
endif

FEATURES ?=
ifneq ($(FEATURES),)
FEATURE_ARG := --features $(FEATURES)
else
FEATURE_ARG :=
endif

ASCIIDOCTOR ?= asciidoctor

CARGO_DEB_VERSION = 1.28.0

FREEBSD_VERSION ?= 13
NETBSD_VERSION ?= 9

MAN_SRC := $(wildcard doc/man/*.adoc)
MAN_DEST := $(patsubst %.adoc,%.1,$(MAN_SRC)) $(patsubst %.adoc,%.1.gz,$(MAN_SRC))

DOC_SRC := $(wildcard doc/man/*.adoc) $(wildcard doc/*.adoc)
XHTML_DEST := $(patsubst %.adoc,%.xhtml,$(DOC_SRC))
HTML_DEST := $(patsubst %.adoc,%.html,$(DOC_SRC))

all:
	cargo build --release $(FEATURE_ARG)

clean:
	cargo clean
	$(RM) -fr assets target tmp
	for i in "$(DOCKER_STAMPS)"; \
	do \
		[ ! -f "$$i" ] || docker image rm -f "$$i"; \
	done
	$(RM) -f $(DOCKER_FILES) $(DOCKER_STAMPS)
	$(RM) -f *.md *.md+
	$(RM) -fr tmp
	$(RM) -fr doc/man/*.1 doc/man/*.1.gz
	$(RM) lawn/README.adoc

test: all
	cargo test $(FEATURE_ARG)

test-integration: all
	rspec

doc: $(MAN_DEST) $(XHTML_DEST) $(HTML_DEST)
	echo $(MAN_DEST)

%.xhtml: %.adoc
	$(ASCIIDOCTOR) -b xhtml5 -o $@ $^

%.html: %.adoc
	$(ASCIIDOCTOR) -b html5 -o $@ $^

%.1: %.adoc
	$(ASCIIDOCTOR) -b manpage -o $@ $^

%.1.gz: %.1
	gzip -9fnk $^

%.md: %.adoc
	asciidoctor -o $@+ -b docbook5 $^
	pandoc -f docbook -t commonmark -o $@ $@+
	$(RM) $@+

lawn/README.adoc: README.adoc
	ruby -pe '$$_.gsub!(%r[link:doc/], "https://github.com/bk2204/lawn/tree/dev/doc/")' $^ >$@

%/README.md: doc/README-base.adoc

package-%: %/README.md
	(cd $(^D) && cargo package --locked --allow-dirty)

package: $(PACKAGE_TARGETS)

assets:
	mkdir -p $@

assets/changelog-%.md: CHANGELOG.adoc assets
	script/extract-changelog $* | asciidoctor -o $@+ -b docbook5 -
	pandoc -f docbook -t commonmark -o $@ $@+
	$(RM) $@+

# We do not require both of these commands here since nightly Rust may be
# missing one or more of these. When run under CI, they should be present for
# stable Rust and catch any issues.
#
# Note if we're using rustup, cargo-clippy may exist in the PATH even if clippy
# isn't installed, but it may be a wrapper that just fails when invoked. Check
# that it can successfully print help output to check if we really have clippy.
# The same goes for rustfmt.
lint:
	if command -v cargo-clippy && cargo-clippy --help >/dev/null 2>&1; \
	then \
	        $(MAKE) clippy; \
	fi
	if command -v rustfmt && rustfmt --help >/dev/null 2>&1; \
	then \
	        $(MAKE) fmt; \
	fi

ci: $(CI_TARGETS)

ci-%: test/Dockerfile.%.stamp
	mkdir -p target/assets
	docker run --rm \
		$(PLATFORM_ARG) \
		-v "$(PWD)/target/assets:/usr/src/lawn/target/debian" \
		-e CARGO_NET_GIT_FETCH_WITH_CLI=true \
		$$(cat "$<") \
		sh -c 'cd /usr/src/lawn && make test-full'

ci-freebsd:
	vagrant init generic/freebsd$(FREEBSD_VERSION)
	for i in $$(seq 10); do vagrant up && break; vagrant halt || true; done
	vagrant ssh -- sudo pkg install -y curl git gmake rubygem-asciidoctor rubygem-rspec rust
	vagrant ssh -- git init /home/vagrant/lawn
	GIT_SSH_COMMAND='f() { shift; vagrant ssh -- "$$@"; };f' git push vagrant@localhost:/home/vagrant/lawn HEAD:refs/heads/dev
	vagrant ssh -- "cd /home/vagrant/lawn && git checkout $$(git rev-parse HEAD) && gmake test-full FEATURES=$(FEATURES)"

ci-netbsd:
	vagrant init generic/netbsd$(NETBSD_VERSION)
	for i in $$(seq 10); do vagrant up && break; vagrant halt || true; done
	vagrant ssh -- sudo /usr/pkg/bin/pkgin update
	vagrant ssh -- sudo /usr/pkg/bin/pkgin -y install mozilla-rootcerts-openssl curl git gmake ruby31-asciidoctor ruby31-rspec rust
	vagrant ssh -- git init /home/vagrant/lawn
	GIT_SSH_COMMAND='f() { shift; vagrant ssh -- "$$@"; };f' git push vagrant@localhost:/home/vagrant/lawn HEAD:refs/heads/dev
	vagrant ssh -- "cd /home/vagrant/lawn && git checkout $$(git rev-parse HEAD) && gmake test-full ASCIIDOCTOR=asciidoctor31  CARGO_HTTP_MULTIPLEXING=false FEATURES=$(FEATURES)"

test-full:
	$(MAKE) all
	$(MAKE) doc
	$(MAKE) test
	$(MAKE) test-integration
	$(MAKE) lint

test/Dockerfile.%.stamp: test/Dockerfile.% $(SRC)
	docker build $(PLATFORM_ARG) --iidfile="$@" -f "$<" .

test/Dockerfile.%: test/Dockerfile.%.erb $(INCLUDES)
	test/template "$<" >"$@"

clippy:
	rm -rf target/debug target/release
	cargo clippy $(FEATURE_ARG) -- -A clippy::unknown-clippy-lints -A clippy::manual-strip -A clippy::needless_borrow -A clippy::bad_bit_mask -D warnings

fmt:
	if rustfmt --help | grep -qse --check; \
	then \
			rustfmt --edition=2018 --check $$(find . -name '*.rs' | grep -v '^./target'); \
	else \
			rustfmt --edition=2018 --write-mode diff $$(find . -name '*.rs' | grep -v '^./target'); \
	fi

.PHONY: all lint ci clean doc clippy fmt test

# Red Sky Arsenal — build system
#
# Targets:
#   build           — build local host binaries into ./bin
#   build-all       — cross-compile the agent + core for all supported OS/arch
#   dist            — package release archives + SHA-256 checksums into ./dist
#   release         — dist + git tag (caller must pass VERSION=x.y.z)
#   clean           — remove ./bin and ./dist
#   test            — run go test ./...
#
# Cross-compile matrix (agent + core):
#   linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
#   windows/amd64 windows/arm64 freebsd/amd64

VERSION    ?= v3.0.0-dev
BINDIR     := bin
DISTDIR    := dist/$(VERSION)
LDFLAGS    := -s -w -X main.version=$(VERSION)

CORE_NAME  := redsky-core
AGENT_NAME := redsky-agent

# host build
.PHONY: build
build:
	@mkdir -p $(BINDIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(CORE_NAME) ./cmd/redsky-core
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(AGENT_NAME) ./cmd/redsky-agent
	@echo "built $(BINDIR)/$(CORE_NAME) $(BINDIR)/$(AGENT_NAME)"

# cross-compile matrix
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64

.PHONY: build-all
build-all:
	@mkdir -p $(DISTDIR)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "building $(CORE_NAME) for $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" \
			-o $(DISTDIR)/$(CORE_NAME)-$$os-$$arch$$ext ./cmd/redsky-core || exit 1; \
		echo "building $(AGENT_NAME) for $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" \
			-o $(DISTDIR)/$(AGENT_NAME)-$$os-$$arch$$ext ./cmd/redsky-agent || exit 1; \
	done
	@echo "all binaries in $(DISTDIR)"

# package into tarballs/zips with checksums
.PHONY: dist
dist: build-all
	@cd $(DISTDIR) && \
	for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		stage="redsky-$(VERSION)-$$os-$$arch"; \
		rm -rf "$$stage"; mkdir -p "$$stage"; \
		cp $(CORE_NAME)-$$os-$$arch$$ext "$$stage/"; \
		cp $(AGENT_NAME)-$$os-$$arch$$ext "$$stage/"; \
		cp ../docs/FRAMEWORK.md "$$stage/README.md" 2>/dev/null || true; \
		if [ "$$os" = "windows" ]; then \
			zip -q -r "$$stage.zip" "$$stage"; \
		else \
			tar czf "$$stage.tar.gz" "$$stage"; \
		fi; \
		rm -rf "$$stage"; \
	done && \
	sha256sum *.tar.gz *.zip > SHA256SUMS 2>/dev/null || \
	shasum -a 256 *.tar.gz *.zip > SHA256SUMS
	@echo "packaged release in $(DISTDIR):"
	@ls -la $(DISTDIR)/

# tag + report (user runs gh release create separately)
.PHONY: release
release: dist
	git tag -a $(VERSION) -m "Red Sky Arsenal $(VERSION)"
	git push origin $(VERSION)
	@echo "tagged $(VERSION). Now run:"
	@echo "  gh release create $(VERSION) --title 'Red Sky Arsenal $(VERSION)' $(DISTDIR)/*.tar.gz $(DISTDIR)/*.zip $(DISTDIR)/SHA256SUMS"

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	rm -rf $(BINDIR) dist

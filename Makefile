# relay-htcp build helpers.
#
# The admin UI is embedded with go:embed and SQLite uses modernc.org/sqlite,
# so every target works with CGO disabled and needs no frontend build step.

BINARY      ?= relay-htcp
PKG         ?= ./cmd/relay-htcp
DIST        ?= dist
GO          ?= go

# Local builds get the platform suffix so `make build` works on every OS;
# release archives keep the plain name and add the platform themselves.
ifeq ($(OS),Windows_NT)
LOCAL_BINARY := $(BINARY).exe
else
LOCAL_BINARY := $(BINARY)
endif

export CGO_ENABLED ?= 0

# The release workflow passes VERSION=v1.2.3; local builds fall back to
# git describe so `relay-htcp version` always shows something meaningful.
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
BUILD_FLAGS := -trimpath -ldflags "$(LDFLAGS)"

# Override with e.g. PLATFORMS="linux/amd64 windows/amd64".
PLATFORMS   ?= linux/amd64 linux/arm64 linux/386 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.DEFAULT_GOAL := build

.PHONY: all build run test vet fmt-check tidy licenses release clean-dist clean help

## all: 静态检查 + 测试（提交前跑一遍）
all: vet test

## build: 编译当前平台的二进制到 ./$(LOCAL_BINARY)
build:
	$(GO) build $(BUILD_FLAGS) -o "$(LOCAL_BINARY)" $(PKG)

## run: 直接运行服务端（当前目录有 server.yaml 时自动加载）
run:
	$(GO) run $(PKG)

## test: 运行全部测试
test:
	$(GO) test ./...

## vet: go vet 静态检查
vet:
	$(GO) vet ./...

## fmt-check: 检查 gofmt，格式不一致时报错（CI 用）
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "以下文件需要 gofmt："; echo "$$out"; exit 1; fi; \
	echo "gofmt 检查通过"

## tidy: 整理 go.mod / go.sum
tidy:
	$(GO) mod tidy

## licenses: 收集依赖许可证到 $(DIST)/THIRD_PARTY_LICENSES，并复制 LICENSE
licenses:
	@GO="$(GO)" sh scripts/third-party-licenses.sh "$(DIST)" "$(VERSION)"

## release: 交叉编译各平台发布包（tar.gz / zip）并生成 SHA256SUMS
release:
	@$(MAKE) --no-print-directory clean-dist
	@$(MAKE) --no-print-directory licenses
	@set -e; \
	for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		name="$(BINARY)-$(VERSION)-$$os-$$arch"; \
		echo "==> $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO) build $(BUILD_FLAGS) -o "$(DIST)/$$name$$ext" $(PKG); \
		if [ "$$os" = "windows" ] && command -v zip >/dev/null 2>&1; then \
			( cd "$(DIST)" && zip -q "$$name.zip" "$$name$$ext" LICENSE THIRD_PARTY_LICENSES ); \
		else \
			if [ "$$os" = "windows" ]; then echo "    未找到 zip，改用 tar.gz 打包"; fi; \
			tar -C "$(DIST)" -czf "$(DIST)/$$name.tar.gz" "$$name$$ext" LICENSE THIRD_PARTY_LICENSES; \
		fi; \
		rm -f "$(DIST)/$$name$$ext"; \
	done; \
	cd "$(DIST)"; \
	files=""; \
	for f in *.tar.gz *.zip; do \
		if [ -f "$$f" ]; then files="$$files $$f"; fi; \
	done; \
	if [ -z "$$files" ]; then echo "没有生成任何发布包"; exit 1; fi; \
	if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum $$files > SHA256SUMS; \
	else \
		shasum -a 256 $$files > SHA256SUMS; \
	fi; \
	echo "发布包已生成于 $(DIST)/ (VERSION=$(VERSION))"; \
	ls -1

## clean-dist: 删除 $(DIST) 目录
clean-dist:
	@rm -rf "$(DIST)"

## clean: 删除本地二进制
clean:
	@rm -f "$(BINARY)" "$(BINARY).exe"

## help: 列出所有可用目标
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'

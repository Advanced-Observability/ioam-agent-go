BINARY          := ioam-agent
BINARY_PFRING   := ioam-agent-pfring

IMAGE_AGENT     := ioam-agent
IMAGE_PFRING    := ioam-agent-pfring

DOCKER_DIR      := docker
DOCKER_AGENT    := $(DOCKER_DIR)/agent.Dockerfile
DOCKER_PFRING   := $(DOCKER_DIR)/agent-pfring.Dockerfile

GO              := go
DOCKER          := docker

CGO_LDFLAGS     := -L/usr/local/lib -Wl,-rpath,/usr/local/lib

GO_SOURCES := $(shell find . -type f -name '*.go')

.PHONY: all

all: ioam-agent

ioam-agent: $(GO_SOURCES)
	@echo "[*] Building $(BINARY)..."
	@$(GO) build -o $(BINARY)

ioam-agent-pfring: $(GO_SOURCES)
	@echo "[*] Building $(BINARY_PFRING)..."
	@CGO_ENABLED=1 \
	CGO_LDFLAGS="$(CGO_LDFLAGS)" \
	$(GO) build -tags pfring -o $(BINARY_PFRING)

docker: docker-agent docker-pfring

docker-agent: $(BINARY) $(DOCKER_AGENT)
	@echo "[*] Building Docker image $(IMAGE_AGENT)..."
	@$(DOCKER) build \
		-f $(DOCKER_AGENT) \
		-t $(IMAGE_AGENT) \
		.

docker-pfring: $(BINARY_PFRING) $(DOCKER_PFRING)
	@echo "[*] Building Docker image $(IMAGE_PFRING)..."
	@$(DOCKER) build \
		-f $(DOCKER_PFRING) \
		-t $(IMAGE_PFRING) \

clean:
	@echo "[*] Removing executables..."
	@rm -f $(BINARY) $(BINARY_PFRING)

MODULE = equality
ARCH = amd64
PLATFORMS = linux windows openbsd
# https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63

BIN_DIR = ./bin
SRC_DIR = ./src

all: $(PLATFORMS:%=build-%)

build-%:
	@echo "Building $(MODULE) for $*..."
	OUTPUT=$(MODULE)-$(ARCH)-$*$(if $(filter $*,windows),.exe,) ; \
	GOOS=$* GOARCH=$(ARCH) go build -o $(BIN_DIR)/$$OUTPUT $(SRC_DIR)

clean:
	@echo "Cleaning binaries..."
	rm -f $(BIN_DIR)/$(MODULE)-$(ARCH)-*
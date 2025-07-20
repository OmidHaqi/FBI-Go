BINDER_SRC=internal/binder/binder.go
BINDER_SO=binder.so
LOADER_SRC=cmd/fbi/main.go
LOADER_BIN=fbi

.PHONY: all build-binder build-loader clean

all: build-binder build-loader

build-binder:
	go build -buildmode=c-shared -o $(BINDER_SO) $(BINDER_SRC)

build-loader:
	go build -o $(LOADER_BIN) $(LOADER_SRC)

clean:
	rm -f $(BINDER_SO) $(LOADER_BIN) binder.h

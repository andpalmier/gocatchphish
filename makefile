all: catchphish

catchphish: build
	@go build -o build/catchphish cmd/*.go

install: catchphish
	@cp build/catchphish /usr/bin/
	@chmod a+x /usr/bin/catchphish

build:
	@mkdir -p build

clean:
	@rm -rf build

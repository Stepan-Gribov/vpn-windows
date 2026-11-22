BUILDDIR := $(CURDIR)/build
SOURCE := $(CURDIR)/Source
IOS_SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
SIM_SDK := $(shell xcrun --sdk iphonesimulator --show-sdk-path)
MIN_IOS := 16.0

.PHONY: all clean device simulator xcframework

all: xcframework

$(BUILDDIR):
	mkdir -p $(BUILDDIR)/device $(BUILDDIR)/simulator $(BUILDDIR)/headers

device: $(BUILDDIR)
	cd $(SOURCE) && \
	CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
	CGO_CFLAGS="-isysroot $(IOS_SDK) -arch arm64 -miphoneos-version-min=$(MIN_IOS)" \
	CGO_LDFLAGS="-isysroot $(IOS_SDK) -arch arm64 -miphoneos-version-min=$(MIN_IOS)" \
	CC="$(shell xcrun --sdk iphoneos -f clang) -isysroot $(IOS_SDK) -arch arm64 -miphoneos-version-min=$(MIN_IOS)" \
	go build -buildmode=c-archive -trimpath -tags ios -ldflags "-s -w" \
	-o $(BUILDDIR)/device/libKindlyTurn.a .
	cp $(BUILDDIR)/device/libKindlyTurn.h $(BUILDDIR)/headers/KindlyTurn.h

simulator: $(BUILDDIR)
	cd $(SOURCE) && \
	CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
	CGO_CFLAGS="-isysroot $(SIM_SDK) -arch arm64 -miphonesimulator-version-min=$(MIN_IOS)" \
	CGO_LDFLAGS="-isysroot $(SIM_SDK) -arch arm64 -miphonesimulator-version-min=$(MIN_IOS)" \
	CC="$(shell xcrun --sdk iphonesimulator -f clang) -isysroot $(SIM_SDK) -arch arm64 -miphonesimulator-version-min=$(MIN_IOS)" \
	go build -buildmode=c-archive -trimpath -tags ios -ldflags "-s -w" \
	-o $(BUILDDIR)/simulator/libKindlyTurn.a .

xcframework: device simulator
	cp $(CURDIR)/include/module.modulemap $(BUILDDIR)/headers/module.modulemap
	rm -rf $(BUILDDIR)/KindlyTurn.xcframework
	xcodebuild -create-xcframework \
	-library $(BUILDDIR)/device/libKindlyTurn.a -headers $(BUILDDIR)/headers \
	-library $(BUILDDIR)/simulator/libKindlyTurn.a -headers $(BUILDDIR)/headers \
	-output $(BUILDDIR)/KindlyTurn.xcframework

clean:
	rm -rf $(BUILDDIR)


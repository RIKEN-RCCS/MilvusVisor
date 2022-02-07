NAME = hypervisor_bootloader
TARGET = aarch64-uefi
TARGET_JSON = config/$(TARGET).json

CARGO = cargo


all:  .FORCE
	$(CARGO) xbuild --release --target $(TARGET_JSON)

clean:
	$(CARGO) clean

fmt:
	$(CARGO) fmt

default:
	$(MAKE) all

.FORCE:

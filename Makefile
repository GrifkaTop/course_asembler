BUILD = build
FASM  = fasm
LD    = ld

all: $(BUILD)/server $(BUILD)/client $(BUILD)/keygen

$(BUILD)/server: server.asm proto.inc crypto.inc net.inc
	$(FASM) server.asm $(BUILD)/server.o
	$(LD) -o $(BUILD)/server $(BUILD)/server.o

$(BUILD)/client: client.asm proto.inc crypto.inc net.inc
	$(FASM) client.asm $(BUILD)/client.o
	$(LD) -o $(BUILD)/client $(BUILD)/client.o

$(BUILD)/keygen: keygen.asm
	$(FASM) keygen.asm $(BUILD)/keygen.o
	$(LD) -o $(BUILD)/keygen $(BUILD)/keygen.o

clean:
	rm -f $(BUILD)/server $(BUILD)/server.o \
	      $(BUILD)/client $(BUILD)/client.o \
	      $(BUILD)/keygen $(BUILD)/keygen.o

cleandata:
	rm -f $(BUILD)/data.bin $(BUILD)/*.key
	@echo "Ключи и база данных удалены"

restart:
	@bash restart.sh

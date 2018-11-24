
all: sysu-h3c

sysu-h3c: sysu-h3c.o packet.o io.o base64.o

clean:
	rm ./*.o
.PHONY: clean
CC = gcc
prom = sysu-h3c
bindir = /usr/local/bin
deps = $(shell find ./ -name "*.h")
src = $(shell find ./ -name "*.c")
obj = $(src:%.c=%.o) 

all:$(prom)

$(prom): $(obj)
	$(CC) -o $(prom) $(obj)

%.o: %.c $(deps)
	$(CC) -c $< -o $@

clean:
	rm -rf $(prom) $(obj)

install:
	install -d $(bindir)
	install -m0755 $(prom) $(bindir)

uninstall:
	rm $(bindir)/$(prom)

.PHONY: all clean install uninstall
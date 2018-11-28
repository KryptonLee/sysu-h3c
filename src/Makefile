CC = gcc
prom = sysu-h3c
deps = $(shell find ./ -name "*.h")
src = $(shell find ./ -name "*.c")
obj = $(src:%.c=%.o) 

$(prom): $(obj)
	$(CC) -o $(prom) $(obj)

%.o: %.c $(deps)
	$(CC) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(obj)
CC := gcc
CFLAGS := -Wall -Wextra
LDFLAGS := -luarf

TARGET := virt2phys

# Disable default implicit rules. Otherwise, make tries to rebuilt Makefile
MAKEFLAGS += -r

.PHONY: all
all: $(TARGET)

%: %.o
	@echo "Link $@"
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)


%.o: %.c
	@echo "Compile $@"
	$(CC) -c -o $@ $(CFLAGS) $<


.PHONY: clean
clean:
	@echo "Clean"
	rm -rf $(TARGET)
	find -name "*.o" -delete

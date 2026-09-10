# See src/linux/Makefile: append so environment/command-line CFLAGS survive.
override CFLAGS += -Wall -Wextra -Werror -I../include
OBJS = main.o
LIBS =
SRC_DIR = ../src/linux

all: injector

injector: $(OBJS) $(SRC_DIR)/libinjector.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o injector $(OBJS) $(SRC_DIR)/libinjector.a $(LIBS) -ldl

main.o: main.c

clean:
	$(RM) injector $(OBJS)

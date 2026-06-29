CFLAGS = -Wall -I../include
OBJS = main.o
LIBS =
SRC_DIR = ../src/linux

all: injector

injector: $(OBJS) $(SRC_DIR)/libinjector.a
	$(CC) -o injector $(OBJS) $(SRC_DIR)/libinjector.a $(LIBS)

main.o: main.c

clean:
	$(RM) injector $(OBJS)

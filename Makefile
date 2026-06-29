SRC_DIR = src/linux

all:
	cd $(SRC_DIR) && $(MAKE)
	cd cmd && $(MAKE)

check:
	cd tests && $(MAKE) check

clean:
	cd $(SRC_DIR) && $(MAKE) clean
	cd cmd && $(MAKE) clean
	cd tests && $(MAKE) clean

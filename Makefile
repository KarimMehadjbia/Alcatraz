all: alcatraz

check: alcatraz
	bats check.bats
clean:
	rm alcatraz

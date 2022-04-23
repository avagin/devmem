MEMSIZE = $(shell echo $$((1<<31)))
BUFSIZE = $(shell echo $$((1<<20)))
run: procmem
	./procmem splice /tmp/procmem.out $(BUFSIZE) $(MEMSIZE)
	./procmem mem /tmp/procmem.out $(BUFSIZE) $(MEMSIZE)
	./procmem process_vm_readv /tmp/procmem.out  $(BUFSIZE) $(MEMSIZE)
procmem: procmem.c
	gcc -Wall -o procmem procmem.c

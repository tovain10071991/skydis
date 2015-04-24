#export LD_LIBRARY_PATH=/home/user/Documents/udis86-1.7.2/build/lib

UDIS86_INCLUDE := /home/user/Documents/udis86-1.7.2/build/include/
ELF_INCLUDE += /home/user/Documents/libelf-0.8.13/build/include/
UDIS86_LIBRARY := /home/user/Documents/udis86-1.7.2/build/lib/
ELF_LIBRARY += /home/user/Documents/libelf-0.8.13/build/lib/

CFLAGS := -c -g -I $(UDIS86_INCLUDE) -I $(ELF_INCLUDE)
LFLAGS := -I $(UDIS86_INCLUDE) -I $(ELF_INCLUDE) -L $(UDIS86_LIBRARY) -L $(ELF_LIBRARY)

EXECUTE := dis_ls
SOURCE := $(EXECUTE).c
OBJECT := $(EXECUTE).o

all:  $(EXECUTE)

$(EXECUTE): $(EXECUTE).o
	$(CC) $(LFLAGS) -o $(EXECUTE) $(EXECUTE).o -ludis86 -lelf

$(EXECUTE).o: $(EXECUTE).c
	$(CC) $(CFLAGS) -o $(EXECUTE).o $(EXECUTE).c

clean:
	rm $(EXECUTE) $(EXECUTE).o

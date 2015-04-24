#export LD_LIBRARY_PATH=/home/user/Documents/udis86-1.7.2/build/lib

INCLUDE := /home/user/Documents/udis86-1.7.2/build/include/
LIBRARY := /home/user/Documents/udis86-1.7.2/build/lib/
STATIC := /home/user/Documents/udis86-1.7.2/build/lib/libudis86.a
CFLAGS := -c -g -I $(INCLUDE)
LFLAGS := -I $(INCLUDE) -L $(LIBRARY)

all: get_start.shared get_start.static

get_start.shared: get_start.o
	$(CC) $(LFLAGS) -o get_start.shared get_start.o -ludis86

get_start.static: get_start.o
	$(CC) -o get_start.static get_start.o $(STATIC)

get_start.o: get_start.c
	$(CC) $(CFLAGS) -o get_start.o get_start.c

clean:
	rm get_start.shared get_start.static get_start.o

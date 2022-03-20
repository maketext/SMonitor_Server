net: net.o sqlite3.o
	gcc -o net net.o sqlite3.o -lsocket -lnsl -lpthread -ldl
sqlite3.o: sqlite3.c
	gcc -c sqlite3.c -lpthread -ldl
net.o: net.c
	gcc -c net.c -lsocket -lnsl
clean:
	rm -f net net.o sqlite3.o
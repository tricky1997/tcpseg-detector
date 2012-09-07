CC=gcc
CFLAGS=-g -Wall -Wextra
LIBS=-ldnet -lpthread -lpcap
echo_src=echo.c
echo_obj=$(echo_src:%.c=%.o)
test_src=detector.c
test_obj=$(test_src:%.c=%.o)
.PHONY: clean

detector:$(test_obj)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

echo:$(echo_obj)
	$(CC) -o $@ $(CFLAGS) $^ 

clean:
	rm -f detector echo $(echo_obj) $(test_obj)

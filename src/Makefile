LDFLAGS=-lpthread -lv4l2
CFLAGS=-Wall -O3

netcam: netcam.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf *.o netcam

LDFLAGS=-lpthread -lv4l2
CFLAGS=-Wall -O3

netcam: netcam.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf *.o netcam

install:
	mkdir -p /usr/local/bin
	cp netcam /usr/local/bin
	cp netcam.sh /etc/init.d/
	update-rc.d netcam.sh defaults

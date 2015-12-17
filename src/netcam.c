/* a simple IP netcam for raspberry pi using low-level v4l2 API */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <syslog.h>

#include <libv4l2.h>
#include <libv4lconvert.h>
#include <linux/videodev2.h>

#define VIDEO_DEVICE	"/dev/video0"
#define CLEAR(x)	memset(&(x), 0, sizeof(x))
#define VIDEO_WIDTH	320
#define VIDEO_HEIGHT	240
#define MAX_CONNECTION	30
#define SERVER_PORT	8081
#define MAX_BUFFER_SIZE	4096
#define TARGET_FPS	15

#define INDEX_HTML	"\
<HTML>\r\n\
<HEAD>\r\n\
<TITLE>	IP Network cam </TITLE>\r\n\
</HEAD>\r\n\
<BODY>\r\n\
	<H2> IP Network camera	</H2>\r\n\
	<table border=1 bgcolor=#00000000> <tr><td><image src=/stream_mjpeg/></td></tr></table>\r\n\
</body>\r\n\
</html>\r\n\
"

struct buffer {
        void   *start;
        size_t length;
};

struct client_info {
	int fd;
	struct sockaddr_in sockaddr;
};

static pthread_mutex_t mutex;
static int active_client_count;
static struct buffer image;

static void xioctl(int fh, int request, void *arg)
{
        int r;

        do {
                r = v4l2_ioctl(fh, request, arg);
        } while (r == -1 && ((errno == EINTR) || (errno == EAGAIN)));

        if (r == -1) {
                syslog(LOG_ERR, "ioctl failed: %s",strerror(errno));
                exit(EXIT_FAILURE);
        }
}

static void* start_camera (void *unused)
{
	int r, fd;
        fd_set fds;
        struct timeval tv;
        struct v4l2_buffer buf;
        struct v4l2_requestbuffers req;
        enum v4l2_buf_type type;
        unsigned int i, n_buffers;
        struct buffer *buffers;
        struct v4l2_format fmt;
	struct ifaddrs *ipaddrs, *tmp;

	fd = v4l2_open(VIDEO_DEVICE, O_RDWR | O_NONBLOCK, 0);
	if (fd < 0) {
		syslog(LOG_ERR, "failed to open /dev/video0: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	syslog(LOG_DEBUG, "[%s] opened\n", VIDEO_DEVICE);

	CLEAR(fmt);
	fmt.type		= V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt.fmt.pix.width	= VIDEO_WIDTH;
	fmt.fmt.pix.height	= VIDEO_HEIGHT;
	fmt.fmt.pix.pixelformat	= V4L2_PIX_FMT_MJPEG;
	fmt.fmt.pix.field	= V4L2_FIELD_INTERLACED;
	xioctl(fd, VIDIOC_S_FMT, &fmt);
	if (fmt.fmt.pix.pixelformat != V4L2_PIX_FMT_MJPEG) {
		syslog(LOG_WARNING,
			"%s did not accept MJPEG format. Can't proceed.\n",
			VIDEO_DEVICE);
		exit(EXIT_FAILURE);
	}

	if ((fmt.fmt.pix.width != VIDEO_WIDTH) ||
		(fmt.fmt.pix.height != VIDEO_HEIGHT))
		syslog(LOG_DEBUG, "Warning: driver is sending image at %dx%d\n",
			fmt.fmt.pix.width, fmt.fmt.pix.height);

	syslog(LOG_DEBUG, "[%s] configured MJPEG @ %dx%d\n", VIDEO_DEVICE,
		fmt.fmt.pix.width, fmt.fmt.pix.height);

	CLEAR(req);
	req.count = 4;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;
	xioctl(fd, VIDIOC_REQBUFS, &req);

	syslog(LOG_DEBUG, "[%s] configure %d buffers\n", VIDEO_DEVICE, req.count);

	buffers = calloc(req.count, sizeof(*buffers));
	for (n_buffers = 0; n_buffers < req.count; ++n_buffers) {
		CLEAR(buf);

		buf.type        = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory      = V4L2_MEMORY_MMAP;
		buf.index       = n_buffers;

		xioctl(fd, VIDIOC_QUERYBUF, &buf);

		buffers[n_buffers].length = buf.length;
		buffers[n_buffers].start = v4l2_mmap(NULL, buf.length,
			      PROT_READ | PROT_WRITE, MAP_SHARED,
			      fd, buf.m.offset);

		if (MAP_FAILED == buffers[n_buffers].start) {
			syslog(LOG_ERR, "failed to mmap: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		syslog(LOG_DEBUG, "[%s] mmap index=%d, start=%p len=%d\n", VIDEO_DEVICE,
			n_buffers, buffers[n_buffers].start, buf.length);

		if (!image.start) {
			image.start = malloc(sizeof(char) * buf.length);
			if (!image.start) {
				syslog(LOG_ERR, "no memory\n");
				exit(EXIT_FAILURE);
			}
			image.length = buf.length;
		}
	}

	for (i = 0; i < n_buffers; ++i) {
		CLEAR(buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = i;
		xioctl(fd, VIDIOC_QBUF, &buf);
	}

	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	xioctl(fd, VIDIOC_STREAMON, &type);

	syslog(LOG_DEBUG, "[%s] start streaming\n", VIDEO_DEVICE);
	getifaddrs(&ipaddrs);
	tmp = ipaddrs;
	while (tmp) {
		if (tmp && tmp->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *paddr = (struct sockaddr_in*) tmp->ifa_addr;
			syslog(LOG_DEBUG,"http://%s:%d\n", inet_ntoa(paddr->sin_addr),
				SERVER_PORT);
		}
		tmp = tmp->ifa_next;
	}

	while (1) {
		do {
			FD_ZERO(&fds);
			FD_SET(fd, &fds);

			/* Timeout. */
			tv.tv_sec = 10;
			tv.tv_usec = 0;

			r = select(fd + 1, &fds, NULL, NULL, &tv);
		} while ((r == -1 && (errno = EINTR)));

		if (r == -1) {
			syslog(LOG_ERR, "select failed: %s", strerror(errno));
			break;
		}

		CLEAR(buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		xioctl(fd, VIDIOC_DQBUF, &buf);

		pthread_mutex_lock(&mutex);
		image.length = buf.length;
		memcpy(image.start, buffers[buf.index].start, buf.length);
		pthread_mutex_unlock(&mutex);

		xioctl(fd, VIDIOC_QBUF, &buf);
	}

	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	xioctl(fd, VIDIOC_STREAMOFF, &type);
	syslog(LOG_DEBUG, "[%s] stopping streaming\n", VIDEO_DEVICE);

	for (i = 0; i < n_buffers; ++i) {
		v4l2_munmap(buffers[i].start, buffers[i].length);
		syslog(LOG_DEBUG, "[%s] unmap index=%d buffer=%p\n", VIDEO_DEVICE,
			i, buffers[i].start);
	}

	v4l2_close(fd);
	syslog(LOG_DEBUG, "[%s] closed\n", VIDEO_DEVICE);

	return NULL;
}

static void* start_client (void *args)
{
	char *data;
	int fd, len;
	char *message;
	struct client_info *info = (struct client_info*)args;
	unsigned int sleep_us;

	data = malloc(sizeof(char) * VIDEO_WIDTH * VIDEO_HEIGHT * 4);
	if (!data) {
		syslog(LOG_ERR, "no memory");
		return NULL;
	}

	message = malloc(sizeof(char) * MAX_BUFFER_SIZE);
	if (!message) {
		perror("no memory");
		free(data);
		return NULL;
	}

	fd = info->fd;
	syslog(LOG_DEBUG, "establised connection from host '%s' on port '%d'\n",
		inet_ntoa(info->sockaddr.sin_addr),
		ntohs(info->sockaddr.sin_port));

	while(1) {
		pthread_mutex_lock(&mutex);
		len = image.length;
		memcpy(data, image.start, len);
		pthread_mutex_unlock(&mutex);

		/* send start header */
		memset(message, '\0', MAX_BUFFER_SIZE);
		snprintf(message, MAX_BUFFER_SIZE,
			"HTTP/1.1 200 OK\r\n"
			"Cache-Control: no-cache\r\n"
			"Cache-Control: private\r\n"
			"Pragma: no-cache\r\n"
			"Content-Type: multipart/x-mixed-replace;"
			"boundary=fooboundary\r\n\r\n"
			"--fooboundary\r\n"
			"Content-type: image/jpeg\r\n"
			"Content-Length: %d\r\n\r\n", len);

		if (send(fd, message, strlen(message), MSG_NOSIGNAL) < 0)
			goto failed;

		/* send the image */
		if (send(fd, data, len, MSG_NOSIGNAL) < 0)
			goto failed;

		/* send remaining header */
		memset(message, '\0', MAX_BUFFER_SIZE);
		snprintf(message, MAX_BUFFER_SIZE, "\r\n--fooboundary\r\n");
		if (send(fd, message, strlen(message), MSG_NOSIGNAL) < 0)
			goto failed;

		sleep_us = 1000 * (((double)1/TARGET_FPS) * 1000);
		usleep(sleep_us); /* throttle to targeted fps */
	}
failed:
	syslog(LOG_DEBUG, "closing connection from host '%s' on port '%d'\n",
		inet_ntoa(info->sockaddr.sin_addr),
		ntohs(info->sockaddr.sin_port));
	free(args);
	pthread_mutex_lock(&mutex);
	active_client_count--;
	pthread_mutex_unlock(&mutex);
	free(message);
	free(data);
	close(fd);
	return NULL;
}

static void http_error(int fd)
{
	char str[MAX_BUFFER_SIZE];
	char ERR_TOO_MANY_CONNECTION[] = 
		"<TITLE>ERROR</TITLE><H2>Too many connection!</H2>";

	snprintf(str, MAX_BUFFER_SIZE,
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/html;\r\n\r\n");

	send(fd, str, strlen(str), MSG_NOSIGNAL);
	send(fd, ERR_TOO_MANY_CONNECTION, strlen(ERR_TOO_MANY_CONNECTION),
		MSG_NOSIGNAL);
	close(fd);
}

static void add_new_connection (int server_fd)
{
	int fd;
	pthread_t tid;
	socklen_t size;
	struct sockaddr_in client;
	struct client_info *info;
	char buf[MAX_BUFFER_SIZE] = {0};

	size = sizeof(client);
	fd = accept(server_fd, (struct sockaddr*)&client, &size);
	if (fd < 0) {
		syslog(LOG_ERR, "failed to accept connection:%s",strerror(errno));
		return;
	}

	/* read the browser header */
	recv(fd, buf, MAX_BUFFER_SIZE, MSG_NOSIGNAL);

	/* if header contain 'stream_mjpeg' url then start streaming
	 * otherwise send the HTML index page.
	 */
	if (strstr(buf, "stream_mjpeg")) {
		/* check if we have reached to the connection limit */
		pthread_mutex_lock(&mutex);
		if (active_client_count == MAX_CONNECTION) {
			pthread_mutex_unlock(&mutex);
			http_error(fd);
			syslog(LOG_ERR, "too many connection!");
		}
		active_client_count++;
		pthread_mutex_unlock(&mutex);

		info = malloc(sizeof(*info));
		if (!info) {
			syslog(LOG_ERR, "no memory");
			return;
		}
		info->fd = fd;
		memcpy(&info->sockaddr, &client, size);
		pthread_create(&tid, NULL, start_client, (void*)info);

	} else {

		snprintf(buf, MAX_BUFFER_SIZE,
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/html;\r\n"
			"Content-Length: %d\r\n\r\n"
			"%s", strlen(INDEX_HTML), INDEX_HTML);
		send(fd, buf, strlen(buf), MSG_NOSIGNAL);
		close(fd);
	}

	return;
}

static int create_sock (int port)
{
	int fd;
	struct sockaddr_in server;
	
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		syslog(LOG_ERR, "socket create failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(port);

	if (bind(fd, (struct sockaddr*) &server, sizeof(server)) < 0) {
		syslog(LOG_ERR, "socket bind failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (listen(fd, 3) < 0) {
		syslog(LOG_ERR, "socket listen failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	syslog(LOG_INFO, "server is listening on port '%d'\n", port);
	return fd;
}

int main(int argc, char **argv)
{
	int i, server_fd;
	pthread_t camera_tid;
	fd_set active_fd_set, read_fd_set;

	openlog(argv[0], LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);

	/* make this as daemon */
	if (daemon(0, 1) < 0) {
		syslog(LOG_ERR, "failed to init deamon\n");
		exit(EXIT_FAILURE);
	}
	/* create a server socket */
	server_fd = create_sock(SERVER_PORT);
	
	/* spawn image capture thread */
	pthread_mutex_init(&mutex, NULL);
	pthread_create(&camera_tid, NULL, start_camera, NULL);

	FD_ZERO(&active_fd_set);
	FD_SET(server_fd, &active_fd_set);

	while(1) {
		/* block until input arrives on one or more active sockets */
		read_fd_set = active_fd_set;
		if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {
			syslog(LOG_ERR, "select failure: %s", strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* service all the socket with input pending */
		for(i=0; i < FD_SETSIZE; ++i) {
			if (FD_ISSET(i, &read_fd_set)) {
				if (i == server_fd)
					add_new_connection(i);
			}
		}
	}

	pthread_join(camera_tid, NULL);

        return 0;
}

/*
 * a simple IP netcam for raspberry pi using low-level v4l2 API
 *
 * Author: Brijesh Singh <brijesh.ksingh@gmail.com>
 */

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
#define VIDEO_WIDTH	352
#define VIDEO_HEIGHT	288
#define MAX_CONNECTION	10
#define SERVER_PORT	8081
#define MAX_BUFFER_SIZE	4096
#define NUM_CIRC_BUFS	30

#define INDEX_HTML	"\
<HTML>\r\n\
<HEAD>\r\n\
<TITLE>	IP Network cam </TITLE>\r\n\
</HEAD>\r\n\
<BODY>\r\n\
	<table>\r\n\
	<tr><td><center><b>Raspberry pi network camera</b></center></td></tr>\r\n\
	<tr><td><table border=1 bgcolor=#000000><tr><td><image src=/stream_mjpeg/></td></tr></table></tr></td>\r\n\
	</table>\r\n\
</body>\r\n\
</html>\r\n\
"

struct buffer {
        void   *start;
        size_t length;
	struct timeval timestamp;
};

struct circ_buffer {
	int prerolling;
	int head, tail;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	pthread_cond_t prerolled;
	struct buffer data[NUM_CIRC_BUFS];
};

struct client_info {
	int fd;
	struct sockaddr_in sockaddr;
	struct circ_buffer *circ_buffer;
};

static int imagesize;
static int camera_running;
static pthread_mutex_t mutex;
static struct client_info clients[MAX_CONNECTION];

static void queue_get(struct circ_buffer *circ_buf, struct buffer *buf)
{
	pthread_mutex_lock(&circ_buf->mutex);

	/* queue is empty, block the caller */
	if (circ_buf->head == circ_buf->tail)
		pthread_cond_wait(&circ_buf->cond, &circ_buf->mutex);

	/* copy the data from circular buffer and advance the head */
	buf->length = circ_buf->data[circ_buf->head].length;
	buf->timestamp = circ_buf->data[circ_buf->head].timestamp;
	memcpy(buf->start, circ_buf->data[circ_buf->head].start, buf->length);
	circ_buf->head = (circ_buf->head + 1) % NUM_CIRC_BUFS;

	pthread_mutex_unlock(&circ_buf->mutex);
}

static void queue_put(struct circ_buffer *circ_buf, struct buffer *buf)
{
	int head, tail;

	pthread_mutex_lock(&circ_buf->mutex);
	/* copy the data into circular buffer and advance the tail */
	head = circ_buf->head;
	tail = circ_buf->tail;
	memcpy(circ_buf->data[tail].start, buf->start, buf->length);
	circ_buf->data[tail].length = buf->length;
	circ_buf->data[tail].timestamp = buf->timestamp;
	tail = (tail + 1) % NUM_CIRC_BUFS;

	/* if client is waiting for buffer to be prerolled then notify it */
	if (circ_buf->prerolling && (tail >= NUM_CIRC_BUFS - 2)) {
		circ_buf->prerolling = 0;
		pthread_cond_broadcast(&circ_buf->prerolled);
	}

	/* queue is full */
	if (tail == head)
		head = head + 1;

	/* reset the head (if needed) */
	if (head >= NUM_CIRC_BUFS)
		head = 0;

	circ_buf->head = head;
	circ_buf->tail = tail;

	/* notify client thread */
	pthread_cond_broadcast(&circ_buf->cond);
	pthread_mutex_unlock(&circ_buf->mutex);
}

static void broadcast_image(struct buffer *buf)
{
	int i;

	/* iterate through all active clients and put the data in there circular buffer */
	pthread_mutex_lock(&mutex);
	for (i = 0; i < MAX_CONNECTION; i++) {
		if (clients[i].fd && clients[i].circ_buffer)
			queue_put(clients[i].circ_buffer, buf);
	}
	pthread_mutex_unlock(&mutex);
}

static void free_circ_buffer(struct circ_buffer *buf)
{
	int i;

	if (buf) {
		printf("free circular buffer %p\n", buf);
		for (i = 0; i < NUM_CIRC_BUFS; i++)
			if (buf->data[i].start)
				free(buf->data[i].start);
		pthread_mutex_destroy(&buf->mutex);
		pthread_cond_destroy(&buf->cond);
		free(buf);
	}
}

static struct circ_buffer* alloc_circ_buffer()
{
	int i;
	struct circ_buffer *buf;

	buf = calloc(1, sizeof(*buf));
	if (!buf)
		return NULL;

	pthread_mutex_init(&buf->mutex, NULL);
	pthread_cond_init(&buf->cond, NULL);
	pthread_cond_init(&buf->prerolled, NULL);

	for (i = 0; i < NUM_CIRC_BUFS; i++) {
		buf->data[i].start = malloc(imagesize);
		if ((buf->data[i].start) == NULL) {
			syslog(LOG_ERR, "malloc() failed %s\n", strerror(errno));
			goto failed;
		}
	}

	printf("allocate circular buffer %p(%.2fKB)\n", buf,
		(double)(imagesize * NUM_CIRC_BUFS) / 1024);
	return buf;
failed:
	free_circ_buffer(buf);
	return NULL;
}

static int xioctl(int fh, int request, void *arg)
{
        int r;

        do {
                r = v4l2_ioctl(fh, request, arg);
        } while (r == -1 && ((errno == EINTR) || (errno == EAGAIN)));

        if (r == -1) {
                syslog(LOG_ERR, "ioctl failed: %s",strerror(errno));
        }

	return r;
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
        struct buffer *buffers, image_buf;
        struct v4l2_format fmt;
	struct ifaddrs *ipaddrs, *tmp;

	fd = v4l2_open(VIDEO_DEVICE, O_RDWR | O_NONBLOCK, 0);
	if (fd < 0) {
		syslog(LOG_ERR, "failed to open /dev/video0: %s", strerror(errno));
		goto failed;
	}
	printf("[%s] opened\n", VIDEO_DEVICE);

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
		goto failed;
	}

	if ((fmt.fmt.pix.width != VIDEO_WIDTH) ||
		(fmt.fmt.pix.height != VIDEO_HEIGHT))
		syslog(LOG_DEBUG, "Warning: driver is sending image at %dx%d\n",
			fmt.fmt.pix.width, fmt.fmt.pix.height);

	printf("[%s] configured MJPEG @ %dx%d\n", VIDEO_DEVICE,
		fmt.fmt.pix.width, fmt.fmt.pix.height);

	CLEAR(req);
	req.count = 4;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;
	if (xioctl(fd, VIDIOC_REQBUFS, &req) < 0)
		goto failed;

	printf("[%s] configure %d buffers\n", VIDEO_DEVICE, req.count);

	buffers = calloc(req.count, sizeof(*buffers));
	for (n_buffers = 0; n_buffers < req.count; ++n_buffers) {
		CLEAR(buf);

		buf.type        = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory      = V4L2_MEMORY_MMAP;
		buf.index       = n_buffers;

		if (xioctl(fd, VIDIOC_QUERYBUF, &buf) < 0)
			goto failed;

		buffers[n_buffers].length = buf.length;
		buffers[n_buffers].start = v4l2_mmap(NULL, buf.length,
			      PROT_READ | PROT_WRITE, MAP_SHARED,
			      fd, buf.m.offset);

		if (MAP_FAILED == buffers[n_buffers].start) {
			syslog(LOG_ERR, "mmap() failed: %s", strerror(errno));
			goto failed;
		}

		printf("[%s] mmap index=%d, start=%p len=%d\n", VIDEO_DEVICE,
			n_buffers, buffers[n_buffers].start, buf.length);

		imagesize = buf.length;
	}

	for (i = 0; i < n_buffers; ++i) {
		CLEAR(buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.index = i;
		if (xioctl(fd, VIDIOC_QBUF, &buf) < 0)
			goto unmap_buffer;
	}

	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (xioctl(fd, VIDIOC_STREAMON, &type) < 0)
		goto unmap_buffer;

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

	camera_running = 1;

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
			goto stop_stream;
		}

		CLEAR(buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		if (xioctl(fd, VIDIOC_DQBUF, &buf) < 0)
			goto stop_stream;

		/* send buffer to clients */
		image_buf.start = buffers[buf.index].start;
		image_buf.length = buf.length;
		image_buf.timestamp = buf.timestamp;
		broadcast_image(&image_buf);

		if (xioctl(fd, VIDIOC_QBUF, &buf) < 0)
			goto stop_stream;
	}

stop_stream:
	type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	xioctl(fd, VIDIOC_STREAMOFF, &type);
	syslog(LOG_DEBUG, "[%s] stopping streaming\n", VIDEO_DEVICE);

unmap_buffer:
	for (i = 0; i < n_buffers; ++i) {
		v4l2_munmap(buffers[i].start, buffers[i].length);
		printf("[%s] unmap index=%d buffer=%p\n", VIDEO_DEVICE,
			i, buffers[i].start);
	}

failed:
	v4l2_close(fd);
	printf("[%s] closed\n", VIDEO_DEVICE);
	pthread_detach(pthread_self());
	camera_running = 0;

	return NULL;
}

static int time_diff(struct timeval *end, struct timeval *start)
{
	int ms = 0;

	ms = (end->tv_sec - start->tv_sec) * 1000;
	ms += (end->tv_usec - end->tv_usec) / 1000;
	return ms;
}

static void* start_client (void *args)
{
	int fd;
	struct buffer *buf;
	char message[MAX_BUFFER_SIZE];
	struct timeval start_time, end_time;
	struct client_info *info = (struct client_info*)args;

	syslog(LOG_DEBUG, "establised connection from host '%s' on port '%d'\n",
		inet_ntoa(info->sockaddr.sin_addr),
		ntohs(info->sockaddr.sin_port));

	fd = info->fd;

	buf = calloc(1, sizeof(*buf));
	if (!buf) {
		printf("malloc() failed\n");
		goto failed;
	}

	buf->start = malloc(imagesize);
	if (!buf->start) {
		printf("malloc() failed\n");
		goto failed;
	}

	info->circ_buffer = alloc_circ_buffer();
	if (!info->circ_buffer) {
		syslog(LOG_ERR, "calloc() failed");
		goto failed;
	}

	/* wait for circular buffer to be prerolled */
	pthread_mutex_lock(&info->circ_buffer->mutex);
	info->circ_buffer->prerolling = 1;
	gettimeofday(&start_time, NULL);
	pthread_cond_wait(&info->circ_buffer->prerolled, &info->circ_buffer->mutex);
	gettimeofday(&end_time, NULL);
	pthread_mutex_unlock(&info->circ_buffer->mutex);
	printf("took %d ms to preroll the buffers\n", time_diff(&end_time, &start_time));

	/* send http start header */
	memset(message, '\0', MAX_BUFFER_SIZE);
	snprintf(message, MAX_BUFFER_SIZE,
		"HTTP/1.1 200 OK\r\n"
		"Content-type: multipart/x-mixed-replace; boundary=fooboundary\r\n\r\n");

	if (send(fd, message, strlen(message), MSG_NOSIGNAL) < 0)
		goto failed;

	while(camera_running) {
		/* get image buffer from the queue */
		queue_get(info->circ_buffer, buf);

		/* send JPEG boundary header */
		memset(message, '\0', MAX_BUFFER_SIZE);
		snprintf(message, MAX_BUFFER_SIZE,
			"--fooboundary\r\n"
			"Content-type: image/jpeg\r\n\r\n");
		if (send(fd, message, strlen(message), MSG_NOSIGNAL) < 0)
			goto failed;

		/* send the image */
		if (send(fd, buf->start, buf->length, MSG_NOSIGNAL) < 0)
			goto failed;
	}
failed:
	syslog(LOG_DEBUG, "closing connection from host '%s' on port '%d'\n",
		inet_ntoa(info->sockaddr.sin_addr),
		ntohs(info->sockaddr.sin_port));

	pthread_mutex_lock(&mutex);
	free_circ_buffer(info->circ_buffer);
	memset(info, '\0', sizeof(*info));
	pthread_mutex_unlock(&mutex);

	if (buf) {
		free(buf->start);
		free(buf);
	}

	close(fd);
	pthread_detach(pthread_self());

	return NULL;
}

static void http_error(int fd, char *message)
{
	char buf[MAX_BUFFER_SIZE];

	snprintf(buf, MAX_BUFFER_SIZE,
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html;\r\n"
		"Content-Length: %d\r\n\r\n"
		"%s", strlen(message), message);
	send(fd, buf, strlen(buf), MSG_NOSIGNAL);
	close(fd);
}

static void add_new_connection (int server_fd)
{
	int i, fd;
	pthread_t tid;
	socklen_t size;
	struct sockaddr_in client;
	struct client_info *info = NULL;
	char buf[MAX_BUFFER_SIZE] = {0};

	size = sizeof(client);
	fd = accept(server_fd, (struct sockaddr*)&client, &size);
	if (fd < 0) {
		syslog(LOG_ERR, "failed to accept connection:%s",strerror(errno));
		return;
	}

	if (!camera_running) {
		http_error(fd, "failed to connect to camera!");
		return;
	}

	/* read the browser header */
	recv(fd, buf, MAX_BUFFER_SIZE, MSG_NOSIGNAL);

	/* if header contain 'stream_mjpeg' url then start streaming
	 * otherwise send the HTML index page.
	 */
	if (strstr(buf, "stream_mjpeg")) {
		/* find a available client info object */
		pthread_mutex_lock(&mutex);
		for (i = 0; i < MAX_CONNECTION; i++) {
			if (!clients[i].fd) {
				info = &clients[i];
				break;
			}
		}
		pthread_mutex_unlock(&mutex);

		if (i >= MAX_CONNECTION) {
			http_error(fd, "Error: too many connections!");
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

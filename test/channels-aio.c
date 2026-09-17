#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"

static const size_t size = 8000000; // large enough to split across AIO buffers
static const size_t smallsize = 100000; // size of the data to transfer without AIO
static const size_t nchannels = 4; // number of simultaneous channels

struct aio_info {
	int callbacks;
	size_t size;
	struct aio_info *previous;
	struct sync_flag flag;
};

struct channel_info {
	char *data;
	struct aio_info aio_infos[2];
};

static size_t b_received_len;
static struct sync_flag b_received_flag;

static void aio_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len, void *priv) {
	(void)mesh;
	(void)channel;
	(void)data;
	(void)len;

	struct aio_info *info = priv;

	if(info->previous) {
		assert(info->previous->callbacks == 1);
	}

	info->callbacks++;
	info->size += len;
	set_sync_flag(&info->flag, true);
}

static void receive_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, const void *data, size_t len) {
	(void)mesh;
	(void)channel;
	(void)data;

	b_received_len += len;

	if(b_received_len >= smallsize) {
		set_sync_flag(&b_received_flag, true);
	}
}

static bool node_is_keyed(meshlink_handle_t *mesh, meshlink_node_t *node) {
	devtool_node_status_t st;
	devtool_get_node_status(mesh, node, &st);
	bool keyed = st.meta_connected && st.validkey;
	devtool_free_node_status(&st);
	return keyed;
}

/* AIO, not UDP. Persistently force META without deleting recent[] so delayed
   bridge probe replies cannot move this test back onto UDP. */
static void stay_on_meta(meshlink_handle_t *a, meshlink_handle_t *b) {
	meshlink_node_t *a_b = meshlink_get_node(a, "b");
	meshlink_node_t *b_a = meshlink_get_node(b, "a");
	assert(a_b && b_a);
	assert_after(node_is_keyed(a, a_b) && node_is_keyed(b, b_a), 20);
	devtool_set_udp_confirmed(a, a_b, false);
	devtool_set_udp_confirmed(b, b_a, false);
	devtool_force_meta(a, a_b, true);
	devtool_force_meta(b, b_a, true);
}

static bool accept_cb(meshlink_handle_t *mesh, meshlink_channel_t *channel, uint16_t port, const void *data, size_t len) {
	assert(port && port <= nchannels + 1);
	assert(!data);
	assert(!len);

	if(port <= nchannels) {
		struct channel_info *infos = mesh->priv;
		struct channel_info *info = &infos[port - 1];

		assert(meshlink_channel_aio_receive(mesh, channel, info->data, size / 4, aio_cb, &info->aio_infos[0]));
		assert(meshlink_channel_aio_receive(mesh, channel, info->data + size / 4, size - size / 4, aio_cb, &info->aio_infos[1]));
	} else {
		meshlink_set_channel_receive_cb(mesh, channel, receive_cb);
	}

	return true;
}

int main(void) {
	init_sync_flag(&b_received_flag);

	meshlink_set_log_cb(NULL, MESHLINK_WARNING, log_cb);

	// Prepare data buffers

	char *outdata = malloc(size);
	assert(outdata);

	for(size_t i = 0; i < size; i++) {
		outdata[i] = i;
	}

	struct channel_info in_infos[nchannels];

	struct channel_info out_infos[nchannels];

	memset(in_infos, 0, sizeof(in_infos));

	memset(out_infos, 0, sizeof(out_infos));

	for(size_t i = 0; i < nchannels; i++) {
		init_sync_flag(&in_infos[i].aio_infos[0].flag);
		init_sync_flag(&in_infos[i].aio_infos[1].flag);
		init_sync_flag(&out_infos[i].aio_infos[0].flag);
		init_sync_flag(&out_infos[i].aio_infos[1].flag);
		in_infos[i].aio_infos[1].previous = &in_infos[i].aio_infos[0];
		out_infos[i].aio_infos[1].previous = &out_infos[i].aio_infos[0];

		in_infos[i].data = malloc(size);
		assert(in_infos[i].data);
		out_infos[i].data = outdata;
	}

	// Open two new meshlink instance.

	meshlink_handle_t *mesh_a, *mesh_b;
	open_meshlink_pair(&mesh_a, &mesh_b, "channels_aio");

	// Set the callbacks.

	mesh_b->priv = in_infos;

	meshlink_set_channel_accept_cb(mesh_b, accept_cb);

	// Start both instances

	start_meshlink_pair(mesh_a, mesh_b);
	stay_on_meta(mesh_a, mesh_b);

	// Open channels from a to b.

	meshlink_node_t *b = meshlink_get_node(mesh_a, "b");
	assert(b);

	meshlink_channel_t *channels[nchannels + 1];

	for(size_t i = 0; i < nchannels + 1; i++) {
		channels[i] = meshlink_channel_open(mesh_a, b, i + 1, NULL, NULL, 0);
		assert(channels[i]);
	}

	// Send a large buffer of data on each channel.

	for(size_t i = 0; i < nchannels; i++) {
		assert(meshlink_channel_aio_send(mesh_a, channels[i], outdata, size / 3, aio_cb, &out_infos[i].aio_infos[0]));
		assert(meshlink_channel_aio_send(mesh_a, channels[i], outdata + size / 3, size - size / 3, aio_cb, &out_infos[i].aio_infos[1]));
	}

	// Send a little bit on the last channel using a regular send

	assert(meshlink_channel_send(mesh_a, channels[nchannels], outdata, smallsize) == (ssize_t)smallsize);

	// Wait for everyone to finish.

	assert(wait_sync_flag(&b_received_flag, 60));

	for(size_t i = 0; i < nchannels; i++) {
		assert(wait_sync_flag(&out_infos[i].aio_infos[0].flag, 60));
		assert(wait_sync_flag(&out_infos[i].aio_infos[1].flag, 60));
		assert(wait_sync_flag(&in_infos[i].aio_infos[0].flag, 60));
		assert(wait_sync_flag(&in_infos[i].aio_infos[1].flag, 60));
	}

	// Check that everything is correct.

	assert(b_received_len == smallsize);

	for(size_t i = 0; i < nchannels; i++) {
		// Data should be transferred intact.
		assert(!memcmp(in_infos[i].data, out_infos[i].data, size));

		// One callback for each AIO buffer.
		assert(out_infos[i].aio_infos[0].callbacks == 1);
		assert(out_infos[i].aio_infos[1].callbacks == 1);
		assert(in_infos[i].aio_infos[0].callbacks == 1);
		assert(in_infos[i].aio_infos[1].callbacks == 1);

		// Correct size sent and received.
		assert(out_infos[i].aio_infos[0].size == size / 3);
		assert(out_infos[i].aio_infos[1].size == size - size / 3);
		assert(in_infos[i].aio_infos[0].size == size / 4);
		assert(in_infos[i].aio_infos[1].size == size - size / 4);

		// Per-channel AIO order is asserted by the second buffer's callback.

		free(in_infos[i].data);
	}

	// Clean up.

	close_meshlink_pair(mesh_a, mesh_b);
	free(outdata);
}

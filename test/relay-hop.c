#include "meshlink.h"
#include "utils.h"
#include <assert.h>

void relay_hop_tests(meshlink_handle_t *mesh);
void relay_envelope_tests(meshlink_handle_t *mesh);
void relay_mtu_tests(meshlink_handle_t *mesh);
void relay_send_tests(meshlink_handle_t *mesh);

int main(void) {
	meshlink_handle_t *mesh = meshlink_open_ephemeral("nmn", "relay-hop", DEV_CLASS_BACKBONE);
	assert(mesh);
	relay_hop_tests(mesh);
	relay_envelope_tests(mesh);
	relay_mtu_tests(mesh);
	relay_send_tests(mesh);
	meshlink_close(mesh);
	return 0;
}

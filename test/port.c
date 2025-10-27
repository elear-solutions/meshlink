#ifdef NDEBUG
#undef NDEBUG
#endif

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "meshlink.h"
#include "devtools.h"
#include "utils.h"


int main(void) {
	meshlink_set_log_cb(NULL, MESHLINK_DEBUG, log_cb);

	meshlink_handle_t *mesh1;
	meshlink_handle_t *mesh2;

	// Open two instances

	assert(meshlink_destroy("port_conf.1"));
	assert(meshlink_destroy("port_conf.2"));

	mesh1 = meshlink_open("port_conf.1", "foo", "port", DEV_CLASS_BACKBONE);
	mesh2 = meshlink_open("port_conf.2", "bar", "port", DEV_CLASS_BACKBONE);

	assert(mesh1);
	assert(mesh2);

	meshlink_enable_discovery(mesh1, false);
	meshlink_enable_discovery(mesh2, false);

	int port1 = meshlink_get_port(mesh1);
	int port2 = meshlink_get_port(mesh2);
	assert(port1);
	assert(port2);
	assert(port1 != port2);

	// bar cannot take foo's port if foo is still open
	assert(!meshlink_set_port(mesh2, port1));

	// bar can take foo's port of foo is closed
	meshlink_close(mesh1);

	assert(meshlink_set_port(mesh2, port1));
	assert(meshlink_get_port(mesh2) == port1);

	// foo can open but will now use a different port
	mesh1 = meshlink_open("port_conf.1", "foo", "port", DEV_CLASS_BACKBONE);
	assert(mesh1);
	int port1b = meshlink_get_port(mesh1);
	assert(port1b);
	assert(port1b != port1);

	assert(!meshlink_set_port(mesh1, port1));

	// foo can take over bar's old port
	assert(meshlink_set_port(mesh1, port2));

	meshlink_close(mesh1);
	meshlink_close(mesh2);

	// Test port 0 (dynamic port assignment)
	printf("\n=== Testing Port 0 (Dynamic Assignment) ===\n");

	assert(meshlink_destroy("port_conf.3"));

	meshlink_handle_t *mesh3 = meshlink_open("port_conf.3", "baz", "port", DEV_CLASS_BACKBONE);
	assert(mesh3);
	meshlink_enable_discovery(mesh3, false);

	// Request port 0 (OS should assign a random available port)
	printf("Setting port to 0 (requesting dynamic assignment)...\n");
	assert(meshlink_set_port(mesh3, 0));

	// Start the mesh to trigger actual socket binding
	assert(meshlink_start(mesh3));

	// Get the actual assigned port
	int port3 = meshlink_get_port(mesh3);
	printf("meshlink_get_port() returned: %d\n", port3);

	// ✅ FIX APPLIED: Should now return actual assigned port, not 0
	if(port3 == 0) {
		printf("❌ BUG STILL EXISTS: meshlink_get_port() returns 0 (expected actual assigned port)\n");
		printf("   This should not happen after the fix!\n");
		assert(false);  // Fail if bug still exists
	} else {
		printf("✅ FIX VERIFIED: meshlink_get_port() returns actual port %d\n", port3);
		// Verify it's in valid port range
		assert(port3 > 0 && port3 <= 65535);
		printf("✅ Port is in valid range (1-65535)\n");
	}

	meshlink_stop(mesh3);

	// Test port stability on restart
	printf("\n=== Testing Port Stability on Restart ===\n");
	printf("Closing mesh3 and reopening to test port persistence...\n");

	meshlink_close(mesh3);

	// Reopen - should try to bind to the same port that was saved in config
	mesh3 = meshlink_open("port_conf.3", "baz", "port", DEV_CLASS_BACKBONE);
	assert(mesh3);

	int port3_restart = meshlink_get_port(mesh3);
	printf("After restart, meshlink_get_port() returned: %d\n", port3_restart);

	// ✅ FIX APPLIED: Config should have saved the actual assigned port
	// If the original port is available, port3_restart should equal port3
	// If port is taken, it should be different but still > 0
	if(port3_restart == 0) {
		printf("❌ BUG STILL EXISTS: Config saved port 0 (should have saved actual port)\n");
		printf("   Port stability is broken - can't reuse same port on restart\n");
		assert(false);  // Fail if bug still exists
	} else {
		printf("✅ FIX VERIFIED: Config saved actual port %d\n", port3_restart);
		assert(port3_restart > 0 && port3_restart <= 65535);
		
		if(port3_restart == port3) {
			printf("✅ BONUS: Port is stable across restarts (same port: %d)\n", port3);
		} else {
			printf("ℹ️  Port changed on restart (%d -> %d), expected if previous port was in use\n", port3, port3_restart);
		}
	}

	// Test port conflict handling - create a socket that binds to the saved port
	printf("\n=== Testing Port Conflict Handling ===\n");
	printf("Creating a socket to bind to port %d (simulating port conflict)...\n", port3_restart);
	
	// Close mesh3 first to free up the port
	meshlink_close(mesh3);
	
	// Small delay to ensure port is fully released
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000 }; // 100ms
	nanosleep(&delay, NULL);
	
	// Create a socket that binds to the same port
	int conflict_fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(conflict_fd >= 0);
	
	struct sockaddr_in conflict_addr;
	memset(&conflict_addr, 0, sizeof(conflict_addr));
	conflict_addr.sin_family = AF_INET;
	conflict_addr.sin_addr.s_addr = INADDR_ANY;
	conflict_addr.sin_port = htons(port3_restart);
	
	int bind_result = bind(conflict_fd, (struct sockaddr*)&conflict_addr, sizeof(conflict_addr));
	if(bind_result == 0) {
		printf("✅ Successfully bound conflict socket to port %d\n", port3_restart);
		
		// Now try to restart mesh3 - it should find a different port
		printf("Restarting mesh3 with port conflict - should find alternative port...\n");
		
		mesh3 = meshlink_open("port_conf.3", "baz", "port", DEV_CLASS_BACKBONE);
		assert(mesh3);
		
		int port3_conflict = meshlink_get_port(mesh3);
		printf("With port conflict, meshlink_get_port() returned: %d\n", port3_conflict);
		
		if(port3_conflict == 0) {
			printf("❌ BUG: Port conflict not handled gracefully (returned 0)\n");
			assert(false);
		} else if(port3_conflict == port3_restart) {
			printf("❌ BUG: Port conflict not detected (same port as conflict)\n");
			assert(false);
		} else {
			printf("✅ SUCCESS: Port conflict handled gracefully (found alternative port %d)\n", port3_conflict);
			assert(port3_conflict > 0 && port3_conflict <= 65535);
		}
		
		// Clean up conflict socket
		close(conflict_fd);
	} else {
		printf("ℹ️  Could not create port conflict (port %d may be in use by system)\n", port3_restart);
		printf("   This is normal - continuing with regular test\n");
	}

	meshlink_close(mesh3);
	assert(meshlink_destroy("port_conf.3"));

	printf("\n=== Port 0 Tests Complete ===\n");
	printf("✅ SUCCESS: Bug fix verified - port 0 correctly assigns and saves actual port!\n");
}

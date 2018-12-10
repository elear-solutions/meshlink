check_PROGRAMS = node_sim_relay node_sim_gateway node_sim_sleepy

node_sim_relay_SOURCES = node_sim_relay.c ../common/common_handlers.c ../common/test_step.c ../common/mesh_event_handler.c
node_sim_relay_LDADD = ../../../src/libmeshlink.la
node_sim_relay_CFLAGS = -D_GNU_SOURCE

node_sim_gateway_SOURCES = node_sim_gateway.c ../common/common_handlers.c ../common/test_step.c ../common/mesh_event_handler.c
node_sim_gateway_LDADD = ../../../src/libmeshlink.la
node_sim_gateway_CFLAGS = -D_GNU_SOURCE

node_sim_sleepy_SOURCES = node_sim_sleepy.c ../common/common_handlers.c ../common/test_step.c ../common/mesh_event_handler.c
node_sim_sleepy_LDADD = ../../../src/libmeshlink.la
node_sim_sleepy_CFLAGS = -D_GNU_SOURCE

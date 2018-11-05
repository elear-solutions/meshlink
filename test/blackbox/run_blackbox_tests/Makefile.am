check_PROGRAMS = run_blackbox_tests

run_blackbox_tests_SOURCES = 						\
	run_blackbox_tests.c 									\
	../common/network_sim.c   							
	
run_blackbox_tests_LDADD = ../../../src/libmeshlink.la -llxc -lcmocka
run_blackbox_tests_CFLAGS = -D_GNU_SOURCE -fsanitize=leak


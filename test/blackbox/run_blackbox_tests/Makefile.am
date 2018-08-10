check_PROGRAMS = run_blackbox_tests

run_blackbox_tests_SOURCES = run_blackbox_tests.c test_cases.c execute_tests.c ../common/containers.c ../common/common_handlers.c ../common/test_step.c test_cases_open.c test_cases_start.c test_cases_stop_close.c test_cases_pmtu.c test_cases_get_self.c test_cases_send.c test_cases_get_node.c test_cases_add_addr.c test_cases_get_ex_addr.c test_cases_add_ex_addr.c test_cases_get_port.c test_cases_blacklist.c test_cases_whitelist.c test_cases_default_blacklist.c test_cases_channel_open.c test_cases_channel_close.c test_cases_channel_send.c test_cases_channel_shutdown.c
run_blackbox_tests_LDADD = ../../../src/libmeshlink.la -llxc -lcmocka
run_blackbox_tests_CFLAGS = -D_GNU_SOURCE

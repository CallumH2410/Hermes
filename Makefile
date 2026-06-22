# SPDX-License-Identifier: Apache-2.0

BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = topology.json
DEFAULT_PROG = hermes_line.p4

# Extra arguments passed through to run_hermes.py
# Usage examples:
#   sudo make run                                    # Single probe mode
#   sudo make run RUN_ARGS="--throughput --num-probes 50 --delay-ms 10"  # Custom throughput
#   sudo make run-throughput                        # Throughput test (50 probes, 10ms delay)
RUN_ARGS ?=

include ../../utils/Makefile

RUNNER := $(abspath run_hermes.py)

run: build
	# Start Hermes server in a separate terminal / shell:
	@echo "Compile Hermes C++ server with:  g++ -O2 -std=c++17 -o hermes_server hermes_server.cpp"
	@echo "Then run:  ./hermes_server 5555"
	@echo ""
	sudo PATH=$(PATH) ${P4_EXTRA_SUDO_OPTS} python3 $(RUNNER) \
		--topo $(abspath $(TOPO)) \
		--p4info $(abspath $(BUILD_DIR)/hermes_line.p4.p4info.txtpb) \
		--bmv2-json $(abspath $(BUILD_DIR)/hermes_line.json) \
		$(RUN_ARGS)

# Convenience target for throughput testing
run-throughput: build
	@echo "Running throughput test (50 probes, 10ms delay)"
	@echo "Start Hermes server in a separate terminal: ./hermes_server 5555"
	@echo ""
	sudo PATH=$(PATH) ${P4_EXTRA_SUDO_OPTS} python3 $(RUNNER) \
		--topo $(abspath $(TOPO)) \
		--p4info $(abspath $(BUILD_DIR)/hermes_line.p4.p4info.txtpb) \
		--bmv2-json $(abspath $(BUILD_DIR)/hermes_line.json) \
		--throughput --num-probes 50 --delay-ms 10

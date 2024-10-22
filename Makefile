AGENT_DIR = ./cmd
AGENT_BIN_NAME = bamboo-agent

.PHONY: all-platform
all-platform:
	build/build.sh $(AGENT_DIR) $(AGENT_BIN_NAME) all

.PHONY: build
build:
	build/build.sh $(AGENT_DIR) $(AGENT_BIN_NAME)

.PHONY: clean
clean:
	build/clean.sh

agent:
	cd src/pare_frida_mcp/agent && npm install && npm run build

test:
	/home/edible/Projects/PARE/.venv/bin/python -m pytest

.PHONY: agent test

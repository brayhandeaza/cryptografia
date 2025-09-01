.PHONY: all


publish:
	@echo "Building..."
	@yarn run build

	@echo "Asigning new version..."
	@npm version patch

	@echo "Publishing..."
	@npm publish

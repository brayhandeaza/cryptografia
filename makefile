.PHONY: all


publish:
	@echo "Building..."
	@yarn run build

	@echo "Asigning new version..."
	@npm version minor 

	@echo "Publishing..."
	npm publish

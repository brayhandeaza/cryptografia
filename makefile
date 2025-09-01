.PHONY: all


publish:
	@npm unpublish cryptografia@0.0.0
	@yarn run publish

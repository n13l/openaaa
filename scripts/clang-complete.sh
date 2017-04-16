find . -name "*.h" -exec dirname {} \; | sort | uniq > .complete

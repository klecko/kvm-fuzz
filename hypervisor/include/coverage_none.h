#ifndef _COVERAGE_NONE_H
#define _COVERAGE_NONE_H

class CoverageNone {
public:
	bool operator==(const CoverageNone& other) const { return true; }
	void reset() {}
	size_t count() const { return 0; }
	bool add(const CoverageNone& other) { return false; }
};

#endif
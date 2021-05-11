#include "common.h"

#if defined(ENABLE_COVERAGE_BREAKPOINTS)
#include "coverage_breakpoints.h"
typedef CoverageBreakpoints<std::set<vaddr_t>> Coverage;
typedef SharedCoverageBreakpoints SharedCoverage;

#elif defined(ENABLE_COVERAGE_INTEL_PT)
#include "coverage_intel_pt.h"
typedef CoverageIntelPT Coverage;
typedef SharedCoverageIntelPT SharedCoverage;

#else
#include "coverage_none.h"
typedef CoverageNone Coverage;
typedef CoverageNone SharedCoverage;

#endif
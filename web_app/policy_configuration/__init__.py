"""FMC Access Control Policy replication feature.

All backend code for fetching Access Control Policies (ACPs) from a *source*
FMC, serializing them to YAML, and pushing them (with dependency resolution)
to the currently connected *target* FMC lives under this package.

The React UI lives under ``frontend/src/pages/policy-config/`` (Vite build
requirement); only this package contains the Python implementation.
"""

__all__ = ["api", "models", "services", "dependency_resolution", "validation", "yaml"]

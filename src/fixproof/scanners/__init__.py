"""Scanner wrappers. Each module has run(...) that writes the scanner's own output and
parse(path) -> {"findings": {cve: [detail, ...]}, "meta": {...}} used by the matrix."""
from . import needrestart, osv, trivy, vuls

FILE_SCANNERS = {"trivy": trivy, "osv-scanner": osv}
LIVE_SCANNERS = {"vuls": vuls, "needrestart": needrestart}

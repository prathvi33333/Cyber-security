import nmap
import requests
from report import generate_report

# NVD API for vulnerabilities
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def scan_target(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-sV")  # service detection
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port].get('version', '')
                results.append({
                    "host": host,
                    "port": port,
                    "service": service,
                    "version": version
                })
    return results

def fetch_cves(service):
    try:
        response = requests.get(NVD_API, params={"keywordSearch": service}, timeout=10)
        if response.status_code == 200:
            cves = response.json().get("vulnerabilities", [])
            return [c["cve"]["id"] for c in cves[:3]]  # return top 3 CVEs
    except:
        pass
    return []

if __name__ == "__main__":
    target = input("Enter target IP/Domain: ")
    scan_results = scan_target(target)

    full_report = []
    for res in scan_results:
        vulns = fetch_cves(res["service"])
        res["vulnerabilities"] = vulns
        full_report.append(res)

    # Generate PDF Report
    generate_report(target, full_report)
    print("[+] Scan complete. Report saved as report.pdf")
  

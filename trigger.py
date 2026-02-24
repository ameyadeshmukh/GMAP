from tasks import run_nmap, run_nuclei

repo = "https://github.com/example/repo"

nmap_result = run_nmap.delay(repo)
nuclei_result = run_nuclei.delay(repo)

print("NMAP scan:")
print(nmap_result.state)
print(nmap_result.get())
print(nmap_result.state)

print("Nuclei scan:")
print(nuclei_result.state)
print(nuclei_result.get())
print(nuclei_result.state)

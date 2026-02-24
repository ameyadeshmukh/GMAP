from GMAP.backend.tasks import run_nmap, run_nuclei

repo = "https://github.com/example/repo"

run_nmap.delay(repo)
run_nuclei.delay(repo)

print("Tasks submitted")
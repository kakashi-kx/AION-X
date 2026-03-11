from fastapi import FastAPI
from backend.scanner import run_scan
from modules.recon.subdomain_scanner import find_subdomains

app = FastAPI()

@app.get("/")
def home():
    return {"message": "AION-X API running"}

@app.get("/scan")
def scan(target: str):
    return run_scan(target)

@app.get("/subdomains")
def subdomains(domain: str):
    return find_subdomains(domain)

from fastapi import FastAPI
from backend.scanner import run_scan
from modules.recon.subdomain_scanner import find_subdomains
from modules.recon.wayback_urls import get_wayback_urls

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

@app.get("/wayback")
def wayback(domain: str):
    return get_wayback_urls(domain)

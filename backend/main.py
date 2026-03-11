from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from backend.scanner import run_scan
from modules.recon.subdomain_scanner import find_subdomains
from modules.recon.wayback_urls import get_wayback_urls
from modules.recon.otx_urls import get_otx_urls
from modules.recon.recon_engine import run_full_recon

app = FastAPI(title="AION-X API")

# Enable CORS so frontend JS can call API easily
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # you can restrict this to your frontend domain later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")

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

@app.get("/otx")
def otx(domain: str):
    return get_otx_urls(domain)

@app.get("/recon")
async def recon(domain: str):
    return await run_full_recon(domain)

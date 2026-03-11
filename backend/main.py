from fastapi import FastAPI
from backend.scanner import run_scan

app = FastAPI()

@app.get("/")
def home():
    return {"message": "AION-X API running"}

@app.get("/scan")
def scan(target: str):

    result = run_scan(target)

    return result

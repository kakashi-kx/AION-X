def build_attack_surface(recon_data):

    endpoints = set()

    endpoints.update(recon_data["js_endpoints"].get("endpoints", []))
    endpoints.update(recon_data["wayback"].get("urls", []))
    endpoints.update(recon_data["otx_urls"].get("urls", []))

    params = recon_data["parameters"].get("parameters", [])

    return {
        "endpoints": list(endpoints),
        "parameters": params
    }

import requests
import csv
from ntiva_constants import IGNORE


def write_out(headers_list, input_list, output_file):
    with open(output_file, 'w', encoding='utf-8', newline='') as output_csv:
        writer = csv.writer(output_csv, quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(headers_list)
        writer.writerows(input_list)


def get_all_items(base_url, headers):
    items = []
    page = 1

    while True:
        resp = requests.get(base_url, headers=headers, params={
            "pageSize": 100,
            "pageTotal": "true",
            "page": page
        })
        if resp.status_code == 200:
            data = resp.json()
            page_items = data.get("items", [])
            pages = data.get("pages", {})
            total_items = pages.get("items", 0)

            items.extend(page_items)
            print(f"  Page {page}: fetched {len(page_items)} (total so far: {len(items)} of {total_items})")

            if len(items) >= total_items or len(page_items) == 0:
                break

            page += 1
        else:
            print(f"  Failed ({resp.status_code}): {base_url} – {resp.text}")
            break

    return items


def extract_value(item):
    """Different exclusion types store their value in different fields."""
    return (
        item.get("value")       # path, posixPath, virtualPath, process, web, pua
        or item.get("path")     # some older responses
        or item.get("appName")  # exploitMitigation
        or item.get("name")     # behavioral, pua fallback
        or ""
    )

def process_export(client_id, client_secret, exclusion_out, allowed_out):
    export_list = []
    allowed_list = []

    exclusion_headers = ['type', 'value']
    allowed_headers   = ['name', 'allowed_by']
    params = {"pageSize": 100, "pageTotal": "true"}

    #Get Access Token
    auth_url = "https://id.sophos.com/api/v2/oauth2/token"
    auth_data = {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "token",
    }
    response = requests.post(auth_url, data=auth_data)
    if response.status_code == 200:
        access_token = response.json()["access_token"]
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept":        "application/json",
        }
        print("Authentication successful.")
    else:
        print(f"Authentication failed: {response.status_code} – {response.text}")
        exit()


    # get tenantId + correct regional API host
    whoami_url = "https://api.central.sophos.com/whoami/v1"
    whoami_resp = requests.get(whoami_url, headers=headers)
    if whoami_resp.status_code == 200:
        whoami = whoami_resp.json()
        tenant_id  = whoami["id"]
        api_host   = whoami["apiHosts"]["dataRegion"]
        print(f"Tenant ID : {tenant_id}")
        print(f"API Host  : {api_host}")
        # Add tenant header — required for all subsequent calls
        headers["X-Tenant-ID"] = tenant_id
    else:
        print(f"Whoami failed: {whoami_resp.status_code} – {whoami_resp.text}")
        exit()


    #  Pull Global Scanning Exclusions
    exclusion_endpoints = {
        "scanning":  f"{api_host}/endpoint/v1/settings/exclusions/scanning",
        "websites":  f"{api_host}/endpoint/v1/settings/exclusions/websites",
        "exploits":  f"{api_host}/endpoint/v1/settings/exclusions/exploit-mitigation/applications",
        "amsi":      f"{api_host}/endpoint/v1/settings/exclusions/amsi",
    }

    exclusion_headers_csv = ["exclusion_type", "path", "value", "description"]
    export_list = []

    print("\n--- Global Scanning Exclusions ---")
    for excl_type, url in exclusion_endpoints.items():
        items = get_all_items(url, headers)
        print(f"  [{excl_type}] {len(items)} records found")

        for item in items:
            row = [
                item.get("type"),
                extract_value(item),
                item.get("description", ""),
                item.get("scanMode", ""),   # realTime, scheduled, or both — for path types
            ]
            ignore = 0
            for ignore_type in IGNORE:
                for cell in row:
                    if ignore_type.casefold() in cell.casefold():
                        ignore += 1
            if ignore == 0:
                export_list.append(row)


    write_out(exclusion_headers_csv, export_list, exclusion_out)


    # Pull Global Allowed Applications
    allowed_apps_url = f"{api_host}/endpoint/v1/settings/allowed-items"
    allowed_apps_response = requests.get(allowed_apps_url, headers=headers)
    if allowed_apps_response.status_code == 200:
        allowed_apps_data = allowed_apps_response.json()
        print("\n--- Global Allowed Applications ---")
        for app in allowed_apps_data.get("items", []):
            row = [app.get("name"), app.get("allowed_by")]
            print(f"  Name: {row[0]}, Allowed by: {row[1]}")
            allowed_list.append(row)
    else:
        print(f"Failed to retrieve allowed apps: {allowed_apps_response.status_code} – {allowed_apps_response.text}")

    write_out(allowed_headers, allowed_list, allowed_out)
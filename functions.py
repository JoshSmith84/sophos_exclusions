import requests
import csv
from ntiva_constants import EX_IGNORE, AL_IGNORE


def write_out(headers_list, input_list, output_file):
    with open(output_file, 'w', encoding='utf-8', newline='') as output_csv:
        writer = csv.writer(output_csv, quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(headers_list)
        writer.writerows(input_list)


def filter_csv_rows(row, filter_list, output_list):
    ignore = 0
    for ignore_type in filter_list:
        for cell in row:
            if ignore_type.casefold() in cell.casefold():
                ignore += 1
    if ignore == 0:
        output_list.append(row)


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


def process_export(sophos_id, sophos_secret, exclusions_out, allowed_out, status_callback=None):

    def update(msg):
        if status_callback:
            status_callback(msg)

    exclude_list = []
    exclude_headers = ["exclusion_type", "path", "value", "description"]
    allowed_list = []
    allowed_headers = ['path', 'type', 'comment', 'created_at', 'updated_at']

    update("Authenticating...")

    #Get Access Token
    auth_url = "https://id.sophos.com/api/v2/oauth2/token"
    auth_data = {
        "grant_type":    "client_credentials",
        "client_id":     sophos_id,
        "client_secret": sophos_secret,
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
        update("Authentication failed! Check your Client ID or Client Secret")
        return None, None

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
        whoami_error = f"Whoami failed: {whoami_resp.status_code} – {whoami_resp.text}"
        print(whoami_error)
        update(whoami_error)

    update("Fetching exclusions...")

    #  Pull Global Scanning Exclusions
    exclusion_endpoints = {
        "scanning":  f"{api_host}/endpoint/v1/settings/exclusions/scanning",
        "websites":  f"{api_host}/endpoint/v1/settings/exclusions/websites",
        "exploits":  f"{api_host}/endpoint/v1/settings/exclusions/exploit-mitigation/applications",
        "amsi":      f"{api_host}/endpoint/v1/settings/exclusions/amsi",
    }

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
            filter_csv_rows(row, EX_IGNORE, exclude_list)

    update("Writing exclusions...")
    exclude_count = len(exclude_list)
    if exclude_count > 0:
        write_out(exclude_headers, exclude_list, exclusions_out)

    update("Fetching allowed apps...")
    # Pull Global Allowed Applications
    allowed_apps_url = f"{api_host}/endpoint/v1/settings/allowed-items"
    allowed_apps_response = requests.get(allowed_apps_url, headers=headers)

    if allowed_apps_response.status_code == 200:
        allowed_apps_data = allowed_apps_response.json()
        for item in allowed_apps_data.get("items", []):
            row = [
                item.get("properties", {}).get("path"),
                item.get("type"),
                item.get("comment", ""),
                item.get("createdAt", ""),
                item.get("updatedAt", ""),
            ]
            filter_csv_rows(row, AL_IGNORE, allowed_list)

    else:
        print(f"Failed to retrieve allowed apps: {allowed_apps_response.status_code} – {allowed_apps_response.text}")

    allowed_count = len(allowed_list)
    if allowed_count > 0:
        write_out(allowed_headers, allowed_list, allowed_out)

    return exclude_count, allowed_count
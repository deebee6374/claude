"""
fix_project_reference.py

Populates the "Project Reference" lookup column on the Dataverse
Project Assignment table (crce4_projectassignment) by matching each
row to a Projects_V3 record (crce4_projects_v3) on ProjectNumber
(crce4_projectnumber).

Intended location on the target machine:
    C:\\BidDesk\\fix_project_reference.py

Log file written to:
    C:\\BidDesk\\fix_project_reference_log.txt

Setup:
    pip install msal requests

Authentication:
    Uses MSAL's device code flow, so no custom Azure AD app
    registration is required. It authenticates with a well-known
    Microsoft first-party public client ID (the "Azure PowerShell"
    client) that is pre-consented in virtually every tenant for
    Dynamics CRM / Dataverse access. Running the script will print a
    URL and a short code -- open the URL in any browser, enter the
    code, and sign in with an account that has access to the
    Dataverse environment.

    If your tenant blocks public client / device code sign-ins via
    Conditional Access, you'll need to register your own Azure AD
    app (public client, "Allow public client flows" = Yes) and set
    CLIENT_ID below to that app's Application (client) ID.
"""

import logging
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple

import msal
import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

TENANT_ID = "62733cf2-3cb1-466a-a95f-8bd76baac8de"
DATAVERSE_URL = "https://org8a0356fe.crm.dynamics.com"

# Well-known Microsoft first-party public client ("Microsoft Azure
# PowerShell"). Pre-consented in most tenants for Dataverse access,
# which is what lets device code flow work without a custom app
# registration.
CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc7"

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = [f"{DATAVERSE_URL}/.default"]

API_VERSION = "v9.2"
API_ROOT = f"{DATAVERSE_URL}/api/data/{API_VERSION}"

ASSIGNMENT_LOGICAL_NAME = "crce4_projectassignment"
PROJECT_LOGICAL_NAME = "crce4_projects_v3"
PROJECT_NUMBER_FIELD = "crce4_projectnumber"

# Logical name of the lookup field on crce4_projectassignment that
# points to crce4_projects_v3 (the "Project Reference" column). Leave
# as None to auto-discover it from Dataverse relationship metadata;
# set it explicitly here if you already know it (e.g.
# "crce4_projectreference") to skip the lookup.
LOOKUP_FIELD_LOGICAL_NAME: Optional[str] = None

LOG_FILE = r"C:\BidDesk\fix_project_reference_log.txt"

PAGE_SIZE = 5000
MAX_RETRIES = 5
RETRY_BACKOFF_SECONDS = 5

# --------------------------------------------------------------------------
# Logging setup
# --------------------------------------------------------------------------

logger = logging.getLogger("fix_project_reference")
logger.setLevel(logging.DEBUG)

_file_handler = logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8")
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
)
logger.addHandler(_file_handler)

_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(_console_handler)


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def get_access_token() -> str:
    app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)

    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
        if result and "access_token" in result:
            logger.info("Reused cached token for %s", accounts[0].get("username"))
            return result["access_token"]

    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise RuntimeError(f"Failed to create device flow: {flow}")

    logger.info(flow["message"])
    print(flow["message"])

    result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        error = result.get("error")
        description = result.get("error_description")
        raise RuntimeError(f"Authentication failed: {error} - {description}")

    logger.info("Authentication succeeded.")
    return result["access_token"]


# --------------------------------------------------------------------------
# Dataverse Web API helpers
# --------------------------------------------------------------------------

def build_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
    }


def request_with_retry(
    method: str, url: str, headers: Dict[str, str], **kwargs
) -> requests.Response:
    attempt = 0
    while True:
        attempt += 1
        response = requests.request(method, url, headers=headers, **kwargs)

        if response.status_code == 429 or response.status_code >= 500:
            if attempt >= MAX_RETRIES:
                return response
            retry_after = int(
                response.headers.get("Retry-After", RETRY_BACKOFF_SECONDS)
            )
            logger.warning(
                "Request to %s returned %s, retrying in %ss (attempt %s/%s)",
                url,
                response.status_code,
                retry_after,
                attempt,
                MAX_RETRIES,
            )
            time.sleep(retry_after)
            continue

        return response


def get_entity_set_name(headers: Dict[str, str], logical_name: str) -> str:
    url = (
        f"{API_ROOT}/EntityDefinitions(LogicalName='{logical_name}')"
        "?$select=EntitySetName"
    )
    response = request_with_retry("GET", url, headers)
    response.raise_for_status()
    return response.json()["EntitySetName"]


def discover_lookup_field(headers: Dict[str, str]) -> str:
    """Find the logical name of the lookup field on
    crce4_projectassignment that references crce4_projects_v3, by
    inspecting Dataverse relationship metadata."""
    url = (
        f"{API_ROOT}/EntityDefinitions(LogicalName='{ASSIGNMENT_LOGICAL_NAME}')"
        "/ManyToOneRelationships"
        "?$select=ReferencingAttribute,ReferencedEntity,SchemaName"
    )
    response = request_with_retry("GET", url, headers)
    response.raise_for_status()
    relationships = response.json().get("value", [])

    matches = [
        rel
        for rel in relationships
        if rel.get("ReferencedEntity") == PROJECT_LOGICAL_NAME
    ]

    if not matches:
        raise RuntimeError(
            f"Could not find a lookup field on {ASSIGNMENT_LOGICAL_NAME} "
            f"that references {PROJECT_LOGICAL_NAME}. Set "
            "LOOKUP_FIELD_LOGICAL_NAME manually at the top of the script."
        )

    if len(matches) > 1:
        names = ", ".join(m["ReferencingAttribute"] for m in matches)
        logger.warning(
            "Multiple lookup fields reference %s: %s. Using the first one. "
            "Set LOOKUP_FIELD_LOGICAL_NAME explicitly if this is wrong.",
            PROJECT_LOGICAL_NAME,
            names,
        )

    field_name = matches[0]["ReferencingAttribute"]
    logger.info("Discovered lookup field: %s", field_name)
    return field_name


def get_all_records(
    headers: Dict[str, str], entity_set: str, select_fields: Iterable[str]
) -> List[dict]:
    select = ",".join(select_fields)
    url = f"{API_ROOT}/{entity_set}?$select={select}&$top={PAGE_SIZE}"

    records: List[dict] = []
    while url:
        response = request_with_retry("GET", url, headers)
        response.raise_for_status()
        payload = response.json()
        records.extend(payload.get("value", []))
        url = payload.get("@odata.nextLink")

    return records


def update_lookup(
    headers: Dict[str, str],
    assignment_entity_set: str,
    assignment_id: str,
    lookup_field: str,
    project_entity_set: str,
    project_id: str,
) -> None:
    url = f"{API_ROOT}/{assignment_entity_set}({assignment_id})"
    body = {f"{lookup_field}@odata.bind": f"/{project_entity_set}({project_id})"}

    response = request_with_retry("PATCH", url, headers, json=body)
    if response.status_code not in (200, 204):
        raise RuntimeError(
            f"HTTP {response.status_code}: {response.text.strip()}"
        )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> None:
    logger.info("=" * 70)
    logger.info("Starting Project Reference lookup fix-up")
    logger.info("Dataverse URL: %s", DATAVERSE_URL)
    logger.info("Tenant ID: %s", TENANT_ID)

    token = get_access_token()
    headers = build_headers(token)

    assignment_entity_set = get_entity_set_name(headers, ASSIGNMENT_LOGICAL_NAME)
    project_entity_set = get_entity_set_name(headers, PROJECT_LOGICAL_NAME)
    logger.info("Project Assignment entity set: %s", assignment_entity_set)
    logger.info("Projects_V3 entity set: %s", project_entity_set)

    lookup_field = LOOKUP_FIELD_LOGICAL_NAME or discover_lookup_field(headers)

    assignment_id_field = f"{ASSIGNMENT_LOGICAL_NAME}id"
    project_id_field = f"{PROJECT_LOGICAL_NAME}id"

    logger.info("Retrieving Project Assignment rows...")
    assignments = get_all_records(
        headers,
        assignment_entity_set,
        [assignment_id_field, PROJECT_NUMBER_FIELD],
    )
    logger.info("Retrieved %s Project Assignment rows.", len(assignments))

    logger.info("Retrieving Projects_V3 rows...")
    projects = get_all_records(
        headers, project_entity_set, [project_id_field, PROJECT_NUMBER_FIELD]
    )
    logger.info("Retrieved %s Projects_V3 rows.", len(projects))

    # Build ProjectNumber -> project id map, warning on duplicates.
    project_by_number: Dict[str, str] = {}
    duplicate_numbers: Dict[str, int] = {}
    for project in projects:
        number = project.get(PROJECT_NUMBER_FIELD)
        if not number:
            continue
        number = str(number).strip()
        if number in project_by_number:
            duplicate_numbers[number] = duplicate_numbers.get(number, 1) + 1
            continue
        project_by_number[number] = project[project_id_field]

    for number, count in duplicate_numbers.items():
        logger.warning(
            "ProjectNumber '%s' appears on %s Projects_V3 records; "
            "using the first one encountered.",
            number,
            count,
        )

    success_count = 0
    failure_count = 0
    unmatched_count = 0

    for assignment in assignments:
        assignment_id = assignment[assignment_id_field]
        raw_number = assignment.get(PROJECT_NUMBER_FIELD)
        number = str(raw_number).strip() if raw_number else ""

        if not number:
            unmatched_count += 1
            logger.warning(
                "UNMATCHED: Assignment %s has no ProjectNumber value.",
                assignment_id,
            )
            continue

        project_id = project_by_number.get(number)
        if not project_id:
            unmatched_count += 1
            logger.warning(
                "UNMATCHED: Assignment %s ProjectNumber '%s' has no "
                "matching Projects_V3 record.",
                assignment_id,
                number,
            )
            continue

        try:
            update_lookup(
                headers,
                assignment_entity_set,
                assignment_id,
                lookup_field,
                project_entity_set,
                project_id,
            )
            success_count += 1
            logger.info(
                "SUCCESS: Assignment %s (ProjectNumber '%s') -> "
                "Projects_V3 %s",
                assignment_id,
                number,
                project_id,
            )
        except Exception as exc:
            failure_count += 1
            logger.error(
                "FAILURE: Assignment %s (ProjectNumber '%s') -> "
                "Projects_V3 %s: %s",
                assignment_id,
                number,
                project_id,
                exc,
            )

    logger.info("=" * 70)
    logger.info("Run complete.")
    logger.info("  Total Project Assignment rows: %s", len(assignments))
    logger.info("  Updated successfully: %s", success_count)
    logger.info("  Failed updates: %s", failure_count)
    logger.info("  Unmatched rows: %s", unmatched_count)
    logger.info("Log written to: %s", LOG_FILE)


if __name__ == "__main__":
    main()

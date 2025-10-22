#!/usr/bin/env python3
"""
find_drive_folders.py

Search Google Drive (My Drive + Shared Drives) for folders whose names match a list.
Outputs folders_found.csv with: id, name, full_path, drive_type, drive_id, owners, createdTime, modifiedTime

Auth: Service account with domain-wide delegation (best for eDiscovery) OR user OAuth.
Scopes: https://www.googleapis.com/auth/drive.metadata.readonly

Usage examples:
  python find_drive_folders.py --names "Finance;HR;Project Phoenix" --match contains
  python find_drive_folders.py --names-file folder_names.txt --match exact
  python find_drive_folders.py --drive-id 0AFxxxxx (to target one Shared Drive)
"""

import argparse
import csv
import os
import sys
from typing import Dict, List, Optional, Tuple
from collections import deque

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# ---------- Auth helpers ----------
def get_drive_service_with_sa(sa_path: str, subject: Optional[str] = None):
    scopes = ["https://www.googleapis.com/auth/drive.metadata.readonly"]
    creds = service_account.Credentials.from_service_account_file(sa_path, scopes=scopes)
    if subject:
        creds = creds.with_subject(subject)  # domain-wide delegation to an admin or target user
    return build("drive", "v3", credentials=creds, cache_discovery=False)

# ---------- Path reconstruction with caching ----------
def build_path_for_item(drive, file_id: str, cache: Dict[str, dict]) -> Tuple[str, str, str]:
    """
    Returns (full_path, drive_type, drive_id) for the item by walking parents.
    Caches metadata to minimize API calls.
    """
    path_parts = deque()
    current_id = file_id
    drive_type = "myDrive"
    drive_id = ""

    while current_id:
        if current_id in cache:
            meta = cache[current_id]
        else:
            meta = drive.files().get(
                fileId=current_id,
                fields="id,name,parents,driveId,teamDriveId",
                supportsAllDrives=True,
            ).execute()
            cache[current_id] = meta

        name = meta.get("name", "")
        parents = meta.get("parents", [])
        path_parts.appendleft(name)

        # Record drive identifiers if present
        if meta.get("driveId"):
            drive_id = meta["driveId"]
            drive_type = "sharedDrive"
        elif meta.get("teamDriveId"):  # legacy field
            drive_id = meta["teamDriveId"]
            drive_type = "sharedDrive"

        if not parents:
            break
        # In Drive, most items have a single parent; multiple parents are rare since 2017
        current_id = parents[0]

    full_path = "/".join(path_parts)
    return full_path, drive_type, drive_id

# ---------- Core search ----------
def search_folders(
    drive,
    targets: List[str],
    match: str = "contains",
    drive_id: Optional[str] = None,
) -> List[dict]:
    """
    Searches for folders whose name matches any of the targets.
    match = 'contains' (case-insensitive) or 'exact' (case-insensitive)
    Optionally restrict to a single Shared Drive (drive_id).
    """
    results = []
    fields = "nextPageToken, files(id,name,parents,owners,createdTime,modifiedTime,driveId)"
    base_filters = "mimeType='application/vnd.google-apps.folder' and trashed=false"

    # API-side name matching is case-sensitive. We’ll fetch candidates, then apply case-insensitive filtering locally.
    # To keep candidate sets small, we use a broad contains query for each target.
    def candidate_query_for(target: str) -> str:
        # Gentle broadening to keep total pages reasonable
        t = target.replace("'", "\\'")
        return f"{base_filters} and name contains '{t}'"

    # When targeting a single Shared Drive
    corpora = "allDrives"
    kwargs = {
        "includeItemsFromAllDrives": True,
        "supportsAllDrives": True,
        "pageSize": 1000,
        "fields": fields,
    }
    if drive_id:
        corpora = "drive"
        kwargs.update({"corpora": corpora, "driveId": drive_id})
    else:
        kwargs.update({"corpora": corpora})

    seen_ids = set()

    for target in targets:
        page_token = None
        while True:
            try:
                resp = drive.files().list(
                    q=candidate_query_for(target),
                    pageToken=page_token,
                    **kwargs,
                ).execute()
            except HttpError as e:
                print(f"[ERROR] Drive API list failed: {e}", file=sys.stderr)
                break

            for f in resp.get("files", []):
                if f["id"] in seen_ids:
                    continue
                name = f.get("name", "")
                if match.lower() == "exact":
                    if name.lower() != target.lower():
                        continue
                else:
                    if target.lower() not in name.lower():
                        continue
                results.append(f)
                seen_ids.add(f["id"])

            page_token = resp.get("nextPageToken")
            if not page_token:
                break

    return results

# ---------- Owners helper ----------
def owner_str(owners: List[dict]) -> str:
    if not owners:
        return ""
    names = []
    for o in owners:
        display = o.get("displayName") or o.get("emailAddress") or "Unknown"
        email = o.get("emailAddress")
        names.append(f"{display} <{email}>" if email else display)
    return "; ".join(names)

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="Find folders in Google Drive by name.")
    ap.add_argument("--service-account", help="Path to service account JSON", required=True)
    ap.add_argument("--delegate", help="User to impersonate (domain-wide delegation)", required=False)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--names", help="Semicolon-separated list of target folder names")
    group.add_argument("--names-file", help="Text file with one folder name per line")
    ap.add_argument("--match", choices=["contains", "exact"], default="contains", help="Match mode (case-insensitive)")
    ap.add_argument("--drive-id", help="Limit search to a specific Shared Drive ID", required=False)
    ap.add_argument("--out", default="folders_found.csv", help="Output CSV path")
    args = ap.parse_args()

    # Collect targets
    if args.names:
        targets = [s.strip() for s in args.names.split(";") if s.strip()]
    else:
        with open(args.names_file, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]

    if not targets:
        print("No targets provided.", file=sys.stderr)
        sys.exit(1)

    drive = get_drive_service_with_sa(args.service_account, args.delegate)

    print(f"Searching for {len(targets)} target name(s) with match={args.match} ...")
    hits = search_folders(drive, targets, match=args.match, drive_id=args.drive_id)
    print(f"Candidate folders found: {len(hits)}")

    # Build path + flatten owners
    path_cache: Dict[str, dict] = {}
    rows = []
    for f in hits:
        full_path, drive_type, drv_id = build_path_for_item(drive, f["id"], path_cache)
        rows.append({
            "id": f["id"],
            "name": f.get("name", ""),
            "full_path": full_path,
            "drive_type": drive_type,
            "drive_id": drv_id or f.get("driveId", ""),
            "owners": owner_str(f.get("owners", [])),
            "createdTime": f.get("createdTime", ""),
            "modifiedTime": f.get("modifiedTime", ""),
        })

    # Write CSV
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=[
            "id", "name", "full_path", "drive_type", "drive_id",
            "owners", "createdTime", "modifiedTime"
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} folder record(s) to {args.out}")

if __name__ == "__main__":
    main()

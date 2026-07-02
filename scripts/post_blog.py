"""
Post the technical blog to dev.to and Medium via their APIs.

Usage:
    python scripts/post_blog.py --devto --api-key YOUR_DEVTO_KEY
    python scripts/post_blog.py --medium --api-key YOUR_MEDIUM_KEY

dev.to: https://dev.to/settings/extensions → generate API key
Medium: https://medium.com/me/settings → integration tokens
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BLOG_PATH = REPO_ROOT / "docs" / "blog" / "why-your-sast-misses-86-percent.md"
BLOG_URL = "https://ansede.onrender.com/blog"
CANONICAL_URL = BLOG_URL
TAGS = ["security", "python", "devops", "sast", "cybersecurity", "webdev"]


def read_blog():
    raw = BLOG_PATH.read_text(encoding="utf-8")
    # Strip frontmatter
    if raw.startswith("---"):
        end = raw.find("---", 3)
        if end != -1:
            raw = raw[end + 3:].strip()
    # Get title from first heading
    lines = raw.split("\n")
    title = next((l.lstrip("# ").strip() for l in lines if l.startswith("# ")), None)
    return title, raw


def post_devto(api_key, title, body, dry_run=False):
    """Post to dev.to via API."""
    url = "https://dev.to/api/articles"
    data = {
        "article": {
            "title": title,
            "body_markdown": body,
            "published": True,
            "tags": TAGS,
            "canonical_url": CANONICAL_URL,
            "description": "A data-driven comparison: why pattern-matching SAST tools miss 77% of CVEs, and how interprocedural taint analysis closes the gap.",
            "series": "SAST Deep-Dives",
        }
    }

    if dry_run:
        print("[DRY RUN] Would POST to dev.to:")
        print(f"  Title: {title}")
        print(f"  Body: {len(body)} chars")
        print(f"  Tags: {TAGS}")
        return

    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={
            "Content-Type": "application/json",
            "api-key": api_key,
            "User-Agent": "ansede-blog-bot/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as r:
            result = json.loads(r.read())
        print(f"✅ Posted to dev.to: {result.get('url', 'unknown')}")
        print(f"   Article ID: {result.get('id')}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"❌ dev.to error {e.code}: {body[:500]}")
        sys.exit(1)


def post_medium(api_key, title, body, dry_run=False):
    """Post to Medium via API."""
    # First get user info
    req = urllib.request.Request(
        "https://api.medium.com/v1/me",
        headers={
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "ansede-blog-bot/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            user = json.loads(r.read())
        user_id = user["data"]["id"]
        print(f"Medium user: {user['data']['name']} (ID: {user_id})")
    except urllib.error.HTTPError as e:
        print(f"❌ Medium auth error {e.code}: {e.read().decode()[:300]}")
        sys.exit(1)

    # Post article
    url = f"https://api.medium.com/v1/users/{user_id}/posts"
    data = {
        "title": title,
        "contentFormat": "markdown",
        "content": body,
        "tags": TAGS,
        "canonicalUrl": CANONICAL_URL,
        "publishStatus": "public",
    }

    if dry_run:
        print("[DRY RUN] Would POST to Medium:")
        print(f"  Title: {title}")
        print(f"  Body: {len(body)} chars")
        return

    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "ansede-blog-bot/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as r:
            result = json.loads(r.read())
        print(f"✅ Posted to Medium: {result.get('data', {}).get('url', 'unknown')}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"❌ Medium error {e.code}: {body[:500]}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Post technical blog to blogging platforms")
    parser.add_argument("--devto", action="store_true", help="Post to dev.to")
    parser.add_argument("--medium", action="store_true", help="Post to Medium")
    parser.add_argument("--api-key", help="API key for the platform")
    parser.add_argument("--dry-run", action="store_true", help="Preview without posting")
    args = parser.parse_args()

    title, body = read_blog()
    if not title:
        print("ERROR: Could not find title in blog post")
        sys.exit(1)

    print(f"Blog: '{title}' ({len(body)} characters)")
    print(f"Canonical URL: {CANONICAL_URL}")
    print()

    if args.devto:
        if not args.api_key:
            print("ERROR: --api-key required for dev.to. Get one at https://dev.to/settings/extensions")
            sys.exit(1)
        post_devto(args.api_key, title, body, args.dry_run)

    if args.medium:
        if not args.api_key:
            print("ERROR: --api-key required for Medium. Get one at https://medium.com/me/settings")
            sys.exit(1)
        post_medium(args.api_key, title, body, args.dry_run)

    if not args.devto and not args.medium:
        print("Specify --devto and/or --medium to post.")
        print("\nQuick start:")
        print("  python scripts/post_blog.py --devto --api-key YOUR_DEVTO_KEY --dry-run")
        print("  python scripts/post_blog.py --devto --api-key YOUR_DEVTO_KEY  # actually post")


if __name__ == "__main__":
    main()

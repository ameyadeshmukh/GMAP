def validate_target(url: str):
    # basic URL format
    if not url.startswith("http://") and not url.startswith("https://"):
        return False, "INVALID_FORMAT"

    # must be GitHub repo
    if "github.com" not in url:
        return False, "NOT_GITHUB_REPO"

    # must follow GitHub repo structure (github.com/user/repo)
    parts = url.replace("https://", "").replace("http://", "").split("/")

    if len(parts) < 3 or parts[1] == "" or parts[2] == "":
        return False, "INVALID_REPO_FORMAT"

    return True, "VALID"
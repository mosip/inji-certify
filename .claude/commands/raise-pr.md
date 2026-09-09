# raise-pr

Create a PR from a new branch in the fork to the upstream repo.

## Rules (always enforce, no exceptions)
- **Never push to `upstream`** — its push URL is intentionally set to `DISABLED`.
- **Always push to `origin`** (the personal fork).
- **Always target `upstream/develop`** as the PR base branch, unless the user explicitly specifies a different base.
- **No co-author lines** in commit messages (no `Co-Authored-By:` trailers).
- **No Claude attribution** in the PR body (no `🤖 Generated with Claude Code` footer).
- Branch names must follow the pattern: `feat/`, `fix/`, `docs/`, or `chore/` prefix.

## Steps

1. **Resolve remotes dynamically** — derive all values from git at runtime:
   ```
   git remote get-url origin    # e.g. https://github.com/alice/inji-certify.git
   git remote get-url upstream  # e.g. https://github.com/inji/inji-certify.git
   ```
   Parse these URLs to extract:
   - `FORK_OWNER` — the owner segment of the `origin` URL (e.g. `alice`)
   - `UPSTREAM_OWNER/UPSTREAM_REPO` — from the `upstream` URL (e.g. `inji/inji-certify`)

2. **Verify push to upstream is disabled**:
   ```
   git remote -v
   ```
   Confirm the `upstream` push URL shows `DISABLED`. Abort if it does not.

3. **Fetch latest base branch** from upstream (default: `develop`):
   ```
   git fetch upstream develop
   ```

4. **Create a branch from upstream/develop**:
   ```
   git checkout -b <branch-name> upstream/develop
   ```
   - Derive the branch name from the change being made.
   - Ask the user for a branch name if it is not clear from context.

5. **Stage and commit the changes** (all uncommitted/untracked work):
   ```
   git add <files>
   git commit -s -m "<concise subject line>

   <optional body explaining what and why>"
   ```
   - The `-s` flag adds a `Signed-off-by:` trailer (required by inji).
   - Do **not** add any `Co-Authored-By:` or attribution trailers.

6. **Push to the fork**:
   ```
   git push origin <branch-name>
   ```

7. **Create the PR** using the dynamically resolved values:
   ```
   gh pr create \
     --repo <UPSTREAM_OWNER>/<UPSTREAM_REPO> \
     --base develop \
     --head <FORK_OWNER>:<branch-name> \
     --title "<PR title>" \
     --body "<PR description>"
   ```
   - PR body should describe *what* changed and *why*. No Claude attribution footer.

8. **Report the PR URL** to the user.

## Arguments

Optional argument `$ARGUMENTS` may contain:
- A custom base branch (e.g. `master`) — if provided, use it instead of `develop`.
- A branch name or short description to use for naming the feature branch.

Parse `$ARGUMENTS` and apply accordingly before starting.

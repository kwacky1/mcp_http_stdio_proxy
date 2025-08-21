# Release Workflow Fix

## Problem

The build and release workflow didn't run when tags `v1.0.0` and `v1.0.1` were pushed because:

1. Tags were created and pushed on 2025-08-21T05:58:45Z
2. Release workflow was added later on 2025-08-21T16:00:05+10:00
3. GitHub Actions only trigger on events that occur AFTER the workflow file exists in the repository

## Solution

Enhanced the release workflow (`.github/workflows/release.yml`) to support both automatic and manual triggering:

### Changes Made

1. **Added `workflow_dispatch` trigger** with tag input parameter
2. **Added tag determination logic** to handle both automatic (tag push) and manual (workflow dispatch) events
3. **Updated checkout step** to use the determined tag reference
4. **Updated release creation** to use the correct tag name

### Usage

#### For Future Tags (Automatic)
```bash
git tag v1.0.2
git push origin v1.0.2
```

#### For Existing Tags (Manual)
1. Go to Actions → Build and Release workflow
2. Click "Run workflow"
3. Enter the tag name (e.g., `v1.0.0`)
4. Click "Run workflow"

## Testing

- ✅ YAML syntax validated
- ✅ Go build tested successfully
- ✅ Workflow supports both trigger methods
- ✅ Documentation updated in README.md

## Next Steps

To create releases for the existing tags:
1. Navigate to the repository's Actions tab
2. Select the "Build and Release" workflow  
3. Manually trigger it with `v1.0.0` and `v1.0.1` as inputs
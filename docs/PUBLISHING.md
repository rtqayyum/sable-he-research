# Publishing checklist

Use the clean public package only.

```bash
rsync -av --delete --exclude='.git' /path/to/sable_public_clean_v0.4.1/ ~/GitHub/sable-he-research/
cd ~/GitHub/sable-he-research
git status
git add .
git commit -m "Clean public release v0.4.1"
git pull --rebase origin main
git push origin main
git tag v0.4.1
git push origin v0.4.1
```

Build and upload only the current version:

```bash
rm -rf dist build *.egg-info src/*.egg-info
python -m build
python -m twine check dist/*
python -m twine upload dist/sable_he_research-0.4.1*
```

If private files were already pushed to GitHub history, removing them in a new commit is not enough. Rewrite history with a tool such as `git filter-repo` or recreate the repository, then rotate any exposed secrets.

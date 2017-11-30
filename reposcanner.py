#!/usr/bin/python3

import argparse
import binascii
import datetime
import math
import os
import re
import signal
import sys

from collections import Counter
try:
    from git import *
    from git.exc import NoSuchPathError
except ImportError:
    print("\nPython git module missing (apt-get install python-git)\n")
    sys.exit(1)

###########
# Classes #
###########
class col:
    if sys.stdout.isatty():
        green = '\033[32m'
        blue = '\033[94m'
        red = '\033[31m'
        brown = '\033[33m'
        end = '\033[0m'
    else:   # Colours mess up redirected output, disable them
        green = ""
        blue = ""
        red = ""
        brown = ""
        end = ""


class Commit():
    def __init__(self, sha, author, date, branch):
        self.paths = {}
        self.sha = sha
        self.date = datetime.datetime.utcfromtimestamp(date).strftime('%d/%m/%Y %H:%M:%S')
        self.author = author
        self.branch = branch

    def add_path(self, path):
        self.paths[path] = Path(path)

    def get_path(self, path):
        if path in self.paths:
            return path
        else:
            return False

    def add_item(self, path, key_string, full_string):
        self.paths[path].add_item(key_string, full_string)

    def get_items(self, path):
        return self.paths[path].get_items()


class Path():
    def __init__(self, path):
        self.path = path
        self.items = {}

    def add_item(self, key_string, full_string):
        self.items[key_string] = full_string

    def get_items(self):
        return self.items.items()

#############
# Functions #
#############

# Calculate entropy
def get_entropy(data):
    if len(data) <= 1:
        return 0
    p, lns = Counter(data), float(len(data))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())

def final_output(loot, error=False):
    for sha,commit in loot.items():
        print("%sCommit : %s@%s%s" % (col.blue, branch, sha, col.end))
        print("%sDate : %s%s" % (col.blue, commit.date, col.end))
        print("%sAuthor : %s%s" % (col.blue, commit.author, col.end))
        for path in commit.paths:
            print("%s%s%s" % (col.brown, path, col.end))
            for key,full in commit.get_items(path):
                output_string = full.replace(key, col.green + key + col.end)
                print(output_string)
            print("")
        print("")
    if error:
        sys.exit(1)
    else:
        sys.exit(0)

# Main parsing loop
def scan_branch(repo, branch, count):
    global loot, scanned_commits, regexes_key, regexes_full

    prev_commit = None
    print("Scanning branch %s" % str(branch))
    for count,commit in enumerate(repo.iter_commits(branch, max_count=args.count)):
        if sys.stdout.isatty():
            print("Parsing commit %s%s%s\r" % (col.green, count, col.end), end="", flush=True)
        if not prev_commit:
            prev_commit = commit
            continue
        sha = prev_commit.hexsha
        if sha in scanned_commits:
            prev_commit = commit
            continue
        diff = commit.diff(prev_commit)
        author = commit.author
        date = commit.authored_date
        for index in diff:
            path = index.a_path
            if path.lower().endswith(ignored_extensions) or path.lower().endswith(ignored_files):
                continue
            difftext = commit.diff(prev_commit, create_patch=True, paths=path)
            for blob in difftext:
                try:
                    lines = blob.diff.decode("utf-8").split("\n")
                except UnicodeDecodeError:
                    lines = str(blob.diff).split("\n")
                for line in lines:
                    if not line.startswith("+"):
                        continue
                    matches = re.findall("((^|\n).*?([a-zA-Z0-9+/=]{16,}|[A-Fa-f0-9]{12,).*?($|\n))", line[1:])
                    for m in matches:
                        entropy = 0
                        full_string = m[0].lstrip()
                        key_string = m[2]
                        # Very long strings are probably embeded files
                        if len(full_string) > args.length:
                            continue

                        entropy = get_entropy(key_string)
                        # Check if string is hexadecimal
                        try:
                            binascii.unhexlify(key_string)
                            # Lower entropy requirement for hex strings
                            entropy += 1.3
                        except ValueError:
                            pass
                        if entropy > args.entropy:
                            # Ignore certain patterns and strings we've already seen
                            if key_string in key_strings_found:
                                continue

                            # Check against regexes of boring patterns to include
                            matched = False
                            for regex in regexes_key:
                                if re.search(regex, key_string):
                                    matched = True
                                    break
                            if not matched:
                                for regex in regexes_full:
                                    if re.match(regex, full_string):
                                        matched = True
                                        break
                            if matched:
                                continue

                            key_strings_found.append(key_string)
                            if args.verbose:
                                print("%s : %s" % (entropy, key_string))

                            # Add the commit if it doesn't exist
                            if not sha in loot:
                                loot[sha] = Commit(sha, author, date, branch)
                            if loot[sha].get_path(path):
                                loot[sha].add_item(path, key_string, full_string)
                            else:
                                loot[sha].add_path(path)
                                loot[sha].add_item(path, key_string, full_string)
        prev_commit = commit
        scanned_commits.append(sha)
    print("")



# Declare some variables
key_strings_found = []
found = []
loot = {}
scanned_commits = []
ignored_extensions = (
                     ".css", ".woff", ".woff2", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".tiff",
                     ".ttf", ".eot", ".pyc", ".exe", ".dll", ".jar", ".apk", ".gz", ".zip", "csproj"
                     )
ignored_files = (
                "composer.lock",
                "vendor/composer/installed.json",
                "gemfile.lock",
                "yarn.lock",
                "package-lock.json"

                )
regexes_key = []
regexes_full = []

# Search for these strings in the key string
regexes_key.append(re.compile("[a-z]+/[a-z]+/[a-z]+/[a-z]+", re.IGNORECASE))    # Path
regexes_key.append(re.compile("abcdef", re.IGNORECASE))                         # Alphabet
regexes_key.append(re.compile("[a-z]+[A-Z][a-z]+[A-Z[a-z]+[A-Z][a-zA-Z]+"))     # camelCase
# Match against the full string
regexes_full.append(re.compile("Subproject commit [a-f0-9]{40}"))               # Subproject commit
regexes_full.append(re.compile("\"commit\": \"[a-f0-9]{40}\""))                 # Commit message
regexes_full.append(re.compile("publicKeyToken=\"[a-f0-9]{16}\""))              # .NET Public Key Token
regexes_full.append(re.compile(".*[a-f0-9]{12,}\.(css|js)", re.IGNORECASE))     # CSS or JS filenames
regexes_full.append(re.compile("[<>]{7} [a-f0-9]{40}", re.IGNORECASE))          # CSS or JS filenames

# Catch Ctrl+C
def signal_handler(signal, frame):
    print("%sCaught Ctrl+C, exiting..%s" % (col.red, col.end))
    final_output(loot, True)
signal.signal(signal.SIGINT, signal_handler)

# Parse arguments
parser = argparse.ArgumentParser('reposcanner.py', formatter_class=lambda prog:argparse.HelpFormatter(prog,max_help_position=40))
parser.add_argument('-r', '--repo', help='Repo to scan', dest='repo', required=True)
parser.add_argument('-c', '--count', help='Number of commits to scan (default 500)', dest='count', default=500, type=int)
parser.add_argument('-e', '--entropy', help='Minimum entropy to report (default 4.3)', dest='entropy', default=4.3, type=float)
parser.add_argument('-l', '--length', help='Maxmimum line length (default 500)', dest='length', default=500, type=int)
parser.add_argument('-a', '--all-branches', help='Scan all branches', dest='all_branches', action='store_true', default=False)
parser.add_argument('-b', '--branch', help='Branch to scan', dest='branch' )
parser.add_argument('-v', '--verbose', help='Verbose output', dest='verbose', action='store_true', default=False)
args = parser.parse_args()

# Check if repo exists locally, otherwise try and clone it
try:
    repo_name = args.repo.rsplit("/", 1)[1]
except IndexError:
    repo_name = args.repo
if os.path.isdir(repo_name):
    try:
        repo = Repo(repo_name)
        print("Using local copy of repo...")
    except NoSuchPathError:
        print(col.red + "Invalid repo " + repo_name + col.end)
        sys.exit(1)
else:
    try:
        print("Trying to clone repo %s from %s..." % (repo_name, args.repo))
        repo = Repo.clone_from(args.repo, repo_name)
        print("Repo cloned sucessfully.\n")
    except GitCommandError as e:
        print("\n%sFailed to clone repo%s\n" % (col.red, col.end))
        print(e)
        sys.exit(1)

branches = repo.refs
# Off by one
args.count += 1

# Get active branch if none specified
if not args.branch:
    branch = repo.active_branch
else:
    branch = "origin/" + args.branch
    try:
        branch = repo.heads[branch]
    except Exception as e:
        print(e)
        print("%sInvalid branch specified%s\n" % (col.red, col.end))
        sys.exit(1)

if args.all_branches:
    for branch in branches:
        # Skip tags, HEAD and any invalid branches
        if (
                isinstance(branch, TagReference)
                or str(branch) == "origin/HEAD"
                or not str(branch).startswith("origin")
           ):
            continue
        scan_branch(repo, branch, args.count)
else:
    scan_branch(repo, branch, args.count)


# Output
if sys.stdout.isatty():
    print("                                          \r", end="")

final_output(loot)


"""
"Antivirus"
"""

import os
from pathlib import Path
import click
import hashlib


def get_file_sha256_string(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest().upper()


def string_for_group(group, entries) -> str:
    entries = list(filter(lambda x: x[0] == group, entries))
    lines = []
    for type, name, orig_hash, new_hash in entries:
        line = f"{name} - {orig_hash}"
        if new_hash:
            line += f" -> {new_hash}"
        lines.append(line)
    return "\n".join(lines)


def save_report_entries(entries, path):
    origin_list = string_for_group("origin", entries)
    changed_list = string_for_group("changed", entries)
    infected_list = string_for_group("infected", entries)

    report = f"Origin hash:\n{origin_list}\nChanged:\n{changed_list}\nInfected:\n{infected_list}\n"

    with open(path, "w") as f:
        f.write(report)
    print(f"Wrote {path}")


def read_good_hash_list(good_hash_list_path):
    with open(good_hash_list_path, "r") as f:
        files_and_hashes = [line.strip().split(" ") for line in f.readlines()]
    return {k: v for k, v in files_and_hashes}


def read_bad_hash_list(bad_hash_list):
    with open(bad_hash_list, "r") as f:
        hashes = [line.strip() for line in f.readlines()]
    return set(hashes)


@click.group()
def antivirus():
    pass


@antivirus.command("scan_dir")
@click.argument("dir", type=click.Path(exists=True, file_okay=False))
@click.argument("bad_hash_list", type=click.Path(exists=True, dir_okay=False))
@click.argument("good_hash_list", type=click.Path(exists=True, dir_okay=False))
@click.argument("report_file", type=click.Path(exists=False))
def scan_dir(dir, bad_hash_list, good_hash_list, report_file):
    files = [Path(dir) / f for f in os.listdir(dir)]

    name_to_orig = read_good_hash_list(good_hash_list)
    bad_hash_set = read_bad_hash_list(bad_hash_list)

    report_entries = []

    for file in files:
        file_hash = get_file_sha256_string(file)
        origin_hash = name_to_orig.get(file.name, file_hash)
        matches_origin = file_hash == origin_hash
        is_bad_hash = file_hash in bad_hash_set

        match is_bad_hash, matches_origin:
            case True, True | False:
                report_entry = ("infected", file.name, origin_hash, file_hash)
            case False, False:
                report_entry = ("changed", file.name, origin_hash, file_hash)
            case False, True:
                report_entry = ("origin", file.name, origin_hash, None)
        report_entries.append(report_entry)

    save_report_entries(report_entries, report_file)


@antivirus.command("gen_hash_base")
@click.argument("dir", type=click.Path(exists=True))
@click.argument("hashlist_out", type=click.Path(exists=False))
def gen_hash_base(dir, hashlist_out):
    files = [Path(dir) / f for f in os.listdir(dir)]
    files_and_hashes = [f"{f.name} {get_file_sha256_string(f)}" for f in files]
    with open(hashlist_out, "w") as f:
        f.write("\n".join(files_and_hashes))
    print(f"Wrote {hashlist_out}")


if __name__ == "__main__":
    antivirus()

# python infosec_labs/5/antivirus.py gen_hash_base data/files data/HashList.txt
# python infosec_labs/5/antivirus.py scan_dir data/files_infected_17 data/VirusHashList.txt data/HashList.txt infosec_labs/5/report.txt

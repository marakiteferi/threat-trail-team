import zipfile, os, json

zip_dir = r"c:\Users\Golden Leaf\OneDrive\Documents\projects\ThreatTrail"
for fname in sorted(os.listdir(zip_dir)):
    if fname.endswith(".zip"):
        print(f"\n=== {fname} ===")
        zpath = os.path.join(zip_dir, fname)
        with zipfile.ZipFile(zpath) as zf:
            for info in zf.infolist()[:10]:
                print(f"  {info.filename}  ({info.file_size} bytes)")
            # Try to read a JSON file to see format
            for info in zf.infolist():
                if info.filename.endswith(".json"):
                    with zf.open(info) as f:
                        raw = f.read().decode("utf-8")
                        lines = [l.strip() for l in raw.strip().split("\n") if l.strip()]
                        print(f"  -> {len(lines)} JSON lines")
                        if lines:
                            first = json.loads(lines[0])
                            print(f"  -> First item keys: {list(first.keys())}")
                            print(f"  -> Sample: {json.dumps(first, indent=2)[:800]}")
                    break

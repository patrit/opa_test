#!//usr/bin/env python3

import sched, time, hashlib, json, subprocess

scheduler = sched.scheduler(time.time, time.sleep)

HASHES = {}
RENEW = False

def recreate_bundle():
    global RENEW
    if not RENEW:
        return
    print("recreate bundle")
    subprocess.call("opa build src --optimize=1 --entrypoint=authz -t wasm", shell=True, timeout = 10)
    subprocess.call("opa inspect bundle.tar.gz", shell=True, timeout = 10)
    RENEW = False
    scheduler.enter(5, 3, grab_gwg_education)

def grab_gwg_education() -> None:
    global RENEW
    print("running grab_gwg_education")
    filename = "src/gwg/data.json"
    # generate atm - request.get() afterwards
    data = [f"K{x:06d}" for x in range(1000)]
    datastr = json.dumps(data)
    hash = HASHES.get(filename, "")
    hashnew = hashlib.sha512(datastr.encode("utf-8")).hexdigest()
    if hash != hashnew:
        print(f"Creating {filename}: {hashnew}")
        with open(filename, "w") as fptr:
            fptr.write(datastr)
        RENEW = True
        HASHES[filename] = hashnew
    scheduler.enter(5, 1, grab_gwg_education)


def grab_dwh() -> None:
    global RENEW
    print("running grab_dwh")
    filename = "src/dwh/data.json"
    # generate atm - request.get() afterwards
    hierarchy = [f"B{x:06d}" for x in range(1000, 1010)]
    data = {f"B{x:06d}": hierarchy for x in range(100000)}
    datastr = json.dumps(data)
    hash = HASHES.get(filename, "")
    hashnew = hashlib.sha512(datastr.encode("utf-8")).hexdigest()
    if hash != hashnew:
        print(f"Creating {filename}: {hashnew}")
        with open(filename, "w") as fptr:
            fptr.write(datastr)
        RENEW = True
        HASHES[filename] = hashnew
    scheduler.enter(10, 2, grab_dwh)


if __name__ == "__main__":
    scheduler.enter(0, 1, grab_gwg_education)
    scheduler.enter(0, 2, grab_dwh)
    scheduler.enter(0, 3, recreate_bundle)
    scheduler.run()

#!/usr/bin/env python3
"""Deliver the OpenStack aggregate-capacity snapshot to a metrics database.

Runs the vendored collector (openstack-aggregate-capacity.py) with
--format prometheus, then delivers the snapshot one of two ways:

  push mode (VM_IMPORT_URL or VM_URL set): POSTs the snapshot to
  VictoriaMetrics' Prometheus text exposition import endpoint,
  /api/v1/import/prometheus. The output carries no timestamps, so
  VictoriaMetrics stamps each sample with the current time on arrival --
  exactly what a periodically pushed snapshot wants.

  publish mode (no VM URL set, CAPACITY_SNAPSHOT set): atomically writes
  the snapshot to that file and exits. Point it at node_exporter's textfile
  directory, e.g. /var/lib/node_exporter/textfile/openstack_capacity.prom,
  on a host that Prometheus (or vmagent) already scrapes, and the same
  5-minute snapshot reaches the database through the existing scrape path.
  Prometheus stamps the samples at scrape time, so a 5-minute refresh shows
  as steps between scrapes. A failed run leaves the last good file in
  place -- alert on freshness with
  changes(openstack_capacity_scrape_duration_seconds[15m]) == 0,
  because a dead publisher keeps serving the old, static file: the value
  still arrives with a fresh timestamp, but stops changing.

Designed to run from a systemd timer or cron on a management host that has
OpenStack credentials (clouds.yaml / OS_CLOUD / application credentials).
Configuration is via environment only, so the same script works identically
under systemd's EnvironmentFile, cron and an interactive shell.

Environment variables (all optional unless marked required):

    VM_IMPORT_URL     push mode target: the full import endpoint URL.
                      single-node VM:  https://vm.example.com/api/v1/import/prometheus
                      VM cluster:      http://vminsert:8480/insert/prometheus/<account>/api/v1/import/prometheus
                      Omit it (together with VM_URL) for publish mode.
    VM_URL            alternative to VM_IMPORT_URL: the base URL, the import
                      path is appended automatically
    VM_TOKEN          bearer token, sent as "Authorization: Bearer ..."
    VM_AUTH_HEADER    whole header, e.g. "Authorization: Basic <base64>";
                      takes precedence over VM_TOKEN. Use it when the front
                      door wants something other than a bearer token
    CAPACITY_SCRIPT   collector path
                      (default: openstack-aggregate-capacity.py beside this script)
    CAPACITY_ARGS     arguments for the collector (default: "--all")
    CAPACITY_TIMEOUT  wall-clock budget for the collector in seconds (default 600)
    CAPACITY_SNAPSHOT the delivered payload is also written here, atomically.
                      In publish mode (no VM URL configured) this file IS the
                      destination, e.g. node_exporter's
                      /var/lib/node_exporter/textfile/openstack_capacity.prom;
                      in push mode it is an inspection copy of what was sent
    VM_PUSH_RETRIES   retries after the first attempt (default 2)
    VM_PUSH_TIMEOUT   per-attempt HTTP timeout in seconds (default 60)
    VM_PUSH_SLEEP     seconds between attempts (default 2)
    VM_PUSH_LOCKFILE  lock file preventing overlapping runs
                      (default: ${TMPDIR:-/tmp}/openstack-capacity-metrics.lock)
    VM_PUSH_INSECURE  1 to skip TLS verification towards VictoriaMetrics

Exit codes:

    0  delivered: pushed, published to the textfile, or dry-run succeeded
    1  configuration error
    2  collector failed or produced an unusable snapshot
    3  push failed after retries
    4  a previous run still holds the lock

The openstack_capacity_scrape_success series emitted by the collector is the
staleness canary: alert on its absence (or time() - last_over_time(...) exceeding
two scheduled intervals) rather than on this script's exit code alone.
"""

import argparse
import fcntl
import os
import shlex
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

SINGLE_NODE_IMPORT_PATH = "/api/v1/import/prometheus"

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_COLLECTOR = 2
EXIT_PUSH = 3
EXIT_SKIPPED = 4


class Fatal(Exception):
    """Abort with a clean message instead of a traceback.

    Carries the exit code the caller should use, so the distinct failure
    classes stay distinguishable in logs and alerting.
    """

    def __init__(self, message, code=EXIT_CONFIG):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def resolve_import_url():
    """Return the VictoriaMetrics import endpoint URL, or None for publish mode.

    None (neither VM_IMPORT_URL nor VM_URL set) selects publish mode: the
    snapshot is written to CAPACITY_SNAPSHOT instead of being POSTed. The
    caller rejects the "no URL and no snapshot" combination separately.
    """
    url = os.environ.get("VM_IMPORT_URL", "").strip()
    base = os.environ.get("VM_URL", "").strip()
    if url and base:
        raise Fatal("set only one of VM_IMPORT_URL and VM_URL, not both")
    if not url and not base:
        return None
    if not url:
        url = base.rstrip("/") + SINGLE_NODE_IMPORT_PATH
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise Fatal("endpoint %r must start with http:// or https://" % url)
    return url


def auth_headers():
    """Build extra request headers from VM_AUTH_HEADER / VM_TOKEN."""
    raw = os.environ.get("VM_AUTH_HEADER", "").strip()
    token = os.environ.get("VM_TOKEN", "").strip()
    if raw and token:
        print(
            "warning: both VM_AUTH_HEADER and VM_TOKEN are set; using "
            "VM_AUTH_HEADER and ignoring VM_TOKEN",
            file=sys.stderr,
        )
    if raw:
        name, sep, value = raw.partition(":")
        if not sep or not name.strip() or not value.strip():
            raise Fatal(
                'VM_AUTH_HEADER must look like "Name: value", e.g. '
                '"Authorization: Basic <base64>"'
            )
        return {name.strip(): value.strip()}
    if token:
        return {"Authorization": "Bearer %s" % token}
    return {}


def env_int(name, default):
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        raise Fatal("%s must be an integer, got %r" % (name, raw))


def env_float(name, default):
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        raise Fatal("%s must be a number, got %r" % (name, raw))


def env_bool(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Run serialization
# ---------------------------------------------------------------------------


def acquire_lock(path):
    """Take the run lock; a lock held by a live previous run is a skip.

    The lock protects against a cron tick firing while the previous run is
    still busy against OpenStack or VictoriaMetrics. The skip is its own exit
    code (4) rather than a failure: the run that holds the lock is still the
    one reporting whatever happens next.
    """
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    except OSError as exc:
        raise Fatal("cannot open lock file %s: %s" % (path, exc))
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise Fatal(
            "a previous run still holds the lock %s - skipping this run" % path,
            code=EXIT_SKIPPED,
        )
    # The pid makes the lock file self-explanatory for anyone inspecting it.
    os.ftruncate(fd, 0)
    os.write(fd, ("%d\n" % os.getpid()).encode())
    return fd


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def default_collector_path():
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "openstack-aggregate-capacity.py"
    )


def run_collector(script, arguments, timeout):
    """Run the collector and return its Prometheus snapshot as bytes.

    The collector's stderr passes straight through to our stderr so its
    warnings reach the journal/cron mail without ever being mixed into the
    payload. --format prometheus is appended after CAPACITY_ARGS so a stale
    --format from an old configuration can never make us POST table output.
    """
    if not os.path.isfile(script):
        raise Fatal("collector script %s not found; set CAPACITY_SCRIPT" % script)
    command = [sys.executable, script] + arguments + ["--format", "prometheus"]
    try:
        proc = subprocess.run(command, stdout=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Fatal(
            "collector still running after %ss - gave up; a slow cloud should "
            "raise CAPACITY_TIMEOUT, a stuck one needs investigating" % timeout,
            code=EXIT_COLLECTOR,
        )
    if proc.returncode != 0:
        raise Fatal(
            "collector exited %d - not pushing; run '%s' manually to see why"
            % (proc.returncode, " ".join(command)),
            code=EXIT_COLLECTOR,
        )
    payload = proc.stdout
    if b"openstack_capacity_scrape_success" not in payload:
        raise Fatal(
            "collector output has no openstack_capacity_scrape_success series - "
            "not pushing a snapshot whose staleness could not be alerted on; "
            "the collector's warnings above should say why",
            code=EXIT_COLLECTOR,
        )
    return payload


# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------


def make_opener(insecure):
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context)
        )
    return urllib.request.build_opener()


def push(opener, url, payload, headers, attempts, timeout, sleep_s):
    """POST the snapshot; transient failures retry, client errors do not.

    HTTP 429 and 5xx, connection failures and timeouts are retried - those are
    the "VictoriaMetrics is briefly unreachable" cases. Any other HTTP status
    means the request itself is wrong (bad URL, bad auth, bad payload) and
    retrying would only hide the real problem, so it fails immediately.
    """
    last_error = None
    for attempt in range(1, attempts + 1):
        if attempt > 1:
            time.sleep(sleep_s)
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "text/plain; charset=utf-8", **headers},
            method="POST",
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                response.read()
                return
        except urllib.error.HTTPError as exc:
            body = exc.read(300).decode(errors="replace").strip()
            reason = "HTTP %s from %s: %s" % (exc.code, url, body)
            if exc.code != 429 and exc.code < 500:
                raise Fatal(reason, code=EXIT_PUSH)
            last_error = reason
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = "%s: %s" % (url, exc)
        if attempt < attempts:
            print(
                "push attempt %d/%d failed (%s) - retrying in %ss"
                % (attempt, attempts, last_error, sleep_s),
                file=sys.stderr,
            )
    raise Fatal(
        "push failed after %d attempt(s): %s" % (attempts, last_error),
        code=EXIT_PUSH,
    )


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


def write_snapshot(payload, path):
    """Atomically write the pushed payload, so a reader never sees a partial file."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(directory):
        raise Fatal("snapshot directory %s does not exist" % directory)
    fd, temporary = tempfile.mkstemp(
        dir=directory, prefix=".%s." % os.path.basename(path)
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except OSError as exc:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise Fatal("could not write snapshot %s: %s" % (path, exc))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Push an OpenStack hypervisor capacity snapshot to "
        "VictoriaMetrics. All configuration comes from the environment; "
        "see the module docstring or the README for the variables."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run the collector and report what would be delivered, but deliver "
        "nothing: no POST in push mode, no textfile write in publish mode. "
        "In push mode CAPACITY_SNAPSHOT is still written, as an inspection "
        "copy of the exact payload; in publish mode that file IS the "
        "delivery, so it is left untouched.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    started = time.monotonic()
    try:
        url = resolve_import_url()
        headers = auth_headers()
        snapshot = os.environ.get("CAPACITY_SNAPSHOT", "").strip()
        if url is None and not snapshot:
            raise Fatal(
                "no destination configured. Set VM_IMPORT_URL or VM_URL to push "
                "to VictoriaMetrics, and/or CAPACITY_SNAPSHOT to publish the "
                "snapshot as a textfile for Prometheus"
            )

        retries = env_int("VM_PUSH_RETRIES", 2)
        if retries < 0:
            raise Fatal("VM_PUSH_RETRIES must be >= 0")
        attempts = retries + 1
        push_timeout = env_int("VM_PUSH_TIMEOUT", 60)
        if push_timeout < 1:
            raise Fatal("VM_PUSH_TIMEOUT must be at least 1 second")
        sleep_s = env_float("VM_PUSH_SLEEP", 2.0)
        if sleep_s < 0:
            raise Fatal("VM_PUSH_SLEEP must be >= 0")
        collector_timeout = env_int("CAPACITY_TIMEOUT", 600)
        if collector_timeout < 1:
            raise Fatal("CAPACITY_TIMEOUT must be at least 1 second")

        lockfile = os.environ.get("VM_PUSH_LOCKFILE") or os.path.join(
            tempfile.gettempdir(), "openstack-capacity-metrics.lock"
        )
        lock_fd = acquire_lock(lockfile)
        try:
            collector = os.environ.get("CAPACITY_SCRIPT") or default_collector_path()
            collector_args = shlex.split(os.environ.get("CAPACITY_ARGS", "--all"))
            payload = run_collector(collector, collector_args, collector_timeout)
            series = sum(
                1
                for line in payload.splitlines()
                if line.strip() and not line.startswith(b"#")
            )

            if url is None:
                # Publish mode: the textfile IS the destination. A failed run
                # never replaces the last good file, Prometheus keeps serving
                # it, and the changes()-based staleness alert is the signal.
                if args.dry_run:
                    print(
                        "dry-run: would publish %d series (%d bytes) to %s"
                        % (series, len(payload), snapshot)
                    )
                else:
                    write_snapshot(payload, snapshot)
                    print(
                        "published %d series (%d bytes) to %s in %.1fs; no push "
                        "target configured - Prometheus picks this up via "
                        "node_exporter's textfile collector"
                        % (
                            series,
                            len(payload),
                            snapshot,
                            time.monotonic() - started,
                        )
                    )
                return EXIT_OK

            if args.dry_run:
                print(
                    "dry-run: would push %d series (%d bytes) to %s"
                    % (series, len(payload), url)
                )
            else:
                opener = make_opener(env_bool("VM_PUSH_INSECURE"))
                push(opener, url, payload, headers, attempts, push_timeout, sleep_s)
                print(
                    "pushed %d series (%d bytes) to %s in %.1fs"
                    % (series, len(payload), url, time.monotonic() - started)
                )

            if snapshot:
                # Push mode: an inspection copy of exactly what was sent.
                write_snapshot(payload, snapshot)
            return EXIT_OK
        finally:
            os.close(lock_fd)
    except Fatal as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return exc.code


if __name__ == "__main__":
    sys.exit(main())

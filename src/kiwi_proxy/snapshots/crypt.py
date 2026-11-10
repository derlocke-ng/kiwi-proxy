"""Encryption for snapshots: gpg, symmetric, AES-256, and nothing of our own.

Why gpg: it is on every machine these apps run on, and a snapshot opens by hand
without any kiwi app::

    gpg -d FILE.snap.gpg | zstd -d | tar -x

The passphrase reaches gpg through a pipe (``--passphrase-fd``), never through argv
or the environment. Every call gets a private, empty ``--homedir`` that is removed
afterwards, so the user's own ``~/.gnupg`` (keys, agent, configuration) is never
touched, and ``--no-symkey-cache`` keeps the passphrase out of any agent.

The passphrase is stretched with gpg's strongest setting (iterated and salted
SHA-512 at the maximum count). Every file uses it: an attacker goes for the
cheapest file, so there is no cheaper one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from .. import paths
from .errors import BadPassphrase, SnapshotError

S2K_COUNT = 65011712  # gpg's maximum; tests lower it for speed
TOOLS = ("gpg", "zstd")
CHUNK = 1 << 20


def missing_tools() -> list[str]:
    """The programs snapshots need that this machine lacks."""
    return [t for t in TOOLS if not shutil.which(t)]


@contextmanager
def _gpg_home() -> Iterator[str]:
    base = paths.runtime_dir()
    base.mkdir(parents=True, exist_ok=True)
    home = tempfile.mkdtemp(prefix="gpg-", dir=base)  # 0700
    try:
        yield home
    finally:
        if shutil.which("gpgconf"):
            subprocess.run(  # noqa: S603
                ["gpgconf", "--homedir", home, "--kill", "all"],
                capture_output=True,
                check=False,
            )
        shutil.rmtree(home, ignore_errors=True)


def _passphrase_fd(passphrase: str) -> int:
    """A pipe gpg reads the passphrase from; the read end is returned. The write end
    is filled and closed at once (a passphrase is far below a pipe's buffer)."""
    if not passphrase:
        raise SnapshotError("the passphrase is empty")
    if "\n" in passphrase or "\r" in passphrase:
        raise SnapshotError("a passphrase cannot contain a line break")
    read, write = os.pipe()
    try:
        os.write(write, passphrase.encode() + b"\n")
    finally:
        os.close(write)
    return read


def _gpg(home: str, fd: int) -> list[str]:
    return [
        "gpg",
        "--homedir",
        home,
        "--batch",
        "--quiet",
        "--no-tty",
        "--no-keyring",  # symmetric only: no key database is made or read
        "--no-symkey-cache",
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        str(fd),
    ]


def _encrypt_args(home: str, fd: int, out: Path) -> list[str]:
    return [
        *_gpg(home, fd),
        "--symmetric",
        "--cipher-algo",
        "AES256",
        "--s2k-mode",
        "3",
        "--s2k-digest-algo",
        "SHA512",
        "--s2k-count",
        str(S2K_COUNT),
        "--compress-algo",
        "none",  # zstd has compressed it already, and better
        "--output",
        str(out),
    ]


def _failure(stderr: bytes, what: str) -> SnapshotError:
    text = stderr.decode(errors="replace").strip()
    lowered = text.lower()
    if "bad session key" in lowered or "bad passphrase" in lowered:
        return BadPassphrase("the passphrase does not fit")
    last = text.splitlines()[-1] if text else "gpg failed"
    return SnapshotError(f"{what}: {last}")


def _read(fh) -> bytes:
    fh.seek(0)
    return fh.read()


# ------------------------------------------------------------- small payloads
def encrypt_bytes(data: bytes, out: Path, passphrase: str) -> None:
    """Encrypt `data` into the file `out` (which must not exist)."""
    with _gpg_home() as home:
        fd = _passphrase_fd(passphrase)
        try:
            proc = subprocess.run(  # noqa: S603
                _encrypt_args(home, fd, out),
                input=data,
                capture_output=True,
                pass_fds=(fd,),
                check=False,
            )
        finally:
            os.close(fd)
    if proc.returncode != 0:
        out.unlink(missing_ok=True)
        raise _failure(proc.stderr, f"could not write {out.name}")


def decrypt_bytes(path: Path, passphrase: str) -> bytes:
    with _gpg_home() as home:
        fd = _passphrase_fd(passphrase)
        try:
            proc = subprocess.run(  # noqa: S603
                [*_gpg(home, fd), "--decrypt", str(path)],
                capture_output=True,
                pass_fds=(fd,),
                check=False,
            )
        finally:
            os.close(fd)
    if proc.returncode != 0:
        raise _failure(proc.stderr, f"could not read {path.name}")
    return proc.stdout


# ------------------------------------------------------------------ archives
def encrypt_tar(out: Path, passphrase: str, fill: Callable[[tarfile.TarFile], None]) -> None:
    """Stream a tar archive that `fill` writes, through zstd, into gpg, into `out`.

    Nothing unencrypted touches the disk: tar goes into zstd's stdin, zstd's output
    is gpg's input, and gpg writes the file. On any failure `out` is removed."""
    if missing := missing_tools():
        raise SnapshotError(f"snapshots need {' and '.join(missing)}, which this machine lacks")
    with (
        _gpg_home() as home,
        tempfile.TemporaryFile() as zstd_err,
        tempfile.TemporaryFile() as gpg_err,
    ):
        fd = _passphrase_fd(passphrase)
        zstd = subprocess.Popen(  # noqa: S603
            ["zstd", "-q", "-3", "-T0", "-c"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=zstd_err,
        )
        try:
            gpg = subprocess.Popen(  # noqa: S603
                _encrypt_args(home, fd, out),
                stdin=zstd.stdout,
                stderr=gpg_err,
                pass_fds=(fd,),
            )
        except OSError:
            zstd.kill()
            zstd.wait()
            raise
        finally:
            os.close(fd)
        assert zstd.stdin is not None and zstd.stdout is not None
        zstd.stdout.close()  # gpg holds it now
        broken = False
        try:
            with tarfile.open(fileobj=zstd.stdin, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                fill(tar)
        except BrokenPipeError:
            broken = True
        except BaseException:
            zstd.kill()
            gpg.kill()
            zstd.wait()
            gpg.wait()
            out.unlink(missing_ok=True)
            raise
        finally:
            try:
                zstd.stdin.close()
            except BrokenPipeError:
                broken = True
        zstd_rc, gpg_rc = zstd.wait(), gpg.wait()
        if broken or zstd_rc or gpg_rc:
            out.unlink(missing_ok=True)
            if gpg_rc:
                raise _failure(_read(gpg_err), f"could not write {out.name}")
            raise SnapshotError(
                f"could not write {out.name}: "
                + (_read(zstd_err).decode(errors="replace").strip() or "zstd stopped")
            )


def _member_filter(member: tarfile.TarInfo, dest: str) -> tarfile.TarInfo | None:
    """tarfile's "data" filter, except that a symbolic link keeps its target: a home
    has links to /usr and to absolute paths of its own. A file is still never
    written through a link to outside the destination ("data" checks that for every
    file that follows)."""
    if member.issym():
        return tarfile.tar_filter(member, dest)
    return tarfile.data_filter(member, dest)


def decrypt_tar(path: Path, passphrase: str, dest: Path) -> None:
    """Unpack the archive in `path` into `dest`. gpg checks the file's integrity only
    at its end, so a failure after files were written raises too: the caller unpacks
    into a staging folder and keeps nothing of it then."""
    if missing := missing_tools():
        raise SnapshotError(f"snapshots need {' and '.join(missing)}, which this machine lacks")
    dest.mkdir(parents=True, exist_ok=True)
    with (
        _gpg_home() as home,
        tempfile.TemporaryFile() as zstd_err,
        tempfile.TemporaryFile() as gpg_err,
    ):
        fd = _passphrase_fd(passphrase)
        try:
            gpg = subprocess.Popen(  # noqa: S603
                [*_gpg(home, fd), "--decrypt", str(path)],
                stdout=subprocess.PIPE,
                stderr=gpg_err,
                pass_fds=(fd,),
            )
        finally:
            os.close(fd)
        assert gpg.stdout is not None
        zstd = subprocess.Popen(  # noqa: S603
            ["zstd", "-q", "-d", "-c"],
            stdin=gpg.stdout,
            stdout=subprocess.PIPE,
            stderr=zstd_err,
        )
        gpg.stdout.close()
        assert zstd.stdout is not None
        problem: Exception | None = None
        try:
            with tarfile.open(fileobj=zstd.stdout, mode="r|") as tar:
                tar.extractall(dest, filter=_member_filter)
            while zstd.stdout.read(CHUNK):  # the padding after the archive
                pass
        except (tarfile.TarError, OSError, ValueError) as exc:
            problem = exc
            zstd.kill()
            gpg.kill()
        finally:
            zstd.stdout.close()
        gpg_rc, zstd_rc = gpg.wait(), zstd.wait()
        if gpg_rc:
            raise _failure(_read(gpg_err), f"could not read {path.name}")
        if zstd_rc or problem:
            raise SnapshotError(f"could not unpack {path.name}: {problem or 'zstd failed'}")

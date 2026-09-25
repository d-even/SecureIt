"""
The ledger itself: an append-only, hash-chained, JSON-Lines file.

Why a plain file and not a database? Because "append-only" should be an
actual filesystem property, not just an API convention — in a real
offline deployment this file would sit on write-once/append-only storage
(or, with real Fabric, be replicated across independent peer nodes so no
single copy can be secretly edited). Here it's one file for simplicity,
but every operation is written as if that stronger guarantee exists.

Three independent layers of tamper-evidence, from weakest to strongest:
  1. hash chain      — editing a block changes its hash, breaking the
                        next block's prev_hash link.
  2. endorsements     — editing a block's record invalidates every
                        validator org's endorsement signature, which was
                        computed over the ORIGINAL bytes.
  3. recipient sig    — editing a block's record also invalidates the
                        recipient's own ML-DSA signature.
An attacker who edits one block and also recomputes every downstream
hash (defeating layer 1) still can't forge layers 2 and 3 without the
validators' AND the recipient's private keys.
"""

import json
import os

from crypto import record as record_mod
from . import block as block_mod
from . import endorsement as endorsement_mod
from . import validators as validators_mod


class Ledger:
    def __init__(self, ledger_path: str, validators_dir: str, threshold: int = 2):
        self.ledger_path = ledger_path
        self.validators_dir = validators_dir
        self.threshold = threshold
        self._ensure_genesis()

    # ---------- storage ----------

    def _ensure_genesis(self) -> None:
        if not os.path.exists(self.ledger_path) or os.path.getsize(self.ledger_path) == 0:
            genesis = block_mod.make_genesis_block()
            with open(self.ledger_path, "w") as f:
                f.write(json.dumps(genesis) + "\n")

    def _read_all_blocks(self) -> list[dict]:
        blocks = []
        with open(self.ledger_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    blocks.append(json.loads(line))
        return blocks

    def _append_raw(self, block: dict) -> None:
        # Real "append-only" storage would refuse anything but this exact
        # operation (e.g. O_APPEND with no truncate/seek permission).
        with open(self.ledger_path, "a") as f:
            f.write(json.dumps(block) + "\n")

    def _latest_block(self) -> dict:
        return self._read_all_blocks()[-1]

    # ---------- writing ----------

    def commit_record(self, record: dict, record_signature: bytes,
                       recipient_public_key: bytes, endorsements: list[dict]) -> dict:
        """
        Commits a new block IF AND ONLY IF:
          - the recipient's own signature on the record is valid, AND
          - at least `self.threshold` DISTINCT known validators have
            endorsed this exact (record, record_signature) pair.
        Raises ValueError naming exactly what failed, otherwise — this
        should never silently commit a bad record.
        """
        if not record_mod.verify_record(record, record_signature, recipient_public_key):
            raise ValueError("cannot commit: recipient's own signature does not verify")

        registry = validators_mod.load_validator_registry(self.validators_dir)
        endorsed_by = set()
        for e in endorsements:
            vid = e["validator_id"]
            if vid not in registry:
                raise ValueError(f"cannot commit: endorsement from unknown validator '{vid}'")
            if not endorsement_mod.verify_endorsement(e, record, record_signature, registry[vid]):
                raise ValueError(f"cannot commit: endorsement from '{vid}' does not verify")
            endorsed_by.add(vid)

        if len(endorsed_by) < self.threshold:
            raise ValueError(
                f"cannot commit: only {len(endorsed_by)} valid, distinct endorsement(s) "
                f"(need at least {self.threshold})"
            )

        latest = self._latest_block()
        new_block = block_mod.make_block(
            index=latest["index"] + 1,
            prev_hash=latest["hash"],
            record=record,
            record_signature=record_signature,
            recipient_public_key=recipient_public_key,
            endorsements=endorsements,
        )
        self._append_raw(new_block)
        return new_block

    # ---------- reading / leak-tracing lookup ----------

    def get_by_session_id(self, session_id: str) -> dict | None:
        """This is what Phase 3's watermark extraction feeds into: given a
        session_id recovered from a leaked file, find the ledger block
        that proves who decrypted it."""
        for b in self._read_all_blocks():
            if b["record"] is not None and b["record"].get("session_id") == session_id:
                return b
        return None

    # ---------- integrity check ----------

    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Walks every block and re-checks all three tamper-evidence layers.
        Returns (is_valid, list_of_problems). An empty problem list means
        the entire chain — every hash link, every endorsement, every
        recipient signature — is exactly as it was when committed.
        """
        issues: list[str] = []
        blocks = self._read_all_blocks()
        registry = validators_mod.load_validator_registry(self.validators_dir)

        expected_prev_hash = block_mod.GENESIS_PREV_HASH
        for b in blocks:
            i = b["index"]

            recomputed_hash = block_mod.compute_hash(block_mod.block_without_hash(b))
            if recomputed_hash != b["hash"]:
                issues.append(f"block {i}: stored hash does not match its own content (edited in place)")

            if b["prev_hash"] != expected_prev_hash:
                issues.append(f"block {i}: prev_hash does not match the actual previous block (chain broken)")

            if i != 0:
                rec = b["record"]
                sig = block_mod.get_record_signature_bytes(b)
                pk = block_mod.get_recipient_public_key_bytes(b)

                if not record_mod.verify_record(rec, sig, pk):
                    issues.append(f"block {i}: recipient's signature no longer verifies")

                valid_endorsers = set()
                for e in b["endorsements"]:
                    vid = e["validator_id"]
                    if vid not in registry:
                        issues.append(f"block {i}: endorsement from unrecognized validator '{vid}'")
                        continue
                    esig = block_mod.get_endorsement_signature_bytes(e)
                    if endorsement_mod.verify_endorsement(
                        {"validator_id": vid, "endorsement_signature": esig}, rec, sig, registry[vid]
                    ):
                        valid_endorsers.add(vid)
                    else:
                        issues.append(f"block {i}: endorsement from '{vid}' no longer verifies")

                if len(valid_endorsers) < self.threshold:
                    issues.append(
                        f"block {i}: only {len(valid_endorsers)} valid endorsement(s) remain "
                        f"(policy requires {self.threshold})"
                    )

            expected_prev_hash = b["hash"]

        return (len(issues) == 0, issues)
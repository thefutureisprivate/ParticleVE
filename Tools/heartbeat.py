"""Receiver-side checks use a receipt timestamp written by that receiver."""

from datetime import datetime

from particleve.common import require
from particleve.config import integer


def freshness(receipt, installation_uuid, *, now, maximum_age_seconds=900):
    integer(maximum_age_seconds, 60, "heartbeat maximum age")
    require(maximum_age_seconds <= 3600, "heartbeat maximum age cannot exceed one hour")
    require(receipt.get("schema") == 1, "unknown receiver receipt")
    require(receipt["report"].get("schema") == 1, "unknown host-report schema")
    require(
        receipt["report"]["installation_uuid"] == installation_uuid, "heartbeat is for another installation"
    )
    age = (now - datetime.fromisoformat(receipt["received_at"])).total_seconds()
    require(0 <= age <= maximum_age_seconds, "host heartbeat is missing, stale or in the future")
    require(receipt["report"]["result"] == "pass", "host reported a health event requiring attention")
    return {"fresh": True, "age_seconds": age}

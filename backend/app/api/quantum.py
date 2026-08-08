from __future__ import annotations

import json
from functools import partial
from typing import Annotated

import anyio
import anyio.to_thread
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..database import get_db
from ..models import QuantumExperiment
from ..quantum.executor import run_security_lab
from ..security import CurrentUser
from .common import audit

router = APIRouter(prefix="/api/v2/quantum", tags=["quantum-demo"])
settings = get_settings()


#: One lab run at a time, process-wide.
#:
#: This is the most expensive thing the service will ever be asked to do, and it exists to
#: demonstrate a protocol rather than to serve anyone. Letting several run concurrently
#: would let a handful of clicks saturate both cores of a box that also carries the
#: operator's panel, billing and status sites. Queueing is the correct answer: a demo can
#: wait, production traffic cannot.
_LAB_LIMITER = anyio.CapacityLimiter(1)


class ExperimentRequest(BaseModel):
    # Ceilings cut from 8192 shots / 20000 rounds. Nothing is demonstrated at the top of
    # that range that is not demonstrated at the top of this one, and the difference is
    # seconds of a shared CPU.
    shots: int = Field(default=1024, ge=128, le=2048)
    bb84_rounds: int = Field(default=2048, ge=256, le=4096)
    intercept_rate: float = Field(default=0.0, ge=0.0, le=1.0)


@router.post("/experiment")
async def run_experiment(
    body: ExperimentRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not settings.quantum_lab_enabled:
        raise HTTPException(404, "the quantum lab is not enabled on this deployment")
    try:
        # In a worker thread, never on the event loop. `run_security_lab` is seconds of
        # synchronous simulation; running it inline stops every other request in the
        # process -- message relay, WebSocket fan-out, health checks -- until it returns.
        result = await anyio.to_thread.run_sync(
            partial(
                run_security_lab,
                shots=body.shots,
                bb84_rounds=body.bb84_rounds,
                intercept_rate=body.intercept_rate,
            ),
            limiter=_LAB_LIMITER,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None

    qrng = result.get("qrng", {})
    bb84 = result.get("bb84", {})
    experiment = QuantumExperiment(
        actor_id=user.id,
        backend=result["backend"],
        algorithm=result["algorithm"],
        shots=body.shots,
        observed_bias=str(qrng.get("observed_bias")) if qrng.get("observed_bias") is not None else None,
        qber=str(bb84.get("qber")) if bb84.get("qber") is not None else None,
        passed=bool(result["passed"]),
        result_json=json.dumps(result),
    )
    db.add(experiment)
    await audit(db, event="quantum.experiment", actor_id=user.id, request=request, detail=f"pass={result['passed']}")
    await db.commit()
    await db.refresh(experiment)
    return {"id": experiment.id, **result, "created_at": experiment.created_at}


@router.get("/experiments")
async def list_experiments(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    rows = (
        await db.execute(
            select(QuantumExperiment)
            .where(QuantumExperiment.actor_id == user.id)
            .order_by(QuantumExperiment.created_at.desc())
            .limit(50)
        )
    ).scalars().all()
    return [
        {
            "id": row.id,
            "backend": row.backend,
            "algorithm": row.algorithm,
            "shots": row.shots,
            "observed_bias": row.observed_bias,
            "qber": row.qber,
            "passed": row.passed,
            "created_at": row.created_at,
        }
        for row in rows
    ]

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import QuantumExperiment
from ..quantum.executor import run_security_lab
from ..security import CurrentUser
from .common import audit

router = APIRouter(prefix="/api/v2/quantum", tags=["quantum-demo"])


class ExperimentRequest(BaseModel):
    shots: int = Field(default=1024, ge=128, le=8192)
    bb84_rounds: int = Field(default=2048, ge=256, le=20000)
    intercept_rate: float = Field(default=0.0, ge=0.0, le=1.0)


@router.post("/experiment")
async def run_experiment(
    body: ExperimentRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    try:
        result = run_security_lab(
            shots=body.shots,
            bb84_rounds=body.bb84_rounds,
            intercept_rate=body.intercept_rate,
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

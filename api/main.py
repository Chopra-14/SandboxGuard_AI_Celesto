import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field, validator
from sqlalchemy import create_engine, Column, String, DateTime, Text, select
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://ledger:ledger@ledger:5432/ledger")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Run(Base):
    __tablename__ = "runs"

    run_id = Column(String, primary_key=True, index=True)
    sandbox_name = Column(String, index=True)
    problem_id = Column(String, index=True)
    state = Column(String, index=True)
    execution_target = Column(String, default="celesto_sandbox")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


Base.metadata.create_all(bind=engine)


class RunCreate(BaseModel):
    run_id: str = Field(..., min_length=1)
    sandbox_name: str = Field(..., min_length=1)
    problem_id: str = Field(..., min_length=1)
    state: str = Field(..., pattern="^(created|ready|running|succeeded|failed|deleted)$")
    execution_target: str = Field(..., pattern="^celesto_sandbox$")

    @validator("sandbox_name")
    def validate_sandbox_name(cls, v):
        if not v.startswith("sbx-"):
            raise ValueError("sandbox_name must start with 'sbx-'")
        suffix = v[4:]
        if len(suffix) < 8:
            raise ValueError("sandbox_name must have at least 8 characters after 'sbx-'")
        if not suffix.islower() or not suffix.isalnum():
            raise ValueError("sandbox_name suffix must be lowercase alphanumeric")
        return v


class RunResponse(BaseModel):
    run_id: str
    sandbox_name: str
    problem_id: str
    state: str
    execution_target: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="Celesto Run Ledger API", lifespan=lifespan)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/runs", response_model=List[RunResponse])
async def list_runs(db: Session = next(get_db())):
    runs = db.execute(select(Run).order_by(Run.created_at.desc())).scalars().all()
    return runs


@app.post("/api/runs", response_model=RunResponse, status_code=status.HTTP_201_CREATED)
async def create_run(run: RunCreate, db: Session = next(get_db())):
    if run.execution_target != "celesto_sandbox":
        raise HTTPException(
            status_code=400,
            detail="execution_target must be 'celesto_sandbox'"
        )

    existing = db.execute(select(Run).where(Run.run_id == run.run_id)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="run_id already exists")

    db_run = Run(**run.model_dump())
    db.add(db_run)
    db.commit()
    db.refresh(db_run)
    return db_run
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, model_validator


class SOC2FleetPdfRequest(BaseModel):
    # No single agent field. Leave both empty -> ALL agents.
    # Or pass a subset by id and/or name.
    agent_ids: Optional[List[int]] = None
    agent_names: Optional[List[str]] = None
    from_dt: datetime
    to_dt: datetime
    bucket: str = "day"

    @model_validator(mode="after")
    def _check(self):
        if self.to_dt <= self.from_dt:
            raise ValueError("to_dt must be after from_dt.")
        if self.bucket not in ("hour", "day"):
            raise ValueError("bucket must be 'hour' or 'day'.")
        return self

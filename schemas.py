from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class SecretTokenBase(BaseModel):
    token: str
    description: str
    isadmin: int

class SecretTokenCreate(SecretTokenBase):
    pass

class SecretToken(SecretTokenBase):
    id: int
    token: str
    description: str
    isadmin: int

    class Config:
        orm_mode = True
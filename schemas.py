from pydantic import BaseModel
from typing import Optional

class token(BaseModel):
    access_token:str
    token_type:str

class tokendata(BaseModel):
    username:Optional[str]=None

class user(BaseModel):
    user_id:int
    name:str
    status:bool

class userinDB(user):
    hashed_password:str

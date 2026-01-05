from fastapi import FastAPI , Depends ,HTTPException 
from jose import JWTError ,jwt
from fastapi.security import OAuth2PasswordBearer , OAuth2PasswordRequestForm
from pydantic import BaseModel ,Field
from typing import Annotated , Optional 
from passlib.context import CryptContext
from datetime import datetime ,timedelta  #timedelta is used to add and subract the time and dates etc ,,means it shows the durations of the time
from schemas  import token , tokendata ,user ,userinDB
from database import ake_goals_db
  
SECRET_KEY="edc324c1362bce0dbb2fc7cc0ffa4eda477a03a570947f0cf9b26366b86fd263"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=30

app=FastAPI()

pwd_context=CryptContext(schemes='bcrypt',deprecated='auto')
oauth_2_scheme=OAuth2PasswordBearer(tokenUrl='token')

class data(BaseModel):     
    name:Annotated[str,Field(...,min_length=4,max_length=20)]      # models are for the request body ,.,.we can not use them in the get body
                                                                    # if we want to use the model we will have to do it in the post body

def verify_password(plain_pasword,hashed_password):
    return pwd_context.verify(plain_pasword ,hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(ake_goals_db,username):
    if username in ake_goals_db:
        user_data=ake_goals_db[username]
        return userinDB(**user_data)

def authinticate_user(ake_goals_db,username:str,password:str):
    user=get_user(ake_goals_db,username)
    if not user:
        return False
    if not verify_password(password,user.hashed_password):
        return False
    return user

def create_access_token(data:dict,expires_delta:Optional[timedelta]=None):
    to_encode=data.copy()
    if expires_delta:
        expire=datetime.utcnow() + expires_delta
    else:
        expire=datetime.utcnow() + timedelta (minutes=15)
    
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt

async 


@app.post('/name')
async def name(name:data):
    return {'name':name.name}


@app.get('/home{item_id}')
async def home(item_id:int,query:str="khan"):
    return {'id':item_id,"name":query}
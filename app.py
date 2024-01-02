from fastapi import FastAPI, Depends, HTTPException, status, Request, Query, Form, Cookie, Response, APIRouter
from fastapi.security import OAuth2PasswordBearer, HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic_settings import BaseSettings
from sqlalchemy.orm import Session, relationship, sessionmaker
from sqlalchemy import func, create_engine, inspect, Column, Integer, String, ForeignKey, Text, JSON, DateTime, Index, CheckConstraint, Boolean
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from passlib.hash import pbkdf2_sha256
from fastapi.templating import Jinja2Templates
from datetime import datetime
from typing import Optional
from starlette.staticfiles import StaticFiles
from starlette.responses import RedirectResponse
from fastapi.exceptions import HTTPException
from fastapi.responses import FileResponse
import ctypes.util
import jwt
import schemas
import logging

app = FastAPI()

jvm_library = ctypes.util.find_library('jvm')

@app.exception_handler(HTTPException)
async def unauthorized_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return templates.TemplateResponse("401.html", {"request": request})
    # Handle other exceptions normally
    return None

class Settings(BaseSettings):
    local_csv_file_upload_folder: str
    app_secret_key: str
    cloud_connector_api_key: str
    cloud_connector_api_key_description: str
    oracle_jar_path: str
    mail_from: str
    mail_port: int
    mail_username: str
    mail_password: str
    mail_server: str
    mail_starttls: bool
    mail_ssl_tls: bool

    class Config:
        env_file = ".env"

settings = Settings()

api_key = settings.cloud_connector_api_key

if api_key is not None:
    hashed_key = pbkdf2_sha256.using(rounds=260000).hash(api_key)
else:
    raise ValueError("\n\nError! Environment variable 'cloud_connector_api_key' is not set\n\n")

Base = declarative_base()

class TokenData:
    def __init__(self, username):
        self.username = username

    def __dict__(self):
        return {"username": self.username}

class SecretToken(Base):
    __tablename__ = "secret_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    description = Column(String(120), nullable=False)
    isadmin = Column(Integer, default=0, nullable=False)

SQLALCHEMY_DATABASE_URL = "sqlite:///./test0002a.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

inspector = inspect(engine)
table_exists = "secret_tokens" in inspector.get_table_names()

security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")
templates.env.globals['now'] = datetime.now

conf = ConnectionConfig(
    MAIL_FROM = settings.mail_from,
    MAIL_PORT = settings.mail_port,
    MAIL_USERNAME = settings.mail_username,
    MAIL_PASSWORD = settings.mail_password,
    MAIL_SERVER = settings.mail_server,
    MAIL_STARTTLS = settings.mail_starttls,
    MAIL_SSL_TLS = settings.mail_ssl_tls
)

secret_key = settings.app_secret_key

with Session(engine) as session:

    print("\n\nsession initialization\n\n")

    logging.basicConfig(level = logging.INFO)
    logging.info('test logging')

    if not table_exists:
        Base.metadata.create_all(bind=engine)

    secret_token_count = session.query(SecretToken).count()
api_key_descr = settings.cloud_connector_api_key_description
if secret_token_count == 0:
    new_secret_token = SecretToken(id=1, token=hashed_key, description=api_key_descr, isadmin=1)

    try:
        session.add(new_secret_token)
        session.commit()
    except IntegrityError as e:
        session.rollback()
        raise ValueError(f"Error inserting new SecretToken record: {str(e)}")
    finally:
        secret_token_count = session.query(SecretToken).count()
        print(f"secret_token_count finally: {secret_token_count}")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

date_format_default = "%Y-%m-%d"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_users(db: Session):
    return db.query(SecretToken).all()

class AuthError(Exception):
    pass

ALGORITHM = "HS256"

async def get_current_user(request: Request, token: str = Query(None), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    if token is None:
        logging.basicConfig(level = logging.INFO)
        logging.info('debug get_current_user - token is None')
        return None
    else:
        logging.basicConfig(level = logging.INFO)
        logging.info('debug get_current_user - token is NOT None')
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        isadmin: str = payload.get("isadmin")
        if isadmin is None:
            raise credentials_exception
        id: str = payload.get("id")
        if id is None:
            raise credentials_exception
        description: str = payload.get("description")
        if description is None:
            raise credentials_exception
        return {"id": id, "description": description, "isadmin": isadmin}
    except AuthError:
        raise credentials_exception

templates = Jinja2Templates(directory="templates")
templates.env.globals['now'] = datetime.now

router = APIRouter()

def get_token_cookie(token: Optional[str] = Cookie(None)):
    logging.basicConfig(level = logging.INFO)
    if token:
        #cookie_header = response.headers.get('set-cookie')
        #logging.info(f'debug logout - Set-Cookie header: {cookie_header}')
        logging.info(f'debug get_token_cookie - token content: {token}')
        if token == "":
            logging.info('debug get_token_cookie - token is empty')
            return None
        try:
            jwt.decode(token, secret_key, algorithms=[ALGORITHM], verify_exp=True)
            logging.info('debug get_token_cookie - token is NOT None')
        except jwt.ExpiredSignatureError:
            logging.info('debug get_token_cookie - token is expired')
            return None
        except jwt.DecodeError:
            logging.info('debug get_token_cookie - token could not be decoded')
            return None
        except jwt.InvalidTokenError:
            logging.info('debug get_token_cookie - token is invalid')
            return None
    else:
        logging.info('debug get_token_cookie - token is None')
    return token

@app.get("/favicon.ico")
async def favicon():
    return FileResponse("static/favicon.ico")

@app.get("/home", name="home", response_class=HTMLResponse)
#async def index(request: Request, token: str = Depends(get_token_cookie), current_user: schemas.SecretToken = Depends(get_current_user), db: Session = Depends(get_db), msg: str = Cookie(None)):
async def index(request: Request, token: str = Depends(get_token_cookie), db: Session = Depends(get_db), msg: str = Cookie(None)):
    if token is None:
        logging.basicConfig(level = logging.INFO)
        logging.info("debug get home - token is None")
        return templates.TemplateResponse("login.html", {"request": request})

    current_user = await get_current_user(request, token, db)

    if current_user:
        current_user_items = current_user.items()
        logging.info(f"debug current_user_items: {current_user_items}")
        current_user_id = current_user['id']
        user_description = current_user['description']

    user_schedules = ""
    user_datasources = ""
    java_version = ""
    which_java = ""
    object_names = ""
    data = {"logout_url": app.url_path_for('logout'),}
    response = templates.TemplateResponse("dashboard.html", {"request": request, "message": msg, "description": user_description, "schedules": user_schedules, "datasources": user_datasources, "current_user_id": current_user_id, "jvm_library": jvm_library, "java_version": java_version, "which_java": which_java, "current_user": current_user, "object_names": object_names, "data": data})
    response.delete_cookie(key="msg")
    return response

def create_jwt_token(data: dict):
    return jwt.encode(data, secret_key, algorithm=ALGORITHM)

@app.post("/login")
async def login(request: Request, token: str = Form(...), db: Session = Depends(get_db)):
    
    logging.basicConfig(level = logging.INFO)
    logging.info("post /login")

    users = get_users(db)

    if users:
        logging.debug(f"debug /login - users count: {len(users)}")
    else:
        logging.debug(f"debug /login - Error! users is null")

    authenticated_user = None
    for user in users:
        if pbkdf2_sha256.verify(token, user.token):
            authenticated_user = user
            break

    data = {}

    if authenticated_user:
        user_description = authenticated_user.description
        logging.info('debug 1111')
        data = {"logout_url": app.url_path_for('logout'),}
        response = templates.TemplateResponse('dashboard.html', {
            "request": request, 
            "description": user_description, 
            "current_user_id": authenticated_user.id, 
            "current_user_isadmin": authenticated_user.isadmin, 
            "current_user": authenticated_user, 
            "data": data
        })
        #return response
        logging.info('debug 1114')
        user_data = {"sub": "token", "id": authenticated_user.id, "description": user_description, "isadmin": authenticated_user.isadmin, "scopes": ["read", "write"]}
        token_jwt = create_jwt_token(user_data)
        response.set_cookie("token", token_jwt)
        logging.info('debug 1115')

        return response
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid secret token. Please try again.",
            headers={"WWW-Authenticate": "Basic"},
        )

@app.get("/login", name="login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "", current_user: schemas.SecretToken = Depends(get_current_user)):
    if current_user is not None:
        logging.info('debug login get - current_user is not None')
        if next:
            response = RedirectResponse(url=next)
        else:
            data = {"logout_url": app.url_path_for('logout'),}
            response = templates.TemplateResponse('dashboard.html', {"request": request, "current_user": current_user, "data": data})
        return response
    else:
        messages = ['please authenticate']
        logging.basicConfig(level = logging.INFO)
        logging.info("get /login")
        logging.info('debug login get - current_user is None')
        logging.info(f'debug login get - request: {str(request)}')
        now = datetime.now()
        logging.info(f'debug login get - now: {now}')
        return templates.TemplateResponse('login.html', {"request": request, "messages": messages}), 200

@app.get("/logout", name="logout")
async def logout(response: Response,):
    logging.basicConfig(level = logging.INFO)
    logging.info('debug logout - before deleting cookie')
    response.delete_cookie("token")
    logging.info('debug logout - after deleting cookie')

    set_cookie_header = response.headers.get('set-cookie')
    if set_cookie_header and 'token=;' in set_cookie_header:
        logging.info('debug logout - cookie deletion confirmed')
    else:
        logging.info('debug logout - cookie deletion not confirmed')
        response.set_cookie(key="token", value="", expires=0)
        #response.set_cookie("token", None)
        logging.info('debug logout - setting token cookie as empty')
        set_cookie_header = response.headers.get('set-cookie')
        if set_cookie_header and 'token=;' in set_cookie_header:
            logging.info('debug logout - cookie deletion confirmed')
        else:
            logging.info('debug logout - cookie deletion not confirmed')
            response.delete_cookie(key="token")
            logging.info('debug logout - after deleting cookie (2)')

    set_cookie_header = response.headers.get('set-cookie')
    logging.info(f'debug logout - Set-Cookie header: {set_cookie_header}')

    #return RedirectResponse(url="/logged_out", status_code=303)
    return {"status":"logged out"}

'''
@app.get("/")
async def root():
    return {"message": "welcome"}
'''

@app.get('/', response_class=HTMLResponse)
def logout(request: Request, response: Response):
    home_url = app.url_path_for('home')
    html_content = f"""
    <html>
        <body>
            <a href="{home_url}">click here to go home</a>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/{path:path}", include_in_schema=False)
async def catch_all(path: str):
    raise HTTPException(status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
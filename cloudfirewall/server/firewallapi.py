import models
from fastapi import FastAPI,Depends
from pydantic import BaseModel

from database import SessionLocal, engine
from sqlalchemy.orm import Session
from models import Firewall


app = FastAPI()

models.Base.metadata.create_all(bind=engine)

rulesets = []

class Firewall1(BaseModel):

    table: str
    chain: str
    protocol: str
    port: int
    rule: str

    class Config:
        orm_mode =True
# Dependency

def get_db():

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/commands")
def get_command():
   return rulesets

@app.post("/commands")
def add_command(command: Firewall1, db: Session = Depends(get_db)):

    firewall = Firewall()

    firewall.table_name = command.table
    firewall.chain = command.chain
    firewall.protocol = command.protocol
    firewall.port = command.port
    firewall.rule = command.rule

    db.add(firewall)
    db.commit()

    return "success"










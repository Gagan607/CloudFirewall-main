from sqlalchemy import Column, Integer, String

from database import Base


class Firewall(Base):
    __tablename__ = "cloudfirewall"

    id = Column(Integer, primary_key=True, index=True)
    table_name = Column(String,unique=True,index=True)
    chain = Column(String,unique=True,index=True)
    protocol = Column(String,unique=True,index=True)
    port = Column(Integer,unique=True,index=True)
    rule = Column(String,unique=True,index=True)




from sqlalchemy.ext.asyncio import  AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
import json

from .base import Base
from .tables import *

from config.config import DB_ENDPOINT , DB_NAME , DB_PASSWORD , DB_USER



class DBWriter:
    def __init__(self):
        self._dbuser     = DB_USER
        self._dbpassword = DB_PASSWORD
        self._dbendpoint = DB_ENDPOINT
        self._dbname     = DB_NAME
        
        self._DATABASE_URL = (
            f"postgresql+asyncpg://{self._dbuser}:{self._dbpassword}"
            f"@{self._dbendpoint}:5432/{self._dbname}"
        )

        self._async_engine = create_async_engine(self._DATABASE_URL)
        self._AsyncSessionLocal = sessionmaker(
            self._async_engine, class_=AsyncSession, expire_on_commit=False
        )
        # ← no asyncio.run() here; caller must await self.init()

    async def init(self):
        async with self._async_engine.begin() as conn:
            try:
                await conn.run_sync(Base.metadata.create_all)
            except SQLAlchemyError as e:
                raise RuntimeError(f"Failed to initialize tables: {e}")

    async def get_async_db(self):
        async with self._AsyncSessionLocal() as session:
            try:
                yield session
            finally:
                await session.close()




    async def write_into_db(self, e: dict):
        try:
            f = e.get("file") or {}
            p = e.get("process") or {}
            n = e.get("network") or {}
            u = e.get("user") or {}
            h = e.get("host") or {}

            async with self._AsyncSessionLocal() as session:
                event = Events(
                    event_id=e.get("event_id"),
                    timestamp=e.get("timestamp"),
                    category=e.get("category"),
                    action=e.get("action"),
                    outcome=e.get("outcome"),
                    severity=e.get("severity"),
                    collector=e.get("collector"),
                    host_hostname=h.get("hostname"),
                    host_os=h.get("os_type"),
                    user_name=u.get("name"),
                    file_path=f.get("path"),
                    file_sha256=f.get("sha256"),
                    process_name=p.get("name"),
                    process_pid=p.get("pid"),
                    net_src_ip=n.get("src_ip"),
                    net_dst_ip=n.get("dst_ip"),
                    net_dst_port=n.get("dst_port"),
                    risk_score=e.get("risk_score"),
                    mitre_technique=e.get("mitre_technique"),
                    raw_log=e.get("raw_log"),
                    payload=json.dumps(e, default=str),
                )

                session.add(event)
                await session.commit()

        except SQLAlchemyError as ex:
            self._logger.error(f"DB write error: {ex}")
            raise

    


    async def write_into_db_batch(self , events:list[dict]):
        if not events:
            return

   
        try:
            async with self._AsyncSessionLocal() as session:

                rows = []
                for e in events:
                    f = e.get("file") or {}
                    p = e.get("process") or {}
                    n = e.get("network") or {}
                    u = e.get("user") or {}
                    h = e.get("host") or {}

                    curr_event = Events(
                        event_id=e.get("event_id"),
                        timestamp=e.get("timestamp"),
                        category=e.get("category").value,
                        action=e.get("action").value,
                        outcome=e.get("outcome").value,
                        severity=e.get("severity").value,
                        collector=e.get("collector"),
                        host_hostname=h.get("hostname"),
                        host_os=h.get("os_type"),
                        user_name=u.get("name"),
                        file_path=f.get("path"),
                        file_sha256=f.get("sha256"),
                        process_name=p.get("name"),
                        process_pid=p.get("pid"),
                        net_src_ip=n.get("src_ip"),
                        net_dst_ip=n.get("dst_ip"),
                        net_dst_port=n.get("dst_port"),
                        risk_score=e.get("risk_score"),
                        mitre_technique=e.get("mitre_technique"),
                        raw_log=e.get("raw_log"),
                        payload=json.dumps(e, default=str),
                    )
                    rows.append(curr_event)
                async with session.begin():
                    session.add_all(rows)

        except SQLAlchemyError as ex:
            self._logger.error(f"DB write error: {ex}")
            raise
"""
app/database.py
Database configuration and ORM models for OSINT scan data.
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

# Database configuration
DATABASE_URL = "sqlite:///./osint_scans.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite with async
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """
    Tabel Scans: Menyimpan status & metadata dari setiap sesi audit/scan.
    """
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g., DOMAIN_NAME, IP_ADDRESS
    status: Mapped[str] = mapped_column(String(32), default="PENDING")    # PENDING, RUNNING, COMPLETED, FAILED
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relasi ke ScanResults
    results: Mapped[List["ScanResult"]] = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, target='{self.target}', status='{self.status}')>"


class ScanResult(Base):
    """
    Tabel ScanResults: Menyimpan setiap entitas event yang ditemukan selama scan.
    Memiliki self-referential relation (source_event_id) untuk melacak asal-usul data (parent-child relationship).
    """
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    module_name: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # e.g., DOMAIN_NAME, IP_ADDRESS
    event_data: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Tracking Data Lineage (Parent-Child)
    source_event_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("scan_results.id", ondelete="SET NULL"), 
        nullable=True
    )
    
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc)
    )

    # Relasi ORM
    scan: Mapped["Scan"] = relationship("Scan", back_populates="results")
    source_event: Mapped[Optional["ScanResult"]] = relationship("ScanResult", remote_side=[id])

    def __repr__(self) -> str:
        return f"<ScanResult(id={self.id}, module='{self.module_name}', type='{self.event_type}', data='{self.event_data}')>"


def init_db():
    """Inisialisasi tabel di database."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Dependency Provider untuk FastAPI Session handling."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
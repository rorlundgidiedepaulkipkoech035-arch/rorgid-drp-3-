"""SQLAlchemy 2.0 ORM models (the database schema). The same models run on PostgreSQL and SQLite.

Timestamps are stored as ISO-8601 UTC text (YYYY-MM-DDTHH:MM:SSZ) so they sort correctly and print the same
on every database. Flags (approved, used, auto_report) are 0/1 integers."""
from typing import Optional

from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "companies"
    id: Mapped[int] = mapped_column(primary_key=True)
    legal_name: Mapped[str] = mapped_column(String(200))
    registration_number: Mapped[str] = mapped_column(String(64), unique=True)
    website: Mapped[Optional[str]] = mapped_column(String(255))
    official_email: Mapped[str] = mapped_column(String(255))
    phone: Mapped[Optional[str]] = mapped_column(String(64))
    address: Mapped[Optional[str]] = mapped_column(String(255))
    country: Mapped[Optional[str]] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="pending")        # pending | approved | suspended
    verification_token: Mapped[str] = mapped_column(String(64))
    auto_report: Mapped[int] = mapped_column(Integer, default=0)
    kra_pin: Mapped[Optional[str]] = mapped_column(String(16), unique=True)
    trademark_number: Mapped[Optional[str]] = mapped_column(String(64))
    verified_at: Mapped[Optional[str]] = mapped_column(String(20))
    created_at: Mapped[str] = mapped_column(String(20))


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[Optional[int]] = mapped_column(ForeignKey("companies.id"))   # empty for platform admins
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[str] = mapped_column(String(20))


class CompanyBrand(Base):
    __tablename__ = "company_brands"
    __table_args__ = (UniqueConstraint("company_id", "brand"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"))
    brand: Mapped[str] = mapped_column(String(63))
    approved: Mapped[int] = mapped_column(Integer, default=0)


class CompanyDomain(Base):
    __tablename__ = "company_domains"
    __table_args__ = (UniqueConstraint("company_id", "domain"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"))
    domain: Mapped[str] = mapped_column(String(253))
    approved: Mapped[int] = mapped_column(Integer, default=0)


class CompanyDocument(Base):
    __tablename__ = "company_documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    doc_type: Mapped[str] = mapped_column(String(40))
    filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255))
    mime: Mapped[str] = mapped_column(String(100))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), unique=True)       # one file can be registered only once
    serial: Mapped[str] = mapped_column(String(64), unique=True)       # key serial number issued for this file
    uploaded_at: Mapped[str] = mapped_column(String(20))


class ProtectedAsset(Base):
    """A logo or marketing asset with a hidden serial number embedded by src/stego.py."""
    __tablename__ = "protected_assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255))
    serial: Mapped[str] = mapped_column(String(64), unique=True)
    original_sha256: Mapped[str] = mapped_column(String(64))
    watermarked_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[str] = mapped_column(String(20))


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("company_id", "domain"), Index("ix_findings_company_status", "company_id", "status"))
    id: Mapped[int] = mapped_column(primary_key=True)
    company_id: Mapped[int] = mapped_column(ForeignKey("companies.id"))
    domain: Mapped[str] = mapped_column(String(253))
    reason: Mapped[Optional[str]] = mapped_column(Text)
    sha256: Mapped[Optional[str]] = mapped_column(String(64))
    serial: Mapped[Optional[str]] = mapped_column(String(64))
    screenshot: Mapped[Optional[str]] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(24), default="pending_review")
    detected_at: Mapped[str] = mapped_column(String(20))
    updated_at: Mapped[str] = mapped_column(String(20))


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[str] = mapped_column(String(20))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    used: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[str] = mapped_column(String(20))


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[str] = mapped_column(String(20))
    user_id: Mapped[Optional[int]] = mapped_column(Integer)
    company_id: Mapped[Optional[int]] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[Optional[str]] = mapped_column(Text)

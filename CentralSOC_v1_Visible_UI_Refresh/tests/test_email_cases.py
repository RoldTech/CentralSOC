from types import SimpleNamespace
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from regexsoc.db.models import Base, EmailCase, AuditLog
from regexsoc.email_security.cases import save_case, update_case, list_cases


def test_save_and_update_case():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    parsed = SimpleNamespace(headers=SimpleNamespace(subject='Invoice', from_=[SimpleNamespace(raw='test@example.org')]))
    verdict = SimpleNamespace(classification='SUSPICIOUS', score=65)
    with Session(engine) as db:
        c = save_case(db, b'From: test@example.org\nSubject: Invoice\n\ntest', parsed, verdict, analyst='analyst')
        assert c.sha256 and len(c.sha256) == 64
        assert list_cases(db)[0].id == c.id
        update_case(db, c, status='Investigating', note='Needs header review', analyst='analyst')
        db.commit()
    with Session(engine) as db:
        c = db.scalar(select(EmailCase))
        assert c.status == 'Investigating'
        assert len(list(db.scalars(select(AuditLog)))) == 2
        with pytest.raises(ValueError):
            update_case(db, c, status='Closed', note='', analyst='analyst')
        assert c.status == 'Investigating'


def test_case_transaction_rollback():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    parsed = SimpleNamespace(headers=SimpleNamespace(subject='test', from_=[]))
    verdict = SimpleNamespace(classification='BENIGN', score=0)
    with Session(engine) as db:
        save_case(db, b'raw', parsed, verdict, analyst='analyst')
        db.rollback()
    with Session(engine) as db:
        assert list_cases(db) == []
        assert db.scalar(select(AuditLog)) is None

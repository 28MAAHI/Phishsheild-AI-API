"""Database access: storing processed records and the read queries behind the API.

Storage is idempotent. A URL is identified by the SHA-256 of its normalised
form (phishing_urls.url_hash, UNIQUE):

  * new URL           -> INSERT ... ON CONFLICT (url_hash) DO NOTHING, so two
                         sources inserting the same URL concurrently cannot
                         create a duplicate or fail the run
  * URL already known -> last_seen / first_seen / status / confidence updated
  * per-source report -> one url_sightings row per (url, source), updated on
                         every later sighting instead of duplicated
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import Select, and_, distinct, exists, func, or_, select
from sqlalchemy.orm import Session, lazyload

from ..db.models import CollectionRun, PhishingURL, Source, URLSighting
from .threat_processor import ProcessedRecord

CHUNK_SIZE = 500


def _insert_for(session: Session):
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:  # pragma: no cover - only PostgreSQL and SQLite are supported
        raise RuntimeError(f"Unsupported database dialect: {dialect}")
    return insert


# ── Sources ──────────────────────────────────────────────────────────────

def get_or_create_source(session: Session, name: str, display_name: str, homepage: str | None) -> Source:
    src = session.scalar(select(Source).where(Source.name == name))
    if src is None:
        insert = _insert_for(session)
        session.execute(insert(Source).values(name=name, display_name=display_name, homepage=homepage)
                        .on_conflict_do_nothing(index_elements=["name"]))
        src = session.scalar(select(Source).where(Source.name == name))
    elif src.display_name != display_name or src.homepage != homepage:
        src.display_name, src.homepage = display_name, homepage
    return src


def list_sources(session: Session) -> list[Source]:
    return list(session.scalars(select(Source).order_by(Source.name)))


# ── Storing collected records ────────────────────────────────────────────

@dataclass
class StoreResult:
    new: int = 0
    existing: int = 0


def store_records(session: Session, source: Source, records: list[ProcessedRecord],
                  collected_at: datetime) -> StoreResult:
    """Upsert a batch of already-processed (valid, batch-deduplicated) records."""
    result = StoreResult()
    insert = _insert_for(session)
    table = PhishingURL.__table__

    for start in range(0, len(records), CHUNK_SIZE):
        chunk = records[start:start + CHUNK_SIZE]
        rows = []
        for r in chunk:
            n = r.normalized
            first_seen = min(r.source_first_seen, collected_at) if r.source_first_seen else collected_at
            rows.append({
                "url": n.url, "url_hash": n.url_hash, "scheme": n.scheme, "hostname": n.hostname,
                "domain": n.domain, "registered_domain": n.registered_domain, "tld": n.tld,
                "port": n.port, "path": n.path, "is_ip": n.is_ip,
                "threat_type": r.threat_type, "confidence": r.confidence, "status": r.status,
                "first_seen": first_seen, "last_seen": collected_at,
                "created_at": collected_at, "updated_at": collected_at,
            })
        inserted = set(session.execute(
            insert(table).values(rows).on_conflict_do_nothing(index_elements=["url_hash"])
            .returning(table.c.url_hash)
        ).scalars())
        result.new += len(inserted)
        result.existing += len(chunk) - len(inserted)

        hashes = [r.normalized.url_hash for r in chunk]
        urls = {u.url_hash: u for u in session.scalars(
            select(PhishingURL).options(lazyload(PhishingURL.sightings)).where(PhishingURL.url_hash.in_(hashes)))}
        sightings = {s.url_id: s for s in session.scalars(
            select(URLSighting).options(lazyload(URLSighting.source))
            .where(URLSighting.source_id == source.id,
                   URLSighting.url_id.in_([u.id for u in urls.values()])))}

        for r in chunk:
            u = urls[r.normalized.url_hash]
            if r.normalized.url_hash not in inserted:
                _update_url(u, r, collected_at)
            s = sightings.get(u.id)
            if s is None:
                session.add(URLSighting(
                    url_id=u.id, source_id=source.id, source_reference=r.source_reference,
                    threat_type=r.threat_type, confidence=r.confidence, status=r.status, tags=r.tags,
                    source_first_seen=r.source_first_seen, first_collected_at=collected_at,
                    last_collected_at=collected_at, source_metadata=r.metadata,
                ))
            else:
                _update_sighting(s, r, collected_at)
        session.flush()
    return result


def _update_url(u: PhishingURL, r: ProcessedRecord, collected_at: datetime) -> None:
    if collected_at > u.last_seen:
        u.last_seen = collected_at
    if r.source_first_seen and r.source_first_seen < u.first_seen:
        u.first_seen = r.source_first_seen
    if r.status is not None:
        u.status = r.status
    if u.threat_type is None and r.threat_type is not None:
        u.threat_type = r.threat_type
    if r.confidence is not None and (u.confidence is None or r.confidence > u.confidence):
        u.confidence = r.confidence
    u.updated_at = collected_at


def _update_sighting(s: URLSighting, r: ProcessedRecord, collected_at: datetime) -> None:
    s.last_collected_at = collected_at
    # Fields reflect the source's latest report; keep old values only when the
    # source simply did not send that field this time.
    for attr, value in (("source_reference", r.source_reference), ("threat_type", r.threat_type),
                        ("confidence", r.confidence), ("status", r.status), ("tags", r.tags),
                        ("source_metadata", r.metadata)):
        if value is not None:
            setattr(s, attr, value)
    if r.source_first_seen and (s.source_first_seen is None or r.source_first_seen < s.source_first_seen):
        s.source_first_seen = r.source_first_seen


# ── Read queries ─────────────────────────────────────────────────────────

@dataclass
class URLFilters:
    source: str | None = None
    threat_type: str | None = None
    domain: str | None = None
    hostname: str | None = None
    status: str | None = None
    seen_since: datetime | None = None
    seen_until: datetime | None = None
    added_since: datetime | None = None


SORT_COLUMNS = {
    "last_seen": PhishingURL.last_seen,
    "first_seen": PhishingURL.first_seen,
    "created_at": PhishingURL.created_at,
    "id": PhishingURL.id,
}


def _apply_filters(stmt: Select, f: URLFilters) -> Select:
    if f.source or f.threat_type:
        cond = [URLSighting.url_id == PhishingURL.id]
        if f.source:
            cond.append(URLSighting.source_id == select(Source.id).where(Source.name == f.source).scalar_subquery())
        if f.threat_type:
            cond.append(URLSighting.threat_type == f.threat_type)
        stmt = stmt.where(exists().where(and_(*cond)))
    if f.domain:
        stmt = stmt.where(or_(PhishingURL.domain == f.domain, PhishingURL.registered_domain == f.domain,
                              PhishingURL.hostname == f.domain))
    if f.hostname:
        stmt = stmt.where(PhishingURL.hostname == f.hostname)
    if f.status:
        stmt = stmt.where(PhishingURL.status == f.status)
    if f.seen_since:
        stmt = stmt.where(PhishingURL.last_seen >= f.seen_since)
    if f.seen_until:
        stmt = stmt.where(PhishingURL.last_seen <= f.seen_until)
    if f.added_since:
        stmt = stmt.where(PhishingURL.created_at >= f.added_since)
    return stmt


def list_urls(session: Session, filters: URLFilters, *, page: int, limit: int,
              sort: str = "-last_seen") -> tuple[list[PhishingURL], int]:
    descending = sort.startswith("-")
    col = SORT_COLUMNS[sort.lstrip("-")]
    total = session.scalar(_apply_filters(select(func.count()).select_from(PhishingURL), filters)) or 0
    order = [col.desc(), PhishingURL.id.desc()] if descending else [col.asc(), PhishingURL.id.asc()]
    stmt = _apply_filters(select(PhishingURL), filters).order_by(*order).offset((page - 1) * limit).limit(limit)
    return list(session.scalars(stmt)), total


def get_url(session: Session, url_id: int) -> PhishingURL | None:
    return session.get(PhishingURL, url_id)


def get_url_by_hash(session: Session, url_hash: str) -> PhishingURL | None:
    return session.scalar(select(PhishingURL).where(PhishingURL.url_hash == url_hash))


def domain_summary(session: Session, domain: str) -> dict | None:
    f = URLFilters(domain=domain)
    row = session.execute(_apply_filters(
        select(func.count(), func.min(PhishingURL.first_seen), func.max(PhishingURL.last_seen))
        .select_from(PhishingURL), f)).one()
    if not row[0]:
        return None
    ids = _apply_filters(select(PhishingURL.id), f).scalar_subquery()
    sources = session.scalars(
        select(Source.name).distinct().join(URLSighting, URLSighting.source_id == Source.id)
        .where(URLSighting.url_id.in_(ids)).order_by(Source.name)).all()
    threat_types = session.scalars(
        select(URLSighting.threat_type).distinct()
        .where(URLSighting.url_id.in_(ids), URLSighting.threat_type.is_not(None))
        .order_by(URLSighting.threat_type)).all()
    hostnames = session.scalar(_apply_filters(select(func.count(distinct(PhishingURL.hostname))), f))
    return {"domain": domain, "url_count": row[0], "hostname_count": hostnames,
            "first_seen": row[1], "last_seen": row[2], "sources": list(sources),
            "threat_types": list(threat_types)}


def stats(session: Session, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    total = session.scalar(select(func.count()).select_from(PhishingURL)) or 0
    domains = session.scalar(select(func.count(distinct(PhishingURL.domain)))) or 0
    by_source = dict(session.execute(
        select(Source.name, func.count(URLSighting.id)).join(URLSighting, URLSighting.source_id == Source.id)
        .group_by(Source.name).order_by(Source.name)).all())
    by_threat = dict(session.execute(
        select(func.coalesce(URLSighting.threat_type, "unknown"), func.count(distinct(URLSighting.url_id)))
        .group_by(func.coalesce(URLSighting.threat_type, "unknown"))).all())
    by_status = dict(session.execute(
        select(func.coalesce(PhishingURL.status, "unknown"), func.count())
        .group_by(func.coalesce(PhishingURL.status, "unknown"))).all())
    added_24h = session.scalar(select(func.count()).select_from(PhishingURL)
                               .where(PhishingURL.created_at >= now - timedelta(hours=24))) or 0
    seen_24h = session.scalar(select(func.count()).select_from(PhishingURL)
                              .where(PhishingURL.last_seen >= now - timedelta(hours=24))) or 0
    newest = session.scalar(select(func.max(PhishingURL.created_at)))
    return {"total_urls": total, "distinct_domains": domains, "urls_added_last_24h": added_24h,
            "urls_seen_last_24h": seen_24h, "newest_url_added_at": newest,
            "by_source": by_source, "by_threat_type": by_threat, "by_status": by_status}


# ── Collection runs ──────────────────────────────────────────────────────

def last_runs_by_source(session: Session) -> dict[int, CollectionRun]:
    latest = (select(CollectionRun.source_id, func.max(CollectionRun.id).label("id"))
              .group_by(CollectionRun.source_id).subquery())
    runs = session.scalars(select(CollectionRun).join(latest, CollectionRun.id == latest.c.id))
    return {r.source_id: r for r in runs}


def list_runs(session: Session, *, source: str | None, status: str | None, page: int,
              limit: int) -> tuple[list[CollectionRun], int]:
    stmt = select(CollectionRun)
    count = select(func.count()).select_from(CollectionRun)
    if source:
        cond = CollectionRun.source_id == select(Source.id).where(Source.name == source).scalar_subquery()
        stmt, count = stmt.where(cond), count.where(cond)
    if status:
        stmt, count = stmt.where(CollectionRun.status == status), count.where(CollectionRun.status == status)
    total = session.scalar(count) or 0
    runs = session.scalars(stmt.order_by(CollectionRun.id.desc()).offset((page - 1) * limit).limit(limit))
    return list(runs), total


def get_run(session: Session, run_id: int) -> CollectionRun | None:
    return session.get(CollectionRun, run_id)

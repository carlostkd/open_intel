"""
api/routes/export.py — Export endpoints for STIX, MISP, and Sigma.

GET /export/{investigation_id}/stix  — download STIX 2.1 bundle as JSON
GET /export/{investigation_id}/misp  — download MISP event as JSON
GET /export/{investigation_id}/sigma — download Sigma rules as ZIP
"""

from __future__ import annotations

import io
import logging
import os
import uuid
import zipfile

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from api.auth import CurrentUser, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()


class ExportSelectedBody(BaseModel):
    """Subset of entity primary keys to include in an export bundle."""

    entity_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------


def _check_investigation_owner(investigation_id: str, current_user: CurrentUser) -> None:
    """Raise 404 if the investigation does not exist, 403 if the user does not own it."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        uid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    try:
        from db.session import get_session
        from db.queries import get_investigation_by_id_or_run
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, uid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            if str(inv.user_id) != str(current_user.user.id):
                raise HTTPException(status_code=403, detail="Forbidden")
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("_check_investigation_owner failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/{investigation_id}/stix")
async def export_stix(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """
    Return STIX 2.1 bundle as JSON download.

    Content-Type: application/json
    Content-Disposition: attachment; filename="open_intel_{id}_stix.json"
    """
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.stix import investigation_to_stix_bundle, bundle_to_json, _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        entities = _load_entities_for_investigation(str(internal_id))
        if not entities:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No exportable entities found for this investigation. "
                    "Ensure the investigation has completed successfully."
                ),
            )
        bundle = investigation_to_stix_bundle(str(internal_id))
        json_str = bundle_to_json(bundle)
        filename = f"open_intel_{investigation_id}_stix.json"
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_stix failed: %s", exc)
        raise HTTPException(status_code=500, detail="STIX export failed")


@router.get("/{investigation_id}/misp")
async def export_misp(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """
    Return MISP event as JSON download.

    Content-Type: application/json
    Content-Disposition: attachment; filename="open_intel_{id}_misp.json"
    """
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.misp import investigation_to_misp_event, misp_event_to_json  # noqa: PLC0415
        from export.stix import _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        entities = _load_entities_for_investigation(str(internal_id))
        if not entities:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No exportable entities found for this investigation. "
                    "Ensure the investigation has completed successfully."
                ),
            )
        event = investigation_to_misp_event(str(internal_id))
        json_str = misp_event_to_json(event)
        filename = f"open_intel_{investigation_id}_misp.json"
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_misp failed: %s", exc)
        raise HTTPException(status_code=500, detail="MISP export failed")


@router.get("/{investigation_id}/sigma")
async def export_sigma(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> StreamingResponse:
    """
    Generate Sigma rules and return as a ZIP download.

    Content-Type: application/zip
    Content-Disposition: attachment; filename="open_intel_{id}_sigma.zip"
    """
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.sigma import (  # noqa: PLC0415
            entities_to_sigma_rules,
            sigma_rule_to_yaml,
        )
        from export.stix import _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        entities = _load_entities_for_investigation(str(internal_id))
        if not entities:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No exportable entities found for this investigation. "
                    "Ensure the investigation has completed successfully."
                ),
            )
        rules = entities_to_sigma_rules(entities)
        if not rules:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No Sigma-compatible entities found (requires IP_ADDRESS, "
                    "ONION_URL, CVE_NUMBER, MALWARE_FAMILY, or RANSOMWARE_GROUP)."
                ),
            )

        # Build zip in memory
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rule in rules:
                rule_id = rule.get("id", str(uuid.uuid4()))
                yaml_content = sigma_rule_to_yaml(rule)
                zf.writestr(f"{rule_id}.yml", yaml_content)
        buf.seek(0)

        filename = f"open_intel_{investigation_id}_sigma.zip"
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_sigma failed: %s", exc)
        raise HTTPException(status_code=500, detail="Sigma export failed")


@router.post("/{investigation_id}/stix/selected")
async def export_stix_selected(
    investigation_id: str,
    body: ExportSelectedBody,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """STIX bundle including only the given entity rows (or all if *entity_ids* is empty)."""
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.stix import investigation_to_stix_bundle, bundle_to_json  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        bundle = investigation_to_stix_bundle(
            str(internal_id),
            entity_ids=body.entity_ids or None,
        )
        json_str = bundle_to_json(bundle)
        filename = f"open_intel_{investigation_id}_stix.json"
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_stix_selected failed: %s", exc)
        raise HTTPException(status_code=500, detail="STIX export failed")


@router.post("/{investigation_id}/misp/selected")
async def export_misp_selected(
    investigation_id: str,
    body: ExportSelectedBody,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """MISP JSON including only the given entities (or all if *entity_ids* is empty)."""
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.misp import investigation_to_misp_event, misp_event_to_json  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        event = investigation_to_misp_event(
            str(internal_id),
            entity_ids=body.entity_ids or None,
        )
        json_str = misp_event_to_json(event)
        filename = f"open_intel_{investigation_id}_misp.json"
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_misp_selected failed: %s", exc)
        raise HTTPException(status_code=500, detail="MISP export failed")


@router.post("/{investigation_id}/sigma/selected")
async def export_sigma_selected(
    investigation_id: str,
    body: ExportSelectedBody,
    current_user: CurrentUser = Depends(get_current_user),
) -> StreamingResponse:
    """Sigma ZIP built from a subset of entities (or all if *entity_ids* is empty)."""
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.sigma import (  # noqa: PLC0415
            entities_to_sigma_rules,
            sigma_rule_to_yaml,
        )
        from export.stix import _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        filter_ids = None
        if body.entity_ids:
            filter_ids = []
            for raw in body.entity_ids:
                try:
                    filter_ids.append(uuid.UUID(str(raw)))
                except (ValueError, AttributeError):
                    continue
        entities = _load_entities_for_investigation(
            str(internal_id),
            entity_ids=filter_ids,
        )
        rules = entities_to_sigma_rules(entities)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rule in rules:
                rule_id = rule.get("id", str(uuid.uuid4()))
                yaml_content = sigma_rule_to_yaml(rule)
                zf.writestr(f"{rule_id}.yml", yaml_content)
        buf.seek(0)

        filename = f"open_intel_{investigation_id}_sigma.zip"
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_sigma_selected failed: %s", exc)
        raise HTTPException(status_code=500, detail="Sigma export failed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_internal_investigation_id(investigation_id: str) -> uuid.UUID:
    """Map URL *investigation_id* (primary key or ``run_id``) to internal investigation PK."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        uid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import get_investigation_by_id_or_run  # noqa: PLC0415

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, uid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            return inv.id
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("_resolve_internal_investigation_id failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


def _validate_uuid(value: str) -> None:
    """Raise HTTPException 422 if value is not a valid UUID string."""
    try:
        uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

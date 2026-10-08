from __future__ import annotations
import asyncio, os, uuid
import click
from sqlalchemy import select
from app.core.database import session_factory
from app.models.admin import Admin, AdminRole
from app.security.passwords import hash_password
from app.core import logging as aegis_logging

log = aegis_logging.logger

async def _create(email: str, password: str, name: str | None) -> None:
    sf = session_factory()
    async with sf() as session:
        r = await session.execute(select(Admin).where(Admin.email == email))
        existing = r.scalar_one_or_none()
        if existing:
            click.echo(f'Admin {email} already exists.')
            return
        admin = Admin(id=uuid.uuid4(), email=email, password_hash=hash_password(password),
            full_name=name, role=AdminRole.SUPER_ADMIN)
        session.add(admin)
        await session.commit()
        click.echo(f'Admin created: {email} (id={admin.id})')

@click.command()
@click.option('--email', envvar='AEGIS_ADMIN_EMAIL', prompt=True)
@click.option('--password', envvar='AEGIS_ADMIN_PASSWORD', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--name', default=None, help='Display name')
def cli(email: str, password: str, name: str | None) -> None:
    import os
    os.environ.setdefault('AEGIS_ENV_FILE', os.path.join(os.path.dirname(__file__), '..', '..', '.env'))
    asyncio.run(_create(email, password, name))

if __name__ == '__main__':
    cli()

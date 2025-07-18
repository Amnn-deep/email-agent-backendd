from app.database import engine
from app.models.user import User
from sqlalchemy import inspect, text

# Add new columns if they don't. exist (for dev convenience)
def add_column_if_not_exists(table, column):
    insp = inspect(engine)
    if column not in [col['name'] for col in insp.get_columns(table)]:
        with engine.connect() as conn:
            conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} VARCHAR'))

if __name__ == "__main__":
    add_column_if_not_exists('users', 'google_refresh_token')
    add_column_if_not_exists('users', 'google_token_expiry')
    print("Columns added if not present.")

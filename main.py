from database.db import Database

db = Database()
history = db.get_history()

for item in history:
    print(item)
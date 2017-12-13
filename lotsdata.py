from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from model import Category, Item, Base, User

engine = create_engine('sqlite:///usersWithOAuth.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Create dummy user


item_1 = Item(user_id=1, title="test1", description="test1", category_id=1)

session.add(item_1)
session.commit()

item_1 = Item(user_id=1, title="test2", description="test2", category_id=2)

session.add(item_1)
session.commit()

item_1 = Item(user_id=1, title="test3", description="test3", category_id=2)

session.add(item_1)
session.commit()

item_1 = Item(user_id=1, title="test4", description="test4", category_id=1)

session.add(item_1)
session.commit()

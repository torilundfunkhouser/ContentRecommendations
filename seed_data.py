#!/usr/bin/python

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Content, Base, Recommendations, User

import re

engine = create_engine('sqlite:///recommendations.db')
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
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

User2 = User(name="Tori Funkhouser", email="tori@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User2)
session.commit()


# Netflix content
content1 = Content(user_id=1, name="Netflix")

session.add(content1)
session.commit()


rec2 = Recommendations(user_id=1, name="The Crown", description="a young queen learns \
                        how to rule in post-WWII England", source="Netflix",
                        content=content1)

session.add(rec2)
session.commit()


rec3 = Recommendations(user_id=1, name="Bojack Horseman", description="An aging famous actor \
                        who is also a horse has an existential crisis",
                        source="Netflix", content=content1)

session.add(rec3)
session.commit()


# Amazon Prime content
content2 = Content(user_id=1, name="Amazon Originals")

session.add(content2)
session.commit()


rec4 = Recommendations(user_id=1, name="Sneaky Pete", description="a con man gets out of jail \
                                                moves in with a family of bailbondsman.", 
                                                source="Amazon Originals", content=content2)

session.add(rec4)
session.commit()


rec5 = Recommendations(user_id=1, name="The Marvelous Mrs. Masel", description="A wealthy NYC \
                        housewife in the 1950's becomes a standup comedian.",
                        source="Amazon Originals", content=content2)

session.add(rec5)
session.commit()

# Hulu content
content3 = Content(user_id=1, name="Hulu")

session.add(content3)
session.commit()


rec6 = Recommendations(user_id=1, name="The Handmaid's Tale", description="Fertile women get \
                                                abducted in post-apocalypse.", 
                                                source="Hulu", content=content3)

session.add(rec6)
session.commit()

print "added content items!"

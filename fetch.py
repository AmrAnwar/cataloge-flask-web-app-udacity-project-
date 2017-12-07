from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from model import Base, Restaurant, User
from flask import session as login_session
import random
import string

import json
from flask import make_response

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


def fetch_user(user_id=None):
    data = session.query(Restaurant).filter_by(user_id=user_id).all()
    print data[0].user.username

if __name__ == '__main__':
    fetch_user(1)
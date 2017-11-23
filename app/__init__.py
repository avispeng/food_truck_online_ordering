from flask import Flask

webapp = Flask(__name__)

from app import main
from app import truck_owner
from app import refresh

webapp.secret_key = 'HoldOnToTheMemoriesTheyWillHoldOnToYou'
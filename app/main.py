from flask import render_template, url_for
from app import webapp


@webapp.route('/')
def main():
    """
    Welcome page where you could choose either customer entrance or truck owner entrance
    :return: a html page
    """
    return render_template("main.html",title="Food Truck Online Ordering System")